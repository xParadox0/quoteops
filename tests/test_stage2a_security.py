"""Stage 2a cross-cutting security: CSRF and Origin on every POST, response headers on every route
including errors, links in mail never built from the Host header, nothing secret in the logs, and
the page rules (no script, no external request, labelled fields)."""
import importlib
import logging
import re

import pytest
from fastapi.testclient import TestClient

from tests.stage2a_support import (  # noqa: F401  (adb and env are fixtures)
    BASE, NEW_PASSWORD, PASSWORD, account, adb, app_csrf, csrf_from, env, finish_signup, forgot,
    form_csrf, login, path_of, reset_link, session_cookie, signed_up, signup, token_of,
    verify_link,
)

CSP = ("default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none';"
       " base-uri 'none'")


# --- CSRF and Origin --------------------------------------------------------------------------------

def _state(env):
    with env.owner() as c:
        return {
            "companies": c.execute("SELECT count(*) FROM company").fetchone()[0],
            "users": c.execute("SELECT array_agg(pw_hash ORDER BY email) FROM app_user").fetchone()[0],
            "verified": c.execute("SELECT count(email_verified_at) FROM app_user").fetchone()[0],
            "sessions": c.execute("SELECT count(*) FROM session").fetchone()[0],
            "throttle": c.execute("SELECT count(*), coalesce(sum(hits), 0) FROM auth_throttle").fetchone(),
            "mails": len(env.mails()),
        }


def _prepare(env, route):
    """Returns (client, path, valid form data) for one POST route, with an account in place."""
    owner = account(env, "owner@shop.test")
    if route == "logout":
        return owner, "/logout", {"csrf": app_csrf(owner)}
    c = env.client()
    if route == "signup":
        return c, "/signup", {"csrf": form_csrf(c, "/signup"), "email": "new@shop.test",
                              "company": "New", "terms": "yes"}
    if route == "login":
        return c, "/login", {"csrf": form_csrf(c, "/login"), "email": "owner@shop.test",
                             "password": PASSWORD}
    if route == "forgot":
        return c, "/forgot", {"csrf": form_csrf(c, "/forgot"), "email": "owner@shop.test"}
    if route == "verify":
        signed_up(env, "new@shop.test", ip="192.0.2.201")
        link = verify_link(env, "new@shop.test")
        return c, "/verify", {"csrf": csrf_from(c.get(path_of(link)).text), "token": token_of(link),
                              "password": NEW_PASSWORD, "company": "New", "terms": "yes"}
    forgot(env.client(), "owner@shop.test")
    token = token_of(reset_link(env, "owner@shop.test"))
    return c, "/reset", {"csrf": csrf_from(c.get("/reset", params={"token": token}).text),
                         "token": token, "password": NEW_PASSWORD}


def _other_session_csrf(env, route):
    if route == "logout":
        other = account(env, "other@shop.test", ip="192.0.2.200")
        return app_csrf(other)
    other = env.client()
    return form_csrf(other, "/login")


ROUTES = ["signup", "verify", "login", "forgot", "reset", "logout"]
MODES = ["missing", "wrong", "other_session", "wrong_origin", "null_origin", "no_origin_no_referer",
         "foreign_referer"]


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("route", ROUTES)
def test_post_refused_without_valid_csrf_or_origin(env, route, mode):
    client, path, data = _prepare(env, route)
    headers = {}
    if mode == "missing":
        data.pop("csrf")
    elif mode == "wrong":
        data["csrf"] = "A" * len(data["csrf"])
    elif mode == "other_session":
        data["csrf"] = _other_session_csrf(env, route)
    elif mode == "wrong_origin":
        headers["Origin"] = "https://evil.example"
    elif mode == "null_origin":
        headers["Origin"] = "null"
    before = _state(env)
    if mode in ("no_origin_no_referer", "foreign_referer"):
        saved = client.headers.pop("Origin")
        if mode == "foreign_referer":
            headers["Referer"] = "https://evil.example/login"
        try:
            r = client.post(path, data=data, headers=headers)
        finally:
            client.headers["Origin"] = saved
    else:
        r = client.post(path, data=data, headers=headers)
    assert r.status_code == 403, (route, mode, r.status_code)
    assert "set-cookie" not in r.headers
    assert _state(env) == before


@pytest.mark.parametrize("route", ROUTES)
def test_post_accepted_with_valid_csrf_and_origin(env, route):
    client, path, data = _prepare(env, route)
    before = _state(env)
    r = client.post(path, data=data)
    after = _state(env)
    assert r.status_code in (200, 303), (route, r.status_code, r.text)
    # The change each accepted POST implies.
    if route == "signup":
        assert after["companies"] == before["companies"] + 1
        assert "/verify?token=" in env.mails_to("new@shop.test")[-1].body
    elif route == "login":
        assert r.status_code == 303 and after["sessions"] == before["sessions"] + 1
        assert "qo_session=" in r.headers.get("set-cookie", "")
    elif route == "forgot":
        assert after["mails"] == before["mails"] + 1
        assert "/reset?token=" in env.mails_to("owner@shop.test")[-1].body
    elif route == "verify":
        assert after["users"] != before["users"] and after["verified"] == before["verified"] + 1
        assert after["sessions"] == before["sessions"] and "qo_session=" not in r.headers.get(
            "set-cookie", "")
    elif route == "reset":
        assert after["users"] != before["users"] and after["sessions"] == 0
        assert after["mails"] == before["mails"] + 1
    else:
        assert r.status_code == 303 and after["sessions"] == before["sessions"] - 1


def test_referer_is_used_when_origin_is_absent(env):
    account(env, "owner@shop.test")
    c = env.client()
    data = {"csrf": form_csrf(c, "/login"), "email": "owner@shop.test", "password": PASSWORD}
    c.headers.pop("Origin")
    r = c.post("/login", data=data, headers={"Referer": BASE + "/login"})
    assert r.status_code == 303


# --- headers ----------------------------------------------------------------------------------------

def _assert_headers(r, cache="no-store"):
    h = r.headers
    assert h.get("content-security-policy") == CSP, r.url
    assert h.get("x-content-type-options") == "nosniff", r.url
    assert h.get("referrer-policy") == "same-origin", r.url
    assert h.get("x-frame-options") == "DENY", r.url
    if cache == "no-store":
        assert h.get("cache-control") == "no-store", r.url
    else:
        assert "max-age" in h.get("cache-control", ""), r.url


def test_headers_on_every_route(env):
    signed = account(env, "owner@shop.test")
    anon = env.client()
    for c in (anon, signed):
        for path in ("/", "/app", "/login", "/signup", "/forgot", "/reset", "/reset?token=x",
                     "/verify", "/verify?token=x", "/terms", "/privacy", "/healthz", "/nope"):
            _assert_headers(c.get(path))
        _assert_headers(c.delete("/login"))  # 405
        _assert_headers(c.post("/login", data={}))  # 403
    _assert_headers(anon.get("/static/app.css"), cache="static")
    assert anon.get("/static/app.css").headers["content-type"].startswith("text/css")


def test_404_405_422_are_generic_html(env):
    c = env.client()
    r = c.get("/nope")
    assert r.status_code == 404 and r.headers["content-type"].startswith("text/html")
    assert "detail" not in r.text
    r = c.delete("/login")
    assert r.status_code == 405 and r.headers["content-type"].startswith("text/html")
    assert set(r.headers["allow"].replace(" ", "").split(",")) == {"GET", "POST"}
    from fastapi import FastAPI
    t = FastAPI()
    importlib.import_module("quoteops.app").configure(t)

    @t.get("/n")
    def n(x: int):
        return {"x": x}

    r = TestClient(t, base_url=BASE).get("/n?x=notanumber")
    assert r.status_code == 422 and r.headers["content-type"].startswith("text/html")
    assert "notanumber" not in r.text and "int_parsing" not in r.text and "integer" not in r.text
    _assert_headers(r)


def test_500_is_generic_with_headers_and_logs_class_only(env, monkeypatch, caplog):
    auth = importlib.import_module("quoteops.auth")

    class SecretBoom(Exception):
        pass

    def boom(*a, **kw):
        raise SecretBoom("detail-that-must-not-leak owner@shop.test")

    # Sign-in, not sign-up: the sign-up inserts now run after the answer and cannot change it.
    monkeypatch.setattr(auth, "_lookup", boom)
    caplog.set_level(logging.DEBUG)
    r = login(env.client(raise_server_exceptions=False), "owner@shop.test")
    assert r.status_code == 500 and r.headers["content-type"].startswith("text/html")
    assert "detail-that-must-not-leak" not in r.text and "SecretBoom" not in r.text
    _assert_headers(r)
    texts = [x.getMessage() + str(x.exc_text or "") for x in caplog.records]
    assert any("SecretBoom" in t for t in texts)
    assert not any("detail-that-must-not-leak" in t or "owner@shop.test" in t for t in texts)
    assert not any(x.exc_info for x in caplog.records)


# --- Host header injection --------------------------------------------------------------------------

def test_mail_links_ignore_host_header(env):
    evil = {"Host": "evil.example", "X-Forwarded-Host": "evil.example"}
    c = env.client()
    c.headers.update(evil)
    signup(c, "owner@shop.test")
    signup(c, "owner@shop.test")   # a second verification mail: the account is not verified
    forgot(c, "owner@shop.test")
    finish_signup(c, verify_link(env, "owner@shop.test"))
    login(c, "owner@shop.test")
    forgot(c, "owner@shop.test")
    token = token_of(reset_link(env, "owner@shop.test"))
    r = c.get("/reset", params={"token": token})
    c.post("/reset", data={"csrf": csrf_from(r.text), "token": token, "password": NEW_PASSWORD})
    mails = env.mails()
    assert len(mails) >= 5
    links = [x for m in mails for x in m.links]
    assert links
    for m in mails:
        assert "evil.example" not in m.body
    assert all(x.startswith(BASE + "/") for x in links), links


# --- logs -------------------------------------------------------------------------------------------

def test_no_token_password_or_email_in_logs(env, caplog):
    caplog.set_level(logging.DEBUG)
    email = "secretive.owner@shop.test"
    c = env.client()
    signup(c, email)
    verify = token_of(verify_link(env, email))
    finish_signup(c, verify_link(env, email))
    login(c, email, "wrong password here")
    login(c, email)
    session = session_cookie(c)
    csrf = app_csrf(c)
    forgot(c, email)
    reset = token_of(reset_link(env, email))
    r = c.get("/reset", params={"token": reset})
    c.post("/reset", data={"csrf": csrf_from(r.text), "token": reset, "password": NEW_PASSWORD})
    login(c, email, NEW_PASSWORD)
    c.post("/logout", data={"csrf": app_csrf(c)})
    secrets_ = [email, "secretive.owner", PASSWORD, NEW_PASSWORD, "wrong password here", verify,
                reset, session, csrf]
    # httpx and httpcore are the test client's own loggers, not the application's.
    records = [x for x in caplog.records if not x.name.startswith(("httpx", "httpcore"))]
    for x in records:
        text = f"{x.getMessage()} {x.args!r} {x.exc_text or ''}"
        for s in secrets_:
            assert s not in text, (x.name, s)


# --- pages ------------------------------------------------------------------------------------------

def test_pages_have_no_script_no_external_requests_and_labelled_fields(env):
    signed = account(env, "owner@shop.test")
    forgot(env.client(), "owner@shop.test")
    reset = path_of(reset_link(env, "owner@shop.test"))
    pages = {p: env.client().get(p) for p in ("/login", "/signup", "/forgot", "/terms", "/privacy")}
    pages[reset] = env.client().get(reset)
    pages["/app"] = signed.get("/app")
    for p, r in pages.items():
        assert r.status_code == 200, p
        html = r.text
        assert "<script" not in html.lower() and "javascript:" not in html.lower(), p
        assert " style=" not in html and "<style" not in html, p
        assert not re.search(r'(src|href|action)="(https?:)?//', html), p
        for m in re.finditer(r"<input([^>]*)>", html):
            attrs = m.group(1)
            if 'type="hidden"' in attrs:
                continue
            ident = re.search(r'id="([^"]+)"', attrs)
            assert ident, (p, attrs)
            assert f'<label for="{ident.group(1)}"' in html, (p, ident.group(1))
        assert 'href="/static/app.css"' in html, p


def test_terms_and_privacy_are_marked_as_drafts(env):
    for p in ("/terms", "/privacy"):
        text = env.client().get(p).text.lower()
        assert "draft" in text and "not yet the published" in text, p


def test_css_has_tokens_focus_and_light_theme(env):
    css = env.client().get("/static/app.css").text
    for token in ("#090B10", "#F7F9FC", "#B8C2D1", "#55DFFF", "#7A5CFF", "#FF667D"):
        assert token.lower() in css.lower(), token
    assert "prefers-color-scheme: light" in css
    assert ":focus-visible" in css and "44px" in css
    assert "@import" not in css and "url(" not in css
