"""Stage 2b part 2: the admin service (quoteops.admin_app). One-step sign-in with email, password
and an authenticator code; every failure is the same answer; one scrypt and three code checks on
every path; the throttles; sessions in admin_session; CSRF and Origin; headers; and the
separation from the public web app."""
import hashlib
import importlib
import logging
import re
import threading

import psycopg
import pytest
from fastapi.testclient import TestClient

from tests.stage2a_support import (  # noqa: F401  (adb and env are fixtures)
    BASE, IP_HEADER, PASSWORD, SECRET, account, adb, csrf_from, env, forgot, form_csrf,
    session_cookie, signup,
)
from tests.stage2b2_support import (  # noqa: F401  (aenv is a fixture)
    ADMIN_BASE, ADMIN_EMAIL, ADMIN_PASSWORD, ADMIN_SECRET, GENERIC, STEP, T0, TRY_LATER, aenv,
    admin_csrf, admin_login, admin_throttle_key, company_user, mod, page_csrf, sha256,
    signed_in_admin,
)
from tests.test_stage2a_fix3 import _assert_busy, _blocked, _no_connection, _throttle_rows

CSP = ("default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none';"
       " base-uri 'none'")
COOKIE_RE = re.compile(r"[A-Za-z0-9_-]{43}")


def _count(monkeypatch, module, name):
    calls = []
    real = getattr(module, name)

    def counting(*a, **kw):
        calls.append(1)
        return real(*a, **kw)
    monkeypatch.setattr(module, name, counting)
    return calls


def _counters(aenv):
    """(scrypt computations, HOTP computations) made from now on."""
    return (_count(aenv.monkeypatch, mod("passwords"), "_scrypt"),
            _count(aenv.monkeypatch, mod("totp"), "hotp"))


def _assert_headers(r):
    h = r.headers
    assert h.get("content-security-policy") == CSP, r.url
    assert h.get("x-content-type-options") == "nosniff", r.url
    assert h.get("referrer-policy") == "same-origin", r.url
    assert h.get("x-frame-options") == "DENY", r.url
    assert h.get("cache-control") == "no-store", r.url
    assert "strict-transport-security" not in h  # the web app sends none either


def _set_cookie(r, name):
    found = [v for k, v in r.headers.multi_items() if k == "set-cookie" and v.startswith(name + "=")]
    assert len(found) == 1, r.headers
    return found[0]


def _far_code(aenv, secret):
    """A well-formed code of the secret that is not valid in the window around the clock."""
    window = {aenv.code(secret, k) for k in (-1, 0, 1)}
    for k in range(10, 40):
        code = aenv.code(secret, k)
        if code not in window:
            return code
    raise AssertionError("no code outside the window")


def _wide_limits(aenv):
    aenv.monkeypatch.setenv("QO_ADMIN_LOGIN_FAILS_PER_EMAIL", "100")
    aenv.monkeypatch.setenv("QO_ADMIN_LOGIN_FAILS_PER_IP", "1000")


# --- routes ---------------------------------------------------------------------------------------

def test_the_admin_service_has_exactly_these_routes(aenv):
    app = mod("admin_app").app
    routes = {(r.path, frozenset(r.methods)) for r in app.routes}
    assert routes == {("/healthz", frozenset({"GET", "HEAD"})), ("/", frozenset({"GET"})),
                      ("/login", frozenset({"GET"})), ("/login", frozenset({"POST"})),
                      ("/admin", frozenset({"GET"})), ("/logout", frozenset({"POST"}))}
    assert app.docs_url is None and app.redoc_url is None and app.openapi_url is None


def test_anonymous_answers(aenv):
    c = aenv.admin_client()
    r = c.get("/")
    assert r.status_code == 303 and r.headers["location"] == "/login"
    r = c.get("/admin")
    assert r.status_code == 303 and r.headers["location"] == "/login"
    r = c.get("/login")
    assert r.status_code == 200
    for name in ("email", "password", "code", "csrf"):
        assert f'name="{name}"' in r.text, name
    assert 'autocomplete="one-time-code"' in r.text and 'inputmode="numeric"' in r.text
    assert "<a " not in r.text and "<script" not in r.text and "/static/" not in r.text
    for path in ("/docs", "/redoc", "/openapi.json", "/static/app.css", "/app", "/signup",
                 "/team", "/forgot", "/nope"):
        r = c.get(path)
        assert r.status_code == 404, path
        assert r.headers["content-type"].startswith("text/html") and "detail" not in r.text


@pytest.mark.parametrize("method,path,allow", [
    ("DELETE", "/login", {"GET", "POST"}), ("PUT", "/login", {"GET", "POST"}),
    ("GET", "/logout", {"POST"}), ("POST", "/admin", {"GET"}), ("POST", "/healthz", {"GET", "HEAD"}),
    ("POST", "/", {"GET"})])
def test_wrong_methods_answer_405_with_allow(aenv, method, path, allow):
    r = aenv.admin_client().request(method, path)
    assert r.status_code == 405 and r.headers["content-type"].startswith("text/html")
    assert set(r.headers["allow"].replace(" ", "").split(",")) == allow
    _assert_headers(r)


def test_healthz_uses_the_admin_role(aenv, monkeypatch):
    users, real = [], psycopg.connect

    def connect(conninfo="", **kw):
        users.append(psycopg.conninfo.conninfo_to_dict(conninfo, **kw).get("user"))
        return real(conninfo, **kw)
    monkeypatch.setattr(psycopg, "connect", connect)
    c = aenv.admin_client()
    r = c.get("/healthz")
    assert r.status_code == 200 and r.text == "ok"
    assert c.head("/healthz").status_code == 200
    assert users and set(users) == {"qo_admin"}
    monkeypatch.setenv("QO_DB_PORT", "1")
    r = c.get("/healthz")
    assert r.status_code == 503 and r.json() == {"detail": "database check failed"}
    _assert_headers(r)


# --- sign-in success ------------------------------------------------------------------------------

def test_sign_in_with_password_and_code(aenv):
    secret = aenv.create_admin()
    c = aenv.admin_client(ip="192.0.2.50")
    r = admin_login(c, code=aenv.code(secret))
    assert r.status_code == 303 and r.headers["location"] == "/admin"
    cookie = _set_cookie(r, "qo_admin")
    attrs = [a.strip().lower() for a in cookie.split(";")]
    value = cookie.split(";", 1)[0].split("=", 1)[1]
    assert COOKIE_RE.fullmatch(value)
    assert "httponly" in attrs and "secure" in attrs and "samesite=strict" in attrs
    assert "path=/" in attrs and "max-age=28800" in attrs
    assert not any(a.startswith("domain") for a in attrs)
    with aenv.owner() as o:
        rows = o.execute("SELECT id_hash, user_id, host(created_ip),"
                         " extract(epoch FROM expires_at - now()) FROM admin_session").fetchall()
        last = o.execute("SELECT last_counter FROM admin_factor").fetchone()[0]
    assert len(rows) == 1
    id_hash, uid, ip, left = rows[0]
    assert bytes(id_hash) == sha256(value) and bytes(id_hash) != value.encode()
    assert uid == aenv.user_id(ADMIN_EMAIL) and ip == "192.0.2.50"
    assert 8 * 3600 - 60 < float(left) <= 8 * 3600
    assert last == int(T0) // STEP
    page = c.get("/admin")
    assert page.status_code == 200
    assert ADMIN_EMAIL in page.text and "Session ends" in page.text
    assert 'action="/logout"' in page.text and 'method="post"' in page.text
    assert "<a " not in page.text and "<script" not in page.text
    assert c.get("/").headers["location"] == "/admin"
    r = c.get("/login")
    assert r.status_code == 303 and r.headers["location"] == "/admin"


def test_pre_session_cookie_is_strict_and_http_only(aenv):
    r = aenv.admin_client().get("/login")
    attrs = [a.strip().lower() for a in _set_cookie(r, "qo_admin_csrf").split(";")]
    assert "httponly" in attrs and "secure" in attrs and "samesite=strict" in attrs


def test_previous_and_next_step_accepted_and_older_codes_refused(aenv):
    secret = aenv.create_admin()
    assert admin_login(aenv.admin_client(), code=aenv.code(secret, -1)).status_code == 303
    assert admin_login(aenv.admin_client(), code=aenv.code(secret, 1)).status_code == 303
    # The current step's code is older than the one just used: refused.
    assert admin_login(aenv.admin_client(), code=aenv.code(secret, 0)).status_code == 400
    aenv.tick(2)
    assert admin_login(aenv.admin_client(), code=aenv.code(secret)).status_code == 303
    assert aenv.admin_sessions() == 3


@pytest.mark.parametrize("steps", [-2, 2])
def test_two_steps_away_refused(aenv, steps):
    secret = aenv.create_admin()
    code = aenv.code(secret, steps)
    assert code not in {aenv.code(secret, k) for k in (-1, 0, 1)}
    r = admin_login(aenv.admin_client(), code=code)
    assert r.status_code == 400 and GENERIC in r.text
    assert aenv.admin_sessions() == 0


def test_session_hours_setting(aenv):
    aenv.monkeypatch.setenv("QO_ADMIN_SESSION_HOURS", "2")
    secret = aenv.create_admin()
    r = admin_login(aenv.admin_client(), code=aenv.code(secret))
    assert "max-age=7200" in _set_cookie(r, "qo_admin").lower()
    left = aenv.scalar("SELECT extract(epoch FROM expires_at - now()) FROM admin_session")
    assert 2 * 3600 - 60 < float(left) <= 2 * 3600


# --- every failure looks the same -----------------------------------------------------------------

def test_every_failure_is_the_same_answer_with_one_scrypt(aenv):
    _wide_limits(aenv)
    secret = aenv.create_admin()
    off = aenv.create_admin("off@ops.test")
    with aenv.owner() as o:
        o.execute("UPDATE app_user SET disabled_at = now() WHERE email = 'off@ops.test'")
    for email, role in (("owner@shop.test", "owner"), ("est@shop.test", "estimator"),
                        ("view@shop.test", "viewer")):
        company_user(aenv, email, role)
    good, far = aenv.code(secret), _far_code(aenv, secret)
    fullwidth = "".join(chr(0xFF10 + int(ch)) for ch in good)
    arabic = "".join(chr(0x0660 + int(ch)) for ch in good)
    cases = {
        "unknown address": ("nobody@ops.test", ADMIN_PASSWORD, good),
        "not an address": ("not-an-address", ADMIN_PASSWORD, good),
        "owner, right password, made-up code": ("owner@shop.test", PASSWORD, "123456"),
        "owner, right password, the admin's code": ("owner@shop.test", PASSWORD, good),
        "estimator": ("est@shop.test", PASSWORD, good),
        "viewer": ("view@shop.test", PASSWORD, "654321"),
        "disabled admin": ("off@ops.test", ADMIN_PASSWORD, aenv.code(off)),
        "wrong password, right code": (ADMIN_EMAIL, ADMIN_PASSWORD + "x", good),
        "right password, wrong code": (ADMIN_EMAIL, ADMIN_PASSWORD, far),
        "wrong password, wrong code": (ADMIN_EMAIL, "nope nope nope", far),
        "two steps back": (ADMIN_EMAIL, ADMIN_PASSWORD, aenv.code(secret, -2)),
        "two steps ahead": (ADMIN_EMAIL, ADMIN_PASSWORD, aenv.code(secret, 2)),
        "empty code": (ADMIN_EMAIL, ADMIN_PASSWORD, ""),
        "five digits": (ADMIN_EMAIL, ADMIN_PASSWORD, good[:5]),
        "seven digits": (ADMIN_EMAIL, ADMIN_PASSWORD, good + "0"),
        "letters": (ADMIN_EMAIL, ADMIN_PASSWORD, "abcdef"),
        "space inside": (ADMIN_EMAIL, ADMIN_PASSWORD, good[:3] + " " + good[3:]),
        "space around": (ADMIN_EMAIL, ADMIN_PASSWORD, " " + good),
        "trailing newline": (ADMIN_EMAIL, ADMIN_PASSWORD, good + "\n"),
        "fullwidth digits": (ADMIN_EMAIL, ADMIN_PASSWORD, fullwidth),
        "arabic-indic digits": (ADMIN_EMAIL, ADMIN_PASSWORD, arabic),
        "empty password": (ADMIN_EMAIL, "", good),
    }
    c = aenv.admin_client()
    csrf = admin_csrf(c)
    scrypts, hotps = _counters(aenv)
    answers = {}
    for name, (email, password, code) in cases.items():
        before = (len(scrypts), len(hotps))
        r = admin_login(c, email, password, code, csrf=csrf)
        answers[name] = r
        assert (len(scrypts) - before[0], len(hotps) - before[1]) == (1, 3), name
    ref = answers["right password, wrong code"]
    assert ref.status_code == 400 and GENERIC in ref.text
    assert ADMIN_EMAIL not in ref.text
    for name, r in answers.items():
        assert r.status_code == ref.status_code, name
        assert r.content == ref.content, name
        assert sorted(r.headers.multi_items()) == sorted(ref.headers.multi_items()), name
    assert aenv.admin_sessions() == 0
    assert aenv.scalar("SELECT max(last_counter) FROM admin_factor") == 0


def test_replay_of_a_used_code_is_refused_like_a_wrong_code(aenv):
    secret = aenv.create_admin()
    code = aenv.code(secret)
    assert admin_login(aenv.admin_client(), code=code).status_code == 303
    c = aenv.admin_client()
    csrf = admin_csrf(c)
    scrypts, hotps = _counters(aenv)
    replay = admin_login(c, code=code, csrf=csrf)
    assert (len(scrypts), len(hotps)) == (1, 3)
    wrong = admin_login(c, code=_far_code(aenv, secret), csrf=csrf)
    assert replay.status_code == 400 and replay.content == wrong.content
    assert aenv.admin_sessions() == 1


def test_the_same_code_in_parallel_gives_exactly_one_session(aenv):
    secret = aenv.create_admin()
    code = aenv.code(secret)
    clients = [aenv.admin_client() for _ in range(2)]
    tokens = [admin_csrf(c) for c in clients]
    barrier, results = threading.Barrier(2), []

    def go(c, csrf):
        barrier.wait(5)
        results.append(admin_login(c, code=code, csrf=csrf).status_code)
    threads = [threading.Thread(target=go, args=(c, t)) for c, t in zip(clients, tokens)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    assert sorted(results) == [303, 400]
    assert aenv.admin_sessions() == 1


def test_a_new_sign_in_deletes_the_old_session_of_that_browser(aenv):
    secret = aenv.create_admin()
    c = aenv.admin_client()
    csrf = admin_csrf(c)  # a signed-in browser is sent from /login to /admin
    assert admin_login(c, code=aenv.code(secret), csrf=csrf).status_code == 303
    first = c.cookies.get("qo_admin")
    aenv.tick()
    assert admin_login(c, code=aenv.code(secret), csrf=csrf).status_code == 303
    assert c.cookies.get("qo_admin") != first
    with aenv.owner() as o:
        hashes = [bytes(r[0]) for r in o.execute("SELECT id_hash FROM admin_session")]
    assert hashes == [sha256(c.cookies.get("qo_admin"))]


# --- throttles ------------------------------------------------------------------------------------

def test_lockout_after_five_failures_blocks_even_the_right_code(aenv):
    secret = aenv.create_admin()
    c = aenv.admin_client()
    csrf = admin_csrf(c)
    for _ in range(5):
        assert admin_login(c, code=_far_code(aenv, secret), csrf=csrf).status_code == 400
    with aenv.owner() as o:
        keys = {bytes(r[0]) for r in o.execute(
            "SELECT key FROM auth_throttle WHERE kind = 'admin_login_email'")}
    assert keys == {admin_throttle_key("admin_login_email", ADMIN_EMAIL)}
    good = aenv.code(secret)
    scrypts, hotps = _counters(aenv)
    blocked = admin_login(c, code=good, csrf=csrf)
    assert blocked.status_code == 429 and GENERIC in blocked.text and TRY_LATER in blocked.text
    assert (len(scrypts), len(hotps)) == (0, 0)
    assert aenv.admin_sessions() == 0
    assert aenv.scalar("SELECT last_counter FROM admin_factor") == 0
    # An unknown address that is blocked gets the same 429 answer.
    for _ in range(6):
        other = admin_login(c, "nobody@ops.test", code="123456", csrf=csrf)
    assert other.status_code == 429 and other.content == blocked.content
    # The block ends.
    with aenv.owner() as o:
        o.execute("UPDATE auth_throttle SET blocked_until = now() - interval '1 second',"
                  " window_start = now() - interval '16 minutes'"
                  " WHERE kind = 'admin_login_email'")
    assert admin_login(c, code=aenv.code(secret), csrf=csrf).status_code == 303
    assert aenv.scalar("SELECT count(*) FROM auth_throttle WHERE key = %s",
                       (admin_throttle_key("admin_login_email", ADMIN_EMAIL),)) == 0


def test_success_resets_the_address_counter(aenv):
    secret = aenv.create_admin()
    c = aenv.admin_client()
    csrf = admin_csrf(c)
    for _ in range(4):
        assert admin_login(c, code="000000", csrf=csrf).status_code == 400
    assert admin_login(c, code=aenv.code(secret), csrf=csrf).status_code == 303
    aenv.tick()
    for _ in range(5):
        assert admin_login(c, code="000000", csrf=csrf).status_code == 400
    assert admin_login(c, code="000000", csrf=csrf).status_code == 429


def test_per_network_limit(aenv):
    aenv.monkeypatch.setenv("QO_ADMIN_LOGIN_FAILS_PER_IP", "3")
    secret = aenv.create_admin()
    a = aenv.admin_client(ip="198.51.100.7")
    for n in range(3):
        assert admin_login(a, f"x{n}@ops.test", code="123456").status_code == 400
    r = admin_login(a, code=aenv.code(secret))
    assert r.status_code == 429 and GENERIC in r.text
    assert aenv.scalar("SELECT count(*) FROM auth_throttle WHERE key = %s",
                       (admin_throttle_key("admin_login_ip", "198.51.100.7"),)) == 1
    assert admin_login(aenv.admin_client(ip="198.51.100.8"), code=aenv.code(secret)
                       ).status_code == 303


def test_throttle_keys_use_the_admin_secret_and_admin_kinds(aenv):
    aenv.create_admin()
    admin_login(aenv.admin_client(ip="198.51.100.9"), code="123456")
    with aenv.owner() as o:
        rows = {(bytes(k), kind) for k, kind in o.execute("SELECT key, kind FROM auth_throttle")}
    assert rows == {(admin_throttle_key("admin_login_ip", "198.51.100.9"), "admin_login_ip"),
                    (admin_throttle_key("admin_login_email", ADMIN_EMAIL), "admin_login_email")}
    web_key = hashlib.sha256(f"admin_login_email|{ADMIN_EMAIL}|{SECRET}".encode()).digest()
    assert web_key not in {k for k, _ in rows}


def test_busy_answers_503_changes_nothing_and_opens_no_connection(aenv):
    secret = aenv.create_admin()
    c = aenv.admin_client()
    csrf = admin_csrf(c)
    answers = []
    with _blocked(aenv):
        for email in (ADMIN_EMAIL, "nobody@ops.test"):
            before = _throttle_rows(aenv)
            with _no_connection(aenv):
                answers.append(admin_login(c, email, code=aenv.code(secret), csrf=csrf))
            assert _throttle_rows(aenv) == before
    for r in answers:
        _assert_busy(r)
        _assert_headers(r)
        assert "qo_admin=" not in r.headers.get("set-cookie", "")
    assert answers[0].content == answers[1].content
    assert aenv.admin_sessions() == 0
    assert aenv.scalar("SELECT last_counter FROM admin_factor") == 0
    assert admin_login(c, code=aenv.code(secret), csrf=csrf).status_code == 303


# --- CSRF and Origin ------------------------------------------------------------------------------

def _state(aenv):
    return (_throttle_rows(aenv), aenv.admin_sessions(),
            aenv.scalar("SELECT max(last_counter) FROM admin_factor"))


@pytest.mark.parametrize("mode", ["missing", "other_browser", "bad_origin", "web_origin",
                                  "no_origin_no_referer", "web_token", "null_origin"])
def test_login_refuses_without_csrf_and_origin(aenv, mode):
    secret = aenv.create_admin()
    origin = {"bad_origin": "https://evil.example", "web_origin": BASE,
              "no_origin_no_referer": None, "null_origin": "null"}.get(mode, ADMIN_BASE)
    c = aenv.admin_client(origin=origin)
    csrf = admin_csrf(c)
    if mode == "missing":
        csrf = ""
    elif mode == "other_browser":
        csrf = admin_csrf(aenv.admin_client())
    elif mode == "web_token":
        w = aenv.client()
        csrf = form_csrf(w, "/login")
        c.cookies.set("qo_csrf", w.cookies.get("qo_csrf"))
    before = _state(aenv)
    good = aenv.code(secret)
    scrypts, hotps = _counters(aenv)
    r = admin_login(c, code=good, csrf=csrf)
    assert r.status_code == 403
    assert (len(scrypts), len(hotps)) == (0, 0)
    assert _state(aenv) == before
    _assert_headers(r)


def test_referer_is_used_when_origin_is_absent(aenv):
    secret = aenv.create_admin()
    c = aenv.admin_client(origin=None)
    csrf = admin_csrf(c)
    r = c.post("/login", data={"csrf": csrf, "email": ADMIN_EMAIL, "password": ADMIN_PASSWORD,
                               "code": aenv.code(secret)},
               headers={"Referer": "https://evil.example/login"})
    assert r.status_code == 403
    r = c.post("/login", data={"csrf": csrf, "email": ADMIN_EMAIL, "password": ADMIN_PASSWORD,
                               "code": aenv.code(secret)},
               headers={"Referer": ADMIN_BASE + "/login"})
    assert r.status_code == 303


def test_logout_needs_the_session_token_and_origin(aenv):
    secret = aenv.create_admin()
    c = signed_in_admin(aenv, secret)
    token = page_csrf(c)
    aenv.tick()
    other = signed_in_admin(aenv, secret)
    other_token = page_csrf(other)
    for data in ({}, {"csrf": ""}, {"csrf": other_token}, {"csrf": token + "x"}):
        r = c.post("/logout", data=data)
        assert r.status_code == 403, data
        _assert_headers(r)
    evil = aenv.admin_client(origin="https://evil.example")
    evil.cookies.set("qo_admin", c.cookies.get("qo_admin"))
    assert evil.post("/logout", data={"csrf": token}).status_code == 403
    web = aenv.admin_client(origin=BASE)
    web.cookies.set("qo_admin", c.cookies.get("qo_admin"))
    assert web.post("/logout", data={"csrf": token}).status_code == 403
    assert c.get("/logout").status_code == 405
    assert aenv.admin_sessions() == 2
    r = c.post("/logout", data={"csrf": token})
    assert r.status_code == 303 and r.headers["location"] == "/login"
    cookie = _set_cookie(r, "qo_admin").lower()
    assert "max-age=0" in cookie or "expires=thu, 01 jan 1970" in cookie
    assert aenv.admin_sessions() == 1
    with aenv.owner() as o:
        assert o.execute("SELECT count(*) FROM admin_session WHERE id_hash = %s",
                         (sha256(c.cookies.get("qo_admin") or "x"),)).fetchone()[0] == 0
    assert c.get("/admin").status_code == 303
    assert other.get("/admin").status_code == 200


# --- sessions -------------------------------------------------------------------------------------

@pytest.mark.parametrize("delta,status", [("1 second", 200), ("-1 second", 303)])
def test_session_lifetime_boundary(aenv, delta, status):
    secret = aenv.create_admin()
    c = signed_in_admin(aenv, secret)
    with aenv.owner() as o:
        o.execute("UPDATE admin_session SET expires_at = now() + %s::interval", (delta,))
    assert c.get("/admin").status_code == status


def test_session_is_never_extended(aenv):
    secret = aenv.create_admin()
    c = signed_in_admin(aenv, secret)
    first = aenv.scalar("SELECT expires_at FROM admin_session")
    for _ in range(3):
        assert c.get("/admin").status_code == 200
    assert aenv.scalar("SELECT expires_at FROM admin_session") == first
    assert "set-cookie" not in c.get("/admin").headers


def test_a_disabled_admin_is_signed_out_at_once(aenv):
    secret = aenv.create_admin()
    c = signed_in_admin(aenv, secret)
    with aenv.owner() as o:
        o.execute("UPDATE app_user SET disabled_at = now()")
    assert c.get("/admin").status_code == 303


@pytest.mark.parametrize("cookie", ["A" * 43, "A" * 42, "A" * 44, "+" * 43, "", "../" * 15,
                                    "A" * 42 + "."])
def test_forged_cookies_are_refused(aenv, cookie):
    secret = aenv.create_admin()
    signed_in_admin(aenv, secret)
    c = aenv.admin_client()
    c.cookies.set("qo_admin", cookie)
    assert c.get("/admin").status_code == 303
    assert c.get("/").headers["location"] == "/login"


def test_cookies_of_the_two_services_do_not_cross(aenv):
    secret = aenv.create_admin()
    admin = signed_in_admin(aenv, secret)
    admin_value = admin.cookies.get("qo_admin")
    owner = account(aenv, "owner@shop.test")
    web_value = session_cookie(owner)
    # The admin cookie means nothing to the public app, under either name.
    for name in ("qo_session", "qo_admin"):
        w = aenv.client()
        w.cookies.set(name, admin_value)
        r = w.get("/app")
        assert r.status_code == 303 and r.headers["location"] == "/login", name
    # The public session cookie means nothing to the admin service, under either name.
    for name in ("qo_session", "qo_admin"):
        a = aenv.admin_client()
        a.cookies.set(name, web_value)
        assert a.get("/admin").status_code == 303, name
    assert admin.get("/admin").status_code == 200 and owner.get("/app").status_code == 200


# --- headers on every answer ----------------------------------------------------------------------

def test_headers_on_every_admin_response(aenv, monkeypatch, caplog):
    secret = aenv.create_admin()
    signed = signed_in_admin(aenv, secret)
    anon = aenv.admin_client()
    for c in (anon, signed):
        for path in ("/", "/login", "/admin", "/healthz", "/nope", "/static/app.css"):
            _assert_headers(c.get(path))
        _assert_headers(c.delete("/login"))
        _assert_headers(c.get("/logout"))
        _assert_headers(c.post("/login", data={}))
        _assert_headers(c.post("/logout", data={}))
    _assert_headers(admin_login(anon, code="000000"))

    class SecretBoom(Exception):
        pass

    def boom(*a, **kw):
        raise SecretBoom("detail-that-must-not-leak root@ops.test")
    monkeypatch.setattr(mod("admin_app"), "_lookup", boom)
    caplog.set_level(logging.DEBUG)
    c = aenv.admin_client(raise_server_exceptions=False)
    r = admin_login(c, code=aenv.code(secret, 1))
    assert r.status_code == 500 and r.headers["content-type"].startswith("text/html")
    assert "detail-that-must-not-leak" not in r.text and "SecretBoom" not in r.text
    assert "<a " not in r.text
    _assert_headers(r)
    texts = [x.getMessage() + str(x.exc_text or "") for x in caplog.records]
    assert any("SecretBoom" in t for t in texts)
    assert not any("detail-that-must-not-leak" in t or ADMIN_EMAIL in t for t in texts)


def test_no_secret_in_the_logs(aenv, caplog):
    caplog.set_level(logging.DEBUG)
    secret = aenv.create_admin()
    code = aenv.code(secret)
    c = signed_in_admin(aenv, secret)
    admin_login(aenv.admin_client(), password="wrong wrong wrong", code=code)
    c.post("/logout", data={"csrf": page_csrf(c)})
    text = caplog.text
    for value in (ADMIN_PASSWORD, code, mod("totp").encode_secret(secret), ADMIN_SECRET):
        assert value not in text


# --- the public app and the sysadmin --------------------------------------------------------------

def test_public_sign_in_treats_the_sysadmin_like_an_unknown_address(aenv):
    aenv.create_admin()
    c = aenv.client()
    csrf = form_csrf(c, "/login")
    unknown = "nope@ops.test"
    assert len(unknown) == len(ADMIN_EMAIL)
    scrypts = _count(aenv.monkeypatch, mod("passwords"), "_scrypt")
    answers = []
    for email in (ADMIN_EMAIL, unknown):
        n = len(scrypts)
        answers.append(c.post("/login", data={"csrf": csrf, "email": email,
                                              "password": ADMIN_PASSWORD}))
        assert len(scrypts) - n == 1
    a, b = answers
    assert a.status_code == b.status_code == 400
    assert a.content.replace(ADMIN_EMAIL.encode(), b"E") == b.content.replace(unknown.encode(), b"E")
    assert sorted(a.headers.multi_items()) == sorted(b.headers.multi_items())
    with aenv.owner() as o:
        hits = sorted(r[0] for r in o.execute("SELECT hits FROM auth_throttle"
                                              " WHERE kind = 'login_email'"))
        assert hits == [1, 1]
        assert o.execute("SELECT count(*) FROM session").fetchone()[0] == 0


def test_public_forgot_and_signup_do_nothing_for_the_sysadmin(aenv):
    aenv.create_admin()
    with aenv.owner() as o:
        before = o.execute("SELECT pw_hash, role, company_id FROM app_user").fetchall()
    forgot(aenv.client(), ADMIN_EMAIL)
    assert signup(aenv.client(ip="192.0.2.77"), ADMIN_EMAIL).status_code == 200
    assert not any("/reset?token=" in m.body for m in aenv.mails_to(ADMIN_EMAIL))
    with aenv.owner() as o:
        assert o.execute("SELECT pw_hash, role, company_id FROM app_user").fetchall() == before
        assert o.execute("SELECT count(*) FROM company").fetchone()[0] == 0


# --- the two services start without each other's settings -----------------------------------------

def _record_users(monkeypatch):
    users, real = [], psycopg.connect

    def connect(conninfo="", **kw):
        users.append(psycopg.conninfo.conninfo_to_dict(conninfo, **kw).get("user"))
        return real(conninfo, **kw)
    monkeypatch.setattr(psycopg, "connect", connect)
    return users


def test_admin_service_runs_without_the_web_settings(aenv, monkeypatch):
    secret = aenv.create_admin()
    for k in ("QO_WEB_PASSWORD", "QO_SECRET", "QO_BASE_URL", "QO_MAIL", "QO_MAIL_DIR",
              "QO_OWNER_PASSWORD", "QO_OWNER_USER"):
        monkeypatch.delenv(k, raising=False)
    users = _record_users(monkeypatch)
    app = mod("admin_app").app
    with TestClient(app, base_url=ADMIN_BASE, headers={"Origin": ADMIN_BASE},
                    follow_redirects=False) as c:
        assert c.get("/healthz").status_code == 200
        r = admin_login(c, code=aenv.code(secret))
        assert r.status_code == 303
        assert c.get("/admin").status_code == 200
        assert c.post("/logout", data={"csrf": page_csrf(c)}).status_code == 303
    assert users and set(users) == {"qo_admin"}


def test_admin_service_refuses_to_start_without_its_password(aenv, monkeypatch):
    monkeypatch.delenv("QO_ADMIN_PASSWORD")
    config = mod("config")
    with pytest.raises(config.ConfigError, match="QO_ADMIN_PASSWORD"):
        with TestClient(mod("admin_app").app):
            pass


def test_web_service_runs_without_the_admin_settings(aenv, monkeypatch):
    for k in ("QO_ADMIN_PASSWORD", "QO_ADMIN_SECRET", "QO_ADMIN_BASE_URL"):
        monkeypatch.delenv(k, raising=False)
    users = _record_users(monkeypatch)
    app = importlib.import_module("quoteops.app").app
    with TestClient(app, base_url=BASE, headers={"Origin": BASE}) as c:
        assert c.get("/login").status_code == 200
    account(aenv, "owner@shop.test")
    assert users and set(users) == {"qo_web"}


def test_admin_app_imports_no_web_route_or_web_connection_module():
    import subprocess
    import sys
    code = ("import sys, quoteops.admin_app; "
            "print(' '.join(sorted(m for m in sys.modules if m.startswith('quoteops'))))")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                         check=True, env={"PATH": "/usr/bin:/bin"}).stdout.split()
    for name in ("quoteops.app", "quoteops.auth", "quoteops.team", "quoteops.dbconn",
                 "quoteops.mail", "quoteops.tokens"):
        assert name not in out, name
    src = mod("admin_app").__file__
    text = open(src, encoding="ascii").read()
    for name in ("web_conninfo", "QO_WEB_PASSWORD", "load_settings(", "lookup_conn",
                 "tenant_conn", "QO_SECRET\""):
        assert name not in text, name
