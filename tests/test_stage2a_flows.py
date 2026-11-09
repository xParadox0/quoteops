"""Stage 2a flows through the web app against a real PostgreSQL: sign-up, verification, sign-in,
sessions, sign-out, password reset, throttling, the company cap, isolation, and the dependencies."""
import hashlib
import importlib
import re
import time
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from tests.stage2a_support import (  # noqa: F401  (adb and env are fixtures)
    BASE, NEW_PASSWORD, PASSWORD, SECRET, account, adb, app_csrf, csrf_from, env,
    finish_signup, forgot, form_csrf, login, path_of, reset_link, session_cookie, sha256,
    signed_up, signup, throttle_key, token_of, verify_link,
)

GENERIC = "The email or password is not correct."
LATER = "Try again in a few minutes."


def _counts(env):
    with env.owner() as c:
        return (c.execute("SELECT count(*) FROM company").fetchone()[0],
                c.execute("SELECT count(*) FROM app_user").fetchone()[0])


def _sessions(env, email=None):
    with env.owner() as c:
        if email is None:
            return [r[0] for r in c.execute("SELECT id_hash FROM session")]
        return [r[0] for r in c.execute(
            "SELECT s.id_hash FROM session s JOIN app_user u ON u.id = s.user_id"
            " WHERE u.email = %s", (email,))]


# --- sign-up ----------------------------------------------------------------------------------------

def test_signup_creates_one_company_and_one_owner_in_one_transaction(env):
    r = signup(env.client(), "Owner@Shop.test", company="  Bengkel Maju  ")
    assert r.status_code == 200 and "Check your email to finish signing up" in r.text
    with env.owner() as c:
        companies = c.execute("SELECT id, name, status, xmin::text FROM company").fetchall()
        users = c.execute("SELECT company_id, email, role, consent_version, consent_at,"
                          " email_verified_at, length(pw_hash), length(pw_salt), xmin::text"
                          " FROM app_user").fetchall()
    assert len(companies) == 1 and len(users) == 1
    cid, name, status, cxmin = companies[0]
    assert re.fullmatch(r"c_[0-9a-f]{32}", cid) and name == "Bengkel Maju" and status == "unverified"
    u = users[0]
    assert u[:4] == (cid, "owner@shop.test", "owner", "draft-0")
    assert u[4] is not None and u[5] is None and u[6:8] == (32, 16)
    assert u[8] == cxmin, "company and owner must be written by the same transaction"
    mails = env.mails_to("owner@shop.test")
    assert len(mails) == 1 and "/verify?token=" in mails[0].body


def test_signup_failure_after_company_insert_leaves_nothing(env, monkeypatch):
    auth = importlib.import_module("quoteops.auth")

    def boom(*a, **kw):
        raise RuntimeError("forced failure after the company insert")

    monkeypatch.setattr(auth, "_insert_owner", boom)
    r = signup(env.client(raise_server_exceptions=False), "owner@shop.test")
    # The insert runs after the answer, so the answer is the usual one; nothing is kept.
    assert r.status_code == 200 and "Check your email to finish signing up" in r.text
    assert _counts(env) == (0, 0)
    assert env.mails() == []


def test_signup_same_response_for_new_and_existing_email(env):
    signed_up(env, "taken@shop.test")
    c = env.client()
    r_existing = signup(c, "taken@shop.test", company="Other")
    r_new = signup(c, "fresh@shop.test", company="Other")
    assert r_existing.status_code == r_new.status_code == 200
    assert r_existing.text == r_new.text
    assert "set-cookie" not in r_existing.headers and "set-cookie" not in r_new.headers
    assert _counts(env) == (2, 2)


def test_signup_existing_email_gets_a_different_mail(env):
    account(env, "taken@shop.test")
    signup(env.client(), "TAKEN@shop.test", company="Other")
    mails = env.mails_to("taken@shop.test")
    assert len(mails) == 2
    first, second = mails
    assert "/verify?token=" in first.body
    assert "/verify?token=" not in second.body and "token=" not in second.body
    assert first.subject != second.subject
    assert "already exists" in second.body and f"{BASE}/forgot" in second.body
    assert "If you did not ask for this, ignore this email." in second.body
    assert _counts(env) == (1, 1)


@pytest.mark.parametrize("field,value,needle", [
    ("email", "not-an-email", "valid email"),
    ("email", "a|b@shop.test", "valid email"),
    ("company", "   ", "company name"),
    ("company", "x" * 81, "company name"),
])
def test_signup_validation_shows_error_next_to_field(env, field, value, needle):
    c = env.client()
    data = {"csrf": form_csrf(c, "/signup"), "email": "owner.person@shop.test",
            "company": "Bengkel", "terms": "yes", field: value}
    r = c.post("/signup", data=data)
    assert r.status_code == 400
    m = re.search(rf'id="{field}-error"[^>]*>([^<]*)<', r.text)
    assert m and needle in m.group(1), r.text
    assert _counts(env) == (0, 0) and env.mails() == []


def _user_state(env):
    with env.owner() as c:
        return c.execute("SELECT u.pw_hash, u.pw_salt, u.email_verified_at, u.consent_at,"
                         " c.name, c.status FROM app_user u JOIN company c ON c.id = u.company_id"
                         ).fetchall()


# The password is chosen at the verification link, so its rules are checked there.
@pytest.mark.parametrize("field,value,needle", [
    ("password", "short", "at least 10"),
    ("password", "password123", "too common"),
    ("password", "owner.person@shop.test", "email"),
    ("password", "owner.person", "email"),
    ("password", "x" * 129, "at most 128"),
    ("company", "   ", "company name"),
    ("company", "x" * 81, "company name"),
])
def test_verify_validation_shows_error_next_to_field(env, field, value, needle):
    signed_up(env, "owner.person@shop.test", company="Bengkel")
    before = _user_state(env)
    kw = {"password": PASSWORD, "company": "Bengkel", field: value}
    r = finish_signup(env.client(), verify_link(env, "owner.person@shop.test"), **kw)
    assert r.status_code == 400
    m = re.search(rf'id="{field}-error"[^>]*>([^<]*)<', r.text)
    assert m and needle in m.group(1), r.text
    assert _user_state(env) == before


def test_signup_requires_terms(env):
    r = signup(env.client(), "owner@shop.test", terms=False)
    assert r.status_code == 400 and 'id="terms-error"' in r.text
    assert _counts(env) == (0, 0)


def test_signup_company_cap(env):
    """Only verified companies count toward the cap (owner decision 2026-11-08)."""
    env.monkeypatch.setenv("QO_MAX_COMPANIES", "2")
    account(env, "one@shop.test")
    account(env, "two@shop.test")
    c = env.client()
    r_new = signup(c, "three@shop.test")
    r_existing = signup(c, "one@shop.test")
    assert r_new.status_code == 403 and "limit" in r_new.text
    assert r_new.text == r_existing.text and r_existing.status_code == 403
    assert _counts(env) == (2, 2)
    assert env.mails_to("three@shop.test") == [] and len(env.mails_to("one@shop.test")) == 1


def test_signup_throttled_per_ip(env):
    for n in range(5):
        assert signup(env.client(ip="198.51.100.4"), f"s{n}@shop.test").status_code == 200
    r = signup(env.client(ip="198.51.100.4"), "s5@shop.test")
    assert r.status_code == 429
    assert _counts(env) == (5, 5) and env.mails_to("s5@shop.test") == []
    assert signup(env.client(ip="198.51.100.5"), "s5@shop.test").status_code == 200


# --- verification -----------------------------------------------------------------------------------

def _status(env, email):
    with env.owner() as c:
        return c.execute("SELECT u.email_verified_at, c.status FROM app_user u"
                         " JOIN company c ON c.id = u.company_id WHERE u.email = %s",
                         (email,)).fetchone()


def test_verify_sets_verified_and_activates_and_is_idempotent(env):
    c = env.client()
    signup(c, "owner@shop.test")
    link = verify_link(env, "owner@shop.test")
    assert _status(env, "owner@shop.test") == (None, "unverified")
    assert c.get(path_of(link)).status_code == 200  # the form: opening the link changes nothing
    assert _status(env, "owner@shop.test") == (None, "unverified")
    r = finish_signup(c, link)
    assert r.status_code == 200 and "verified" in r.text
    at, status = _status(env, "owner@shop.test")
    assert at is not None and status == "active"
    r2 = finish_signup(c, link)
    assert r2.status_code == 200 and "Already verified" in r2.text
    assert _status(env, "owner@shop.test") == (at, "active")


def test_verify_does_not_reactivate_a_suspended_company(env):
    c = env.client()
    signup(c, "owner@shop.test")
    with env.owner() as o:
        o.execute("UPDATE company SET status = 'suspended'")
    assert finish_signup(c, verify_link(env, "owner@shop.test")).status_code == 200
    assert _status(env, "owner@shop.test")[1] == "suspended"


def _bad_verify_tokens(env, good):
    tokens = importlib.import_module("quoteops.tokens")
    payload, sig = good.split(".")
    flip = "A" if sig[0] != "A" else "B"
    return {
        "expired": tokens.make("verify", "owner@shop.test", 48 * 3600, SECRET.encode(),
                               now=time.time() - 48 * 3600 - 5),
        "tampered_sig": payload + "." + flip + sig[1:],
        "tampered_payload": tokens.make("verify", "other@shop.test", 60, SECRET.encode()
                                        ).split(".")[0] + "." + sig,
        "wrong_kind": tokens.make("reset", "owner@shop.test", 3600, SECRET.encode()),
        "wrong_secret": tokens.make("verify", "owner@shop.test", 3600, b"z" * 40),
        "truncated": good[:-4],
        "truncated_short": good[:12],
        "empty": "",
        "unknown_email": tokens.make("verify", "nobody@shop.test", 3600, SECRET.encode()),
    }


def test_verify_refuses_bad_tokens(env):
    c = env.client()
    signup(c, "owner@shop.test")
    good = token_of(verify_link(env, "owner@shop.test"))
    for name, bad in _bad_verify_tokens(env, good).items():
        r = c.get("/verify", params={"token": bad})
        assert r.status_code == 400, name
        assert "not valid" in r.text, name
        assert _status(env, "owner@shop.test") == (None, "unverified"), name


def test_reset_token_does_not_verify(env):
    c = env.client()
    signup(c, "owner@shop.test")
    forgot(c, "owner@shop.test")
    t = token_of(reset_link(env, "owner@shop.test"))
    assert c.get("/verify", params={"token": t}).status_code == 400
    assert _status(env, "owner@shop.test") == (None, "unverified")


# --- login ------------------------------------------------------------------------------------------

def test_login_success_sets_session_cookie_with_flags(env):
    c = env.client()
    signup(c, "owner@shop.test")
    finish_signup(c, verify_link(env, "owner@shop.test"))
    r = login(c, "owner@shop.test")
    assert r.status_code == 303 and r.headers["location"] == "/app"
    cookies = [v for k, v in r.headers.multi_items() if k == "set-cookie" and v.startswith("qo_session=")]
    assert len(cookies) == 1
    parts = [p.strip().lower() for p in cookies[0].split(";")]
    assert "httponly" in parts and "secure" in parts and "path=/" in parts
    assert "samesite=lax" in parts and "max-age=604800" in parts


def test_cookie_secure_follows_config(env):
    env.monkeypatch.setenv("QO_COOKIE_SECURE", "false")
    c = env.client()
    signup(c, "owner@shop.test")
    finish_signup(c, verify_link(env, "owner@shop.test"))
    r = login(c, "owner@shop.test")
    cookie = [v for k, v in r.headers.multi_items() if k == "set-cookie" and v.startswith("qo_session=")][0]
    assert "secure" not in [p.strip().lower() for p in cookie.split(";")]


def test_only_sha256_of_session_token_is_stored_with_7_day_expiry(env):
    c = account(env, "owner@shop.test")
    token = session_cookie(c)
    assert token and len(token) >= 43
    with env.owner() as o:
        rows = o.execute("SELECT id_hash, expires_at - now() FROM session").fetchall()
    assert [r[0] for r in rows] == [sha256(token)]
    assert token.encode() not in [r[0] for r in rows]
    assert timedelta(days=7) - timedelta(minutes=1) < rows[0][1] <= timedelta(days=7)


def test_new_token_on_every_login(env):
    c1 = account(env, "owner@shop.test")
    c2 = env.client()
    assert login(c2, "owner@shop.test").status_code == 303
    t1, t2 = session_cookie(c1), session_cookie(c2)
    assert t1 != t2
    assert sorted(_sessions(env)) == sorted([sha256(t1), sha256(t2)])
    assert login(c2, "owner@shop.test").status_code == 303
    assert session_cookie(c2) not in (t1, t2)


def test_login_failure_identical_for_unknown_email_and_wrong_password(env):
    account(env, "owner@shop.test")
    c = env.client()
    r_unknown = login(c, "nobody@shop.test", "whatever password 1")
    r_wrong = login(c, "owner@shop.test", "whatever password 1")
    assert r_unknown.status_code == r_wrong.status_code == 400
    assert GENERIC in r_unknown.text and LATER not in r_unknown.text
    a = r_unknown.text.replace("nobody@shop.test", "EMAIL")
    b = r_wrong.text.replace("owner@shop.test", "EMAIL")
    assert a == b


def test_unknown_email_runs_one_scrypt(env, monkeypatch):
    account(env, "owner@shop.test")
    c = env.client()
    csrf = form_csrf(c, "/login")
    calls, real = [], hashlib.scrypt
    monkeypatch.setattr(hashlib, "scrypt", lambda pw, **kw: calls.append(kw) or real(pw, **kw))
    c.post("/login", data={"csrf": csrf, "email": "nobody@shop.test", "password": "x" * 12})
    assert len(calls) == 1
    calls.clear()
    c.post("/login", data={"csrf": csrf, "email": "owner@shop.test", "password": "x" * 12})
    assert len(calls) == 1


def test_lockout_after_five_failures_then_expiry(env):
    account(env, "owner@shop.test")
    c = env.client()
    for _ in range(5):
        r = login(c, "owner@shop.test", "wrong password here")
        assert r.status_code == 400 and LATER not in r.text
    r = login(c, "owner@shop.test")  # the right password, but blocked
    assert r.status_code == 429 and GENERIC in r.text and LATER in r.text
    assert "qo_session=" not in r.headers.get("set-cookie", "")
    assert len(_sessions(env)) == 1  # only the one from account()
    with env.owner() as o:  # the clock: the block and its window are over
        o.execute("UPDATE auth_throttle SET blocked_until = now() - interval '1 second',"
                  " window_start = now() - interval '16 minutes' WHERE kind = 'login_email'")
    assert login(c, "owner@shop.test").status_code == 303


def test_lockout_applies_to_unknown_email_too(env):
    c = env.client()
    for _ in range(5):
        assert login(c, "ghost@shop.test", "wrong password here").status_code == 400
    r = login(c, "ghost@shop.test", "wrong password here")
    assert r.status_code == 429 and LATER in r.text


def test_successful_login_resets_email_counter(env):
    account(env, "owner@shop.test")
    c = env.client()
    for _ in range(4):
        login(c, "owner@shop.test", "wrong password here")
    assert login(c, "owner@shop.test").status_code == 303
    with env.owner() as o:
        assert o.execute("SELECT count(*) FROM auth_throttle WHERE kind = 'login_email'"
                         ).fetchone()[0] == 0
    for _ in range(4):
        assert login(c, "owner@shop.test", "wrong password here").status_code == 400
    assert login(c, "owner@shop.test").status_code == 303


def test_throttle_keys_are_hashes_not_raw_values(env):
    c = env.client(ip="192.0.2.77")
    login(c, "Someone@Shop.test", "wrong password here")
    with env.owner() as o:
        rows = {(bytes(r[0]), r[1]) for r in o.execute("SELECT key, kind FROM auth_throttle")}
    assert rows == {(throttle_key("login_email", "someone@shop.test"), "login_email"),
                    (throttle_key("login_ip", "192.0.2.77"), "login_ip")}


def test_per_ip_limit(env):
    account(env, "owner@shop.test")
    ip = "203.0.113.9"
    c = env.client(ip=ip)
    for n in range(30):
        assert login(c, f"ghost{n}@shop.test", "wrong password here").status_code == 400
    r = login(c, "owner@shop.test")
    assert r.status_code == 429 and LATER in r.text
    assert login(env.client(ip="203.0.113.10"), "owner@shop.test").status_code == 303


def test_client_ip_header_ignored_when_not_configured(env):
    env.monkeypatch.delenv("QO_CLIENT_IP_HEADER")
    c = env.client(ip="192.0.2.99")
    login(c, "x@shop.test", "wrong password here")
    with env.owner() as o:
        keys = {bytes(r[0]) for r in o.execute("SELECT key FROM auth_throttle WHERE kind = 'login_ip'")}
    assert keys == {throttle_key("login_ip", "testclient")}


def test_disabled_user_gets_generic_failure(env):
    c = env.client()
    signup(c, "owner@shop.test")
    finish_signup(c, verify_link(env, "owner@shop.test"))
    with env.owner() as o:
        o.execute("UPDATE app_user SET disabled_at = now()")
    r = login(c, "owner@shop.test")
    assert r.status_code == 400 and GENERIC in r.text and _sessions(env) == []


@pytest.mark.parametrize("status", ["suspended", "deleting"])
def test_suspended_company_message_after_correct_password(env, status):
    c = env.client()
    signup(c, "owner@shop.test")
    finish_signup(c, verify_link(env, "owner@shop.test"))
    with env.owner() as o:
        o.execute("UPDATE company SET status = %s", (status,))
    r = login(c, "owner@shop.test")
    assert r.status_code == 403 and "This account is suspended. Contact support" in r.text
    assert _sessions(env) == []
    r = login(c, "owner@shop.test", "wrong password here")
    assert r.status_code == 400 and "suspended" not in r.text


# --- sessions ---------------------------------------------------------------------------------------

def _set_unverified(env, unverified=True):
    """Nobody can sign in before the link is used; this puts a signed-in account back."""
    with env.owner() as o:
        o.execute("UPDATE app_user SET email_verified_at = "
                  + ("NULL" if unverified else "now()"))


def test_app_page_shows_company_email_role_and_banner(env):
    c = account(env, "owner@shop.test", company="Bengkel Maju")
    _set_unverified(env)
    r = c.get("/app")
    assert r.status_code == 200
    for text in ("Bengkel Maju", "owner@shop.test", "owner", 'href="/jobs"',
                 "verify your email"):
        assert text.lower() in r.text.lower(), text
    _set_unverified(env, False)
    assert "verify your email" not in c.get("/app").text.lower()


def test_signed_in_user_is_redirected_from_login_and_root(env):
    c = account(env, "owner@shop.test")
    for path in ("/login", "/"):
        r = c.get(path)
        assert r.status_code == 303 and r.headers["location"] == "/app", path


def test_anonymous_app_redirects_to_login(env):
    r = env.client().get("/app")
    assert r.status_code == 303 and r.headers["location"] == "/login"


def test_logout_deletes_session_and_clears_cookie(env):
    c = account(env, "owner@shop.test")
    token = session_cookie(c)
    r = c.post("/logout", data={"csrf": app_csrf(c)})
    assert r.status_code == 303 and r.headers["location"] == "/login"
    cleared = [v for k, v in r.headers.multi_items() if k == "set-cookie" and v.startswith("qo_session=")]
    assert cleared and ("max-age=0" in cleared[0].lower() or "expires=" in cleared[0].lower())
    assert _sessions(env) == []
    stale = env.client()
    stale.cookies.set("qo_session", token)
    assert stale.get("/app").status_code == 303


@pytest.mark.parametrize("change", [
    "UPDATE session SET expires_at = now() - interval '1 second'",
    "UPDATE app_user SET disabled_at = now()",
    "UPDATE company SET status = 'suspended'",
    "UPDATE company SET status = 'deleting'",
])
def test_session_stops_resolving(env, change):
    c = account(env, "owner@shop.test")
    assert c.get("/app").status_code == 200
    with env.owner() as o:
        o.execute(change)
    r = c.get("/app")
    assert r.status_code == 303 and r.headers["location"] == "/login"


def test_two_companies_never_see_each_other(env):
    a = account(env, "alpha@one.test", company="Alpha Works Unique")
    b = account(env, "bravo@two.test", company="Bravo Lathe Unique")
    pages = ["/", "/app", "/login", "/signup", "/forgot", "/reset", "/verify", "/terms",
             "/privacy", "/healthz", "/nope"]
    for client, mine, theirs in ((a, "Alpha Works Unique", ("Bravo Lathe Unique", "bravo@two.test")),
                                 (b, "Bravo Lathe Unique", ("Alpha Works Unique", "alpha@one.test"))):
        assert mine in client.get("/app").text
        for p in pages:
            r = client.get(p, follow_redirects=True)
            for t in theirs:
                assert t not in r.text, (p, t)
    # A's cookie with B's CSRF token cannot sign B out, and A's sign-out leaves B's session.
    a_hash = sha256(session_cookie(a))
    assert a.post("/logout", data={"csrf": app_csrf(b)}).status_code == 403
    assert a.post("/logout", data={"csrf": app_csrf(a)}).status_code == 303
    assert a_hash not in _sessions(env) and len(_sessions(env)) == 1
    assert b.get("/app").status_code == 200


# --- forgot and reset -------------------------------------------------------------------------------

FORGOT_TEXT = "If that address has an account, we sent a link"


def test_forgot_same_answer_and_mail_only_for_accounts(env):
    signed_up(env, "owner@shop.test")
    c = env.client()
    r1, r2 = forgot(c, "owner@shop.test"), forgot(c, "nobody@shop.test")
    assert r1.status_code == r2.status_code == 200 and r1.text == r2.text
    assert FORGOT_TEXT in r1.text
    assert env.mails_to("nobody@shop.test") == []
    m = env.mails_to("owner@shop.test")[-1]
    assert "/reset?token=" in m.body and "1 hour" in m.body
    assert "If you did not ask for this, ignore this email." in m.body


def test_forgot_does_not_mail_disabled_user(env):
    account(env, "owner@shop.test")
    with env.owner() as o:
        o.execute("UPDATE app_user SET disabled_at = now()")
    before = len(env.mails())
    assert FORGOT_TEXT in forgot(env.client(), "owner@shop.test").text
    assert len(env.mails()) == before


def _reset(client, token, password=NEW_PASSWORD):
    r = client.get("/reset", params={"token": token})
    if r.status_code != 200:
        return r
    return client.post("/reset", data={"csrf": csrf_from(r.text), "token": token,
                                       "password": password})


def test_reset_changes_password_deletes_sessions_and_mails_notice(env):
    c1 = account(env, "owner@shop.test")
    c2 = env.client()
    login(c2, "owner@shop.test")
    assert len(_sessions(env, "owner@shop.test")) == 2
    forgot(env.client(), "owner@shop.test")
    r = _reset(env.client(), token_of(reset_link(env, "owner@shop.test")))
    assert r.status_code == 200 and "password was changed" in r.text
    assert _sessions(env, "owner@shop.test") == []
    assert c1.get("/app").status_code == 303 and c2.get("/app").status_code == 303
    notice = env.mails_to("owner@shop.test")[-1]
    assert "password" in notice.subject.lower() and "changed" in notice.subject.lower()
    assert login(env.client(), "owner@shop.test").status_code == 400
    assert login(env.client(), "owner@shop.test", NEW_PASSWORD).status_code == 303


def test_reset_token_is_single_use(env):
    account(env, "owner@shop.test")
    forgot(env.client(), "owner@shop.test")
    token = token_of(reset_link(env, "owner@shop.test"))
    c = env.client()
    form = c.get("/reset", params={"token": token})
    assert _reset(env.client(), token).status_code == 200
    r = c.post("/reset", data={"csrf": csrf_from(form.text), "token": token,
                               "password": "a third password 77"})
    assert r.status_code == 400 and "not valid" in r.text
    assert env.client().get("/reset", params={"token": token}).status_code == 400
    assert login(env.client(), "owner@shop.test", NEW_PASSWORD).status_code == 303


def test_reset_token_invalid_after_password_changed_another_way(env):
    account(env, "owner@shop.test")
    c = env.client()
    forgot(c, "owner@shop.test")
    first = token_of(reset_link(env, "owner@shop.test"))
    time.sleep(1.1)  # tokens carry whole seconds: the same second gives the same token
    forgot(c, "owner@shop.test")
    second = token_of(reset_link(env, "owner@shop.test"))
    assert first != second
    assert _reset(env.client(), second).status_code == 200
    assert _reset(env.client(), first, "a third password 77").status_code == 400
    forgot(c, "owner@shop.test")
    third = token_of(reset_link(env, "owner@shop.test"))
    with env.owner() as o:  # any other change of the stored hash
        o.execute("UPDATE app_user SET pw_hash = '\\x01'")
    assert _reset(env.client(), third, "a third password 77").status_code == 400


def test_reset_refuses_expired_wrong_kind_and_tampered(env):
    account(env, "owner@shop.test")
    tokens = importlib.import_module("quoteops.tokens")
    with env.owner() as o:
        pw_hash = bytes(o.execute("SELECT pw_hash FROM app_user").fetchone()[0])
    forgot(env.client(), "owner@shop.test")
    good = token_of(reset_link(env, "owner@shop.test"))
    bad = [good[:-3], good + "x", "", token_of(verify_link(env, "owner@shop.test")),
           tokens.make("reset", "owner@shop.test", 3600, SECRET.encode())]
    expired = [t for t in [tokens.make("reset", "owner@shop.test", 3600, SECRET.encode(),
                                       extra=x, now=time.time() - 3605)
                           for x in (hashlib.sha256(pw_hash).digest(), pw_hash, b"")]]
    for t in bad + expired:
        assert _reset(env.client(), t).status_code == 400
    assert login(env.client(), "owner@shop.test").status_code == 303


def test_reset_enforces_password_policy(env):
    account(env, "owner@shop.test")
    forgot(env.client(), "owner@shop.test")
    r = _reset(env.client(), token_of(reset_link(env, "owner@shop.test")), "password123")
    assert r.status_code == 400 and 'id="password-error"' in r.text
    assert login(env.client(), "owner@shop.test").status_code == 303


def test_forgot_throttled_per_address(env):
    account(env, "owner@shop.test")
    before = len(env.mails_to("owner@shop.test"))
    for n in range(4):
        r = forgot(env.client(ip=f"192.0.2.{n + 1}"), "owner@shop.test")
        assert r.status_code == 200 and FORGOT_TEXT in r.text
    assert len(env.mails_to("owner@shop.test")) - before == 3


def test_forgot_throttled_per_ip(env):
    account(env, "owner@shop.test")
    c = env.client(ip="198.51.100.20")
    for n in range(10):
        forgot(c, f"ghost{n}@shop.test")
    before = len(env.mails_to("owner@shop.test"))
    assert FORGOT_TEXT in forgot(c, "owner@shop.test").text
    assert len(env.mails_to("owner@shop.test")) == before
    forgot(env.client(ip="198.51.100.21"), "owner@shop.test")
    assert len(env.mails_to("owner@shop.test")) == before + 1


# --- require_user, require_verified, require_role ---------------------------------------------------

@pytest.fixture
def guarded(env):
    from fastapi import Depends, FastAPI
    from fastapi.responses import PlainTextResponse
    appmod = importlib.import_module("quoteops.app")
    auth = importlib.import_module("quoteops.auth")
    t = FastAPI()
    appmod.configure(t)

    @t.get("/v", response_class=PlainTextResponse)
    def v(p=Depends(auth.require_verified)):
        return f"verified {p.role}"

    @t.get("/owner", response_class=PlainTextResponse)
    def owner(p=Depends(auth.require_role("owner"))):
        return "owner ok"

    @t.get("/staff", response_class=PlainTextResponse)
    def staff(p=Depends(auth.require_role("estimator", "viewer"))):
        return "staff ok"

    def client_for(cookie=None):
        tc = TestClient(t, base_url=BASE, follow_redirects=False)
        if cookie:
            tc.cookies.set("qo_session", cookie)
        return tc
    return client_for


def test_require_verified(env, guarded):
    c = account(env, "owner@shop.test")
    _set_unverified(env)
    r = guarded(session_cookie(c)).get("/v")
    assert r.status_code == 403 and "verify" in r.text.lower()
    _set_unverified(env, False)
    r = guarded(session_cookie(c)).get("/v")
    assert r.status_code == 200 and r.text == "verified owner"
    r = guarded().get("/v")
    assert r.status_code == 303 and r.headers["location"] == "/login"


def test_require_role(env, guarded):
    c = account(env, "owner@shop.test")
    g = guarded(session_cookie(c))
    assert g.get("/owner").text == "owner ok"
    assert g.get("/staff").status_code == 403
    with env.owner() as o:
        o.execute("UPDATE app_user SET role = 'viewer'")
    assert g.get("/owner").status_code == 403
    assert g.get("/staff").text == "staff ok"
    assert guarded().get("/owner").status_code == 303
