"""Stage 2a fix 3, from the first independent review.
D1: one process-wide limit on concurrent scrypt; when no slot frees up in time the answer is 503.
D2: signing up again with the address of an unverified account mails a new verification link.
D3: sign-up and forgot answer before the work that depends on whether the address has an account
(lookup, insert, mail), which runs as a background task after the response."""
import asyncio
import gc
import hashlib
import importlib
import logging
import os
import sys
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlencode

import pytest
import yaml

from tests.stage2a_support import (  # noqa: F401  (adb and env are fixtures)
    BASE, IP_HEADER, NEW_PASSWORD, PASSWORD, SECRET, account, adb, csrf_from, env,
    finish_signup, forgot, form_csrf, login, reset_link, signed_up, signup, token_of,
    verify_link,
)

ROOT = Path(__file__).resolve().parent.parent
BUSY = "The service is busy. Try again in a few minutes."
SIGNUP_DONE = "If the email does not arrive within a few minutes, submit the form again."
FORGOT_TEXT = "If that address has an account, we sent a link"


def _mod(name):
    return importlib.import_module(f"quoteops.{name}")


def _counts(env):
    return env.scalar("SELECT count(*) FROM company"), env.scalar("SELECT count(*) FROM app_user")


def _hits(env):
    return env.scalar("SELECT coalesce(sum(hits), 0) FROM auth_throttle")


def _limit(env, concurrency=None, wait=None):
    """Set the scrypt limit settings; the limiter reads them again at its next use."""
    if concurrency is not None:
        env.monkeypatch.setenv("QO_SCRYPT_CONCURRENCY", str(concurrency))
    if wait is not None:
        env.monkeypatch.setenv("QO_SCRYPT_WAIT_SECONDS", str(wait))
    env.monkeypatch.setattr(_mod("passwords"), "_limit", None, raising=False)


@contextmanager
def _blocked(env):
    """One scrypt slot, held by a blocker thread inside hash_password, and a 0.05 s wait."""
    _limit(env, concurrency=1, wait=0.05)
    real, inside, release = hashlib.scrypt, threading.Event(), threading.Event()
    blocker = threading.Thread(target=_mod("passwords").hash_password, args=("blocker phrase 1",))

    def scrypt(password, **kw):
        if threading.current_thread() is blocker:
            inside.set()
            release.wait(10)
        return real(password, **kw)

    env.monkeypatch.setattr(hashlib, "scrypt", scrypt)
    blocker.start()
    assert inside.wait(5), "the blocker never reached scrypt"
    try:
        yield
    finally:
        release.set()
        blocker.join(10)


def _assert_busy(r):
    assert r.status_code == 503, (r.status_code, r.text)
    assert r.headers.get("retry-after") == "5"
    assert BUSY in r.text
    assert "qo_session=" not in r.headers.get("set-cookie", "")


# --- D1: the scrypt limit -------------------------------------------------------------------------

def test_scrypt_settings_defaults_and_refusals(monkeypatch):
    config = _mod("config")
    for k in ("QO_SCRYPT_CONCURRENCY", "QO_SCRYPT_WAIT_SECONDS"):
        monkeypatch.delenv(k, raising=False)
    assert config.scrypt_limits() == (3, 8.0)
    monkeypatch.setenv("QO_SCRYPT_CONCURRENCY", "2")
    monkeypatch.setenv("QO_SCRYPT_WAIT_SECONDS", "0.05")
    assert config.scrypt_limits() == (2, 0.05)
    for var, bad in (("QO_SCRYPT_CONCURRENCY", "0"), ("QO_SCRYPT_CONCURRENCY", "two"),
                     ("QO_SCRYPT_CONCURRENCY", "1.5"), ("QO_SCRYPT_WAIT_SECONDS", "0"),
                     ("QO_SCRYPT_WAIT_SECONDS", "-1"), ("QO_SCRYPT_WAIT_SECONDS", "soon"),
                     ("QO_SCRYPT_WAIT_SECONDS", "nan"), ("QO_SCRYPT_WAIT_SECONDS", "inf")):
        monkeypatch.setenv("QO_SCRYPT_CONCURRENCY", "2")
        monkeypatch.setenv("QO_SCRYPT_WAIT_SECONDS", "1")
        monkeypatch.setenv(var, bad)
        with pytest.raises(config.ConfigError) as exc:
            config.scrypt_limits()
        assert var in str(exc.value) and bad not in str(exc.value)


def test_load_settings_checks_the_scrypt_settings(monkeypatch):
    config = _mod("config")
    for k in list(os.environ):
        if k.startswith("QO_"):
            monkeypatch.delenv(k)
    monkeypatch.setenv("QO_SECRET", SECRET)
    monkeypatch.setenv("QO_BASE_URL", BASE)
    s = config.load_settings()
    assert (s.scrypt_concurrency, s.scrypt_wait_seconds) == (3, 8.0)
    monkeypatch.setenv("QO_SCRYPT_CONCURRENCY", "0")
    with pytest.raises(config.ConfigError, match="QO_SCRYPT_CONCURRENCY"):
        config.load_settings()


def test_scrypt_settings_reach_the_web_container_and_the_example():
    web = yaml.safe_load((ROOT / "deploy" / "compose.yaml").read_text())["services"]["web"]
    assert web["environment"]["QO_SCRYPT_CONCURRENCY"] == "${QO_SCRYPT_CONCURRENCY:-3}"
    assert web["environment"]["QO_SCRYPT_WAIT_SECONDS"] == "${QO_SCRYPT_WAIT_SECONDS:-8}"
    example = (ROOT / "deploy" / ".env.example").read_text()
    assert "QO_SCRYPT_CONCURRENCY" in example and "QO_SCRYPT_WAIT_SECONDS" in example


def test_every_scrypt_entry_point_raises_busy_when_no_slot_frees(env):
    passwords = _mod("passwords")
    h, salt = passwords.hash_password("milling cutter 7 bright")
    with _blocked(env):
        for call in (lambda: passwords.hash_password("milling cutter 7 bright"),
                     lambda: passwords.verify_password("milling cutter 7 bright", h, salt),
                     lambda: passwords.verify_dummy("milling cutter 7 bright")):
            started = time.monotonic()
            with pytest.raises(passwords.Busy):
                call()
            assert time.monotonic() - started < 2
    assert passwords.verify_password("milling cutter 7 bright", h, salt) is True


def _run_together(jobs):
    """Start every job at the same moment, each in its own thread; returns their results."""
    barrier, results = threading.Barrier(len(jobs)), [None] * len(jobs)

    def run(i, job):
        barrier.wait()
        results[i] = job()

    threads = [threading.Thread(target=run, args=(i, j)) for i, j in enumerate(jobs)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(120)
    return results


def _few_db_connections(env, n=4):
    """At most n database connections of the app at once. The test PostgreSQL container (256 MiB,
    its data on tmpfs) runs out of memory when 12 or 30 threads open connections together; the
    requests still run concurrently, and the scrypt they reach is not inside a connection
    (sign-up) or holds one slot of n while it waits (sign-in)."""
    auth, gate = _mod("auth"), threading.BoundedSemaphore(n)

    def gated(real):
        @contextmanager
        def wrapper(*a, **kw):
            with gate, real(*a, **kw) as conn:
                yield conn
        return wrapper

    env.monkeypatch.setattr(auth, "lookup_conn", gated(auth.lookup_conn))
    env.monkeypatch.setattr(auth, "tenant_conn", gated(auth.tenant_conn))


def _login_job(env, n):
    c = env.client(ip=f"198.51.100.{n + 1}")
    data = {"csrf": form_csrf(c, "/login"), "email": f"ghost{n}@shop.test",
            "password": "wrong password here"}
    return lambda: c.post("/login", data=data).status_code


def _verify_job(env, n):
    """The POST that chooses the password at the verification link: the request that hashes now
    that sign-up has no password."""
    email = f"u{n}@shop.test"
    signed_up(env, email, company=f"Shop {n}", ip=f"203.0.113.{n + 1}")
    c = env.client(ip=f"203.0.113.{n + 1}")
    link = verify_link(env, email)
    data = {"csrf": csrf_from(c.get(link[len(BASE):]).text), "token": token_of(link),
            "password": PASSWORD, "company": f"Shop {n}", "terms": "yes"}
    return lambda: c.post("/verify", data=data).status_code


def test_at_most_the_configured_number_of_scrypt_run_at_once(env):
    _limit(env, concurrency=2)
    jobs = [_login_job(env, n) for n in range(6)] + [_verify_job(env, n) for n in range(6)]
    _few_db_connections(env)
    real, lock, state = hashlib.scrypt, threading.Lock(), {"now": 0, "max": 0, "calls": 0}

    def spy(password, **kw):
        with lock:
            state["now"] += 1
            state["calls"] += 1
            state["max"] = max(state["max"], state["now"])
        try:
            time.sleep(0.05)
            return real(password, **kw)
        finally:
            with lock:
                state["now"] -= 1

    env.monkeypatch.setattr(hashlib, "scrypt", spy)
    statuses = _run_together(jobs)
    assert statuses == [400] * 6 + [200] * 6
    assert state["calls"] == 12
    assert state["max"] == 2, state


def _status_kib(field):
    for line in Path("/proc/self/status").read_text().splitlines():
        if line.startswith(field + ":"):
            return int(line.split()[1])
    raise AssertionError(field)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="reads /proc/self")
def test_thirty_concurrent_verifications_stay_within_the_memory_bound(env):
    """With the default limit (3 slots of 32 MiB) 30 concurrent password choices at the
    verification link must not grow the resident memory by 250 MB; without a limit they need
    about 960 MiB. The slot is taken before any database connection, so the connection cap does
    not space out the scrypt calls."""
    _limit(env)
    env.monkeypatch.setenv("QO_MAX_COMPANIES", "100")
    jobs = [_verify_job(env, n) for n in range(30)]
    _few_db_connections(env)
    gc.collect()
    try:
        Path("/proc/self/clear_refs").write_text("5")  # restart the peak (VmHWM) from now
    except OSError:
        pytest.skip("cannot reset the peak resident memory on this kernel")
    base = _status_kib("VmRSS")
    statuses = _run_together(jobs)
    growth_mb = (_status_kib("VmHWM") - base) * 1024 / 1e6
    assert statuses == [200] * 30
    assert growth_mb < 250, f"peak resident memory grew by {growth_mb:.0f} MB"


def _throttle_rows(env):
    with env.owner() as o:
        return o.execute("SELECT key, kind, hits, window_start, blocked_until FROM auth_throttle"
                         " ORDER BY kind, key").fetchall()


@contextmanager
def _no_connection(env):
    """Fails the test when the code inside opens a database connection."""
    psycopg, opened = importlib.import_module("psycopg"), []
    real = psycopg.connect

    def spy(*a, **kw):
        opened.append(1)
        return real(*a, **kw)

    env.monkeypatch.setattr(psycopg, "connect", spy)
    try:
        yield
    finally:
        env.monkeypatch.setattr(psycopg, "connect", real)
    assert opened == [], f"{len(opened)} database connection(s) opened"


def test_busy_login_answers_503_for_any_address_and_changes_nothing(env):
    account(env, "owner@shop.test")
    c = env.client()
    csrf = form_csrf(c, "/login")
    sessions = env.scalar("SELECT count(*) FROM session")
    answers = []
    with _blocked(env):
        for email in ("owner@shop.test", "nobody@shop.test"):
            before = _throttle_rows(env)
            with _no_connection(env):
                answers.append(c.post("/login", data={"csrf": csrf, "email": email,
                                                      "password": PASSWORD}))
            assert _throttle_rows(env) == before, email  # a busy answer counts nothing
    for r in answers:
        _assert_busy(r)
    assert answers[0].content == answers[1].content
    assert env.scalar("SELECT count(*) FROM session") == sessions
    assert login(c, "owner@shop.test").status_code == 303


def test_signup_never_takes_a_scrypt_slot(env):
    """Sign-up has no password, so it runs no scrypt and never waits for a slot: with the only
    slot held it still answers at once and creates the account."""
    passwords, calls = _mod("passwords"), []
    c = env.client()
    data = {"csrf": form_csrf(c, "/signup"), "email": "new@shop.test", "company": "New",
            "terms": "yes"}
    with _blocked(env):
        for name in ("_limiter", "_scrypt", "hash_password", "verify_password", "verify_dummy"):
            def spy(*a, _name=name, _real=getattr(passwords, name), **kw):
                calls.append(_name)
                return _real(*a, **kw)
            env.monkeypatch.setattr(passwords, name, spy)
        started = time.monotonic()
        r = c.post("/signup", data=data)
        assert time.monotonic() - started < 2
    assert calls == []
    assert r.status_code == 200 and SIGNUP_DONE in r.text
    assert _counts(env) == (1, 1) and len(env.mails_to("new@shop.test")) == 1


def test_busy_reset_answers_503_and_keeps_password_and_token(env):
    account(env, "owner@shop.test")
    forgot(env.client(), "owner@shop.test")
    token = token_of(reset_link(env, "owner@shop.test"))
    c = env.client()
    data = {"csrf": csrf_from(c.get("/reset", params={"token": token}).text), "token": token,
            "password": NEW_PASSWORD}
    pw_hash = bytes(env.scalar("SELECT pw_hash FROM app_user"))
    sessions, mails, hits = env.scalar("SELECT count(*) FROM session"), len(env.mails()), _hits(env)
    with _blocked(env):
        r = c.post("/reset", data=data)
    _assert_busy(r)
    assert bytes(env.scalar("SELECT pw_hash FROM app_user")) == pw_hash
    assert env.scalar("SELECT count(*) FROM session") == sessions
    assert len(env.mails()) == mails and _hits(env) == hits
    assert c.get("/reset", params={"token": token}).status_code == 200
    assert c.post("/reset", data=data).status_code == 200
    assert login(env.client(), "owner@shop.test", NEW_PASSWORD).status_code == 303


# --- D2: a new verification mail for an unverified account ----------------------------------------

def _status(env, email):
    with env.owner() as c:
        return c.execute("SELECT u.email_verified_at, c.status FROM app_user u"
                         " JOIN company c ON c.id = u.company_id WHERE u.email = %s",
                         (email,)).fetchone()


def test_signup_again_after_a_lost_mail_sends_a_new_verification(env, monkeypatch, caplog):
    mail = _mod("mail")
    real, failed = mail.FileMailer.send, []

    def fail_once(self, to, subject, text):
        if not failed:
            failed.append(to)
            raise OSError("disk full at /var/qo-mail owner@shop.test")
        return real(self, to, subject, text)

    monkeypatch.setattr(mail.FileMailer, "send", fail_once)
    caplog.set_level(logging.DEBUG)
    c = env.client()
    r1 = signup(c, "owner@shop.test")
    assert failed == ["owner@shop.test"] and env.mails() == []
    assert _counts(env) == (1, 1) and _status(env, "owner@shop.test") == (None, "unverified")
    r2 = signup(c, "owner@shop.test")
    mails = env.mails_to("owner@shop.test")
    assert len(mails) == 1 and "/verify?token=" in mails[0].body
    assert finish_signup(c, verify_link(env, "owner@shop.test")).status_code == 200
    assert _status(env, "owner@shop.test")[1] == "active"
    r3 = signup(c, "owner@shop.test")  # verified now: the "already exists" mail
    last = env.mails_to("owner@shop.test")[-1]
    assert len(env.mails_to("owner@shop.test")) == 2
    assert "already exists" in last.body and "token=" not in last.body
    assert _counts(env) == (1, 1)
    assert r1.status_code == r2.status_code == r3.status_code == 200
    assert r1.content == r2.content == r3.content and SIGNUP_DONE in r1.text
    texts = [x.getMessage() for x in caplog.records if not x.name.startswith(("httpx", "httpcore"))]
    assert any("OSError" in t for t in texts)
    assert not any("disk full" in t or "owner@shop.test" in t for t in texts)


def test_unverified_account_gets_verification_and_verified_gets_exists(env):
    signed_up(env, "fresh@shop.test")
    account(env, "done@shop.test")
    signup(env.client(), "fresh@shop.test")
    signup(env.client(), "done@shop.test")
    fresh, done = env.mails_to("fresh@shop.test"), env.mails_to("done@shop.test")
    assert len(fresh) == 2 and all("/verify?token=" in m.body for m in fresh)
    assert len(done) == 2 and "already exists" in done[-1].body and "token=" not in done[-1].body


# --- D3: existence-dependent work after the response ----------------------------------------------

def _headers(r):
    return sorted((k, v) for k, v in r.headers.multi_items() if k != "set-cookie")


def test_signup_answers_are_byte_identical_for_every_case(env, monkeypatch):
    signed_up(env, "unverified@shop.test")
    account(env, "verified@shop.test")
    answers = {e: signup(env.client(ip=f"192.0.2.{n + 10}"), e, company="Other")
               for n, e in enumerate(("new@shop.test", "unverified@shop.test",
                                      "verified@shop.test"))}
    mail = _mod("mail")

    def broken(self, to, subject, text):
        raise OSError("no space left")

    monkeypatch.setattr(mail.FileMailer, "send", broken)
    answers["mail fails"] = signup(env.client(ip="192.0.2.20"), "other@shop.test",
                                   company="Other")
    first = answers["new@shop.test"]
    assert first.status_code == 200 and SIGNUP_DONE in first.text
    for case, r in answers.items():
        assert (r.status_code, r.content, _headers(r)) == (
            first.status_code, first.content, _headers(first)), case


def test_forgot_answers_are_byte_identical_for_every_case(env, monkeypatch):
    account(env, "owner@shop.test")
    account(env, "disabled@shop.test", ip="192.0.2.9")
    with env.owner() as o:
        o.execute("UPDATE app_user SET disabled_at = now() WHERE email = 'disabled@shop.test'")
    answers = {e: forgot(env.client(), e)
               for e in ("owner@shop.test", "nobody@shop.test", "disabled@shop.test")}
    mail = _mod("mail")

    def broken(self, to, subject, text):
        raise OSError("no space left")

    monkeypatch.setattr(mail.FileMailer, "send", broken)
    answers["mail fails"] = forgot(env.client(), "owner@shop.test")
    first = answers["owner@shop.test"]
    assert first.status_code == 200 and FORGOT_TEXT in first.text
    for case, r in answers.items():
        assert (r.status_code, r.content, _headers(r)) == (
            first.status_code, first.content, _headers(first)), case


def _asgi_post(path, form, csrf_cookie, order):
    """Drive the ASGI app directly (the TestClient waits for background tasks before it returns).
    Returns the times of the start, of the last response byte and of the end of the app call,
    and appends "response" to order when the last byte is sent."""
    app = _mod("app").app
    body = urlencode(form).encode()
    scope = {
        "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "POST",
        "scheme": "https", "server": ("qo.example", 443), "client": ("192.0.2.33", 50000),
        "root_path": "", "path": path, "raw_path": path.encode(), "query_string": b"",
        "headers": [(b"host", b"qo.example"), (b"origin", BASE.encode()),
                    (b"content-type", b"application/x-www-form-urlencoded"),
                    (b"content-length", str(len(body)).encode()),
                    (b"cookie", f"qo_csrf={csrf_cookie}".encode()),
                    (IP_HEADER.lower().encode(), b"192.0.2.33")],
    }
    out = {}

    async def run():
        done = asyncio.Event()
        delivered = False

        async def receive():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": body, "more_body": False}
            await done.wait()
            return {"type": "http.disconnect"}

        async def send(msg):
            if msg["type"] == "http.response.start":
                out["status"] = msg["status"]
            elif msg["type"] == "http.response.body" and not msg.get("more_body"):
                out["answered"] = time.monotonic()
                order.append("response")
                done.set()

        out["start"] = time.monotonic()
        await app(scope, receive, send)
        out["end"] = time.monotonic()

    asyncio.run(run())
    return out


def _form_cookie(env, page):
    c = env.client()
    html = c.get(page).text
    return csrf_from(html), c.cookies.get("qo_csrf")


def _slow_mailer(monkeypatch, order, delay=0.5):
    mail = _mod("mail")
    real, sent = mail.FileMailer.send, []

    def slow(self, to, subject, text):
        time.sleep(delay)
        real(self, to, subject, text)
        sent.append(time.monotonic())
        order.append("mail")

    monkeypatch.setattr(mail.FileMailer, "send", slow)
    return sent


def _record_lookups(monkeypatch, order):
    auth = _mod("auth")
    real = auth._lookup

    def lookup(conn, email):
        order.append("lookup")
        return real(conn, email)

    monkeypatch.setattr(auth, "_lookup", lookup)


def test_signup_answers_before_the_lookup_and_the_slow_mail(env, monkeypatch):
    csrf, cookie = _form_cookie(env, "/signup")
    order = []
    sent = _slow_mailer(monkeypatch, order)
    _record_lookups(monkeypatch, order)
    out = _asgi_post("/signup", {"csrf": csrf, "email": "new@shop.test", "company": "New",
                                 "terms": "yes"}, cookie, order)
    assert out["status"] == 200
    assert out["answered"] - out["start"] < 0.35, out["answered"] - out["start"]
    assert order == ["response", "lookup", "mail"], order
    assert sent and sent[0] > out["answered"] and out["end"] - out["start"] >= 0.5
    assert len(env.mails_to("new@shop.test")) == 1 and _counts(env) == (1, 1)


def test_signup_for_an_existing_address_answers_before_the_lookup(env, monkeypatch):
    account(env, "owner@shop.test")
    csrf, cookie = _form_cookie(env, "/signup")
    order = []
    sent = _slow_mailer(monkeypatch, order)
    _record_lookups(monkeypatch, order)
    out = _asgi_post("/signup", {"csrf": csrf, "email": "owner@shop.test", "company": "New",
                                 "terms": "yes"}, cookie, order)
    assert out["status"] == 200 and out["answered"] - out["start"] < 0.35
    assert order == ["response", "lookup", "mail"], order
    assert sent and "already exists" in env.mails_to("owner@shop.test")[-1].body


def test_forgot_answers_before_the_lookup_and_the_slow_mail(env, monkeypatch):
    account(env, "owner@shop.test")
    csrf, cookie = _form_cookie(env, "/forgot")
    order = []
    sent = _slow_mailer(monkeypatch, order)
    _record_lookups(monkeypatch, order)
    out = _asgi_post("/forgot", {"csrf": csrf, "email": "owner@shop.test"}, cookie, order)
    assert out["status"] == 200
    assert out["answered"] - out["start"] < 0.35, out["answered"] - out["start"]
    assert order == ["response", "lookup", "mail"], order
    assert sent[0] > out["answered"]
    assert "/reset?token=" in env.mails_to("owner@shop.test")[-1].body


def test_forgot_for_an_unknown_address_answers_before_the_lookup(env, monkeypatch):
    csrf, cookie = _form_cookie(env, "/forgot")
    order = []
    _record_lookups(monkeypatch, order)
    out = _asgi_post("/forgot", {"csrf": csrf, "email": "nobody@shop.test"}, cookie, order)
    assert out["status"] == 200 and order == ["response", "lookup"], order
    assert env.mails() == []


class SecretBoom(Exception):
    pass


def _boom(*a, **kw):
    raise SecretBoom("detail-that-must-not-leak owner@shop.test")


def _app_logs(caplog):
    return [f"{x.getMessage()} {x.args!r} {x.exc_text or ''}" for x in caplog.records
            if not x.name.startswith(("httpx", "httpcore"))], caplog.records


@pytest.mark.parametrize("route", ["signup", "forgot"])
def test_background_error_is_logged_by_class_and_the_request_succeeds(env, monkeypatch, caplog,
                                                                      route):
    auth = _mod("auth")
    caplog.set_level(logging.DEBUG)
    c = env.client()  # raise_server_exceptions: an error that escaped would fail the call
    if route == "signup":
        monkeypatch.setattr(auth, "_create_company_and_owner", _boom)
        r = signup(c, "owner@shop.test")
        assert r.status_code == 200 and SIGNUP_DONE in r.text
        assert _counts(env) == (0, 0)
    else:
        account(env, "owner@shop.test")
        monkeypatch.setattr(auth, "_reset_mail", _boom)
        caplog.clear()
        r = forgot(c, "owner@shop.test")
        assert r.status_code == 200 and FORGOT_TEXT in r.text
    texts, records = _app_logs(caplog)
    assert any("SecretBoom" in t for t in texts)
    assert not any("detail-that-must-not-leak" in t or "owner@shop.test" in t for t in texts)
    assert not any(x.exc_info for x in records)
    assert all("/reset?token=" not in m.body for m in env.mails())


def test_cap_reached_between_answer_and_background_bites_at_verification(env, monkeypatch,
                                                                         caplog):
    """An unverified account does not count toward the cap, so the background task creates it
    and mails the link; the cap refuses at the verification link (owner decision 2026-11-08)."""
    env.monkeypatch.setenv("QO_MAX_COMPANIES", "1")
    auth = _mod("auth")
    real, filled = auth._lookup, []

    def lookup_then_fill(conn, email):
        if not filled:
            filled.append(1)
            with env.owner() as o:
                o.execute("INSERT INTO company (id, name, status) VALUES ('c_other', 'Other',"
                          " 'active')")
        return real(conn, email)

    monkeypatch.setattr(auth, "_lookup", lookup_then_fill)
    caplog.set_level(logging.DEBUG)
    r = signup(env.client(), "late@shop.test")
    assert r.status_code == 200 and SIGNUP_DONE in r.text
    assert _counts(env) == (2, 1) and len(env.mails_to("late@shop.test")) == 1
    texts, _ = _app_logs(caplog)
    assert not any("late@shop.test" in t for t in texts)
    monkeypatch.setattr(auth, "_lookup", real)
    r = finish_signup(env.client(), verify_link(env, "late@shop.test"))
    assert r.status_code == 403 and "Sign-up is closed for now" in r.text
    assert env.scalar("SELECT count(*) FROM app_user WHERE email_verified_at IS NULL") == 1
    assert env.scalar("SELECT status FROM company WHERE id <> 'c_other'") == "unverified"
