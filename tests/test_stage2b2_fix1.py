"""Stage 2b part 2 fix 1, from the first independent review (DEFECT, medium): no request-size
bound before the password work.
(1) Both applications refuse a request body larger than 16384 bytes with 413, before any
handler runs: a declared Content-Length above the limit is refused without reading the body, a
body without Content-Length is counted while it is read and cut at the limit, and a malformed
Content-Length is 400.
(2) A password longer than passwords.MAX_RAW (1024) characters is refused as too long without
being normalised; NFKC shrinks a string by at most 4 to 1, so every such password was already
too long after normalisation, and the bound is proven by scanning every code point."""
import asyncio
import hashlib
import importlib
import itertools
import random
import sys
import unicodedata
from urllib.parse import urlencode

import pytest

from tests.stage2a_support import (  # noqa: F401  (adb and env are fixtures)
    BASE, NEW_PASSWORD, PASSWORD, adb, csrf_from, env, finish_signup, forgot, form_csrf, login,
    path_of, reset_link, signed_up, token_of, verify_link,
)
from tests.stage2b2_support import (  # noqa: F401  (aenv is a fixture)
    ADMIN_BASE, ADMIN_EMAIL, ADMIN_PASSWORD, GENERIC, admin_csrf, aenv,
)
from tests.test_stage2a_fix3 import _no_connection, _throttle_rows
from tests.test_stage2b2_admin import _assert_headers, _counters
from tests.test_stage2b_team import JOINED, invite, invite_link, owner, state, team_csrf

LIMIT = 16384                     # written out, not read from the module: raising it must fail
MAX_RAW = 1024
FORM = {"content-type": "application/x-www-form-urlencoded"}
TOO_LARGE = "The request is too large."
NOT_READ = "The request could not be read."
GENERIC_LOGIN = "The email or password is not correct."
TOO_LONG = "Use at most 128 characters."
ACUTE, E_ACUTE, ALPHA_PSILI_VARIA_YPO = "\\u0301", "\\u00e9", "\\u1f82"


def _u(text: str) -> str:
    """The escapes above stay ASCII in this file."""
    return text.encode("ascii").decode("unicode_escape")


def _mod(name):
    return importlib.import_module(f"quoteops.{name}")


def _padded(data: dict, size: int) -> bytes:
    """The form `data` plus a `pad` field, exactly `size` bytes long."""
    head = urlencode(data) + "&pad="
    n = size - len(head.encode())
    assert n >= 0, "the form alone is larger than the size"
    return (head + "x" * n).encode()


def _assert_refused(r, status: int, admin: bool):
    """The app's own error page with every header of every other error page."""
    assert r.status_code == status, (r.status_code, r.text[:200])
    assert r.headers["content-type"].startswith("text/html")
    _assert_headers(r)
    assert r.headers.get("connection") == "close"
    assert (TOO_LARGE if status == 413 else NOT_READ) in r.text
    # The admin page has no stylesheet; the web page does.
    assert ('href="/static/app.css"' in r.text) is (not admin)


def test_the_limits_are_these_numbers():
    assert _mod("guard").MAX_BODY_BYTES == LIMIT
    assert _mod("passwords").MAX_RAW == MAX_RAW
    assert _mod("passwords").MAX_LENGTH == 128


# --- the body limit through the routes, with the database -----------------------------------------

def _setup_login(aenv):
    c = aenv.client()
    data = {"csrf": form_csrf(c, "/login"), "email": "nobody@shop.test", "password": PASSWORD}

    def normal(r):
        assert r.status_code == 400 and GENERIC_LOGIN in r.text, r.status_code
    return c, "/login", data, normal


def _setup_signup(aenv):
    c = aenv.client()
    data = {"csrf": form_csrf(c, "/signup"), "email": "new@shop.test", "company": "New",
            "terms": "yes"}

    def normal(r):
        assert r.status_code == 200 and "submit the form again" in r.text, r.status_code
        assert len(aenv.mails_to("new@shop.test")) == 1
    return c, "/signup", data, normal


def _setup_forgot(aenv):
    c = aenv.client()
    data = {"csrf": form_csrf(c, "/forgot"), "email": "nobody@shop.test"}

    def normal(r):
        assert r.status_code == 200 and "we sent a link" in r.text, r.status_code
    return c, "/forgot", data, normal


def _setup_verify(aenv):
    signed_up(aenv, "v@shop.test")
    link = verify_link(aenv, "v@shop.test")
    c = aenv.client()
    data = {"csrf": csrf_from(c.get(path_of(link)).text), "token": token_of(link),
            "password": PASSWORD, "company": "Bengkel Maju", "terms": "yes"}

    def normal(r):
        assert r.status_code == 200 and "Email verified" in r.text, r.status_code
    return c, "/verify", data, normal


def _setup_reset(aenv):
    signed_up(aenv, "r@shop.test")
    assert finish_signup(aenv.client(), verify_link(aenv, "r@shop.test")).status_code == 200
    forgot(aenv.client(), "r@shop.test")
    token = token_of(reset_link(aenv, "r@shop.test"))
    c = aenv.client()
    data = {"csrf": csrf_from(c.get("/reset", params={"token": token}).text), "token": token,
            "password": NEW_PASSWORD}

    def normal(r):
        assert r.status_code == 200 and "Password changed" in r.text, r.status_code
    return c, "/reset", data, normal


def _setup_invite(aenv):
    o = owner(aenv)
    invite(o, "new@shop.test")
    link = invite_link(aenv, "new@shop.test")
    c = aenv.client()
    data = {"csrf": csrf_from(c.get(path_of(link)).text), "token": token_of(link),
            "password": PASSWORD, "terms": "yes"}

    def normal(r):
        assert r.status_code == 200 and JOINED in r.text, r.status_code
    return c, "/invite", data, normal


def _setup_team_invite(aenv):
    o = owner(aenv)
    data = {"csrf": team_csrf(o), "email": "new@shop.test", "role": "estimator"}

    def normal(r):
        assert r.status_code == 303 and r.headers["location"] == "/team", r.status_code
    return o, "/team/invite", data, normal


def _setup_admin_login(aenv):
    c = aenv.admin_client()
    data = {"csrf": admin_csrf(c), "email": "nobody@ops.test", "password": ADMIN_PASSWORD,
            "code": "123456"}

    def normal(r):
        assert r.status_code == 400 and GENERIC in r.text, r.status_code
    return c, "/login", data, normal


ROUTES = {"/login": _setup_login, "/signup": _setup_signup, "/forgot": _setup_forgot,
          "/verify": _setup_verify, "/reset": _setup_reset, "/invite": _setup_invite,
          "/team/invite": _setup_team_invite, "admin /login": _setup_admin_login}


def _everything(aenv):
    return (state(aenv), _throttle_rows(aenv), len(aenv.mails()), aenv.admin_sessions(),
            aenv.scalar("SELECT count(*) FROM admin_factor"))


def _slot_spy(monkeypatch):
    passwords, calls = _mod("passwords"), []
    real = passwords.scrypt_slot

    def spy(*a, **kw):
        calls.append(1)
        return real(*a, **kw)
    monkeypatch.setattr(passwords, "scrypt_slot", spy)
    return calls


@pytest.mark.parametrize("route", list(ROUTES))
def test_one_byte_over_the_limit_is_413_and_runs_no_handler(aenv, route):
    """The real form of the route plus padding: one byte over the limit is refused before the
    handler (no connection, no slot, no throttle hit, no change, no mail); the same form at
    exactly the limit gets the route's normal answer."""
    client, path, data, normal = ROUTES[route](aenv)
    before = _everything(aenv)
    slots = _slot_spy(aenv.monkeypatch)
    with _no_connection(aenv):
        r = client.post(path, content=_padded(data, LIMIT + 1), headers=FORM)
    _assert_refused(r, 413, admin=route.startswith("admin"))
    assert slots == []
    assert _everything(aenv) == before
    normal(client.post(path, content=_padded(data, LIMIT), headers=FORM))


@pytest.mark.parametrize("route", ["/login", "/verify", "admin /login"])
def test_a_body_far_over_the_limit_is_413(aenv, route):
    client, path, data, _ = ROUTES[route](aenv)
    before = _everything(aenv)
    with _no_connection(aenv):
        r = client.post(path, content=_padded(data, 2 * 1024 * 1024), headers=FORM)
    _assert_refused(r, 413, admin=route.startswith("admin"))
    assert _everything(aenv) == before


# --- the body limit, driving the ASGI applications directly ---------------------------------------

def _app(which: str):
    return _mod("admin_app").app if which == "admin" else _mod("app").app


class _Entered(Exception):
    pass


def _handler_spy(monkeypatch):
    """Every route of both apps that takes a body loads its settings first; record and stop."""
    calls = []

    def spy(*a, **kw):
        calls.append(1)
        raise _Entered()
    for module, name in (("auth", "load_settings"), ("team", "load_settings"),
                         ("admin_app", "load_admin_settings")):
        monkeypatch.setattr(_mod(module), name, spy)
    return calls


def _drive(app, method: str, path: str, headers: list[tuple[str, str]], chunks):
    """One request through the ASGI app. receive() hands out `chunks` one per call with
    more_body set, then an empty last part, then http.disconnect. Returns the status, the
    response headers, the body and how many receive() calls and body bytes were taken."""
    pulled = {"calls": 0, "bytes": 0}
    parts = iter(chunks)
    finished = False
    sent = []

    async def receive():
        nonlocal finished
        pulled["calls"] += 1
        if finished:
            return {"type": "http.disconnect"}
        chunk = next(parts, None)
        if chunk is None:
            finished = True
            return {"type": "http.request", "body": b"", "more_body": False}
        pulled["bytes"] += len(chunk)
        return {"type": "http.request", "body": chunk, "more_body": True}

    async def send(message):
        sent.append(message)

    scope = {"type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"},
             "http_version": "1.1", "method": method, "scheme": "https", "path": path,
             "raw_path": path.encode(), "root_path": "", "query_string": b"",
             "headers": [(k.lower().encode("latin-1"), v.encode("latin-1")) for k, v in headers],
             "client": ("127.0.0.1", 50000), "server": ("qo.example", 443)}
    asyncio.run(app(scope, receive, send))
    start = [m for m in sent if m["type"] == "http.response.start"]
    assert len(start) == 1, sent
    body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    hdrs = {}
    for k, v in start[0]["headers"]:
        hdrs.setdefault(k.decode("latin-1").lower(), []).append(v.decode("latin-1"))
    return start[0]["status"], hdrs, body.decode("utf-8"), pulled


def _assert_page(status, hdrs, body, expected, which):
    assert status == expected, (status, body[:200])
    assert hdrs["content-type"][0].startswith("text/html")
    assert hdrs["content-security-policy"] == [_mod("guard").CSP]
    assert hdrs["x-content-type-options"] == ["nosniff"]
    assert hdrs["referrer-policy"] == ["same-origin"]
    assert hdrs["x-frame-options"] == ["DENY"]
    assert hdrs["cache-control"] == ["no-store"]
    assert hdrs["connection"] == ["close"]
    assert hdrs["content-length"] == [str(len(body.encode("utf-8")))]
    assert (TOO_LARGE if expected == 413 else NOT_READ) in body
    assert ('href="/static/app.css"' in body) is (which == "web")


APPS_PATHS = [("web", "/login"), ("web", "/verify"), ("web", "/reset"), ("web", "/invite"),
              ("web", "/signup"), ("web", "/forgot"), ("web", "/team/invite"),
              ("admin", "/login"), ("admin", "/logout")]


@pytest.mark.parametrize("which,path", APPS_PATHS)
@pytest.mark.parametrize("declared", [LIMIT + 1, 2 * 1024 * 1024, 10 ** 12])
def test_a_declared_length_over_the_limit_is_refused_before_the_body_is_read(
        monkeypatch, which, path, declared):
    entered = _handler_spy(monkeypatch)
    status, hdrs, body, pulled = _drive(
        _app(which), "POST", path, [("content-type", FORM["content-type"]),
                                    ("content-length", str(declared))],
        itertools.repeat(b"x" * 4096, (LIMIT + 1) // 4096 + 1))
    _assert_page(status, hdrs, body, 413, which)
    assert pulled == {"calls": 0, "bytes": 0}
    assert entered == []


@pytest.mark.parametrize("which,path", APPS_PATHS)
@pytest.mark.parametrize("chunk", [1000, 4096, 65536, 2 * 1024 * 1024])
def test_a_body_without_length_is_cut_at_the_limit(monkeypatch, which, path, chunk):
    """No Content-Length (chunked): the body is counted while it is read; the read stops at
    the chunk that crosses the limit, and the handler never runs on the part that was read.
    The generator has a few chunks more than the limit needs, so the old code ends too."""
    entered = _handler_spy(monkeypatch)
    status, hdrs, body, pulled = _drive(
        _app(which), "POST", path, [("content-type", FORM["content-type"]),
                                    ("transfer-encoding", "chunked")],
        itertools.repeat(b"x" * chunk, LIMIT // chunk + 3))
    _assert_page(status, hdrs, body, 413, which)
    assert LIMIT < pulled["bytes"] <= LIMIT + chunk, pulled
    assert entered == []


@pytest.mark.parametrize("which", ["web", "admin"])
def test_a_body_without_length_at_the_limit_reaches_the_handler(monkeypatch, which):
    entered = _handler_spy(monkeypatch)
    status, _, _, pulled = _drive(
        _app(which), "POST", "/login", [("content-type", FORM["content-type"])],
        [b"x" * 4096] * 4)
    assert pulled["bytes"] == LIMIT
    assert entered == [1] and status == 500  # the spy stopped the handler


@pytest.mark.parametrize("which,path", APPS_PATHS)
@pytest.mark.parametrize("value", ["abc", "-1", "1.5", "", "+12", "0x10", "1 2",
                                   "\\u0661\\u0662"])
def test_a_malformed_content_length_is_400(monkeypatch, which, path, value):
    entered = _handler_spy(monkeypatch)
    raw = _u(value).encode("utf-8").decode("latin-1")
    status, hdrs, body, pulled = _drive(
        _app(which), "POST", path, [("content-type", FORM["content-type"]),
                                    ("content-length", raw)],
        [b"x" * 12])
    _assert_page(status, hdrs, body, 400, which)
    assert pulled["calls"] == 0 and entered == []


@pytest.mark.parametrize("which", ["web", "admin"])
def test_two_different_content_lengths_are_400(monkeypatch, which):
    entered = _handler_spy(monkeypatch)
    status, hdrs, body, pulled = _drive(
        _app(which), "POST", "/login", [("content-type", FORM["content-type"]),
                                        ("content-length", "12"), ("content-length", "13")],
        [b"x" * 12])
    _assert_page(status, hdrs, body, 400, which)
    assert pulled["calls"] == 0 and entered == []


def _chunked_post(client, path, data, cookie_name, origin, which):
    """POST `data`, padded to exactly the limit, in 4096-byte chunks without Content-Length."""
    cookie = client.cookies.get(cookie_name)
    body = _padded(data, LIMIT)
    chunks = [body[i:i + 4096] for i in range(0, len(body), 4096)]
    return _drive(_app(which), "POST", path,
                  [("content-type", FORM["content-type"]), ("origin", origin),
                   ("cookie", f"{cookie_name}={cookie}")], chunks)


def test_a_chunked_form_of_exactly_the_limit_gets_the_normal_answer(aenv):
    client, path, data, _ = _setup_login(aenv)
    status, _, body, pulled = _chunked_post(client, path, data, "qo_csrf", BASE, "web")
    assert pulled["bytes"] == LIMIT
    assert status == 400 and GENERIC_LOGIN in body
    client, path, data, _ = _setup_admin_login(aenv)
    status, _, body, pulled = _chunked_post(client, path, data, "qo_admin_csrf", ADMIN_BASE,
                                            "admin")
    assert pulled["bytes"] == LIMIT
    assert status == 400 and GENERIC in body


def test_get_and_head_are_unaffected(aenv):
    c = aenv.client()
    for path in ("/login", "/signup", "/forgot", "/terms"):
        r = c.get(path)
        assert r.status_code == 200, path
        assert "connection" not in r.headers
    r = c.head("/login")  # the web routes have no HEAD; that stays as it was
    assert r.status_code == 405 and "connection" not in r.headers
    r = c.get("/static/app.css")
    assert r.status_code == 200 and r.headers["cache-control"] == "public, max-age=3600"
    r = c.get("/login", headers={"content-length": "0"})
    assert r.status_code == 200
    a = aenv.admin_client()
    for method, path in (("GET", "/login"), ("GET", "/healthz"), ("HEAD", "/healthz")):
        r = a.request(method, path)
        assert r.status_code == 200, (method, path)
        assert "connection" not in r.headers


# --- the raw password bound -----------------------------------------------------------------------

def _all_code_points():
    return (chr(cp) for cp in range(sys.maxunicode + 1) if not 0xD800 <= cp <= 0xDFFF)


def test_nfkc_shrinks_a_string_by_at_most_four_to_one():
    """The proof behind MAX_RAW. NFKC is NFKD and then canonical composition. (a) No code point
    has an empty NFKD, so NFKD never makes a string shorter. (b) Composition replaces a starter
    and the marks that compose with it by one character whose full canonical decomposition is
    exactly those characters; so one character of the result stands for at most k characters,
    k being the longest canonical decomposition of a character that NFC leaves as it is. Here
    k = 4 (U+1F82, alpha with psili, varia and ypogegrammeni; Hangul syllables are 3). So a
    string of N characters normalises to at least N / k characters, and a password of more
    than MAX_RAW = 1024 >= 128 * 4 characters is longer than 128 after NFKC: refusing it
    unnormalised refuses nothing that was accepted before."""
    passwords = _mod("passwords")
    k, worst, composites = 0, None, []
    for c in _all_code_points():
        assert len(unicodedata.normalize("NFKD", c)) >= 1, hex(ord(c))
        d = unicodedata.normalize("NFD", c)
        if len(d) > 1 and unicodedata.normalize("NFC", d) == c:
            composites.append(d)
            if len(d) > k:
                k, worst = len(d), c
    assert k == 4 and worst == _u(ALPHA_PSILI_VARIA_YPO)
    assert passwords.MAX_RAW >= passwords.MAX_LENGTH * k
    assert passwords.MAX_RAW >= 2 * passwords.MAX_LENGTH * k  # the margin
    # The worst sequences: a decomposed composite, repeated past MAX_RAW.
    for d in composites:
        s = (d * (MAX_RAW // len(d) + 1))[:MAX_RAW + 1]
        out = unicodedata.normalize("NFKC", s)
        assert len(out) * k >= len(s), (d, len(out))
        assert len(out) > passwords.MAX_LENGTH, d
    # Random mixtures of starters, marks, Hangul jamo and other code points.
    rng = random.Random(20261108)
    pool = [c for d in composites for c in d] + [chr(cp) for cp in range(0x1100, 0x11FF)]
    pool += [chr(rng.randrange(0x30000)) for _ in range(2000)]
    pool = [c for c in pool if not 0xD800 <= ord(c) <= 0xDFFF]
    for _ in range(300):
        s = "".join(rng.choice(pool) for _ in range(MAX_RAW + 1))
        assert len(unicodedata.normalize("NFKC", s)) * k >= len(s)


def _normalise_spy(monkeypatch):
    passwords, lengths = _mod("passwords"), []
    real = passwords.normalise

    def spy(value):
        lengths.append(len(value))
        return real(value)
    monkeypatch.setattr(passwords, "normalise", spy)
    return lengths


def _scrypt_spy(monkeypatch):
    calls, real = [], hashlib.scrypt

    def spy(password, **kw):
        calls.append(password)
        return real(password, **kw)
    monkeypatch.setattr(hashlib, "scrypt", spy)
    return calls


def test_policy_error_does_not_normalise_a_huge_password(monkeypatch):
    passwords = _mod("passwords")
    lengths = _normalise_spy(monkeypatch)
    assert passwords.policy_error("x" * 5_000_000, "a@b.test") == TOO_LONG
    assert passwords.policy_error("\x00" * (MAX_RAW + 1), "a@b.test") == TOO_LONG
    assert lengths == []


def test_policy_error_boundary_at_max_raw(monkeypatch):
    """Exactly MAX_RAW still takes the normal path: the control character is found first."""
    passwords = _mod("passwords")
    lengths = _normalise_spy(monkeypatch)
    assert passwords.policy_error("\x00" + "x" * (MAX_RAW - 1), "a@b.test") == \
        "Do not use control characters."
    assert lengths[0] == MAX_RAW
    lengths.clear()
    assert passwords.policy_error("x" * MAX_RAW, "a@b.test") == TOO_LONG
    assert lengths[0] == MAX_RAW
    lengths.clear()
    assert passwords.policy_error("\x00" + "x" * MAX_RAW, "a@b.test") == TOO_LONG
    assert lengths == []


def test_composing_characters_still_count_after_normalising():
    """e + combining acute, 128 times: 256 characters as sent, 128 after NFKC: accepted, and
    the hash checks against the composed form."""
    passwords = _mod("passwords")
    pw = ("e" + _u(ACUTE)) * 128
    assert len(pw) == 256 and len(passwords.normalise(pw)) == 128
    assert passwords.policy_error(pw, "a@b.test") is None
    assert passwords.policy_error(("e" + _u(ACUTE)) * 129, "a@b.test") == TOO_LONG
    h, salt = passwords.hash_password(pw)
    assert passwords.verify_password(_u(E_ACUTE) * 128, h, salt) is True


@pytest.mark.parametrize("check", ["dummy", "real"])
def test_matching_a_huge_password_normalises_nothing_and_runs_one_scrypt(monkeypatch, check):
    passwords = _mod("passwords")
    h, salt = passwords.hash_password("")  # even the hash of "" is not a match
    lengths, calls = _normalise_spy(monkeypatch), _scrypt_spy(monkeypatch)
    for size in (MAX_RAW + 1, 5_000_000):
        pw = "x" * size
        ok = passwords.verify_dummy(pw) if check == "dummy" else passwords.verify_password(pw, h, salt)
        assert ok is False
    assert calls == [b"", b""]
    assert max(lengths) <= MAX_RAW


def test_matching_at_max_raw_takes_the_normal_path(monkeypatch):
    passwords = _mod("passwords")
    lengths, calls = _normalise_spy(monkeypatch), _scrypt_spy(monkeypatch)
    assert passwords.verify_dummy("x" * MAX_RAW) is False
    assert MAX_RAW in lengths and calls == [b""]  # too long after normalising: the empty hash


def test_hash_password_refuses_a_huge_password(monkeypatch):
    passwords = _mod("passwords")
    lengths, calls = _normalise_spy(monkeypatch), _scrypt_spy(monkeypatch)
    for size in (MAX_RAW + 1, 5_000_000):
        with pytest.raises(ValueError) as exc:
            passwords.hash_password("x" * size)
        assert str(exc.value) == TOO_LONG
    assert lengths == [] and calls == []
    passwords.hash_password("x" * MAX_RAW)  # unchanged up to the bound
    assert lengths == [MAX_RAW] and len(calls) == 1


# --- the raw bound through the routes ---------------------------------------------------------------

HUGE = "x" * 10_000  # fits in the body limit, ten times MAX_RAW


def test_web_login_with_a_long_password_normalises_nothing_long_and_runs_one_scrypt(aenv):
    signed_up(aenv, "o@shop.test")
    assert finish_signup(aenv.client(), verify_link(aenv, "o@shop.test")).status_code == 200
    lengths, calls = _normalise_spy(aenv.monkeypatch), _scrypt_spy(aenv.monkeypatch)
    for email in ("o@shop.test", "nobody@shop.test"):
        c = aenv.client()
        csrf = form_csrf(c, "/login")
        lengths.clear()
        calls.clear()
        r = c.post("/login", data={"csrf": csrf, "email": email, "password": HUGE})
        assert r.status_code == 400 and GENERIC_LOGIN in r.text
        assert len(calls) == 1 and max(lengths) <= MAX_RAW, email


def test_admin_login_with_a_long_password_normalises_nothing_long_same_work(aenv):
    aenv.create_admin()
    c = aenv.admin_client()
    csrf = admin_csrf(c)
    lengths = _normalise_spy(aenv.monkeypatch)
    scrypts, hotps = _counters(aenv)
    r = c.post("/login", data={"csrf": csrf, "email": ADMIN_EMAIL, "password": HUGE,
                               "code": "123456"})
    assert r.status_code == 400 and GENERIC in r.text
    assert len(scrypts) == 1 and len(hotps) == 3
    assert max(lengths) <= MAX_RAW


def test_a_multi_megabyte_password_never_reaches_normalise(aenv):
    forms = {route: ROUTES[route](aenv) for route in ("/login", "/verify", "/reset", "/invite",
                                                      "admin /login")}
    lengths = _normalise_spy(aenv.monkeypatch)
    for route, (client, path, data, _) in forms.items():
        r = client.post(path, data={**data, "password": "x" * 3_000_000})
        assert r.status_code == 413, route
    assert lengths == []


@pytest.mark.parametrize("route", ["/verify", "/reset", "/invite"])
def test_choosing_a_long_password_is_refused_without_normalising_it(aenv, route):
    client, path, data, normal = ROUTES[route](aenv)
    before = _everything(aenv)
    lengths, calls = _normalise_spy(aenv.monkeypatch), _scrypt_spy(aenv.monkeypatch)
    r = client.post(path, data={**data, "password": HUGE})
    assert r.status_code == 400 and TOO_LONG in r.text
    assert calls == [] and lengths == []
    assert _everything(aenv) == before
    normal(client.post(path, data=data))


def test_a_password_of_composing_characters_is_accepted_at_verification(aenv):
    signed_up(aenv, "e@shop.test")
    r = finish_signup(aenv.client(), verify_link(aenv, "e@shop.test"),
                      password=("e" + _u(ACUTE)) * 128)
    assert r.status_code == 200 and "Email verified" in r.text
    assert login(aenv.client(), "e@shop.test", _u(E_ACUTE) * 128).status_code == 303


@pytest.mark.parametrize("field", ["password", "code"])
def test_admin_login_with_an_oversized_field_is_413_before_the_slot(aenv, field):
    aenv.create_admin()
    c = aenv.admin_client()
    data = {"csrf": admin_csrf(c), "email": ADMIN_EMAIL, "password": ADMIN_PASSWORD,
            "code": "123456", field: "1" * (LIMIT + 1)}
    before = _everything(aenv)
    slots = _slot_spy(aenv.monkeypatch)
    with _no_connection(aenv):
        r = c.post("/login", data=data)
    _assert_refused(r, 413, admin=True)
    assert slots == [] and _everything(aenv) == before


def test_the_cli_refuses_a_password_over_the_bound_with_the_policy_message(aenv):
    code, out, err = aenv.cli.run("create-admin", ADMIN_EMAIL, stdin="x" * 100_000 + "\n")
    assert code == 1 and TOO_LONG in err and "Nothing was changed." in err
    assert aenv.scalar("SELECT count(*) FROM app_user") == 0
