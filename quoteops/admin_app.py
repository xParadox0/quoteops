"""Stage 2b part 2: the administrator's service (PRD F25, Q5; HLD section 11). A second ASGI
application, run as its own container, that connects to PostgreSQL only as qo_admin. It may be
reachable from the internet, so its sign-in is strong on its own: email, password and an
authenticator code in one step, one generic failure, the scrypt slot first, the sign-in
throttle, and a replay guard on the code. Signed in, it shows who is signed in and a sign-out
button; the administrator pages (F18) come in a later stage."""
import hashlib
import logging
import secrets
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timezone

import psycopg
from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import PlainTextResponse, RedirectResponse, Response
from starlette.exceptions import HTTPException as StarletteHTTPException

from quoteops import guard, pages, passwords, throttle, totp
from quoteops.config import AdminSettings, ConfigError, admin_conninfo, load_admin_settings

log = logging.getLogger("quoteops")

ADMIN_COOKIE, CSRF_COOKIE = "qo_admin", "qo_admin_csrf"
CSRF_COOKIE_SECONDS = 2 * 3600
GENERIC = "The email, password or code is not correct."
TRY_LATER = "Try again in a few minutes."
# The code of an address that is not an active administrator is checked against this fixed
# secret, so that path does the same work as a real one. No administrator has it.
_DUMMY_SECRET = bytes.fromhex("5e1b7c2a9d04f36e8a1c5b7d9e0f2a4c6b8d0e1f")


def _now() -> float:
    """The clock for the code check; tests replace it."""
    return time.time()


def admin_conn() -> psycopg.Connection:
    """The only way this service reaches the database: the qo_admin role."""
    return psycopg.connect(admin_conninfo(), autocommit=True)


def _sha256(value: str) -> bytes:
    return hashlib.sha256(value.encode("utf-8")).digest()


def _message(title: str, text: str, status: int = 200) -> Response:
    return pages.render("admin_message.html", status=status, title=title, text=text)


def _redirect(path: str) -> RedirectResponse:
    return RedirectResponse(path, status_code=303)


def _refused() -> Response:
    return _message("Request refused", "This form has expired or was sent from another site."
                    " Go back, reload the page and try again.", status=403)


def _busy() -> Response:
    """No scrypt slot came free. The slot is taken before anything else, so nothing was counted
    or changed and no connection was opened."""
    response = _message("Service busy", "The service is busy. Try again in a few minutes.",
                        status=503)
    response.headers["Retry-After"] = "5"
    return response


# --- CSRF -----------------------------------------------------------------------------------------

def _form(request: Request, s: AdminSettings, status: int = 200,
          failure: str | None = None) -> Response:
    """The sign-in form, with its pre-session CSRF cookie when the browser has none. The fields
    are never filled in again, so every failure is the same page."""
    cookie = request.cookies.get(CSRF_COOKIE, "")
    fresh = None
    if not guard.COOKIE_RE.fullmatch(cookie):
        cookie = fresh = secrets.token_urlsafe(32)
    response = pages.render("admin_login.html", status=status, title="Administrator sign-in",
                            csrf=guard.mac(s, "admin-csrf-form", cookie), failure=failure)
    if fresh:
        response.set_cookie(CSRF_COOKIE, fresh, max_age=CSRF_COOKIE_SECONDS, path="/",
                            httponly=True, samesite="strict", secure=s.cookie_secure)
    return response


def _pre_session_ok(request: Request, s: AdminSettings, csrf: str) -> bool:
    """Double submit, as the web sign-in: the field is an HMAC (QO_ADMIN_SECRET) of the random
    value in this browser's qo_admin_csrf cookie; and the Origin is the admin service's."""
    if not guard.origin_ok(request, s):
        return False
    cookie = request.cookies.get(CSRF_COOKIE, "")
    return bool(guard.COOKIE_RE.fullmatch(cookie)) and guard.same(
        csrf, guard.mac(s, "admin-csrf-form", cookie))


def session_csrf(s: AdminSettings, session_hash: bytes) -> str:
    return guard.mac(s, "admin-csrf-session", session_hash.hex())


# --- the signed-in administrator ------------------------------------------------------------------

@dataclass(frozen=True)
class Admin:
    user_id: uuid.UUID
    email: str
    expires_at: datetime
    session_hash: bytes


def current_admin(request: Request) -> Admin | None:
    """Resolve the qo_admin cookie through qo_admin_session_lookup; only its sha256 is sent.
    A qo_session cookie of the public app is never read here."""
    token = request.cookies.get(ADMIN_COOKIE)
    if not token or not guard.COOKIE_RE.fullmatch(token):
        return None
    id_hash = _sha256(token)
    with admin_conn() as conn:
        row = conn.execute("SELECT user_id, email, expires_at FROM qo_admin_session_lookup(%s)",
                           (id_hash,)).fetchone()
    if row is None:
        return None
    return Admin(row[0], row[1], row[2], id_hash)


# --- the application ------------------------------------------------------------------------------

@asynccontextmanager
async def _lifespan(app: FastAPI):
    try:
        load_admin_settings()
    except ConfigError as exc:
        log.critical("QuoteOps admin refuses to start: %s", exc)
        raise
    yield


app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=_lifespan)
app.add_middleware(guard.GuardMiddleware, template="admin_message.html", static_prefix=None)
app.add_exception_handler(StarletteHTTPException, guard.http_error_handler(_message))
app.add_exception_handler(RequestValidationError, guard.validation_error_handler(_message))


@app.api_route("/healthz", methods=["GET", "HEAD"], response_class=PlainTextResponse)
def healthz() -> str:
    try:
        with psycopg.connect(admin_conninfo(), connect_timeout=3) as conn:
            if conn.execute("SELECT 1").fetchone() != (1,):
                raise RuntimeError("unexpected result")
    except Exception as exc:
        log.error("healthz database check failed: %s", type(exc).__name__)
        raise HTTPException(status_code=503, detail="database check failed")
    return "ok"


@app.get("/")
def index(request: Request):
    return _redirect("/admin" if current_admin(request) else "/login")


@app.get("/login")
def login_form(request: Request):
    if current_admin(request):
        return _redirect("/admin")
    return _form(request, load_admin_settings())


@app.post("/login")
def login(request: Request, csrf: str = Form(""), email: str = Form(""),
          password: str = Form(""), code: str = Form("")):
    s = load_admin_settings()
    if not _pre_session_ok(request, s, csrf):
        return _refused()
    try:
        # The slot first, before the throttle and any connection: a busy answer counts no
        # attempt, changes nothing and holds no database connection while it waits.
        with passwords.scrypt_slot():
            return _login(request, s, guard.norm_email(email), password, code)
    except passwords.Busy:
        return _busy()


def _failed(request: Request, s: AdminSettings, blocked: bool = False) -> Response:
    """The one failure page: it never says which of email, password or code was wrong."""
    if blocked:
        return _form(request, s, status=429, failure=f"{GENERIC} {TRY_LATER}")
    return _form(request, s, status=400, failure=GENERIC)


def _lookup(conn, email: str):
    """qo_admin_login_lookup as a dict, or None: an active, verified sysadmin with a factor."""
    cur = conn.execute("SELECT user_id, pw_hash, pw_salt, totp_secret, last_counter"
                       " FROM qo_admin_login_lookup(%s)", (email,))
    row = cur.fetchone()
    return dict(zip([d.name for d in cur.description], row)) if row else None


def _login(request: Request, s: AdminSettings, email: str, password: str, code: str) -> Response:
    ip = guard.client_ip(request, s)
    with admin_conn() as conn:
        # Throttle first: a blocked address or network gets no password or code check at all.
        allowed = throttle.hit(conn, "admin_login_ip", ip, s.secret, s.login_fails_per_ip,
                               s.login_window_seconds, s.login_block_seconds)
        allowed = allowed and throttle.hit(conn, "admin_login_email", email, s.secret,
                                           s.login_fails_per_email, s.login_window_seconds,
                                           s.login_block_seconds)
        if not allowed:
            return _failed(request, s, blocked=True)
        admin = _lookup(conn, email) if guard.valid_email(email) else None
        # Both checks run on every path, whatever the first one said: one scrypt (real or
        # dummy) and three code comparisons (against the real or a dummy secret). Unknown
        # address, company account, disabled administrator, wrong password, wrong or malformed
        # code: the same work and the same answer.
        if admin is None:
            password_ok = passwords.verify_dummy(password)
            secret, user_id = _DUMMY_SECRET, None
        else:
            password_ok = passwords.verify_password(password, admin["pw_hash"], admin["pw_salt"])
            secret, user_id = bytes(admin["totp_secret"]), admin["user_id"]
        counter = totp.match(secret, code, _now())
        if not password_ok or counter is None or user_id is None:
            return _failed(request, s)
        # The replay guard: a code whose time step is not later than the last accepted one
        # (the same code again, in parallel or later) fails like a wrong code.
        if not conn.execute("SELECT qo_admin_totp_use(%s, %s)", (user_id, counter)).fetchone()[0]:
            return _failed(request, s)
        throttle.reset(conn, "admin_login_email", email, s.secret)
        old = request.cookies.get(ADMIN_COOKIE)
        if old:
            conn.execute("SELECT qo_admin_session_delete(%s)", (_sha256(old),))
        token = secrets.token_urlsafe(32)
        conn.execute("SELECT qo_admin_session_create(%s, %s, now() + make_interval(hours => %s),"
                     " %s)", (_sha256(token), user_id, s.session_hours, guard.inet(ip)))
    response = _redirect("/admin")
    response.set_cookie(ADMIN_COOKIE, token, max_age=s.session_hours * 3600, path="/",
                        httponly=True, samesite="strict", secure=s.cookie_secure)
    return response


@app.get("/admin")
def admin_home(request: Request):
    s = load_admin_settings()
    admin = current_admin(request)
    if admin is None:
        return _redirect("/login")
    ends = admin.expires_at.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return pages.render("admin_home.html", title="Signed in", email=admin.email, ends=ends,
                        csrf=session_csrf(s, admin.session_hash))


@app.post("/logout")
def logout(request: Request, csrf: str = Form("")):
    s = load_admin_settings()
    if not guard.origin_ok(request, s):
        return _refused()
    token = request.cookies.get(ADMIN_COOKIE)
    if not token:
        return _redirect("/login")
    # The token is an HMAC of this cookie's hash, so it is checked without a database lookup
    # and still lets an administrator whose session no longer resolves remove the row.
    id_hash = _sha256(token)
    if not guard.same(csrf, session_csrf(s, id_hash)):
        return _refused()
    with admin_conn() as conn:
        conn.execute("SELECT qo_admin_session_delete(%s)", (id_hash,))
    response = _redirect("/login")
    response.delete_cookie(ADMIN_COOKIE, path="/", secure=s.cookie_secure, httponly=True,
                           samesite="strict")
    return response
