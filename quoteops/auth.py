"""Stage 2a authentication: sign-up, email verification, sign-in, sessions, sign-out and password
reset (PRD F1 to F4, F16, F17; HLD "Stage 2a: authentication")."""
import hashlib
import logging
import secrets
import uuid
from dataclasses import dataclass

import psycopg
from fastapi import APIRouter, BackgroundTasks, Depends, Form, Request
from fastapi.responses import RedirectResponse, Response

from quoteops import passwords, throttle, tokens
from quoteops.config import Settings, load_settings
from quoteops.dbconn import lookup_conn, tenant_conn
# Shared with the admin service since stage 2b part 2; the old private names stay for the
# callers in this module and in team.py.
from quoteops.guard import COOKIE_RE as _COOKIE_RE
from quoteops.guard import EMAIL_RE as _EMAIL_RE  # noqa: F401
from quoteops.guard import client_ip
from quoteops.guard import inet as _inet
from quoteops.guard import mac as _mac
from quoteops.guard import norm_email as _norm_email
from quoteops.guard import origin_ok as _origin_ok
from quoteops.guard import same as _same
from quoteops.guard import valid_email as _valid_email
from quoteops.mail import mailer
from quoteops.pages import message, render

log = logging.getLogger("quoteops")
router = APIRouter()

TERMS_VERSION = "draft-0"
SESSION_COOKIE, CSRF_COOKIE = "qo_session", "qo_csrf"
SESSION_SECONDS = 7 * 24 * 3600     # absolute; a session is never extended
CSRF_COOKIE_SECONDS = 2 * 3600
VERIFY_SECONDS, RESET_SECONDS = 48 * 3600, 3600
HOUR = 3600
SIGNUP_LOCK = 0x514F5355            # advisory lock id: one activation or purge at a time

GENERIC_LOGIN = "The email or password is not correct."
TRY_LATER = "Try again in a few minutes."
INVALID_LINK = "This link is not valid or has expired. Ask for a new one."
FORGOT_DONE = "If that address has an account, we sent a link. The link works for 1 hour."
# A mail failure is never shown (that would tell whether the address has an account), so the
# answer says what to do when the mail does not come.
SIGNUP_DONE = ("Check your email to finish signing up: open the link in it to choose your"
               " password. If the email does not arrive within a few minutes, submit the form"
               " again.")
ALREADY_VERIFIED = "This email address is already verified. Sign in with your password."


# --- the signed-in user ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Principal:
    user_id: uuid.UUID
    company_id: str
    role: str
    session_hash: bytes


class NotSignedIn(Exception):
    """No valid session: the app answers with a redirect to /login."""


class Forbidden(Exception):
    """Signed in but not allowed: the app answers 403 with this text."""

    def __init__(self, text: str):
        super().__init__(text)
        self.text = text


def _sha256(value: str) -> bytes:
    return hashlib.sha256(value.encode("utf-8")).digest()


def current_principal(request: Request) -> Principal | None:
    """Resolve the session cookie through qo_session_lookup. Only its sha256 is sent to the
    database. A sysadmin session has no company and no page in stage 2a, so it is not signed in."""
    token = request.cookies.get(SESSION_COOKIE)
    if not token or not _COOKIE_RE.fullmatch(token):
        return None
    id_hash = _sha256(token)
    with lookup_conn() as conn:
        row = conn.execute("SELECT user_id, company_id, role FROM qo_session_lookup(%s)",
                           (id_hash,)).fetchone()
    if row is None or row[1] is None:
        return None
    return Principal(row[0], row[1], row[2], id_hash)


def require_user(request: Request) -> Principal:
    principal = current_principal(request)
    if principal is None:
        raise NotSignedIn()
    return principal


def require_verified(principal: Principal = Depends(require_user)) -> Principal:
    with tenant_conn(principal.company_id) as conn:
        row = conn.execute("SELECT email_verified_at FROM app_user WHERE id = %s",
                           (principal.user_id,)).fetchone()
    if row is None or row[0] is None:
        raise Forbidden("Verify your email address first. Open the link we sent when you signed up.")
    return principal


def require_role(*roles: str):
    def dependency(principal: Principal = Depends(require_user)) -> Principal:
        if principal.role not in roles:
            raise Forbidden("Your role does not allow this.")
        return principal
    return dependency


# --- request plumbing -----------------------------------------------------------------------------

def session_csrf(s: Settings, session_hash: bytes) -> str:
    return _mac(s, "csrf-session", session_hash.hex())


def _pre_session_ok(request: Request, s: Settings, csrf: str) -> bool:
    """Double submit for forms shown before a session exists: the field is an HMAC of the random
    value in the short-lived qo_csrf cookie, so a token from another browser never matches."""
    if not _origin_ok(request, s):
        return False
    cookie = request.cookies.get(CSRF_COOKIE, "")
    return bool(_COOKIE_RE.fullmatch(cookie)) and _same(csrf, _mac(s, "csrf-form", cookie))


def _refused() -> Response:
    return message("Request refused", "This form has expired or was sent from another site."
                   " Go back, reload the page and try again.", status=403)


def _form(request: Request, s: Settings, template: str, status: int = 200, **context) -> Response:
    """Render a pre-session form, creating its qo_csrf cookie when the browser has none."""
    cookie = request.cookies.get(CSRF_COOKIE, "")
    fresh = None
    if not _COOKIE_RE.fullmatch(cookie):
        cookie = fresh = secrets.token_urlsafe(32)
    response = render(template, status=status, csrf=_mac(s, "csrf-form", cookie),
                      terms_version=TERMS_VERSION, **context)
    if fresh:
        response.set_cookie(CSRF_COOKIE, fresh, max_age=CSRF_COOKIE_SECONDS, path="/",
                            httponly=True, samesite="lax", secure=s.cookie_secure)
    return response


def _redirect(path: str) -> RedirectResponse:
    return RedirectResponse(path, status_code=303)


def _valid_company(name: str) -> bool:
    return 1 <= len(name) <= 80 and name.isprintable()


def _lookup(conn, email: str):
    """qo_login_lookup as a dict, or None."""
    cur = conn.execute("SELECT id, company_id, pw_hash, pw_salt, role, email_verified_at,"
                       " disabled_at, company_status FROM qo_login_lookup(%s)", (email,))
    row = cur.fetchone()
    return dict(zip([d.name for d in cur.description], row)) if row else None


def _has_account(email: str) -> bool:
    """Whether the address has an account in any company (the email is unique platform-wide)."""
    with lookup_conn() as conn:
        return _lookup(conn, email) is not None


def _busy() -> Response:
    """Every scrypt slot stayed taken (passwords.Busy). The slot is taken before anything else,
    so nothing was counted or changed, no connection was opened and no mail sent."""
    response = message("Service busy", "The service is busy. Try again in a few minutes.",
                       status=503)
    response.headers["Retry-After"] = "5"
    return response


# --- mail text ------------------------------------------------------------------------------------

def _verify_mail(s: Settings, email: str) -> tuple[str, str]:
    link = f"{s.base_url}/verify?token={tokens.make('verify', email, VERIFY_SECONDS, s.secret)}"
    return "Verify your email address for QuoteOps", (
        f"Hello,\n\nThis email was sent to {email} because someone signed up for QuoteOps"
        " with this address.\n\nOpen this link to verify your email address and choose your"
        " password:\n"
        f"{link}\n\nThe link works for 48 hours.\n\n"
        "If you did not ask for this, ignore this email.\n\nQuoteOps\n")


def _exists_mail(s: Settings, email: str) -> tuple[str, str]:
    return "Your QuoteOps account already exists", (
        f"Hello,\n\nThis email was sent to {email} because someone tried to sign up for"
        " QuoteOps with this address.\n\nAn account with this address already exists."
        " No new account was created.\n\nTo sign in, open this link:\n"
        f"{s.base_url}/login\n\nIf you forgot your password, open this link to reset it:\n"
        f"{s.base_url}/forgot\n\nThese two links do not expire.\n\n"
        "If you did not ask for this, ignore this email.\n\nQuoteOps\n")


def _reset_mail(s: Settings, email: str, pw_hash: bytes) -> tuple[str, str]:
    token = tokens.make("reset", email, RESET_SECONDS, s.secret, extra=_fingerprint(pw_hash))
    return "Reset your QuoteOps password", (
        f"Hello,\n\nThis email was sent to {email} because someone asked to reset the"
        " QuoteOps password for this address.\n\nOpen this link to choose a new password:\n"
        f"{s.base_url}/reset?token={token}\n\nThe link works for 1 hour and only once.\n\n"
        "If you did not ask for this, ignore this email.\n\nQuoteOps\n")


def _changed_mail(email: str) -> tuple[str, str]:
    return "Your QuoteOps password was changed", (
        f"Hello,\n\nThis email was sent to {email}.\n\nThe password of your QuoteOps account"
        " was changed.\n\nAll sessions of your account were signed out.\n\n"
        "If you did not do this, contact support at once.\n\nQuoteOps\n")


def _fingerprint(pw_hash: bytes) -> bytes:
    """Binds a reset token to the current password hash: any change makes the token invalid."""
    return hashlib.sha256(b"pw-fingerprint|" + bytes(pw_hash)).digest()


# --- sign-up --------------------------------------------------------------------------------------

def _insert_company(conn, company_id: str, name: str) -> None:
    conn.execute("INSERT INTO company (id, name) VALUES (%s, %s)", (company_id, name))


def _insert_owner(conn, company_id: str, email: str) -> None:
    """The owner gets an unusable credential: a random hash and salt that no password matches
    and nobody knows. The mailbox owner chooses the password at the verification link."""
    pw_hash, pw_salt = secrets.token_bytes(32), secrets.token_bytes(passwords.SALT_BYTES)
    conn.execute("INSERT INTO app_user (id, company_id, email, pw_hash, pw_salt, role,"
                 " consent_version, consent_at) VALUES (%s, %s, %s, %s, %s, 'owner', %s, now())",
                 (uuid.uuid4(), company_id, email, pw_hash, pw_salt, TERMS_VERSION))


def _create_company_and_owner(s: Settings, email: str, name: str) -> str:
    """One transaction under the new company's tenant setting. Returns created or exists. An
    unverified company does not count toward the cap, so there is no cap check and no advisory
    lock here: the cap is checked where the account becomes verified (_cap_closed), and the
    unique email index alone settles two sign-ups of one address."""
    company_id = "c_" + secrets.token_hex(16)
    try:
        with tenant_conn(company_id) as conn:
            _insert_company(conn, company_id, name)
            _insert_owner(conn, company_id, email)
    except psycopg.errors.UniqueViolation:  # the same address signed up a moment ago
        return "exists"
    return "created"


def _purge_unverified(s: Settings) -> int:
    """Delete abandoned sign-ups: unverified companies older than QO_UNVERIFIED_MAX_AGE_HOURS,
    and the oldest beyond the QO_UNVERIFIED_KEEP newest. Under the sign-up lock, so no account
    is being verified meanwhile. Returns the number of companies deleted."""
    with lookup_conn() as conn, conn.transaction():
        conn.execute("SELECT pg_advisory_xact_lock(%s)", (SIGNUP_LOCK,))
        return conn.execute("SELECT qo_purge_unverified(%s::int, %s::int)",
                            (s.unverified_max_age_hours * HOUR, s.unverified_keep)).fetchone()[0]


def _finish_signup(s: Settings, email: str, company: str) -> None:
    """Background task, after the answer: everything that depends on whether the address has an
    account. Purges abandoned sign-ups, creates the company and owner and mails the address: a
    verification link while the account is not verified, so signing up again recovers from a
    lost mail, else the "already exists" mail. Never raises: the answer has gone, so a failure
    is only logged, by class name; a failed purge does not stop the sign-up."""
    try:
        try:
            _purge_unverified(s)
        except Exception as exc:
            log.error("purge of unverified sign-ups failed: %s", type(exc).__name__)
        with lookup_conn() as conn:
            user = _lookup(conn, email)
        if user is None:
            outcome = _create_company_and_owner(s, email, company)
            if outcome == "exists":  # the same address signed up a moment ago
                with lookup_conn() as conn:
                    user = _lookup(conn, email)
        verified = user is not None and user["email_verified_at"] is not None
        mailer(s).send(email, *(_exists_mail(s, email) if verified else _verify_mail(s, email)))
    except Exception as exc:
        log.error("sign-up background task failed: %s", type(exc).__name__)


def _signup_closed() -> Response:
    return message("Sign-up is closed for now",
                   "QuoteOps has reached its limit of companies for now. No account was created."
                   " Try again later.", status=403)


def _cap_closed(conn, s: Settings) -> bool:
    """Whether the verified companies already fill the cap. Called under SIGNUP_LOCK in the
    transaction that would activate a company, so two activations cannot both pass it."""
    return conn.execute("SELECT qo_company_count()").fetchone()[0] >= s.max_companies


def _activation_blocked(conn, s: Settings, company_id: str) -> str | None:
    """In the tenant transaction, before any change: take the sign-up lock, then answer "gone"
    when the company was purged meanwhile, or "closed" when it is unverified and the cap is
    full. Only an unverified company is activated, so a suspended or deleting one passes."""
    conn.execute("SELECT pg_advisory_xact_lock(%s)", (SIGNUP_LOCK,))
    row = conn.execute("SELECT status FROM company WHERE id = %s", (company_id,)).fetchone()
    if row is None:
        return "gone"
    if row[0] == "unverified" and _cap_closed(conn, s):
        return "closed"
    return None


@router.get("/signup")
def signup_form(request: Request):
    if current_principal(request):
        return _redirect("/app")
    return _form(request, load_settings(), "signup.html")


COMPANY_ERROR = "Enter the company name, 1 to 80 characters."
TERMS_ERROR = "Accept the terms to continue."


@router.post("/signup")
def signup(request: Request, background: BackgroundTasks, csrf: str = Form(""),
           email: str = Form(""), company: str = Form(""), terms: str = Form("")):
    """No password here: whoever submits an address does not choose its password; the mailbox
    owner does, at the verification link. So sign-up runs no scrypt and never answers busy."""
    s = load_settings()
    if not _pre_session_ok(request, s, csrf):
        return _refused()
    email, company = _norm_email(email), company.strip()
    errors = {}
    if not _valid_email(email):
        errors["email"] = "Enter a valid email address."
    if not _valid_company(company):
        errors["company"] = COMPANY_ERROR
    if not terms:
        errors["terms"] = TERMS_ERROR
    if errors:
        return _form(request, s, "signup.html", status=400, errors=errors,
                     values={"email": email, "company": company})

    with lookup_conn() as conn:
        if not throttle.hit(conn, "signup_ip", client_ip(request, s), s.secret, s.signup_per_ip,
                            HOUR, HOUR):
            return message("Too many sign-ups", "Too many sign-ups came from this network in the"
                           " last hour. Try again later.", status=429)
        # The cap is checked before the address, so a full system never tells which exist.
        if conn.execute("SELECT qo_company_count()").fetchone()[0] >= s.max_companies:
            return _signup_closed()
        # Over the per-address limit the answer stays the success page, so nobody learns the
        # limit was hit; no mail goes out and nothing is created.
        within = throttle.hit(conn, "signup_email", email, s.secret, s.signup_per_email, HOUR, HOUR)
    # Nothing before the answer depends on whether the address has an account: the lookup, the
    # inserts and the mail run after it.
    if within:
        background.add_task(_finish_signup, s, email, company)
    return message("Check your email", SIGNUP_DONE)


# --- verification ---------------------------------------------------------------------------------

def _verify_user(s: Settings, token: str):
    """The account a genuine, unexpired verification token is for, or None."""
    email = tokens.check(token, "verify", s.secret)
    if not email:
        return None
    with lookup_conn() as conn:
        user = _lookup(conn, email)
    if user is None or user["company_id"] is None:
        return None
    user["email"] = email
    return user


def _link_not_valid() -> Response:
    return message("Link not valid", INVALID_LINK, status=400)


def _already_verified() -> Response:
    return message("Already verified", ALREADY_VERIFIED, link=("/login", "Sign in"))


@router.get("/verify")
def verify_form(request: Request, token: str = ""):
    """Opening the link changes nothing. While the account is not verified it shows the form
    where the mailbox owner chooses the password, confirms the company name and accepts the
    terms."""
    s = load_settings()
    user = _verify_user(s, token)
    if user is None:
        return _link_not_valid()
    if user["email_verified_at"] is not None:
        return _already_verified()
    with tenant_conn(user["company_id"]) as conn:
        name = conn.execute("SELECT name FROM company WHERE id = %s",
                            (user["company_id"],)).fetchone()
    return _form(request, s, "verify.html", token=token,
                 values={"company": name[0] if name else ""})


def _verify(request: Request, s: Settings, token: str, password: str, company: str,
            terms: str) -> Response:
    user = _verify_user(s, token)
    if user is None:
        return _link_not_valid()
    if user["email_verified_at"] is not None:
        return _already_verified()
    company = company.strip()
    errors = {}
    reason = passwords.policy_error(password, user["email"])
    if reason:
        errors["password"] = reason
    if not _valid_company(company):
        errors["company"] = COMPANY_ERROR
    if not terms:
        errors["terms"] = TERMS_ERROR
    if errors:
        return _form(request, s, "verify.html", status=400, token=token, errors=errors,
                     values={"company": company})
    pw_hash, pw_salt = passwords.hash_password(password)  # in the slot the caller holds
    with tenant_conn(user["company_id"]) as conn:
        blocked = _activation_blocked(conn, s, user["company_id"])
        if blocked:  # nothing changed: the account stays unverified
            return _signup_closed() if blocked == "closed" else _link_not_valid()
        # Compare and set: of two submissions of the same link only the first finds the account
        # unverified. The password, the verification and the consent are set together.
        changed = conn.execute(
            "UPDATE app_user SET pw_hash = %s, pw_salt = %s, email_verified_at = now(),"
            " consent_version = %s, consent_at = now() WHERE id = %s AND email_verified_at IS NULL",
            (pw_hash, pw_salt, TERMS_VERSION, user["id"])).rowcount
        if changed == 1:
            # Only an unverified company is renamed and activated; a suspended or deleting one
            # stays as it is.
            conn.execute("UPDATE company SET name = %s, status = 'active'"
                         " WHERE id = %s AND status = 'unverified'", (company, user["company_id"]))
            conn.execute("SELECT qo_session_delete_user(%s)", (user["id"],))
    if changed != 1:
        return _already_verified()
    return message("Email verified", "Your email address is verified and your password is set."
                   " Sign in to continue.", link=("/login", "Sign in"))


@router.post("/verify")
def verify(request: Request, csrf: str = Form(""), token: str = Form(""),
           password: str = Form(""), company: str = Form(""), terms: str = Form("")):
    s = load_settings()
    if not _pre_session_ok(request, s, csrf):
        return _refused()
    try:
        # The slot first: a busy answer has opened no connection and changed nothing.
        with passwords.scrypt_slot():
            return _verify(request, s, token, password, company, terms)
    except passwords.Busy:
        return _busy()


# --- sign-in and sign-out -------------------------------------------------------------------------

def _login_failed(request: Request, s: Settings, email: str, blocked: bool = False) -> Response:
    text = f"{GENERIC_LOGIN} {TRY_LATER}" if blocked else GENERIC_LOGIN
    return _form(request, s, "login.html", status=429 if blocked else 400, failure=text,
                 values={"email": email})


@router.get("/login")
def login_form(request: Request):
    if current_principal(request):
        return _redirect("/app")
    return _form(request, load_settings(), "login.html", failure=None)


@router.post("/login")
def login(request: Request, csrf: str = Form(""), email: str = Form(""),
          password: str = Form("")):
    s = load_settings()
    if not _pre_session_ok(request, s, csrf):
        return _refused()
    try:
        # The slot first, before the throttle and any connection: a busy answer counts no
        # attempt, and a request waiting for a slot holds no database connection.
        with passwords.scrypt_slot():
            return _login(request, s, _norm_email(email), password)
    except passwords.Busy:
        return _busy()


def _login(request: Request, s: Settings, email: str, password: str) -> Response:
    ip = client_ip(request, s)
    with lookup_conn() as conn:
        # Throttle first: a blocked address or network gets no password check at all.
        allowed = throttle.hit(conn, "login_ip", ip, s.secret, s.login_fails_per_ip,
                               s.login_window_seconds, s.login_block_seconds)
        allowed = allowed and throttle.hit(conn, "login_email", email, s.secret,
                                           s.login_fails_per_email, s.login_window_seconds,
                                           s.login_block_seconds)
        if not allowed:
            return _login_failed(request, s, email, blocked=True)
        user = _lookup(conn, email) if _valid_email(email) else None
        # One scrypt in the slot the caller holds. An account that is not verified yet has an
        # unusable hash, so it fails here like a wrong password.
        if user is None:
            passwords.verify_dummy(password)
            return _login_failed(request, s, email)
        if not passwords.verify_password(password, user["pw_hash"], user["pw_salt"]):
            return _login_failed(request, s, email)
        if (user["disabled_at"] is not None or user["company_id"] is None
                or user["company_status"] is None):
            return _login_failed(request, s, email)
        if user["company_status"] in ("suspended", "deleting"):
            # Acceptable to say: the password was right.
            return message("Account suspended", "This account is suspended. Contact support.",
                           status=403)
        throttle.reset(conn, "login_email", email, s.secret)
        old = request.cookies.get(SESSION_COOKIE)
        if old:
            conn.execute("SELECT qo_session_delete(%s)", (_sha256(old),))
        token = secrets.token_urlsafe(32)
        conn.execute("SELECT qo_session_create(%s, %s, now() + make_interval(secs => %s), %s)",
                     (_sha256(token), user["id"], SESSION_SECONDS, _inet(ip)))
    response = _redirect("/app")
    response.set_cookie(SESSION_COOKIE, token, max_age=SESSION_SECONDS, path="/", httponly=True,
                        samesite="lax", secure=s.cookie_secure)
    return response


@router.post("/logout")
def logout(request: Request, csrf: str = Form("")):
    s = load_settings()
    if not _origin_ok(request, s):
        return _refused()
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return _redirect("/login")
    # The token is an HMAC of this cookie's hash, so it is checked without a database lookup and
    # still lets a user whose session no longer resolves remove the row.
    id_hash = _sha256(token)
    if not _same(csrf, session_csrf(s, id_hash)):
        return _refused()
    with lookup_conn() as conn:
        conn.execute("SELECT qo_session_delete(%s)", (id_hash,))
    response = _redirect("/login")
    response.delete_cookie(SESSION_COOKIE, path="/", secure=s.cookie_secure, httponly=True,
                           samesite="lax")
    return response


# --- password reset -------------------------------------------------------------------------------

@router.get("/forgot")
def forgot_form(request: Request):
    return _form(request, load_settings(), "forgot.html")


def _finish_forgot(s: Settings, email: str) -> None:
    """Background task, after the answer: mail a reset link when the address has an account that
    may sign in. Never raises: a failure is only logged, by class name."""
    try:
        with lookup_conn() as conn:
            user = _lookup(conn, email)
        if user and user["company_id"] is not None and user["disabled_at"] is None:
            mailer(s).send(email, *_reset_mail(s, email, user["pw_hash"]))
    except Exception as exc:
        log.error("reset mail background task failed: %s", type(exc).__name__)


@router.post("/forgot")
def forgot(request: Request, background: BackgroundTasks, csrf: str = Form(""),
           email: str = Form("")):
    s = load_settings()
    if not _pre_session_ok(request, s, csrf):
        return _refused()
    email = _norm_email(email)
    if not _valid_email(email):
        return _form(request, s, "forgot.html", status=400,
                     errors={"email": "Enter a valid email address."}, values={"email": email})
    with lookup_conn() as conn:
        allowed = throttle.hit(conn, "forgot_ip", client_ip(request, s), s.secret,
                               s.forgot_per_ip, HOUR, HOUR)
        allowed = allowed and throttle.hit(conn, "forgot_email", email, s.secret,
                                           s.forgot_per_email, HOUR, HOUR)
    if allowed:
        # The lookup and the mail run after the answer, which is the same for every address.
        background.add_task(_finish_forgot, s, email)
    return message("Check your email", FORGOT_DONE)


def _reset_user(s: Settings, token: str):
    """The account a reset token is for, when the token is genuine, unexpired and was made for
    the password hash the account has now."""
    email = tokens.unverified_email(token)
    if not email:
        return None
    with lookup_conn() as conn:
        user = _lookup(conn, email)
    if user is None or user["company_id"] is None or user["disabled_at"] is not None:
        return None
    if tokens.check(token, "reset", s.secret, extra=_fingerprint(user["pw_hash"])) != email:
        return None
    user["email"] = email
    return user


@router.get("/reset")
def reset_form(request: Request, token: str = ""):
    s = load_settings()
    if _reset_user(s, token) is None:
        return message("Link not valid", INVALID_LINK, status=400, link=("/forgot", "Ask for a new link"))
    return _form(request, s, "reset.html", token=token)


@router.post("/reset")
def reset(request: Request, background: BackgroundTasks, csrf: str = Form(""),
          token: str = Form(""), password: str = Form("")):
    s = load_settings()
    if not _pre_session_ok(request, s, csrf):
        return _refused()
    try:
        # The slot first: a busy answer has opened no connection and changed nothing.
        with passwords.scrypt_slot():
            return _reset(request, background, s, token, password)
    except passwords.Busy:
        return _busy()


def _finish_changed(s: Settings, email: str) -> None:
    """Background task, after the answer: tell the owner of the address that the password was
    changed. Never raises: a failure is only logged, by class name."""
    try:
        mailer(s).send(email, *_changed_mail(email))
    except Exception as exc:
        log.error("mail could not be sent: %s", type(exc).__name__)


def _reset(request: Request, background: BackgroundTasks, s: Settings, token: str,
           password: str) -> Response:
    user = _reset_user(s, token)
    if user is None:
        return message("Link not valid", INVALID_LINK, status=400, link=("/forgot", "Ask for a new link"))
    reason = passwords.policy_error(password, user["email"])
    if reason:
        return _form(request, s, "reset.html", status=400, token=token,
                     errors={"password": reason})
    pw_hash, pw_salt = passwords.hash_password(password)  # in the slot the caller holds
    with tenant_conn(user["company_id"]) as conn:
        # A reset activates an unverified company, so the cap applies as at verification.
        blocked = _activation_blocked(conn, s, user["company_id"])
        if blocked == "closed":  # nothing changed: the account stays unverified
            return _signup_closed()
        if blocked == "gone":
            return message("Link not valid", INVALID_LINK, status=400,
                           link=("/forgot", "Ask for a new link"))
        # Compare and set: of two requests with the same token only the first finds the old hash.
        # The reset mail proves control of the mailbox, so an account that was not verified yet
        # is verified now and its company activated; its consent stays as recorded at sign-up.
        changed = conn.execute("UPDATE app_user SET pw_hash = %s, pw_salt = %s,"
                               " email_verified_at = coalesce(email_verified_at, now())"
                               " WHERE id = %s AND pw_hash = %s",
                               (pw_hash, pw_salt, user["id"], user["pw_hash"])).rowcount
        if changed == 1:
            conn.execute("UPDATE company SET status = 'active' WHERE id = %s"
                         " AND status = 'unverified'", (user["company_id"],))
            conn.execute("SELECT qo_session_delete_user(%s)", (user["id"],))
    if changed != 1:
        return message("Link not valid", INVALID_LINK, status=400, link=("/forgot", "Ask for a new link"))
    background.add_task(_finish_changed, s, user["email"])
    return message("Password changed", "Your password was changed. Sign in with the new password.",
                   link=("/login", "Sign in"))


# --- signed-in pages ------------------------------------------------------------------------------

@router.get("/app")
def app_home(principal: Principal = Depends(require_user)):
    s = load_settings()
    with tenant_conn(principal.company_id) as conn:
        row = conn.execute("SELECT c.name, u.email, u.role, u.email_verified_at FROM app_user u"
                           " JOIN company c ON c.id = u.company_id WHERE u.id = %s",
                           (principal.user_id,)).fetchone()
    if row is None:
        raise NotSignedIn()
    from quoteops.permissions import nav_for  # permissions imports this module
    return render("app.html", title=row[0], company=row[0], email=row[1], role=row[2],
                  verified=row[3] is not None, csrf=session_csrf(s, principal.session_hash),
                  nav=nav_for(principal, "app"))


@router.get("/terms")
def terms():
    return render("terms.html", title="Terms (draft)", terms_version=TERMS_VERSION)


@router.get("/privacy")
def privacy():
    return render("privacy.html", title="Privacy (draft)", terms_version=TERMS_VERSION)
