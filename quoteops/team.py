"""Stage 2b part 1: invitations (PRD F5), roles (F6) and the user management they need (HLD
"Stage 2b part 1"). Only the Owner manages users. Every change runs in the Owner's tenant
transaction, so row-level security keeps it inside the Owner's company: an id of another company
finds no row and the answer is 404."""
import hashlib
import logging
import secrets
import uuid
from datetime import timezone

import psycopg
from fastapi import APIRouter, BackgroundTasks, Depends, Form, Request
from fastapi.responses import Response

from quoteops import auth, passwords, throttle
from quoteops.auth import (
    _COOKIE_RE, TERMS_ERROR, TERMS_VERSION, Forbidden, Principal, _busy, _form, _link_not_valid,
    _mac, _norm_email, _origin_ok, _pre_session_ok, _redirect, _refused, _same, _sha256,
    _valid_email, require_user, require_verified, session_csrf,
)
from quoteops.config import Settings, load_settings
from quoteops.dbconn import lookup_conn, tenant_conn
from quoteops.mail import mailer
from quoteops.pages import message, render
from quoteops.permissions import nav_for

log = logging.getLogger("quoteops")
router = APIRouter()

INVITABLE_ROLES = ("estimator", "accountant", "viewer")  # never owner or sysadmin
INVITE_SECONDS = 7 * 24 * 3600      # F5: a link works for 7 days
DAY = 24 * 3600
TEAM_LOCK = 0x514F5445              # first key of the per-company advisory lock (users and invites)
FLASH_COOKIE, FLASH_SECONDS = "qo_flash", 60

JOINED = "Your password is set. Sign in to continue."
FLASH = {
    "sent": "Invitation sent.",
    "invalid": "Enter a valid email address and choose a role. Nothing was sent.",
    "cap": None,  # names the cap, which is a setting
    "revoked": "Invitation revoked.",
    "role": "Role changed.",
    "disabled": "User disabled. Their sessions have ended.",
    "enabled": "User enabled. They can sign in again.",
}


# --- plumbing -------------------------------------------------------------------------------------

def require_owner(principal: Principal = Depends(require_user)) -> Principal:
    """The Owner of the session's company, with a verified address. Anyone else signed in: 403."""
    if principal.role != "owner":
        raise Forbidden("Only the owner of the company manages users and invitations.")
    require_verified(principal)
    with tenant_conn(principal.company_id) as conn:  # row-level security: the Owner's company
        row = conn.execute("SELECT status FROM company WHERE id = %s",
                           (principal.company_id,)).fetchone()
    if row is None or row[0] != "active":
        raise Forbidden("This company is not active.")
    return principal


def _session_ok(request: Request, s: Settings, principal: Principal, csrf: str) -> bool:
    """The Origin check and the session token, as for /logout."""
    return _origin_ok(request, s) and _same(csrf, session_csrf(s, principal.session_hash))


def _lock(conn, company_id: str) -> None:
    """One company's invitations and joins at a time, so the user cap is checked and used in one
    step. The two-key form never collides with the one-key sign-up lock."""
    key = int.from_bytes(hashlib.sha256(company_id.encode("utf-8")).digest()[:4], "big", signed=True)
    conn.execute("SELECT pg_advisory_xact_lock(%s::int, %s::int)", (TEAM_LOCK, key))


def _places_used(conn, email: str | None = None) -> int:
    """Users plus unexpired unused invitations of the tenant's company (row-level security
    limits both counts). A pending invitation of `email` is left out: a new one replaces it."""
    return conn.execute(
        "SELECT (SELECT count(*) FROM app_user) + (SELECT count(*) FROM invite"
        " WHERE used_at IS NULL AND expires_at > now() AND email IS DISTINCT FROM %s::citext)",
        (email,)).fetchone()[0]


def _uuid(value: str) -> uuid.UUID | None:
    try:
        return uuid.UUID(value)
    except ValueError:
        return None


def _audit(conn, principal: Principal, what: str, subject: str) -> None:
    """Ids and field names only (HLD section 3)."""
    conn.execute("INSERT INTO audit_event (company_id, actor, what, subject) VALUES (%s, %s, %s, %s)",
                 (principal.company_id, principal.user_id, what, subject))


def _not_found() -> Response:
    return message("Page not found", "There is no page at this address.", status=404)


def _owner_untouchable() -> Response:
    return message("Not allowed", "The owner's role and access cannot be changed.", status=403)


def _flash_mac(s: Settings, principal: Principal, key: str) -> str:
    return _mac(s, "flash", principal.session_hash.hex(), key)


def _flash(s: Settings, principal: Principal, key: str) -> Response:
    """303 to /team with a one-time note: a fixed key, signed for this session, never user text."""
    response = _redirect("/team")
    response.set_cookie(FLASH_COOKIE, f"{key}.{_flash_mac(s, principal, key)}",
                        max_age=FLASH_SECONDS, path="/team", httponly=True, samesite="lax",
                        secure=s.cookie_secure)
    return response


def _flash_text(request: Request, s: Settings, principal: Principal) -> str | None:
    key, _, mac = request.cookies.get(FLASH_COOKIE, "").partition(".")
    if key not in FLASH or not _same(mac, _flash_mac(s, principal, key)):
        return None
    if key == "cap":
        return (f"The company has reached its limit of {s.max_users_per_company} users, counting"
                " pending invitations. Nothing was sent. Revoke a pending invitation to free a"
                " place.")
    return FLASH[key]


# --- mail text ------------------------------------------------------------------------------------

def _mail_safe(text: str) -> str:
    """A stored name inside a mail line: no line break or other control character, at most 80."""
    return "".join(c if c.isprintable() else " " for c in text)[:80]


def _invite_mail(s: Settings, email: str, company: str, role: str, token: str) -> tuple[str, str]:
    return "You are invited to QuoteOps", (
        f"Hello,\n\nThis email was sent to {email} because the owner of the company"
        f" \"{_mail_safe(company)}\" invited this address to join it on QuoteOps as {role}.\n\n"
        "Open this link to choose your password and join:\n"
        f"{s.base_url}/invite?token={token}\n\nThe link works for 7 days and only once.\n\n"
        "If you did not expect this, ignore this email.\n\nQuoteOps\n")


def _member_exists_mail(s: Settings, email: str) -> tuple[str, str]:
    return "You were invited to a QuoteOps company", (
        f"Hello,\n\nThis email was sent to {email} because someone invited this address to a"
        " company on QuoteOps.\n\nThis address already has a QuoteOps account, so no invitation"
        " was created: an address belongs to one company in QuoteOps.\n\n"
        f"To sign in to your account, open this link:\n{s.base_url}/login\n\n"
        "If you did not expect this, ignore this email.\n\nQuoteOps\n")


# --- the Owner's page -----------------------------------------------------------------------------

@router.get("/team")
def team_page(request: Request, principal: Principal = Depends(require_owner)):
    s = load_settings()
    with tenant_conn(principal.company_id) as conn:
        company = conn.execute("SELECT name FROM company WHERE id = %s",
                               (principal.company_id,)).fetchone()
        users = conn.execute("SELECT id, email::text, role, disabled_at IS NOT NULL,"
                             " email_verified_at IS NOT NULL FROM app_user"
                             " ORDER BY role <> 'owner', email").fetchall()
        pending = conn.execute("SELECT ref, email::text, role, expires_at FROM invite"
                               " WHERE used_at IS NULL AND expires_at > now() ORDER BY email"
                               ).fetchall()
    response = render(
        "team.html", title="Team", company=company[0] if company else "",
        nav=nav_for(principal, "team"),
        users=[{"id": u[0], "email": u[1], "role": u[2], "disabled": u[3], "verified": u[4],
                "locked": u[2] == "owner" or u[0] == principal.user_id} for u in users],
        invites=[{"ref": i[0], "email": i[1], "role": i[2],
                  "expires": i[3].astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}
                 for i in pending],
        used=len(users) + len(pending), cap=s.max_users_per_company, roles=INVITABLE_ROLES,
        flash=_flash_text(request, s, principal), csrf=session_csrf(s, principal.session_hash))
    if FLASH_COOKIE in request.cookies:  # shown once
        response.delete_cookie(FLASH_COOKIE, path="/team", secure=s.cookie_secure, httponly=True,
                               samesite="lax")
    return response


# --- invitations ----------------------------------------------------------------------------------

def _finish_invite(s: Settings, company_id: str, actor: uuid.UUID, email: str, role: str) -> None:
    """Background task, after the answer: everything that depends on whether the address has an
    account. An address with an account (in any company) gets a notice and no invitation; else,
    under the company lock and after the cap check again, the pending invitation of the address
    is replaced and, after a second account check, the link mailed. Never raises: a failure is
    logged by class name only."""
    try:
        if auth._has_account(email):
            mailer(s).send(email, *_member_exists_mail(s, email))
            return
        token = secrets.token_urlsafe(32)
        with tenant_conn(company_id) as conn:
            _lock(conn, company_id)
            company = conn.execute("SELECT name, status FROM company WHERE id = %s",
                                   (company_id,)).fetchone()
            if company is None or company[1] != "active":
                return
            if _places_used(conn, email) >= s.max_users_per_company:
                log.info("invitation not created: the company is at its user cap")
                return
            conn.execute("DELETE FROM invite WHERE email = %s::citext AND used_at IS NULL",
                         (email,))
            conn.execute("INSERT INTO invite (id_hash, company_id, email, role, expires_at,"
                         " created_by) VALUES (%s, %s, %s, %s,"
                         " now() + make_interval(secs => %s), %s)",
                         (_sha256(token), company_id, email, role, INVITE_SECONDS, actor))
        if auth._has_account(email):  # an account made meanwhile: no link, and no row either
            with tenant_conn(company_id) as conn:
                conn.execute("DELETE FROM invite WHERE id_hash = %s", (_sha256(token),))
            mailer(s).send(email, *_member_exists_mail(s, email))
            return
        # Window left (HLD 10): a later account is stopped at accept by the unique email.
        mailer(s).send(email, *_invite_mail(s, email, company[0], role, token))
    except Exception as exc:
        log.error("invitation background task failed: %s", type(exc).__name__)


@router.post("/team/invite")
def team_invite(request: Request, background: BackgroundTasks,
                principal: Principal = Depends(require_owner), csrf: str = Form(""),
                email: str = Form(""), role: str = Form("")):
    """The answer is the same whether or not the address has an account anywhere: the lookup,
    the insert and the mail run after it. Over the cap the note says so and nothing changes;
    over a throttle the answer is "sent" and nothing is sent."""
    s = load_settings()
    if not _session_ok(request, s, principal, csrf):
        return _refused()
    email = _norm_email(email)
    if not _valid_email(email) or role not in INVITABLE_ROLES:
        return _flash(s, principal, "invalid")
    with tenant_conn(principal.company_id) as conn:
        _lock(conn, principal.company_id)
        full = _places_used(conn, email) >= s.max_users_per_company
    if full:
        return _flash(s, principal, "cap")
    with lookup_conn() as conn:
        within = throttle.hit(conn, "invite_company", principal.company_id, s.secret,
                              s.invites_per_day, DAY, DAY)
        within = within and throttle.hit(conn, "invite_email", email, s.secret,
                                         s.invites_per_address_per_day, DAY, DAY)
    if within:
        background.add_task(_finish_invite, s, principal.company_id, principal.user_id, email,
                            role)
    return _flash(s, principal, "sent")


@router.post("/team/invite/revoke")
def team_revoke(request: Request, principal: Principal = Depends(require_owner),
                csrf: str = Form(""), ref: str = Form("")):
    s = load_settings()
    if not _session_ok(request, s, principal, csrf):
        return _refused()
    ref_id = _uuid(ref)
    if ref_id is None:
        return _not_found()
    with tenant_conn(principal.company_id) as conn:
        # No company filter here on purpose: row-level security is the filter.
        gone = conn.execute("DELETE FROM invite WHERE ref = %s AND used_at IS NULL RETURNING ref",
                            (ref_id,)).fetchone()
        if gone:
            _audit(conn, principal, "invite.revoke", f"invite {ref_id}")
    if gone is None:
        return _not_found()
    return _flash(s, principal, "revoked")


# --- roles and access -----------------------------------------------------------------------------

def _target_role(conn, principal: Principal, user: uuid.UUID) -> str | Response:
    """The role of a user of the tenant's company, or the refusal: 404 when row-level security
    finds no such user, 403 for the owner row and for oneself."""
    row = conn.execute("SELECT role FROM app_user WHERE id = %s", (user,)).fetchone()
    if row is None:
        return _not_found()
    if row[0] == "owner" or user == principal.user_id:
        return _owner_untouchable()
    return row[0]


@router.post("/team/role")
def team_role(request: Request, principal: Principal = Depends(require_owner),
              csrf: str = Form(""), user: str = Form(""), role: str = Form("")):
    s = load_settings()
    if not _session_ok(request, s, principal, csrf):
        return _refused()
    target = _uuid(user)
    if target is None:
        return _not_found()
    with tenant_conn(principal.company_id) as conn:
        old = _target_role(conn, principal, target)
        if isinstance(old, Response):
            return old
        if role not in INVITABLE_ROLES:
            return message("Role not valid", "Choose estimator, accountant or viewer.",
                           status=400)
        if role != old:
            conn.execute("UPDATE app_user SET role = %s WHERE id = %s", (role, target))
            _audit(conn, principal, "user.role", f"app_user {target} role {old} -> {role}")
    return _flash(s, principal, "role")


def _set_access(request: Request, principal: Principal, csrf: str, user: str,
                disable: bool) -> Response:
    s = load_settings()
    if not _session_ok(request, s, principal, csrf):
        return _refused()
    target = _uuid(user)
    if target is None:
        return _not_found()
    with tenant_conn(principal.company_id) as conn:
        old = _target_role(conn, principal, target)
        if isinstance(old, Response):
            return old
        if disable:
            changed = conn.execute("UPDATE app_user SET disabled_at = now()"
                                   " WHERE id = %s AND disabled_at IS NULL", (target,)).rowcount
        else:
            changed = conn.execute("UPDATE app_user SET disabled_at = NULL"
                                   " WHERE id = %s AND disabled_at IS NOT NULL", (target,)).rowcount
        # Disabling ends every session at once. Enabling does it too, so a session created by a
        # sign-in that raced the disabling never comes back to life.
        conn.execute("SELECT qo_session_delete_user(%s)", (target,))
        if changed:
            _audit(conn, principal, "user.disable" if disable else "user.enable",
                   f"app_user {target}")
    return _flash(s, principal, "disabled" if disable else "enabled")


@router.post("/team/disable")
def team_disable(request: Request, principal: Principal = Depends(require_owner),
                 csrf: str = Form(""), user: str = Form("")):
    return _set_access(request, principal, csrf, user, disable=True)


@router.post("/team/enable")
def team_enable(request: Request, principal: Principal = Depends(require_owner),
                csrf: str = Form(""), user: str = Form("")):
    return _set_access(request, principal, csrf, user, disable=False)


# --- the invitee ----------------------------------------------------------------------------------

def _open_invite(token: str) -> tuple[bytes, str, str, str] | None:
    """(token hash, company id, email, role) of an unused, unexpired invitation, through
    qo_invite_lookup; None for anything else, including a role that may not be invited."""
    if not _COOKIE_RE.fullmatch(token):
        return None
    id_hash = _sha256(token)
    with lookup_conn() as conn:
        row = conn.execute("SELECT company_id, email::text, role FROM qo_invite_lookup(%s)",
                           (id_hash,)).fetchone()
    if row is None or row[2] not in INVITABLE_ROLES:
        return None
    return id_hash, row[0], row[1], row[2]


def _active_company_name(company_id: str) -> str | None:
    """The name, read under the company's own tenant setting; None unless it is active."""
    with tenant_conn(company_id) as conn:
        row = conn.execute("SELECT name, status FROM company WHERE id = %s",
                           (company_id,)).fetchone()
    return row[0] if row and row[1] == "active" else None


@router.get("/invite")
def invite_form(request: Request, token: str = ""):
    """Opening the link changes nothing."""
    s = load_settings()
    invite = _open_invite(token)
    name = _active_company_name(invite[1]) if invite else None
    if name is None:
        return _link_not_valid()
    return _form(request, s, "invite.html", token=token, company=name, email=invite[2],
                 role=invite[3])


class _Undo(Exception):
    """Leave the tenant transaction and roll it back."""


def _accept(request: Request, s: Settings, token: str, password: str, terms: str) -> Response:
    invite = _open_invite(token)
    if invite is None:
        return _link_not_valid()
    id_hash, company_id, email, role = invite
    errors = {}
    reason = passwords.policy_error(password, email)
    if reason:
        errors["password"] = reason
    if not terms:
        errors["terms"] = TERMS_ERROR
    if errors:
        name = _active_company_name(company_id)
        if name is None:
            return _link_not_valid()
        return _form(request, s, "invite.html", status=400, token=token, company=name,
                     email=email, role=role, errors=errors)
    pw_hash, pw_salt = passwords.hash_password(password)  # in the slot the caller holds
    try:
        with tenant_conn(company_id) as conn:
            _lock(conn, company_id)
            status = conn.execute("SELECT status FROM company WHERE id = %s",
                                  (company_id,)).fetchone()
            if status is None or status[0] != "active":
                return _link_not_valid()
            # The invitation took its place when it was made (users plus pending invitations
            # at most the cap), so only the users count here: one more may join while there
            # are fewer than the cap. This also catches a cap lowered meanwhile.
            if conn.execute("SELECT count(*) FROM app_user").fetchone()[0] >= s.max_users_per_company:
                return message("Company full", "This company has reached its limit of users."
                               " Ask its owner to make room, then open the link again.",
                               status=403)
            # Compare and set: of parallel submissions of one link only the first finds it
            # unused. The new user's address, role and company come from this row, never from
            # the form.
            row = conn.execute("UPDATE invite SET used_at = now() WHERE id_hash = %s"
                               " AND used_at IS NULL AND expires_at > now()"
                               " RETURNING company_id, email::text, role", (id_hash,)).fetchone()
            if row is None:
                return _link_not_valid()
            if row[2] not in INVITABLE_ROLES:
                raise _Undo()
            # Opening the mailed link proves the mailbox, so the address is verified now.
            conn.execute("INSERT INTO app_user (id, company_id, email, pw_hash, pw_salt, role,"
                         " email_verified_at, consent_version, consent_at)"
                         " VALUES (%s, %s, %s, %s, %s, %s, now(), %s, now())",
                         (uuid.uuid4(), row[0], row[1], pw_hash, pw_salt, row[2], TERMS_VERSION))
    except (psycopg.errors.UniqueViolation, _Undo):
        # The address got an account elsewhere meanwhile: the use of the link is rolled back.
        return _link_not_valid()
    return message("Account created", JOINED, link=("/login", "Sign in"))


@router.post("/invite")
def invite_accept(request: Request, csrf: str = Form(""), token: str = Form(""),
                  password: str = Form(""), terms: str = Form("")):
    s = load_settings()
    if not _pre_session_ok(request, s, csrf):
        return _refused()
    try:
        # The slot first: a busy answer has opened no connection and changed nothing.
        with passwords.scrypt_slot():
            return _accept(request, s, token, password, terms)
    except passwords.Busy:
        return _busy()
