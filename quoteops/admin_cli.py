"""Stage 2b part 2: `python -m quoteops create-admin <email>` and `reset-admin <email>` (PRD F25).
Run on the server with the owner (migration) database login, the way `migrate` is; never over
HTTP. This is the only code that creates a sysadmin.

The password is read from the terminal with getpass, twice, when stdin is a terminal, else as
one line of stdin; never from the command line, never echoed or logged. It must pass the same
password rules as every account. The TOTP secret is printed once and cannot be read back."""
import getpass
import sys
import uuid

import psycopg

from quoteops import passwords, totp
from quoteops.config import owner_conninfo
from quoteops.guard import norm_email, valid_email

CONSENT_VERSION = "admin"  # app_user.consent_version is NOT NULL; an administrator accepts no terms


class Refused(Exception):
    """The command changes nothing; the message holds no secret."""


def _read_password(email: str) -> str:
    if sys.stdin.isatty():
        first = getpass.getpass("Password for the administrator: ")
        second = getpass.getpass("Repeat the password: ")
        if first != second:
            raise Refused("the two passwords do not match. Nothing was changed.")
        password = first
    else:
        password = sys.stdin.readline()
        if password.endswith("\n"):
            password = password[:-1]
        if password.endswith("\r"):
            password = password[:-1]
    if not password:
        raise Refused("no password was given. Nothing was changed.")
    reason = passwords.policy_error(password, email)
    if reason:
        raise Refused(f"the password is not accepted: {reason} Nothing was changed.")
    return password


def _address(email: str) -> str:
    email = norm_email(email)
    if not valid_email(email):
        raise Refused("this is not a valid email address. Nothing was changed.")
    return email


def _show_secret(email: str, secret: bytes, what: str) -> None:
    print(f"Administrator {what}: {email}")
    print("Add this secret to an authenticator app (TOTP, SHA1, 6 digits, 30 seconds).")
    print("It is shown only now and cannot be read back; reset-admin makes a new one.")
    print(f"Secret: {totp.encode_secret(secret)}")
    print(f"URI: {totp.otpauth_uri(secret, email)}")


def create_admin(email: str) -> None:
    """A new sysadmin: no company, verified now, a scrypt hash of the password read here, and
    a fresh 20-byte TOTP secret. Refused when the address has any account at all."""
    email = _address(email)
    with psycopg.connect(owner_conninfo()) as conn:
        if conn.execute("SELECT 1 FROM public.app_user WHERE email = %s", (email,)).fetchone():
            raise Refused("an account with this email address already exists."
                          " Nothing was changed.")
    password = _read_password(email)
    pw_hash, pw_salt = passwords.hash_password(password)
    secret = totp.new_secret()
    user_id = uuid.uuid4()
    try:
        with psycopg.connect(owner_conninfo()) as conn, conn.transaction():
            conn.execute("INSERT INTO public.app_user (id, company_id, email, pw_hash, pw_salt,"
                         " role, email_verified_at, consent_version, consent_at)"
                         " VALUES (%s, NULL, %s, %s, %s, 'sysadmin', now(), %s, now())",
                         (user_id, email, pw_hash, pw_salt, CONSENT_VERSION))
            conn.execute("INSERT INTO public.admin_factor (user_id, totp_secret, last_counter)"
                         " VALUES (%s, %s, 0)", (user_id, secret))
    except psycopg.errors.UniqueViolation:  # the address got an account meanwhile
        raise Refused("an account with this email address already exists."
                      " Nothing was changed.") from None
    _show_secret(email, secret, "created")


def reset_admin(email: str) -> None:
    """For an existing sysadmin only: a new password, a new TOTP secret with the replay counter
    back at 0, and every admin session of the account ended, in one transaction. This is the
    recovery path for a lost password or authenticator. A disabled account stays disabled."""
    email = _address(email)
    with psycopg.connect(owner_conninfo()) as conn:
        if not conn.execute("SELECT 1 FROM public.app_user WHERE email = %s AND role = 'sysadmin'"
                            " AND company_id IS NULL", (email,)).fetchone():
            raise Refused("there is no administrator account with this email address."
                          " Nothing was changed.")
    password = _read_password(email)
    pw_hash, pw_salt = passwords.hash_password(password)
    secret = totp.new_secret()
    with psycopg.connect(owner_conninfo()) as conn, conn.transaction():
        row = conn.execute("UPDATE public.app_user SET pw_hash = %s, pw_salt = %s,"
                           " email_verified_at = coalesce(email_verified_at, now())"
                           " WHERE email = %s AND role = 'sysadmin' AND company_id IS NULL"
                           " RETURNING id", (pw_hash, pw_salt, email)).fetchone()
        if row is None:
            raise Refused("there is no administrator account with this email address."
                          " Nothing was changed.")
        conn.execute("INSERT INTO public.admin_factor (user_id, totp_secret, last_counter)"
                     " VALUES (%s, %s, 0) ON CONFLICT (user_id) DO UPDATE"
                     " SET totp_secret = EXCLUDED.totp_secret, last_counter = 0,"
                     " created_at = now()", (row[0], secret))
        conn.execute("DELETE FROM public.admin_session WHERE user_id = %s", (row[0],))
    _show_secret(email, secret, "reset")


COMMANDS = {"create-admin": create_admin, "reset-admin": reset_admin}


def run(command: str, email: str) -> int:
    """0 done, 1 refused. Messages go to stderr and never hold the password or the secret."""
    try:
        COMMANDS[command](email)
    except Refused as exc:
        print(f"{command}: {exc}", file=sys.stderr)
        return 1
    except psycopg.Error as exc:
        print(f"{command}: database error ({type(exc).__name__}). Nothing was changed.",
              file=sys.stderr)
        return 1
    return 0
