"""Stage 2b part 2: `python -m quoteops create-admin <email>` and `reset-admin <email>`, run on the
server with the owner (migration) login. The password comes from the terminal (asked twice) or
one line of stdin, never from argv; the TOTP secret is printed once. No other code path creates a
sysadmin."""
import logging
import os
import re
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

from tests.stage2a_support import (  # noqa: F401  (adb and env are fixtures)
    BASE, PASSWORD, account, adb, csrf_from, env, finish_signup, form_csrf, signup, verify_link,
)
from tests.stage2b2_support import (  # noqa: F401  (aenv is a fixture)
    ADMIN_EMAIL, ADMIN_PASSWORD, aenv, admin_login, b32decode, company_user, mod, secret_from,
    signed_in_admin, uri_from,
)

ROOT = Path(__file__).resolve().parent.parent
NEW_ADMIN_PASSWORD = "brand new admin phrase 7"


def _row(aenv, email=ADMIN_EMAIL):
    with aenv.owner() as c:
        cur = c.execute("SELECT u.id, u.company_id, u.role, u.email_verified_at, u.disabled_at,"
                        " u.consent_version, u.consent_at, u.pw_hash, u.pw_salt, f.totp_secret,"
                        " f.last_counter FROM app_user u LEFT JOIN admin_factor f"
                        " ON f.user_id = u.id WHERE u.email = %s", (email,))
        row = cur.fetchone()
        return dict(zip([d.name for d in cur.description], row)) if row else None


def _users(aenv):
    return aenv.scalar("SELECT count(*) FROM app_user")


# --- create-admin ---------------------------------------------------------------------------------

def test_create_admin_from_stdin(aenv, caplog):
    caplog.set_level(logging.DEBUG)
    code, out, err = aenv.cli.run("create-admin", ADMIN_EMAIL, stdin=ADMIN_PASSWORD + "\n")
    assert code == 0, err
    secret = secret_from(out)
    uri = uri_from(out)
    row = _row(aenv)
    assert row["company_id"] is None and row["role"] == "sysadmin"
    assert row["email_verified_at"] is not None and row["disabled_at"] is None
    assert row["consent_version"] == "admin" and row["consent_at"] is not None
    assert mod("passwords").verify_password(ADMIN_PASSWORD, row["pw_hash"], row["pw_salt"])
    assert len(row["pw_salt"]) == 16 and len(row["pw_hash"]) == 32
    assert bytes(row["totp_secret"]) == secret and len(secret) == 20
    assert row["last_counter"] == 0
    assert uri == mod("totp").otpauth_uri(secret, ADMIN_EMAIL)
    b32 = mod("totp").encode_secret(secret)
    assert out.count("Secret: " + b32) == 1 and out.count("URI: ") == 1
    assert "only now" in out and "cannot be read back" in out
    for text in (out, err, caplog.text):
        assert ADMIN_PASSWORD not in text
    assert b32 not in err and b32 not in caplog.text
    # audit_event.company_id is NOT NULL, so no audit row can name a platform action.
    assert aenv.scalar("SELECT count(*) FROM audit_event") == 0


def test_two_admins_get_different_secrets(aenv):
    a = aenv.create_admin("one@ops.test")
    b = aenv.create_admin("two@ops.test")
    assert a != b


@pytest.mark.parametrize("existing", ["admin", "owner", "unverified", "case"])
def test_create_admin_refuses_an_address_with_any_account(aenv, existing):
    if existing == "admin":
        aenv.create_admin()
        email = ADMIN_EMAIL
    elif existing == "owner":
        account(aenv, "owner@shop.test")
        email = "owner@shop.test"
    elif existing == "unverified":
        assert signup(aenv.client(), "new@shop.test").status_code == 200
        email = "new@shop.test"
    else:
        aenv.create_admin()
        email = ADMIN_EMAIL.upper()
    with aenv.owner() as c:
        before = c.execute("SELECT array_agg((id, role, pw_hash) ORDER BY id) FROM app_user"
                           ).fetchone()[0]
        factors = c.execute("SELECT array_agg((user_id, totp_secret) ORDER BY user_id)"
                            " FROM admin_factor").fetchone()[0]
    code, out, err = aenv.cli.run("create-admin", email, stdin=NEW_ADMIN_PASSWORD + "\n")
    assert code == 1
    assert out == "" and "Secret" not in err and NEW_ADMIN_PASSWORD not in err
    assert "already" in err
    with aenv.owner() as c:
        assert c.execute("SELECT array_agg((id, role, pw_hash) ORDER BY id) FROM app_user"
                         ).fetchone()[0] == before
        assert c.execute("SELECT array_agg((user_id, totp_secret) ORDER BY user_id)"
                         " FROM admin_factor").fetchone()[0] == factors


@pytest.mark.parametrize("email", ["", "no-at-sign", "a@b", "two words@x.test", "a@b@c.test",
                                   "x|y@ops.test", "tab\t@ops.test"])
def test_create_admin_refuses_an_invalid_address(aenv, email):
    code, out, err = aenv.cli.run("create-admin", email, stdin=NEW_ADMIN_PASSWORD + "\n")
    assert code == 1 and out == "" and _users(aenv) == 0
    assert NEW_ADMIN_PASSWORD not in err


@pytest.mark.parametrize("password", ["short", "", "password123", ADMIN_EMAIL, "root",
                                      "long enough\x00but nul", "x" * 129, "\n"])
def test_create_admin_refuses_a_weak_password(aenv, password):
    code, out, err = aenv.cli.run("create-admin", ADMIN_EMAIL, stdin=password + "\n")
    assert code == 1 and out == ""
    assert _users(aenv) == 0 and aenv.scalar("SELECT count(*) FROM admin_factor") == 0
    if len(password) > 3:
        assert password.strip() not in err


def test_create_admin_with_empty_stdin_refuses(aenv):
    code, out, err = aenv.cli.run("create-admin", ADMIN_EMAIL, stdin="")
    assert code == 1 and out == "" and _users(aenv) == 0


def test_only_the_first_line_of_stdin_is_the_password(aenv):
    code, out, _ = aenv.cli.run("create-admin", ADMIN_EMAIL,
                                stdin=ADMIN_PASSWORD + "\r\nsomething else\n")
    assert code == 0
    row = _row(aenv)
    assert mod("passwords").verify_password(ADMIN_PASSWORD, row["pw_hash"], row["pw_salt"])


def test_terminal_asks_twice_and_refuses_a_mismatch(aenv, monkeypatch):
    cli = mod("admin_cli")
    answers = iter([NEW_ADMIN_PASSWORD, NEW_ADMIN_PASSWORD + "x"])
    prompts = []

    def fake_getpass(prompt="Password: ", stream=None):
        prompts.append(prompt)
        return next(answers)
    monkeypatch.setattr(cli.getpass, "getpass", fake_getpass)
    code, out, err = aenv.cli.run("create-admin", ADMIN_EMAIL, tty=True)
    assert code == 1 and len(prompts) == 2 and out == "" and _users(aenv) == 0
    assert "match" in err and NEW_ADMIN_PASSWORD not in err


def test_terminal_twice_the_same_creates(aenv, monkeypatch):
    cli = mod("admin_cli")
    prompts = []

    def fake_getpass(prompt="Password: ", stream=None):
        prompts.append(prompt)
        return NEW_ADMIN_PASSWORD
    monkeypatch.setattr(cli.getpass, "getpass", fake_getpass)
    code, out, err = aenv.cli.run("create-admin", ADMIN_EMAIL, stdin="ignored on a tty\n", tty=True)
    assert code == 0 and len(prompts) == 2
    row = _row(aenv)
    assert mod("passwords").verify_password(NEW_ADMIN_PASSWORD, row["pw_hash"], row["pw_salt"])
    assert NEW_ADMIN_PASSWORD not in out + err


@pytest.mark.parametrize("argv", [["create-admin"], ["create-admin", ADMIN_EMAIL, ADMIN_PASSWORD],
                                  ["create-admin", ADMIN_EMAIL, "--password", ADMIN_PASSWORD],
                                  ["create-admin", "--password=" + ADMIN_PASSWORD, ADMIN_EMAIL],
                                  ["reset-admin"], ["reset-admin", ADMIN_EMAIL, ADMIN_PASSWORD],
                                  ["create-admins", ADMIN_EMAIL]])
def test_the_password_is_never_taken_from_argv(aenv, argv):
    code, out, err = aenv.cli.run(*argv, stdin=ADMIN_PASSWORD + "\n")
    assert code == 2 and out == "" and "usage" in err
    assert _users(aenv) == 0


def test_cli_module_never_reads_argv_for_a_password():
    src = (ROOT / "quoteops" / "admin_cli.py").read_text(encoding="ascii")
    assert "sys.argv" not in src
    assert "getpass.getpass(" in src and "isatty()" in src
    # The CLI uses the owner login only: it never reads the web or admin role passwords.
    for name in ("QO_WEB_PASSWORD", "QO_ADMIN_PASSWORD", "QO_SECRET", "QO_ADMIN_SECRET",
                 "web_conninfo", "admin_conninfo"):
        assert name not in src, name


def test_cli_through_python_dash_m_refuses_extra_arguments(aenv):
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    r = subprocess.run([sys.executable, "-m", "quoteops", "create-admin", ADMIN_EMAIL,
                        ADMIN_PASSWORD], input=ADMIN_PASSWORD + "\n", capture_output=True,
                       text=True, env=env, cwd=ROOT, timeout=60)
    assert r.returncode == 2 and r.stdout == "" and ADMIN_PASSWORD not in r.stderr
    assert _users(aenv) == 0


def test_cli_through_python_dash_m_creates(aenv):
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    r = subprocess.run([sys.executable, "-m", "quoteops", "create-admin", ADMIN_EMAIL],
                       input=ADMIN_PASSWORD + "\n", capture_output=True, text=True, env=env,
                       cwd=ROOT, timeout=120)
    assert r.returncode == 0, r.stderr
    assert bytes(_row(aenv)["totp_secret"]) == secret_from(r.stdout)
    assert ADMIN_PASSWORD not in r.stdout + r.stderr


# --- reset-admin ----------------------------------------------------------------------------------

def test_reset_admin_new_password_new_secret_and_no_sessions(aenv):
    old_secret = aenv.create_admin()
    other_secret = aenv.create_admin("other@ops.test")
    signed_in_admin(aenv, old_secret)
    aenv.tick()
    c2 = aenv.admin_client()
    assert admin_login(c2, code=aenv.code(old_secret)).status_code == 303
    other = aenv.admin_client()
    assert admin_login(other, "other@ops.test", code=aenv.code(other_secret)).status_code == 303
    uid = aenv.user_id(ADMIN_EMAIL)
    assert aenv.scalar("SELECT count(*) FROM admin_session WHERE user_id = %s", (uid,)) == 2
    assert _row(aenv)["last_counter"] > 0

    code, out, err = aenv.cli.run("reset-admin", ADMIN_EMAIL, stdin=NEW_ADMIN_PASSWORD + "\n")
    assert code == 0, err
    new_secret = secret_from(out)
    assert uri_from(out) == mod("totp").otpauth_uri(new_secret, ADMIN_EMAIL)
    assert NEW_ADMIN_PASSWORD not in out + err
    row = _row(aenv)
    assert row["id"] == uid and bytes(row["totp_secret"]) == new_secret != old_secret
    assert row["last_counter"] == 0
    p = mod("passwords")
    assert p.verify_password(NEW_ADMIN_PASSWORD, row["pw_hash"], row["pw_salt"])
    assert not p.verify_password(ADMIN_PASSWORD, row["pw_hash"], row["pw_salt"])
    assert aenv.scalar("SELECT count(*) FROM admin_session WHERE user_id = %s", (uid,)) == 0
    assert other.get("/admin").status_code == 200  # another administrator is untouched
    assert c2.get("/admin").status_code == 303

    aenv.tick()
    fresh = aenv.admin_client()
    assert admin_login(fresh, code=aenv.code(old_secret), password=NEW_ADMIN_PASSWORD
                       ).status_code == 400
    assert admin_login(fresh, code=aenv.code(new_secret), password=ADMIN_PASSWORD
                       ).status_code == 400
    assert admin_login(fresh, code=aenv.code(new_secret), password=NEW_ADMIN_PASSWORD
                       ).status_code == 303


@pytest.mark.parametrize("target", ["owner", "unknown", "case_of_owner"])
def test_reset_admin_refuses_anything_but_a_sysadmin(aenv, target):
    account(aenv, "owner@shop.test")
    email = {"owner": "owner@shop.test", "unknown": "nobody@ops.test",
             "case_of_owner": "OWNER@shop.test"}[target]
    with aenv.owner() as c:
        before = c.execute("SELECT array_agg((id, role, pw_hash, company_id) ORDER BY id)"
                           " FROM app_user").fetchone()[0]
    code, out, err = aenv.cli.run("reset-admin", email, stdin=NEW_ADMIN_PASSWORD + "\n")
    assert code == 1 and out == "" and NEW_ADMIN_PASSWORD not in err
    with aenv.owner() as c:
        assert c.execute("SELECT array_agg((id, role, pw_hash, company_id) ORDER BY id)"
                         " FROM app_user").fetchone()[0] == before
        assert c.execute("SELECT count(*) FROM admin_factor").fetchone()[0] == 0


def test_reset_admin_with_a_weak_password_changes_nothing(aenv):
    secret = aenv.create_admin()
    signed_in_admin(aenv, secret)
    before = _row(aenv)
    code, out, err = aenv.cli.run("reset-admin", ADMIN_EMAIL, stdin="short\n")
    assert code == 1 and out == ""
    assert _row(aenv) == before and aenv.admin_sessions() == 1


def test_reset_admin_gives_a_factor_to_a_sysadmin_without_one(aenv):
    """A sysadmin from an older database has no admin_factor row; reset-admin creates it."""
    with aenv.owner() as c:
        c.execute("INSERT INTO app_user (id, company_id, email, pw_hash, pw_salt, role,"
                  " email_verified_at, consent_version, consent_at) VALUES (%s, NULL, %s,"
                  " '\\x01', '\\x02', 'sysadmin', now(), 'v1', now())", (uuid.uuid4(), ADMIN_EMAIL))
    secret = aenv.reset_admin()
    assert bytes(_row(aenv)["totp_secret"]) == secret
    signed_in_admin(aenv, secret)


# --- end to end -----------------------------------------------------------------------------------

def test_printed_secret_signs_in_at_the_real_time(aenv, monkeypatch):
    import time
    secret = aenv.create_admin()
    monkeypatch.setattr(mod("admin_app"), "_now", time.time)
    c = aenv.admin_client()
    r = admin_login(c, code=mod("totp").totp(secret, time.time()))
    assert r.status_code == 303 and r.headers["location"] == "/admin"
    page = c.get("/admin")
    assert page.status_code == 200 and ADMIN_EMAIL in page.text


# --- no other path creates a sysadmin -------------------------------------------------------------

def _code_without_comments(path: Path) -> str:
    text = path.read_text(encoding="ascii")
    if path.suffix == ".py":
        return "\n".join(line.split("#", 1)[0] for line in text.splitlines())
    return "\n".join(line.split("--", 1)[0] for line in text.splitlines())


def test_only_the_cli_module_names_the_sysadmin_role_in_code():
    """A quoted 'sysadmin' in Python code anywhere but admin_cli.py could only be there to
    write or compare the role; the web and admin services never need it (the database
    functions check the role)."""
    found = []
    for path in sorted((ROOT / "quoteops").rglob("*.py")):
        if path.name == "admin_cli.py":
            continue
        if re.search(r"""['"]sysadmin['"]""", _code_without_comments(path)):
            found.append(path.name)
    assert found == []


def test_only_known_places_insert_into_app_user():
    """auth.py inserts the owner with the literal 'owner'; team.py inserts an invitee with the
    role of the invitation row (CHECK: estimator, accountant, viewer); admin_cli.py inserts the
    sysadmin. The schema inserts no user."""
    inserting = set()
    for path in sorted((ROOT / "quoteops").rglob("*")):
        if path.suffix not in (".py", ".sql", ".html"):
            continue
        if re.search(r"INSERT\s+INTO\s+(public\.)?app_user\b", _code_without_comments(path),
                     re.IGNORECASE):
            inserting.add(path.name)
    assert inserting == {"auth.py", "team.py", "admin_cli.py"}
    cli = (ROOT / "quoteops" / "admin_cli.py").read_text(encoding="ascii")
    assert len(re.findall(r"INSERT\s+INTO\s+(?:public\.)?app_user\b", cli, re.IGNORECASE)) == 1
    auth = _code_without_comments(ROOT / "quoteops" / "auth.py")
    assert "VALUES (%s, %s, %s, %s, %s, 'owner', %s, now())" in auth


def test_public_routes_ignore_a_role_field(aenv):
    """Sign-up, verification, sign-in and reset never read a role from the form."""
    c = aenv.client()
    data = {"csrf": form_csrf(c, "/signup"), "email": "new@shop.test", "company": "New",
            "terms": "yes", "role": "sysadmin", "company_id": ""}
    assert c.post("/signup", data=data).status_code == 200
    link = verify_link(aenv, "new@shop.test")
    r = c.get(link[len(BASE):])
    token = link.split("?token=", 1)[1]
    r = c.post("/verify", data={"csrf": csrf_from(r.text), "token": token, "password": PASSWORD,
                                "company": "New", "terms": "yes", "role": "sysadmin"})
    assert r.status_code == 200
    with aenv.owner() as o:
        assert o.execute("SELECT role, company_id IS NOT NULL FROM app_user").fetchall() == [
            ("owner", True)]
        assert o.execute("SELECT count(*) FROM app_user WHERE role = 'sysadmin'").fetchone()[0] == 0
