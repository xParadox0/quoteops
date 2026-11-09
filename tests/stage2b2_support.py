"""Fixtures and helpers for stage 2b part 2: the administrator's identity and second factor, and
the separate admin service. Builds on the stage 2a fixtures: `aenv` is the web `env` plus the
admin service's settings, a fixed clock for the admin service, and the CLI run in-process."""
import base64
import hashlib
import importlib
import io
import sys

import pytest
from fastapi.testclient import TestClient

from tests.conftest import ADMIN_PW, OWNER, OWNER_PW
from tests.stage2a_support import BASE, IP_HEADER, PASSWORD, Env, csrf_from

ADMIN_BASE = "https://admin.qo.example"
ADMIN_SECRET = "stage2b2-admin-secret-0123456789abcdefgh"
ADMIN_EMAIL = "root@ops.test"
ADMIN_PASSWORD = "admin long phrase 2026"
GENERIC = "The email, password or code is not correct."
TRY_LATER = "Try again in a few minutes."
# 15 seconds into a 30-second step, so the codes of the steps around it are fixed.
T0 = 1_800_000_015.0
STEP = 30

ADMIN_ENV_TO_CLEAR = ["QO_ADMIN_SESSION_HOURS", "QO_ADMIN_LOGIN_FAILS_PER_EMAIL",
                      "QO_ADMIN_LOGIN_FAILS_PER_IP"]


def mod(name):
    return importlib.import_module(f"quoteops.{name}")


def b32decode(text: str) -> bytes:
    return base64.b32decode(text + "=" * (-len(text) % 8))


def sha256(s: str) -> bytes:
    return hashlib.sha256(s.encode()).digest()


def admin_throttle_key(kind: str, value: str) -> bytes:
    return hashlib.sha256(f"{kind}|{value}|{ADMIN_SECRET}".encode()).digest()


class Cli:
    """One run of `python -m quoteops <argv>` in this process, with stdin from a string."""

    def __init__(self, monkeypatch):
        self.monkeypatch = monkeypatch

    def run(self, *argv, stdin: str = "", tty: bool = False):
        fake_in = io.StringIO(stdin)
        fake_in.isatty = lambda: tty
        out, err = io.StringIO(), io.StringIO()
        saved = sys.stdin, sys.stdout, sys.stderr
        sys.stdin, sys.stdout, sys.stderr = fake_in, out, err
        try:
            code = mod("__main__").main(list(argv))
        finally:
            sys.stdin, sys.stdout, sys.stderr = saved
        return code, out.getvalue(), err.getvalue()


def secret_from(output: str) -> bytes:
    lines = [x for x in output.splitlines() if x.startswith("Secret: ")]
    assert len(lines) == 1, output
    return b32decode(lines[0].split(": ", 1)[1].strip())


def uri_from(output: str) -> str:
    lines = [x for x in output.splitlines() if x.startswith("URI: ")]
    assert len(lines) == 1, output
    return lines[0].split(": ", 1)[1].strip()


class AdminEnv(Env):
    def __init__(self, base: Env, monkeypatch):
        super().__init__(base.db, base.mail_dir, monkeypatch)
        self.cli = Cli(monkeypatch)
        self.clock = [T0]

    def admin_client(self, ip: str | None = None, origin: str | None = ADMIN_BASE,
                     **kw) -> TestClient:
        app = mod("admin_app").app
        headers = {}
        if origin:
            headers["Origin"] = origin
        if ip:
            headers[IP_HEADER] = ip
        kw.setdefault("follow_redirects", False)
        return TestClient(app, base_url=ADMIN_BASE, headers=headers, **kw)

    def create_admin(self, email: str = ADMIN_EMAIL, password: str = ADMIN_PASSWORD) -> bytes:
        code, out, err = self.cli.run("create-admin", email, stdin=password + "\n")
        assert code == 0, (out, err)
        return secret_from(out)

    def reset_admin(self, email: str = ADMIN_EMAIL, password: str = ADMIN_PASSWORD) -> bytes:
        code, out, err = self.cli.run("reset-admin", email, stdin=password + "\n")
        assert code == 0, (out, err)
        return secret_from(out)

    def code(self, secret: bytes, steps: int = 0) -> str:
        return mod("totp").totp(secret, self.clock[0] + steps * STEP)

    def tick(self, steps: int = 1) -> None:
        self.clock[0] += steps * STEP

    def user_id(self, email: str):
        return self.scalar("SELECT id FROM app_user WHERE email = %s", (email,))

    def admin_sessions(self) -> int:
        return self.scalar("SELECT count(*) FROM admin_session")


@pytest.fixture
def aenv(env, monkeypatch):
    values = {"QO_ADMIN_PASSWORD": ADMIN_PW, "QO_ADMIN_SECRET": ADMIN_SECRET,
              "QO_ADMIN_BASE_URL": ADMIN_BASE, "QO_OWNER_USER": OWNER,
              "QO_OWNER_PASSWORD": OWNER_PW}
    for k, v in values.items():
        monkeypatch.setenv(k, v)
    for k in ADMIN_ENV_TO_CLEAR:
        monkeypatch.delenv(k, raising=False)
    a = AdminEnv(env, monkeypatch)
    monkeypatch.setattr(mod("admin_app"), "_now", lambda: a.clock[0])
    return a


# --- page helpers ------------------------------------------------------------------------------

def admin_csrf(client) -> str:
    r = client.get("/login")
    assert r.status_code == 200, r.status_code
    return csrf_from(r.text)


def admin_login(client, email=ADMIN_EMAIL, password=ADMIN_PASSWORD, code="000000", csrf=None):
    data = {"csrf": csrf if csrf is not None else admin_csrf(client), "email": email,
            "password": password, "code": code}
    return client.post("/login", data=data)


def signed_in_admin(aenv: AdminEnv, secret: bytes, ip=None):
    c = aenv.admin_client(ip=ip)
    r = admin_login(c, code=aenv.code(secret))
    assert r.status_code == 303 and r.headers["location"] == "/admin", r.text
    return c


def page_csrf(client) -> str:
    r = client.get("/admin")
    assert r.status_code == 200, r.status_code
    return csrf_from(r.text)


def company_user(aenv: AdminEnv, email: str, role: str = "owner", cid: str = "c_one",
                 password: str = PASSWORD, disabled: bool = False) -> None:
    """An account of a company with a real password hash, written as the owner role."""
    pw_hash, pw_salt = mod("passwords").hash_password(password)
    with aenv.owner() as c:
        c.execute("INSERT INTO company (id, name, status) VALUES (%s, 'One', 'active')"
                  " ON CONFLICT (id) DO NOTHING", (cid,))
        c.execute("INSERT INTO app_user (id, company_id, email, pw_hash, pw_salt, role,"
                  " email_verified_at, disabled_at, consent_version, consent_at)"
                  " VALUES (gen_random_uuid(), %s, %s, %s, %s, %s, now(), %s, 'v1', now())",
                  (cid, email, pw_hash, pw_salt, role, "now" if disabled else None))


__all__ = ["ADMIN_BASE", "ADMIN_EMAIL", "ADMIN_PASSWORD", "ADMIN_SECRET", "BASE", "GENERIC",
           "T0", "STEP", "TRY_LATER", "aenv", "admin_csrf", "admin_login", "admin_throttle_key",
           "b32decode", "company_user", "mod", "page_csrf", "secret_from", "sha256",
           "signed_in_admin", "uri_from"]
