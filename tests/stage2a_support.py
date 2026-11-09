"""Fixtures and helpers for the stage 2a tests: a migrated database that is dropped afterwards,
the environment the web app needs, a TestClient on the https base URL, and the file mail box."""
import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from tests.conftest import WEB_PW, Db

BASE = "https://qo.example"
SECRET = "stage2a-test-secret-0123456789abcdef"
PASSWORD = "correct horse battery"
NEW_PASSWORD = "another long phrase 42"
IP_HEADER = "X-Client-IP"

ENV_DEFAULTS_TO_CLEAR = [
    "QO_MAX_COMPANIES", "QO_LOGIN_FAILS_PER_EMAIL", "QO_LOGIN_FAILS_PER_IP",
    "QO_LOGIN_WINDOW_SECONDS", "QO_LOGIN_BLOCK_SECONDS", "QO_FORGOT_PER_EMAIL",
    "QO_FORGOT_PER_IP", "QO_SIGNUP_PER_IP", "QO_SIGNUP_PER_EMAIL", "QO_SCRYPT_CONCURRENCY",
    "QO_SCRYPT_WAIT_SECONDS", "QO_UNVERIFIED_MAX_AGE_HOURS", "QO_UNVERIFIED_KEEP",
    "QO_MAX_USERS_PER_COMPANY", "QO_INVITES_PER_DAY", "QO_INVITES_PER_ADDRESS_PER_DAY",
]


@pytest.fixture
def adb(empty_db):
    """A fresh migrated database without seed rows, dropped afterwards (the test container keeps
    its data on a small tmpfs)."""
    empty_db.migrate()
    yield empty_db
    with Db(empty_db.port, "postgres").connect(autocommit=True) as c:
        c.execute(f'DROP DATABASE IF EXISTS "{empty_db.dbname}" WITH (FORCE)')


@dataclass
class Mail:
    to: str
    subject: str
    body: str

    @property
    def links(self) -> list[str]:
        return re.findall(r"https?://\S+", self.body)


class Env:
    def __init__(self, db: Db, mail_dir: Path, monkeypatch):
        self.db, self.mail_dir, self.monkeypatch = db, mail_dir, monkeypatch

    def client(self, ip: str | None = None, **kw) -> TestClient:
        from quoteops.app import app
        headers = {"Origin": BASE}
        if ip:
            headers[IP_HEADER] = ip
        kw.setdefault("follow_redirects", False)
        return TestClient(app, base_url=BASE, headers=headers, **kw)

    def mails(self) -> list[Mail]:
        out = []
        if not self.mail_dir.exists():
            return out
        for p in sorted(self.mail_dir.iterdir(), key=lambda p: p.stat().st_mtime_ns):
            head, _, body = p.read_text(encoding="utf-8").partition("\n\n")
            fields = dict(line.split(": ", 1) for line in head.splitlines())
            out.append(Mail(fields["To"], fields["Subject"], body))
        return out

    def mails_to(self, email: str) -> list[Mail]:
        return [m for m in self.mails() if m.to == email]

    def owner(self):
        return self.db.connect()

    def scalar(self, sql: str, params=()):
        with self.db.connect() as c:
            return c.execute(sql, params).fetchone()[0]


@pytest.fixture
def env(adb, monkeypatch, tmp_path):
    values = {
        "QO_DB_HOST": "127.0.0.1", "QO_DB_PORT": adb.port, "QO_DB_NAME": adb.dbname,
        "QO_WEB_PASSWORD": WEB_PW, "QO_SECRET": SECRET, "QO_BASE_URL": BASE, "QO_MAIL": "file",
        "QO_MAIL_DIR": str(tmp_path / "mail"), "QO_COOKIE_SECURE": "true",
        "QO_CLIENT_IP_HEADER": IP_HEADER,
    }
    for k, v in values.items():
        monkeypatch.setenv(k, v)
    for k in ENV_DEFAULTS_TO_CLEAR:
        monkeypatch.delenv(k, raising=False)
    return Env(adb, tmp_path / "mail", monkeypatch)


# --- page helpers -------------------------------------------------------------------------------

CSRF_RE = re.compile(r'name="csrf" value="([^"]+)"')


def csrf_from(html: str) -> str:
    m = CSRF_RE.search(html)
    assert m, "no csrf field in the page"
    return m.group(1)


def form_csrf(client, path: str) -> str:
    r = client.get(path)
    assert r.status_code == 200, (path, r.status_code)
    return csrf_from(r.text)


def signup(client, email, company="Bengkel Maju", terms=True):
    """The sign-up form has no password: the mailbox owner chooses it at the verification link."""
    data = {"csrf": form_csrf(client, "/signup"), "email": email, "company": company}
    if terms:
        data["terms"] = "yes"
    return client.post("/signup", data=data)


def login(client, email, password=PASSWORD):
    # The pre-session token is bound to the qo_csrf cookie, not to one form; /forgot shows its
    # form even to a signed-in client, which /login redirects to /app.
    return client.post("/login", data={"csrf": form_csrf(client, "/forgot"), "email": email,
                                       "password": password})


def forgot(client, email):
    return client.post("/forgot", data={"csrf": form_csrf(client, "/forgot"), "email": email})


def path_of(link: str) -> str:
    assert link.startswith(BASE + "/"), link
    return link[len(BASE):]


def link_in(mail: Mail, route: str) -> str:
    found = [x for x in mail.links if x.startswith(f"{BASE}{route}?token=")]
    assert len(found) == 1, mail.body
    return found[0]


def token_of(link: str) -> str:
    return link.split("?token=", 1)[1]


def verify_link(env: Env, email: str) -> str:
    found = [m for m in env.mails_to(email) if any("/verify?token=" in x for x in m.links)]
    assert found, f"no verification mail for {email}"
    return link_in(found[-1], "/verify")


def reset_link(env: Env, email: str) -> str:
    found = [m for m in env.mails_to(email) if any("/reset?token=" in x for x in m.links)]
    assert found, f"no reset mail for {email}"
    return link_in(found[-1], "/reset")


def finish_signup(client, link: str, password=PASSWORD, company="Bengkel Maju", terms=True):
    """Open a verification link and send its form: the password, the company name and the terms.
    Returns the answer to the POST, or the answer to the GET when it shows no form."""
    r = client.get(path_of(link))
    if r.status_code != 200 or 'action="/verify"' not in r.text:
        return r
    data = {"csrf": csrf_from(r.text), "token": token_of(link), "password": password,
            "company": company}
    if terms:
        data["terms"] = "yes"
    return client.post("/verify", data=data)


def signed_up(env: Env, email: str, company="Bengkel Maju", ip=None):
    """Sign up only. The account exists but nobody can sign in until the link is used."""
    assert signup(env.client(ip=ip), email, company=company).status_code == 200


def account(env: Env, email: str, company="Bengkel Maju", ip=None, password=PASSWORD):
    """Sign up, choose the password at the verification link, and sign in. Returns a client
    holding the session cookie."""
    c = env.client(ip=ip)
    assert signup(c, email, company=company).status_code == 200
    r = finish_signup(c, verify_link(env, email), password=password, company=company)
    assert r.status_code == 200 and "/login" in r.text, r.text
    r = login(c, email, password)
    assert r.status_code == 303 and r.headers["location"] == "/app", r.text
    return c


def session_cookie(client) -> str:
    return client.cookies.get("qo_session")


def sha256(s: str) -> bytes:
    return hashlib.sha256(s.encode()).digest()


def throttle_key(kind: str, value: str) -> bytes:
    return hashlib.sha256(f"{kind}|{value}|{SECRET}".encode()).digest()


def app_csrf(client) -> str:
    r = client.get("/app")
    assert r.status_code == 200
    return csrf_from(r.text)
