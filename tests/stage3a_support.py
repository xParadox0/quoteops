"""Stage 3a helpers: companies with one signed-in user per role (rows and sessions written as the
owner, so a test does not pay for sign-up and scrypt), multipart bodies built by hand (so the
order of the parts and every header byte are under the test's control), sample drawings, a raw
ASGI caller for streamed, chunked and stalled bodies, and the file tree of the files volume."""
import asyncio
import hashlib
import hmac
import os
import secrets
import uuid
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from tests.stage2a_support import BASE, SECRET, env  # noqa: F401  (env is a fixture)

ROLES = ("owner", "estimator", "accountant", "viewer")
EDITORS = ("owner", "estimator")
READERS = ("accountant", "viewer")
MB = 1024 * 1024
UPLOAD_ENV = ["QO_MAX_FILE_MB", "QO_MAX_COMPANY_MB", "QO_MAX_JOBS_PER_MONTH", "QO_FILES_DIR"]

PDF = b"%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj\ntrailer << /Root 1 0 R >>\n%%EOF\n"
PNG = (b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00"
       b"\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc\xf8\x0f\x00\x00\x01\x01\x00\x05\x18\xd8N\x00"
       b"\x00\x00\x00IEND\xaeB`\x82")
JPEG = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00" + b"\x00" * 40 + b"\xff\xd9"
DXF = b"  0\nSECTION\n  2\nHEADER\n  9\n$ACADVER\n  1\nAC1009\n  0\nENDSEC\n  0\nEOF\n"
SAMPLES = {"pdf": (PDF, "part.pdf", "application/pdf"), "png": (PNG, "part.png", "image/png"),
           "jpeg": (JPEG, "part.jpg", "image/jpeg"), "dxf": (DXF, "part.dxf", "image/vnd.dxf")}
FIELDS = {"customer": "PT Sinar Logam", "part": "Flange adapter", "qty": "50",
          "material": "S45C", "due": ""}


@pytest.fixture
def jenv(env, monkeypatch, tmp_path):
    """The stage 2a environment plus a files folder of its own."""
    files = tmp_path / "files"
    files.mkdir(mode=0o700)
    for k in UPLOAD_ENV:
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("QO_FILES_DIR", str(files))
    env.files = files
    from quoteops import uploads
    uploads._cooldown.clear()  # the cooldown is process state; no test inherits another's
    return env


def sha256(value: str) -> bytes:
    return hashlib.sha256(value.encode()).digest()


def csrf_for(token: str) -> str:
    """The session CSRF token: an HMAC of the session hash (auth.session_csrf)."""
    return hmac.new(SECRET.encode(), f"csrf-session|{sha256(token).hex()}".encode(),
                    hashlib.sha256).hexdigest()


@dataclass
class User:
    role: str
    id: uuid.UUID
    email: str
    token: str
    client: object

    @property
    def csrf(self) -> str:
        return csrf_for(self.token)


@dataclass
class Company:
    id: str
    users: dict = field(default_factory=dict)

    def __getitem__(self, role) -> User:
        return self.users[role]


def company(env, cid: str, status: str = "active", roles=ROLES, name=None) -> Company:
    """A company with one verified user per role, each with a live session and a client."""
    co = Company(cid)
    with env.owner() as c:
        c.execute("INSERT INTO company (id, name, status) VALUES (%s, %s, %s)",
                  (cid, name or f"Company {cid}", status))
        for role in roles:
            uid, token = uuid.uuid4(), secrets.token_urlsafe(32)
            email = f"{role}@{cid.replace('_', '-')}.test"
            c.execute("INSERT INTO app_user (id, company_id, email, pw_hash, pw_salt, role,"
                      " email_verified_at, consent_version, consent_at)"
                      " VALUES (%s, %s, %s, '\\x00', '\\x00', %s, now(), 'draft-0', now())",
                      (uid, cid, email, role))
            c.execute("INSERT INTO session (id_hash, user_id, expires_at)"
                      " VALUES (%s, %s, now() + interval '1 day')", (sha256(token), uid))
            client = env.client()
            client.cookies.set("qo_session", token)
            co.users[role] = User(role, uid, email, token, client)
    return co


# --- multipart ------------------------------------------------------------------------------------

BOUNDARY = "qo3aBoundary7MA4YWxkTrZu0gW"


def part(name: str, value, filename: str | bytes | None = None, ctype: str | None = None) -> bytes:
    disp = f'form-data; name="{name}"'.encode()
    if filename is not None:
        raw = filename if isinstance(filename, bytes) else filename.encode("utf-8")
        disp += b'; filename="' + raw + b'"'
    head = b"Content-Disposition: " + disp + b"\r\n"
    if ctype:
        head += f"Content-Type: {ctype}\r\n".encode()
    value = value if isinstance(value, bytes) else str(value).encode("utf-8")
    return b"--" + BOUNDARY.encode() + b"\r\n" + head + b"\r\n" + value + b"\r\n"


def body(*parts: bytes) -> bytes:
    return b"".join(parts) + b"--" + BOUNDARY.encode() + b"--\r\n"


def form(csrf: str | None, data: bytes | None, filename="part.pdf", fields=None,
         csrf_last=False, ctype="application/octet-stream") -> bytes:
    """The new job form as a browser sends it: csrf, the fields, then the file."""
    fields = FIELDS if fields is None else fields
    parts = [part(k, v) for k, v in fields.items()]
    if data is not None:
        parts.append(part("file", data, filename=filename, ctype=ctype))
    if csrf is not None:
        parts = parts + [part("csrf", csrf)] if csrf_last else [part("csrf", csrf)] + parts
    return body(*parts)


MULTIPART = f"multipart/form-data; boundary={BOUNDARY}"


def post_upload(client, content: bytes, job: str | None = None, headers=None):
    path = "/jobs/upload" + (f"?job={job}" if job else "")
    return client.post(path, content=content,
                       headers={"Content-Type": MULTIPART, **(headers or {})})


def create(user: User, data=PDF, filename="part.pdf", fields=None,
           ctype="application/octet-stream", **kw):
    return post_upload(user.client, form(user.csrf, data, filename, fields, ctype=ctype), **kw)


def add(user: User, ref: str, data=PDF, filename="more.pdf"):
    return post_upload(user.client, form(user.csrf, data, filename, fields={}), job=ref)


def created_ref(r) -> str:
    assert r.status_code == 303, (r.status_code, r.text[:2000])
    loc = r.headers["location"]
    assert loc.startswith("/jobs/J-"), loc
    return loc.rsplit("/", 1)[1]


# --- the files volume -----------------------------------------------------------------------------

def tree(root: Path) -> dict:
    """Every file under root (relative path -> bytes), symlinks not followed."""
    out = {}
    for dirpath, dirs, files in os.walk(root):
        for f in files:
            p = Path(dirpath) / f
            out[str(p.relative_to(root))] = p.read_bytes() if not p.is_symlink() else b"<link>"
    return out


def tmp_files(root: Path) -> list[str]:
    return [k for k in tree(root) if "/.tmp/" in "/" + k]


def stored_files(root: Path, cid: str) -> list[str]:
    return sorted(k for k in tree(root) if k.startswith(cid + "/") and "/.tmp/" not in "/" + k)


# --- a raw ASGI call ------------------------------------------------------------------------------

@dataclass
class Raw:
    status: int | None = None
    headers: dict = field(default_factory=dict)
    body: bytes = b""
    receives: int = 0     # how many times the app called receive()
    sent: int = 0         # body bytes handed to the app


def asgi(method: str, path: str, chunks, headers: dict | None = None, query: str = "",
         after=None) -> Raw:
    """Call the web app directly. `chunks` is an iterable of bytes, each one http.request
    message (more_body until the last), or of the strings "stall" (receive() never returns)
    and "disconnect" (an http.disconnect message). `after` runs once the body is exhausted."""
    from quoteops.app import app
    out = Raw()
    items = list(chunks) if not callable(chunks) else None
    gen = iter(items) if items is not None else chunks()
    pending = {"next": next(gen, None)}

    async def receive():
        out.receives += 1
        item = pending["next"]
        if item is None:
            await asyncio.sleep(3600)
        if item == "stall":
            await asyncio.sleep(3600)
        if item == "disconnect":
            pending["next"] = None
            return {"type": "http.disconnect"}
        pending["next"] = next(gen, None)
        out.sent += len(item)
        more = pending["next"] is not None
        if not more and after:
            after()
        return {"type": "http.request", "body": item, "more_body": more}

    async def send(msg):
        if msg["type"] == "http.response.start":
            out.status = msg["status"]
            for k, v in msg["headers"]:
                out.headers.setdefault(k.decode().lower(), []).append(v.decode("latin-1"))
        elif msg["type"] == "http.response.body":
            out.body += msg.get("body", b"")

    hdrs = [(b"host", b"qo.example"), (b"origin", BASE.encode())]
    for k, v in (headers or {}).items():
        if v is None:
            hdrs = [(a, b) for a, b in hdrs if a.decode() != k.lower()]
        else:
            hdrs = [(a, b) for a, b in hdrs if a.decode() != k.lower()] + [
                (k.lower().encode(), v.encode("latin-1"))]
    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": method,
             "scheme": "https", "path": path, "raw_path": path.encode(), "root_path": "",
             "query_string": query.encode(), "headers": hdrs, "client": ("127.0.0.1", 5000),
             "server": ("qo.example", 443)}
    asyncio.run(app(scope, receive, send))
    return out


def upload_headers(user: User, length: int | None = None, **extra) -> dict:
    h = {"cookie": f"qo_session={user.token}", "content-type": MULTIPART}
    if length is not None:
        h["content-length"] = str(length)
    h.update(extra)
    return h


def chunked(data: bytes, size: int = 65536):
    return [data[i:i + size] for i in range(0, len(data), size)] or [b""]
