"""Stage 3a: drawing files (PRD F8, F17; HLD section 13). The type is decided from the content,
never from the client's Content-Type; the stored name is random; the multipart body is parsed as
it arrives, so a file is never held in memory, and is written only after the session, the role,
the company, the Origin and the CSRF token have been checked. Nothing here logs a file name,
customer text or content: class names and ids only."""
import codecs
import hashlib
import logging
import os
import re
import secrets
import stat
import threading
import time
import unicodedata
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from urllib.parse import quote

import anyio
from python_multipart.multipart import MultipartParser, parse_options_header

from quoteops.guard import MAX_BODY_BYTES

log = logging.getLogger("quoteops")

MAX_PARALLEL = 4              # uploads at once in this process
SLOT_WAIT_SECONDS = 5.0       # how long an upload waits for a slot before the answer is 503
READ_TIMEOUT_SECONDS = 30.0   # one read of the body; a client that stops sending is cut off
RATE_GRACE_SECONDS = 10.0     # an upload may be slow for this long before its rate is checked
MIN_BYTES_PER_SECOND = 65536  # then it must average this since the grace period began, or stops
COOLDOWN_SECONDS = 60.0       # a company whose upload stalled or crawled may not upload this long
MAX_PARTS = 10                # multipart parts per request
TMP_MAX_AGE_SECONDS = 3600    # the startup sweep removes temporary files older than this
TMP_DIR = ".tmp"
HEAD_BYTES = 1024             # what the type check and the script check look at

# type -> (MIME stored in drawing.mime, file name extensions that agree with it, label)
TYPES = {
    "pdf": ("application/pdf", (".pdf",), "PDF"),
    "dxf": ("image/vnd.dxf", (".dxf",), "DXF"),
    "png": ("image/png", (".png",), "PNG"),
    "jpeg": ("image/jpeg", (".jpg", ".jpeg"), "JPG"),
}
_PNG = b"\x89PNG\r\n\x1a\n"
_SCRIPT = re.compile(rb"<(?:script|html)", re.IGNORECASE)
# DXF: optional UTF-8 BOM and whitespace, the group code 0 on its own line, then SECTION.
_DXF_START = re.compile(rb"\A(?:\xef\xbb\xbf)?[ \t\r\n]*0[ \t]*\r?\n[ \t]*SECTION[ \t]*\r?\n")
_CP1252_UNDEFINED = re.compile(rb"[\x81\x8d\x8f\x90\x9d]")
_COMPANY_DIR = re.compile(r"[A-Za-z0-9_]{1,80}")
STORED_NAME = re.compile(r"[0-9a-f]{32}")


# --- the type, from the content -------------------------------------------------------------------

class Sniffer:
    """Fed the file as it arrives; result() names the type or None. PNG, JPEG and PDF by their
    signatures; DXF as text over the whole file: UTF-8 or cp1252 (ASCII-compatible), no NUL,
    beginning with group code 0 and SECTION, and containing ENDSEC or EOF. Whatever the
    signature, a file whose first 1024 bytes contain <script or <html is refused."""

    def __init__(self):
        self.head = bytearray()
        self.size = 0
        self.nul = False
        self._utf8 = codecs.getincrementaldecoder("utf-8")()
        self.utf8 = True
        self.cp1252 = True
        self.marker = False
        self._tail = b""

    def feed(self, data: bytes) -> None:
        if len(self.head) < HEAD_BYTES:
            self.head += data[:HEAD_BYTES - len(self.head)]
        self.size += len(data)
        if not self.nul and b"\x00" in data:
            self.nul = True
        if self.utf8:
            try:
                self._utf8.decode(data)
            except UnicodeDecodeError:
                self.utf8 = False
        if self.cp1252 and _CP1252_UNDEFINED.search(data):
            self.cp1252 = False
        if not self.marker:
            window = self._tail + data
            self.marker = b"ENDSEC" in window or b"EOF" in window
            self._tail = window[-5:]

    def _text(self) -> bool:
        if self.utf8:
            try:
                self._utf8.decode(b"", final=True)
            except UnicodeDecodeError:
                self.utf8 = False
        return not self.nul and (self.utf8 or self.cp1252)

    def result(self) -> str | None:
        head = bytes(self.head)
        if self.size == 0 or _SCRIPT.search(head):
            return None
        if head.startswith(_PNG) and head[12:16] == b"IHDR":
            return "png"
        if head.startswith(b"\xff\xd8\xff"):
            return "jpeg"
        if b"%PDF-" in head:
            return "pdf"
        if self._text() and self.marker and _DXF_START.match(head):
            return "dxf"
        return None


def detect(data: bytes) -> str | None:
    """The type of a whole file held in memory (tests and small callers)."""
    sniffer = Sniffer()
    for i in range(0, len(data), 65536):
        sniffer.feed(data[i:i + 65536])
    return sniffer.result()


# --- names ----------------------------------------------------------------------------------------

NAME_MAX = 120


def safe_name(raw: str) -> str:
    """The name kept for display and for the download header: the last path component, NFC, no
    control, format (such as direction overrides) or other invisible characters, no leading dots
    or spaces, at most NAME_MAX characters with the extension kept. Never used as a path."""
    name = re.split(r"[/\\]", raw)[-1]
    name = unicodedata.normalize("NFC", name)
    name = "".join(" " if unicodedata.category(c) == "Zs" else c
                   for c in name if c.isprintable() or unicodedata.category(c) == "Zs")
    name = re.sub(r" {2,}", " ", name).strip(" .")
    if len(name) > NAME_MAX:
        stem, ext = os.path.splitext(name)
        ext = ext if len(ext) <= 10 else ""
        name = stem[:NAME_MAX - len(ext)].rstrip(" .") + ext
    return name


def type_of_name(name: str) -> str | None:
    """The type the name's extension stands for, upper or lower case alike."""
    ext = os.path.splitext(name)[1].lower()
    for kind, (_, exts, _) in TYPES.items():
        if ext in exts:
            return kind
    return None


def _ascii_fallback(name: str) -> str:
    out = "".join(c if re.fullmatch(r"[A-Za-z0-9._ ()-]", c) else "_" for c in name)
    return out or "drawing"


def content_disposition(name: str) -> str:
    """attachment, an ASCII fallback and the UTF-8 name, percent-encoded: no quote, no CR or LF,
    no path character can reach the header."""
    name = safe_name(name) or "drawing"
    return (f"attachment; filename=\"{_ascii_fallback(name)}\";"
            f" filename*=UTF-8''{quote(name, safe='')}")


# --- where files live -----------------------------------------------------------------------------

def company_dir(root: str, company_id: str) -> str:
    if not _COMPANY_DIR.fullmatch(company_id):
        raise ValueError("company id cannot name a folder")
    return os.path.join(root, company_id)


def _ensure_dir(path: str) -> None:
    os.makedirs(path, mode=0o700, exist_ok=True)
    st = os.lstat(path)
    if not stat.S_ISDIR(st.st_mode):  # a symlink or a file where the folder should be
        raise OSError("not a directory")


def tmp_dir(root: str, company_id: str) -> str:
    folder = company_dir(root, company_id)
    _ensure_dir(folder)
    path = os.path.join(folder, TMP_DIR)
    _ensure_dir(path)
    return path


def resolve(root: str, company_id: str, stored: str) -> str | None:
    """The real path of a stored drawing when it lies directly inside the company's own folder
    and has a random stored name; None otherwise (the caller answers 404 and logs ids)."""
    base = os.path.realpath(company_dir(root, company_id))
    real = os.path.realpath(os.path.join(root, stored))
    if os.path.dirname(real) != base or not STORED_NAME.fullmatch(os.path.basename(real)):
        return None
    return real


def sweep_tmp(root: str, max_age: float = TMP_MAX_AGE_SECONDS) -> int:
    """Remove temporary upload files older than max_age from every company's .tmp folder; never
    follows a symlink. Returns how many were removed."""
    removed, cutoff = 0, time.time() - max_age
    try:
        companies = list(os.scandir(root))
    except OSError as exc:
        log.error("temporary file sweep failed: %s", type(exc).__name__)
        return 0
    for entry in companies:
        if not entry.is_dir(follow_symlinks=False):
            continue
        tmp = os.path.join(entry.path, TMP_DIR)
        try:
            if not stat.S_ISDIR(os.lstat(tmp).st_mode):
                continue
            for item in os.scandir(tmp):
                st = item.stat(follow_symlinks=False)
                if not stat.S_ISDIR(st.st_mode) and st.st_mtime < cutoff:
                    os.unlink(item.path)
                    removed += 1
        except FileNotFoundError:
            continue
        except OSError as exc:
            log.error("temporary file sweep failed: %s", type(exc).__name__)
    return removed


# --- at most MAX_PARALLEL uploads in the process, one per company ---------------------------------

SLOTS = threading.BoundedSemaphore(MAX_PARALLEL)
_companies: set[str] = set()
_companies_lock = threading.Lock()


class Busy(Exception):
    def __init__(self, which: str):
        super().__init__(which)
        self.which = which  # "process" or "company"


def _claim(company_id: str) -> bool:
    with _companies_lock:
        if company_id in _companies:
            return False
        _companies.add(company_id)
        return True


def _release(company_id: str) -> None:
    with _companies_lock:
        _companies.discard(company_id)


# company id -> the _now() time at which its cooldown ends; only companies currently in cooldown
_cooldown: dict[str, float] = {}


def start_cooldown(company_id: str) -> None:
    with _companies_lock:
        _cooldown[company_id] = _now() + COOLDOWN_SECONDS


def cooldown_left(company_id: str) -> float:
    """Seconds of cooldown left for the company, 0.0 when none. Removes every ended entry."""
    with _companies_lock:
        if not _cooldown:  # nothing to purge: the clock is not read
            return 0.0
        now = _now()
        for key in [k for k, end in _cooldown.items() if end <= now]:
            del _cooldown[key]
        end = _cooldown.get(company_id)
        return 0.0 if end is None else end - now


async def _wait_for(take, which: str) -> None:
    """Poll without blocking a thread, so a cancelled wait can never leave a slot taken."""
    deadline = time.monotonic() + SLOT_WAIT_SECONDS
    while not take():
        if time.monotonic() >= deadline:
            raise Busy(which)
        await anyio.sleep(0.05)


@asynccontextmanager
async def upload_slot(company_id: str):
    """One of the MAX_PARALLEL process slots, then the company's single slot; Busy after
    SLOT_WAIT_SECONDS for either. Taken before a byte of the body is read."""
    await _wait_for(lambda: SLOTS.acquire(blocking=False), "process")
    try:
        await _wait_for(lambda: _claim(company_id), "company")
        try:
            yield
        finally:
            _release(company_id)
    finally:
        SLOTS.release()


# --- the multipart stream -------------------------------------------------------------------------

class Refused(Exception):
    """Stop reading: status and a key for the message."""

    def __init__(self, status: int, key: str):
        super().__init__(key)
        self.status, self.key = status, key


class ClientGone(Exception):
    """The client disconnected before the body ended."""


@dataclass
class Received:
    fields: dict = field(default_factory=dict)
    file_name: str | None = None      # as sent, not yet made safe; never logged
    tmp_path: str | None = None
    size: int = 0
    sha256: object = None
    sniffer: Sniffer | None = None
    complete: bool = False


def boundary_of(content_type: str) -> bytes | None:
    kind, params = parse_options_header(content_type)
    boundary = params.get(b"boundary")
    if kind != b"multipart/form-data" or not boundary or len(boundary) > 200:
        return None
    return boundary


class Stream:
    """The parser's callbacks. Field values and part headers together may use MAX_BODY_BYTES; the
    file part may start only after a csrf part that matched `expected_csrf`, and only then is a
    temporary file (0600, O_EXCL, O_NOFOLLOW) opened in `tmp_folder`."""

    def __init__(self, expected_csrf: str, tmp_folder: str, max_file: int, same):
        self.expected, self.tmp_folder, self.max_file = expected_csrf, tmp_folder, max_file
        self.same = same
        self.out = Received(sha256=hashlib.sha256())
        self.csrf_ok = False
        self.parts = 0
        self.field_bytes = 0
        self._reset()
        self.fd = None

    def _reset(self):
        self.headers, self.hname, self.hvalue = {}, bytearray(), bytearray()
        self.kind, self.name, self.buf = None, None, bytearray()

    def _budget(self, n: int):
        self.field_bytes += n
        if self.field_bytes > MAX_BODY_BYTES:
            raise Refused(413, "fields")

    def on_part_begin(self):
        self.parts += 1
        if self.parts > MAX_PARTS:
            raise Refused(400, "parts")
        self._reset()

    def on_header_field(self, data, start, end):
        self._budget(end - start)
        self.hname += data[start:end]

    def on_header_value(self, data, start, end):
        self._budget(end - start)
        self.hvalue += data[start:end]

    def on_header_end(self):
        self.headers[bytes(self.hname).strip().lower()] = bytes(self.hvalue).strip()
        self.hname, self.hvalue = bytearray(), bytearray()

    def on_headers_finished(self):
        disposition = self.headers.get(b"content-disposition", b"")
        kind, params = parse_options_header(disposition)
        name = params.get(b"name")
        if kind != b"form-data" or name is None:
            raise Refused(400, "malformed")
        self.name = name.decode("utf-8", "replace")
        has_file_name = b"filename" in disposition.lower()
        if self.name != "file":
            if has_file_name:
                raise Refused(400, "malformed")
            self.kind = "field"
            return
        if self.out.tmp_path is not None:
            raise Refused(400, "two_files")
        if not self.csrf_ok:  # checked before any byte of the file is written anywhere
            raise Refused(403, "csrf")
        self.kind = "file"
        self.out.file_name = params.get(b"filename", b"").decode("utf-8", "replace")
        self.out.sniffer = Sniffer()
        path = os.path.join(self.tmp_folder, secrets.token_hex(16) + ".part")
        self.fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                          0o600)
        self.out.tmp_path = path

    def on_part_data(self, data, start, end):
        chunk = data[start:end]
        if self.kind == "file":
            self.out.size += len(chunk)
            if self.out.size > self.max_file:  # at the part of the stream that crosses it
                raise Refused(413, "file")
            view = memoryview(chunk)
            while view:
                view = view[os.write(self.fd, view):]
            self.out.sha256.update(chunk)
            self.out.sniffer.feed(bytes(chunk))
        else:
            self._budget(len(chunk))
            self.buf += chunk

    def on_part_end(self):
        if self.kind == "file":
            self.close()
            return
        try:
            value = bytes(self.buf).decode("utf-8")
        except UnicodeDecodeError:
            raise Refused(400, "malformed") from None
        if self.name == "csrf":
            if self.csrf_ok or not self.same(value, self.expected):
                raise Refused(403, "csrf")
            self.csrf_ok = True
        self.out.fields.setdefault(self.name, value)

    def on_end(self):
        self.out.complete = True

    def close(self):
        """Close the temporary file; it is flushed to disk later, in a worker thread, by
        sync_to_disk, so the event loop never waits for the disk."""
        if self.fd is not None:
            fd, self.fd = self.fd, None
            os.close(fd)

    def discard(self) -> None:
        """Close and remove the temporary file, if it still exists (after a successful store it
        has been renamed and is gone)."""
        if self.fd is not None:
            fd, self.fd = self.fd, None
            os.close(fd)
        remove_quietly(self.out.tmp_path, "temporary upload")

    def callbacks(self):
        return {k: getattr(self, k) for k in (
            "on_part_begin", "on_header_field", "on_header_value", "on_header_end",
            "on_headers_finished", "on_part_data", "on_part_end", "on_end")}


def _now() -> float:
    return time.monotonic()


async def receive_upload(stream: "Stream", receive, boundary: bytes) -> Received:
    """Read and parse the body as it arrives, writing the file part to a temporary file. Raises
    Refused, ClientGone, TimeoutError (a read took longer than READ_TIMEOUT_SECONDS, or the body
    arrived slower than MIN_BYTES_PER_SECOND once RATE_GRACE_SECONDS had passed) or the guard's
    BodyTooLarge. The caller calls stream.discard() on every exit path."""
    parser = MultipartParser(boundary, stream.callbacks())
    started, received = _now(), 0
    while True:
        with anyio.fail_after(READ_TIMEOUT_SECONDS):
            message = await receive()
        if message["type"] == "http.disconnect":
            raise ClientGone()
        body = message.get("body", b"")
        received += len(body)  # every body byte: headers, fields and file
        if body:
            try:
                parser.write(body)
            except (Refused, OSError):  # OSError: the temporary file could not be written
                raise
            except Exception:  # the parser's own errors: not a multipart body we can read
                raise Refused(400, "malformed") from None
        elapsed = _now() - started
        if elapsed > RATE_GRACE_SECONDS and received < MIN_BYTES_PER_SECOND * (
                elapsed - RATE_GRACE_SECONDS):
            raise TimeoutError("upload too slow")
        if not message.get("more_body", False):
            break
    try:
        parser.finalize()
    except Exception:
        raise Refused(400, "malformed") from None
    if not stream.out.complete or stream.fd is not None:
        raise Refused(400, "malformed")
    if not stream.csrf_ok:
        raise Refused(403, "csrf")
    return stream.out


def sync_to_disk(path: str) -> None:
    """fsync a finished temporary file before it is renamed into place."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def remove_quietly(path: str | None, what: str, ids: str = "") -> None:
    """Remove a file; a failure is logged by class name and ids only."""
    if not path:
        return
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    except OSError as exc:
        log.error("%s could not be removed: %s %s", what, type(exc).__name__, ids)
