"""Stage 3a: the upload mechanics (HLD section 13). The per-route body limit and the 16 KB limit
everywhere else, authorisation and the CSRF token before any byte of a file is stored, the 413
paths, chunked bodies, stalled and aborted clients, the upload slots, memory, the type from the
content, and file names that try to escape the company folder or the download header."""
import hashlib
import os
import re
import time
import tracemalloc
import unicodedata
from pathlib import Path

import pytest

from tests.stage2a_support import adb, env  # noqa: F401  (fixtures)
from tests.stage3a_support import (  # noqa: F401  (jenv is a fixture)
    BOUNDARY, DXF, FIELDS, JPEG, MB, MULTIPART, PDF, PNG, SAMPLES, add, asgi, body, chunked,
    company, create, created_ref, form, jenv, part, post_upload, stored_files, tmp_files, tree,
    upload_headers,
)

REFUSED = "This form has expired or was sent from another site."


def _mod(name):
    import importlib
    return importlib.import_module(f"quoteops.{name}")


def rows(env):
    with env.owner() as c:
        return (c.execute("SELECT count(*) FROM job").fetchone()[0],
                c.execute("SELECT count(*) FROM drawing").fetchone()[0],
                c.execute("SELECT count(*) FROM audit_event").fetchone()[0])


def nothing_stored(env):
    assert rows(env) == (0, 0, 0)
    assert [k for k in tree(env.files) if "/.tmp/" not in "/" + k] == []
    assert tmp_files(env.files) == []


# --- the request limits ---------------------------------------------------------------------------

def test_the_route_limit_table_names_exactly_the_upload_route(jenv, monkeypatch):
    guard = _mod("guard")
    assert guard.MAX_BODY_BYTES == 16384
    assert set(guard.ROUTE_BODY_LIMITS) == {("POST", "/jobs/upload")}
    assert guard.ROUTE_BODY_LIMITS[("POST", "/jobs/upload")]() == 25 * MB + guard.UPLOAD_OVERHEAD
    monkeypatch.setenv("QO_MAX_FILE_MB", "3")
    assert guard.ROUTE_BODY_LIMITS[("POST", "/jobs/upload")]() == 3 * MB + guard.UPLOAD_OVERHEAD
    assert guard.UPLOAD_OVERHEAD <= 64 * 1024
    # The admin service has no route limit table, so nothing there may exceed 16 KB.
    from quoteops.admin_app import app as admin
    mws = [m for m in admin.user_middleware if m.cls is guard.GuardMiddleware]
    assert mws and not mws[0].kwargs.get("route_limits")


@pytest.mark.parametrize("path", ["/jobs/J-1001", "/jobs/J-1001/drawings/x/delete", "/login",
                                  "/jobs/upload/", "/Jobs/upload", "/team/invite"])
def test_every_other_route_keeps_the_16_kb_limit(jenv, path):
    a = company(jenv, "c_a")
    created_ref(create(a["owner"]))
    big = b"csrf=" + b"x" * 16400
    p, _, q = path.partition("?")
    for chunks in ([big], chunked(big, 4096)):
        out = asgi("POST", p, chunks, headers={
            "cookie": f"qo_session={a['owner'].token}",
            "content-type": "application/x-www-form-urlencoded",
            "content-length": str(len(big)) if len(chunks) == 1 else None}, query=q)
        assert out.status == 413, (path, out.status)
        assert out.headers["connection"] == ["close"]
    # And the upload route's own limit does not apply to an upload sent to another path.
    out = asgi("POST", "/jobs/J-1001", [form(a["owner"].csrf, PDF + b"x" * 20000)],
               headers=upload_headers(a["owner"], length=len(form(a["owner"].csrf, PDF + b"x" * 20000))))
    assert out.status == 413


def test_a_declared_length_of_1_gb_is_refused_before_a_byte_is_read(jenv):
    a = company(jenv, "c_a")
    start = time.monotonic()
    out = asgi("POST", "/jobs/upload", [b"x" * 100],
               headers=upload_headers(a["owner"], length=1024 ** 3))
    assert time.monotonic() - start < 2
    assert out.status == 413 and out.receives == 0
    assert out.headers["connection"] == ["close"]
    assert b"larger than 25 MB" in out.body
    nothing_stored(jenv)


def test_a_chunked_upload_without_length_is_cut_at_the_limit(jenv, monkeypatch):
    monkeypatch.setenv("QO_MAX_FILE_MB", "1")
    a = company(jenv, "c_a")
    guard = _mod("guard")
    limit = MB + guard.UPLOAD_OVERHEAD
    huge = form(a["owner"].csrf, PDF + b"x" * (3 * MB), fields={})
    out = asgi("POST", "/jobs/upload", chunked(huge, 65536), headers=upload_headers(a["owner"]))
    assert out.status == 413 and out.headers["connection"] == ["close"]
    assert out.sent <= limit + 65536 and out.sent < len(huge)
    nothing_stored(jenv)


def test_the_guard_counts_the_whole_body_of_the_upload_route(jenv, monkeypatch):
    """The parser's own counters (the file, the fields) normally stop a body first; the guard's
    count of every byte is the backstop. With no overhead allowed, a file of exactly the limit
    plus its framing passes the limit, and the guard stops it at the crossing message."""
    monkeypatch.setenv("QO_MAX_FILE_MB", "1")
    guard = _mod("guard")
    monkeypatch.setattr(guard, "UPLOAD_OVERHEAD", 0)
    a = company(jenv, "c_a")
    data = form(a["owner"].csrf, (PDF + b"%" * MB)[:MB])
    # More bytes after the file carry the body past the limit; the file itself is within its
    # own limit, and the guard stops reading at the message that crosses the route limit.
    data = data[:-len(b"--\r\n")] + b"\r\n" + b"e" * 300000
    out = asgi("POST", "/jobs/upload", chunked(data), headers=upload_headers(a["owner"]))
    assert out.status == 413 and out.headers["connection"] == ["close"]
    assert b"larger than 1 MB" in out.body and out.sent <= MB + 65536 * 2 < len(data)
    nothing_stored(jenv)


def test_a_file_of_exactly_the_limit_passes_and_one_byte_more_is_413(jenv, monkeypatch):
    monkeypatch.setenv("QO_MAX_FILE_MB", "1")
    a = company(jenv, "c_a")
    exact = (PDF + b"%" * MB)[:MB]
    assert created_ref(create(a["owner"], exact)) == "J-1001"
    assert jenv.scalar("SELECT bytes FROM drawing") == MB
    before = rows(jenv), stored_files(jenv.files, "c_a")
    over = exact + b"%"
    r = create(a["owner"], over, fields={**FIELDS, "customer": "Kept Customer"})
    assert r.status_code == 413
    assert "larger than 1 MB, the limit for one drawing" in r.text
    assert 'value="Kept Customer"' in r.text
    assert (rows(jenv), stored_files(jenv.files, "c_a")) == before and not tmp_files(jenv.files)
    # The same through the raw stream: refused at the chunk that crosses the limit.
    data = form(a["owner"].csrf, over + b"%" * 300000)
    out = asgi("POST", "/jobs/upload", chunked(data, 4096), headers=upload_headers(a["owner"]))
    assert out.status == 413 and out.sent <= MB + 2 * 4096 + 1024 < len(data)
    assert not tmp_files(jenv.files)


def test_the_fields_beside_the_file_have_the_16_kb_budget(jenv):
    a = company(jenv, "c_a")
    r = create(a["owner"], fields={**FIELDS, "material": "m" * 16500})
    assert r.status_code == 413 and "too long" in r.text
    nothing_stored(jenv)
    many = body(part("csrf", a["owner"].csrf), *[part(f"x{i}", "v") for i in range(10)],
                part("file", PDF, filename="a.pdf"))
    r = post_upload(a["owner"].client, many)
    assert r.status_code == 400 and "more parts" in r.text
    nothing_stored(jenv)


@pytest.mark.parametrize("content_type", ["application/x-www-form-urlencoded", "multipart/form-data",
                                          "multipart/mixed; boundary=x", "text/plain", ""])
def test_a_body_that_is_not_multipart_form_data_is_refused_unread(jenv, content_type):
    a = company(jenv, "c_a")
    out = asgi("POST", "/jobs/upload", [b"csrf=x"],
               headers={**upload_headers(a["owner"]), "content-type": content_type})
    assert out.status == 400 and out.receives == 0
    nothing_stored(jenv)


@pytest.mark.parametrize("data", [
    b"--" + BOUNDARY.encode() + b"\r\nContent-Disposition: form-data; name=\"csrf\"\r\n\r\nabc",
    b"garbage without a boundary",
    b"--" + BOUNDARY.encode() + b"\r\nNo-Colon-Header\r\n\r\nx\r\n--" + BOUNDARY.encode() + b"--\r\n",
])
def test_a_malformed_multipart_body_is_400(jenv, data):
    a = company(jenv, "c_a")
    r = post_upload(a["owner"].client, data)
    assert r.status_code in (400, 403)
    nothing_stored(jenv)


def test_two_file_parts_are_refused(jenv):
    a = company(jenv, "c_a")
    two = body(part("csrf", a["owner"].csrf), *[part(k, v) for k, v in FIELDS.items()],
               part("file", PDF, filename="a.pdf"), part("file", PNG, filename="b.png"))
    r = post_upload(a["owner"].client, two)
    assert r.status_code == 400 and "one drawing at a time" in r.text
    nothing_stored(jenv)


# --- authorisation and CSRF before any byte of a file is stored -----------------------------------

def _big(csrf, before_file=True):
    """A 2 MB upload whose csrf part comes first (or after the file)."""
    return form(csrf, PDF + b"x" * (2 * MB), csrf_last=not before_file)


@pytest.mark.parametrize("case", ["missing", "wrong", "other user", "other company",
                                  "after the file", "empty", "twice"])
def test_csrf_matrix_refuses_without_creating_a_temp_file(jenv, case, monkeypatch):
    a, b = company(jenv, "c_a"), company(jenv, "c_b")
    u = a["owner"]
    made = []
    up = _mod("uploads")
    real_open = os.open

    def watch(path, flags, *args, **kw):
        if "/.tmp/" in str(path):
            made.append(path)
        return real_open(path, flags, *args, **kw)
    monkeypatch.setattr(up.os, "open", watch)
    data = {"missing": _big(None), "wrong": _big("0" * 64), "other user": _big(a["estimator"].csrf),
            "other company": _big(b["owner"].csrf), "after the file": _big(u.csrf, False),
            "empty": _big(""),
            "twice": body(part("csrf", u.csrf), part("csrf", u.csrf),
                          part("file", PDF + b"x" * (2 * MB), filename="a.pdf"))}[case]
    out = asgi("POST", "/jobs/upload", chunked(data), headers=upload_headers(u))
    assert out.status == 403 and REFUSED.encode() in out.body, (case, out.status)
    assert out.headers["connection"] == ["close"]
    assert made == [], case          # not even an empty temporary file was opened
    assert out.sent <= 2 * 65536 < len(data), case  # reading stopped right there
    nothing_stored(jenv)


@pytest.mark.parametrize("origin", [None, "https://evil.example", "null", "https://qo.example.evil",
                                    "http://qo.example"])
def test_origin_matrix_refuses_before_reading_the_body(jenv, origin):
    a = company(jenv, "c_a")
    out = asgi("POST", "/jobs/upload", chunked(_big(a["owner"].csrf)),
               headers={**upload_headers(a["owner"]), "origin": origin})
    assert out.status == 403 and out.receives == 0
    assert out.headers["connection"] == ["close"]
    nothing_stored(jenv)


def test_a_referer_alone_of_our_origin_is_accepted(jenv):
    a = company(jenv, "c_a")
    out = asgi("POST", "/jobs/upload", [form(a["owner"].csrf, PDF)],
               headers={**upload_headers(a["owner"]), "origin": None,
                        "referer": "https://qo.example/jobs/new"})
    assert out.status == 303


@pytest.mark.parametrize("who", ["anonymous", "bad cookie", "viewer", "accountant", "unverified",
                                 "suspended"])
def test_no_session_role_or_company_reads_no_body(jenv, who):
    a = company(jenv, "c_a")
    headers = upload_headers(a["owner"])
    if who == "anonymous":
        headers.pop("cookie")
    elif who == "bad cookie":
        headers["cookie"] = "qo_session=" + "A" * 43
    elif who in ("viewer", "accountant"):
        headers["cookie"] = f"qo_session={a[who].token}"
    else:
        with jenv.owner() as c:
            c.execute("UPDATE company SET status = %s WHERE id = 'c_a'", (who,))
    out = asgi("POST", "/jobs/upload", chunked(_big(a["owner"].csrf)), headers=headers)
    expected = 303 if who in ("anonymous", "bad cookie", "suspended") else 403
    assert out.status == expected and out.receives == 0, (who, out.status)
    assert out.headers["connection"] == ["close"]
    nothing_stored(jenv)


def test_the_upload_route_never_uses_the_buffering_form_parser(jenv, monkeypatch):
    from starlette.requests import Request

    async def forbidden(self, *a, **kw):
        raise AssertionError("request.form() on the upload route")
    monkeypatch.setattr(Request, "form", forbidden)
    monkeypatch.setattr(Request, "_get_form", forbidden)
    monkeypatch.setattr(Request, "body", forbidden)
    a = company(jenv, "c_a")
    assert created_ref(create(a["owner"]))


# --- stalled and aborted clients, the temp files --------------------------------------------------

def test_a_stalled_upload_times_out_and_leaves_no_temp_file(jenv, monkeypatch):
    up = _mod("uploads")
    monkeypatch.setattr(up, "READ_TIMEOUT_SECONDS", 0.3)
    a = company(jenv, "c_a")
    data = form(a["owner"].csrf, PDF + b"x" * 300000)
    seen = []
    start = time.monotonic()
    out = asgi("POST", "/jobs/upload", [data[:200000], "stall"], headers=upload_headers(a["owner"]),
               after=lambda: seen.append(tmp_files(jenv.files)))
    assert time.monotonic() - start < 5
    assert out.status == 408 and out.headers["connection"] == ["close"]
    assert b"stopped arriving" in out.body
    nothing_stored(jenv)


def test_an_aborted_upload_leaves_no_temp_file(jenv):
    a = company(jenv, "c_a")
    data = form(a["owner"].csrf, PDF + b"x" * 300000)
    out = asgi("POST", "/jobs/upload", [data[:200000], "disconnect"],
               headers=upload_headers(a["owner"]))
    assert out.status in (None, 400)
    nothing_stored(jenv)
    # The slots were given back.
    assert created_ref(create(a["owner"]))


def test_the_temp_file_exists_only_while_the_body_streams_and_is_0600(jenv, monkeypatch):
    a = company(jenv, "c_a")
    up = _mod("uploads")
    seen = []
    real = up.Sniffer.feed

    def look(self, chunk):
        for k in tmp_files(jenv.files):
            st = (jenv.files / k).stat()
            seen.append((k, oct(st.st_mode & 0o777), st.st_dev))
        return real(self, chunk)
    monkeypatch.setattr(up.Sniffer, "feed", look)
    ref = created_ref(create(a["owner"], PDF + b"x" * 200000))
    assert seen and all(m == "0o600" and k.startswith("c_a/.tmp/") for k, m, _ in seen)
    final = jenv.files / jenv.scalar("SELECT path FROM drawing")
    assert oct(final.stat().st_mode & 0o777) == "0o600"
    assert final.stat().st_dev == seen[0][2]  # one filesystem, so the rename is atomic
    assert oct((jenv.files / "c_a").stat().st_mode & 0o777) == "0o700"
    assert oct((jenv.files / "c_a" / ".tmp").stat().st_mode & 0o777) == "0o700"
    assert not tmp_files(jenv.files) and ref == "J-1001"


@pytest.mark.parametrize("data,name", [(b"<html>no</html>", "x.png"), (PNG, "x.pdf"), (b"", "x.pdf"),
                                       (b"MZ\x90\x00", "x.pdf")])
def test_a_refused_file_leaves_no_temp_file(jenv, data, name):
    a = company(jenv, "c_a")
    r = create(a["owner"], data, name)
    assert r.status_code == 400
    nothing_stored(jenv)


def test_a_disk_that_refuses_the_write_is_a_visible_failure_and_leaves_nothing(jenv, monkeypatch,
                                                                              caplog):
    import errno
    up = _mod("uploads")

    def full(fd, data):
        raise OSError(errno.ENOSPC, "No space left on device")
    monkeypatch.setattr(up.os, "write", full)
    a = company(jenv, "c_a")
    r = create(a["owner"], PDF, "Rahasia.pdf")
    assert r.status_code == 500
    assert "The drawing could not be stored. Nothing was saved." in r.text
    nothing_stored(jenv)
    messages = " ".join(x.getMessage() for x in caplog.records)
    assert "OSError" in messages and "Rahasia" not in messages


def test_the_startup_sweep_removes_old_temp_files_only(jenv):
    old_dir = jenv.files / "c_a" / ".tmp"
    old_dir.mkdir(parents=True)
    old, fresh = old_dir / "old.part", old_dir / "fresh.part"
    old.write_bytes(b"x")
    fresh.write_bytes(b"y")
    keep = jenv.files / "c_a" / ("a" * 32)
    keep.write_bytes(b"stored")
    target = jenv.files.parent / "target.txt"
    target.write_bytes(b"t")
    link = old_dir / "link.part"
    link.symlink_to(target)
    past = time.time() - 2 * 3600
    for p in (old, keep):
        os.utime(p, (past, past))
    os.utime(link, (past, past), follow_symlinks=False)
    with jenv.client():  # the lifespan runs the sweep
        pass
    assert not old.exists() and fresh.exists() and keep.exists()
    assert not link.is_symlink() and target.read_bytes() == b"t"


# --- the upload slots -----------------------------------------------------------------------------

def test_an_upload_beyond_the_slots_waits_then_gets_503_with_retry_after(jenv, monkeypatch):
    up = _mod("uploads")
    monkeypatch.setattr(up, "SLOT_WAIT_SECONDS", 0.3)
    assert up.MAX_PARALLEL == 4
    a = company(jenv, "c_a")
    assert all(up.SLOTS.acquire(blocking=False) for _ in range(up.MAX_PARALLEL))
    try:
        start = time.monotonic()
        out = asgi("POST", "/jobs/upload", chunked(_big(a["owner"].csrf)),
                   headers=upload_headers(a["owner"]))
        assert 0.25 < time.monotonic() - start < 3
        assert out.status == 503 and out.headers["retry-after"] == ["5"]
        assert out.receives == 0 and out.headers["connection"] == ["close"]
        assert b"busy with other uploads" in out.body
        nothing_stored(jenv)
    finally:
        for _ in range(up.MAX_PARALLEL):
            up.SLOTS.release()
    assert created_ref(create(a["owner"]))


def test_one_upload_at_a_time_per_company(jenv, monkeypatch):
    up = _mod("uploads")
    monkeypatch.setattr(up, "SLOT_WAIT_SECONDS", 0.3)
    a, b = company(jenv, "c_a"), company(jenv, "c_b")
    assert up._claim("c_a")
    try:
        r = create(a["estimator"])
        assert r.status_code == 503 and r.headers["retry-after"] == "5"
        assert "Another upload for your company" in r.text
        assert created_ref(create(b["owner"])) == "J-1001"  # another company is not held up
    finally:
        up._release("c_a")
    assert created_ref(create(a["estimator"])) == "J-1001"


def test_the_slots_are_given_back_after_every_kind_of_end(jenv, monkeypatch):
    up = _mod("uploads")
    monkeypatch.setattr(up, "READ_TIMEOUT_SECONDS", 0.2)
    monkeypatch.setenv("QO_MAX_FILE_MB", "1")
    a = company(jenv, "c_a")
    create(a["owner"], b"<html>", "x.png")
    create(a["owner"], PDF + b"x" * (2 * MB))
    asgi("POST", "/jobs/upload", [form(a["owner"].csrf, PDF)[:300], "stall"],
         headers=upload_headers(a["owner"]))
    asgi("POST", "/jobs/upload", [form(a["owner"].csrf, PDF)[:300], "disconnect"],
         headers=upload_headers(a["owner"]))
    asgi("POST", "/jobs/upload", chunked(_big(None)), headers=upload_headers(a["owner"]))
    assert up.SLOTS._value == up.MAX_PARALLEL and up._companies == set()


# --- memory ---------------------------------------------------------------------------------------

def test_a_file_of_the_maximum_size_streams_in_bounded_memory(jenv):
    """Method: tracemalloc counts every Python allocation of this process (the app, the parser,
    the hashing, psycopg) while a 25 MB upload streams through the ASGI app in 64 KiB messages
    that are generated on the fly, so the test itself never holds the file. The peak must stay
    far below the file size. resource.getrusage's peak RSS is reported too, but it is the
    process's lifetime high-water mark and so only a weak check."""
    import resource
    a = company(jenv, "c_a")
    size = 25 * MB
    head = (b"--" + BOUNDARY.encode() + b"\r\nContent-Disposition: form-data; name=\"csrf\"\r\n\r\n"
            + a["owner"].csrf.encode() + b"\r\n"
            + b"".join(part(k, v) for k, v in FIELDS.items())
            + b"--" + BOUNDARY.encode() + b"\r\nContent-Disposition: form-data; name=\"file\";"
            b" filename=\"big.pdf\"\r\nContent-Type: application/pdf\r\n\r\n")
    tail = b"\r\n--" + BOUNDARY.encode() + b"--\r\n"
    digest = hashlib.sha256()

    def chunks():
        yield head
        sent = 0
        block = PDF + b"%" * (65536 - len(PDF))
        while sent < size:
            piece = block if sent == 0 else b"%" * 65536
            piece = piece[:size - sent]
            digest.update(piece)
            sent += len(piece)
            yield piece
        yield tail
    rss_before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    tracemalloc.start()
    try:
        out = asgi("POST", "/jobs/upload", chunks, headers=upload_headers(a["owner"]))
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    rss_growth_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss - rss_before
    assert out.status == 303, out.body[:500]
    assert jenv.scalar("SELECT bytes FROM drawing") == size
    assert bytes(jenv.scalar("SELECT sha256 FROM drawing")) == digest.digest()
    print(f"tracemalloc peak {peak} bytes for a {size} byte file; peak RSS grew {rss_growth_kb} KiB")
    assert peak < size // 10, peak
    assert rss_growth_kb * 1024 < size // 2, rss_growth_kb


# --- the type, from the content -------------------------------------------------------------------

DXF_BOM = b"\xef\xbb\xbf" + DXF
DXF_CP1252 = b"  0\r\nSECTION\r\n  2\r\nHEADER\r\n999\r\nSt\xfcck \xe9\r\n  0\r\nENDSEC\r\n  0\r\nEOF\r\n"


@pytest.mark.parametrize("data,kind", [
    (PDF, "pdf"), (PNG, "png"), (JPEG, "jpeg"), (DXF, "dxf"), (DXF_BOM, "dxf"),
    (DXF_CP1252, "dxf"), (b"\n\n  0\nSECTION\n" + b"  8\nLAYER\n" * 1000 + b"  0\nEOF\n", "dxf"),
    (b"j" * 1019 + b"%PDF-1.7\n", "pdf"),              # %PDF- ends at the 1024th byte
    (b"j" * 1020 + b"%PDF-1.7\n", None),               # its last byte is the 1025th
    (b"j" * 1024 + b"%PDF-1.7\n", None),               # leading junk beyond 1024 bytes
    (b"", None), (b"\x89PNG\r\n", None), (b"\x89PNG\r\n\x1a\n", None), (b"\xff\xd8", None),
    (b"%PD", None),
    (b"  0\nSECTION\n  2\nHEADER\n", None),           # DXF without ENDSEC or EOF: truncated
    (b"  0\nSECT\x00ION\n  0\nEOF\n", None),           # NUL
    (b"  0\nSECTION\n\x00\n  0\nEOF\n", None),
    (b"  0\nSECTION\n\x81\x9d\n  0\nEOF\n", None),     # neither UTF-8 nor cp1252
    (b"999\nSECTION\n  0\nEOF\n", None),                # does not begin with group code 0
    (b"PK\x03\x04" + b"\x00" * 30, None),               # ZIP, and so docx, xlsx
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 30, None),  # old Office
    (b'<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"></svg>', None),
    (b"<svg onload=alert(1)>", None), (b"<!doctype html><html></html>", None),
    (b"GIF89a" + b"\x00" * 20, None), (b"MZ\x90\x00\x03", None), (b"\x7fELF", None),
    (PNG[:16] + b"<html><script>alert(1)</script>", None),   # polyglot
    (b"%PDF-1.4\n<script>alert(1)</script>", None),
    (b"\xff\xd8\xff\xe0<HTML>", None), (DXF.replace(b"HEADER", b"<ScRiPt>"), None),
    (b"x" * 1100 + b"<script>", None),                  # beyond 1024: not looked at, and no type
])
def test_the_type_is_decided_from_the_content(data, kind):
    up = _mod("uploads")
    assert up.detect(data) == kind
    s = up.Sniffer()  # the same, one byte at a time: markers across chunk borders
    for i in range(len(data)):
        s.feed(data[i:i + 1])
    assert s.result() == kind


def test_a_png_after_its_first_1024_bytes_may_hold_anything():
    up = _mod("uploads")
    assert up.detect(PNG + b"\x00" * 1100 + b"<script>") == "png"


@pytest.mark.parametrize("kind", ["pdf", "png", "jpeg", "dxf"])
def test_each_allowed_type_is_accepted_through_the_route(jenv, kind):
    a = company(jenv, "c_a")
    data, name, mime = SAMPLES[kind]
    created_ref(create(a["owner"], data, name, ctype="text/html"))  # the client's type is ignored
    assert jenv.scalar("SELECT mime FROM drawing") == mime


@pytest.mark.parametrize("data,name,ok", [
    (PDF, "PART.PDF", True), (JPEG, "photo.JPG", True), (JPEG, "photo.jpeg", True),
    (JPEG, "photo.JpEg", True), (DXF, "Plan.Dxf", True), (PNG, "x.PNG", True),
    (PNG, "a.pdf", False), (PDF, "a.png", False), (JPEG, "a.png", False), (DXF, "a.pdf", False),
    (PDF, "a.exe", False), (PDF, "a.pdf.exe", False), (PDF, "a", False), (PDF, "", False),
    (b"<html><body>x</body></html>", "page.png", False), (b"<svg></svg>", "a.svg", False),
    (b"PK\x03\x04" + b"\x00" * 30, "a.pdf", False), (b"", "empty.pdf", False),
    (b"", "empty.dxf", False), (b"  0\nSECTION\n\x00  0\nEOF\n", "nul.dxf", False),
    (b"MZ\x90\x00\x03" + b"\x00" * 60, "setup.pdf", False),
])
def test_the_name_must_agree_with_the_content(jenv, data, name, ok):
    a = company(jenv, "c_a")
    r = create(a["owner"], data, name, ctype="application/pdf")
    if ok:
        created_ref(r)
        return
    assert r.status_code == 400, r.text[:400]
    assert any(t in r.text for t in ("not a PDF, DXF, PNG or JPG drawing", "Rename the file",
                                     "The file is empty", "Choose a drawing to upload"))
    assert 'value="PT Sinar Logam"' in r.text
    nothing_stored(jenv)


def test_the_refusal_names_the_cause_and_the_next_step(jenv):
    a = company(jenv, "c_a")
    r = create(a["owner"], PNG, "drawing.pdf")
    assert "The file name ends in .pdf but the file is a PNG file. Rename the file to end in" \
           " .png, or choose the right file." in r.text
    r = create(a["owner"], b"<html>", "drawing.png")
    assert "This file is not a PDF, DXF, PNG or JPG drawing. Export the drawing as one of these" \
           " types and choose it again." in r.text
    r = create(a["owner"], b"", "drawing.pdf")
    assert "The file is empty. Choose the drawing file again." in r.text


# --- file names -----------------------------------------------------------------------------------

WEIRD = [
    ("../../etc/passwd.png", "passwd.png"),
    ("/etc/passwd.png", "passwd.png"),
    ("..\\..\\windows\\system32\\x.png", "x.png"),
    ("C:\\Users\\me\\drawing.png", "drawing.png"),
    ("a\x00b.png", "ab.png"),
    ("a%0D%0AX-Injected: 1.png", "a%0D%0AX-Injected: 1.png"),
    ("evil\u202egnp.exe.png", "evilgnp.exe.png"),
    ("\u200bzero\u2066width\u2069.png", "zerowidth.png"),
    ("x" * 300 + ".png", "x" * 116 + ".png"),
    ("  .hidden.png  ", "hidden.png"),
    ("caf\u0065\u0301.png", "caf\u00e9.png"),
    ("tab\there.png", "tabhere.png"),
    ("\u4e2d\u6587\u56fe\u7eb8.png", "\u4e2d\u6587\u56fe\u7eb8.png"),
]
ONLY_DOTS = [".", "..", "...", "....", ". .", "/..", "../", "..\\.."]


def _header_safe(h: str) -> None:
    assert h.startswith("attachment; filename=\"") and "inline" not in h
    assert "\r" not in h and "\n" not in h and "\x00" not in h
    m = re.fullmatch(r'attachment; filename="([^"]*)"; filename\*=UTF-8\'\'([A-Za-z0-9%._~-]+)', h)
    assert m, h
    assert "/" not in m.group(1) and "\\" not in m.group(1) and ".." not in m.group(1).strip(".")
    assert all(0x20 <= ord(c) < 0x7f for c in m.group(1))


@pytest.mark.parametrize("raw,expected", WEIRD)
def test_weird_names_stay_inside_the_company_folder_and_come_back_safe(jenv, raw, expected):
    a = company(jenv, "c_a")
    outside_before = sorted(os.listdir(jenv.files.parent))
    ref = created_ref(create(a["owner"], PNG, raw.encode("utf-8")))
    with jenv.owner() as c:
        name, path, did = c.execute("SELECT file_name, path, id FROM drawing").fetchone()
    assert name == expected
    assert re.fullmatch(r"c_a/[0-9a-f]{32}", path)
    files = tree(jenv.files)
    assert list(files) == [path] and files[path] == PNG
    assert sorted(os.listdir(jenv.files.parent)) == outside_before
    assert all(unicodedata.category(c) not in ("Cc", "Cf") for c in name)
    r = a["viewer"].client.get(f"/jobs/{ref}/drawings/{did}")
    assert r.status_code == 200 and r.content == PNG
    _header_safe(r.headers["content-disposition"])


@pytest.mark.parametrize("raw", ONLY_DOTS)
def test_names_of_only_dots_are_refused(jenv, raw):
    a = company(jenv, "c_a")
    r = create(a["owner"], PNG, raw)
    assert r.status_code == 400 and "Rename the file" in r.text
    nothing_stored(jenv)


def test_a_raw_line_break_in_the_part_header_never_reaches_a_header_or_a_path(jenv):
    a = company(jenv, "c_a")
    r = create(a["owner"], PNG, b"a\r\nX-Evil: 1\r\n.png")
    assert r.status_code in (303, 400)
    if r.status_code == 303:
        name = jenv.scalar("SELECT file_name FROM drawing")
        assert "\r" not in name and "\n" not in name
    assert "x-evil" not in {k.lower() for k in r.headers}
    assert all(k.startswith("c_a/") for k in tree(jenv.files))


def test_safe_name_and_header_units():
    up = _mod("uploads")
    assert up.safe_name("") == "" and up.safe_name("../..") == ""
    assert up.safe_name("a/b\\c.pdf") == "c.pdf"
    assert up.content_disposition("") == "attachment; filename=\"drawing\"; filename*=UTF-8''drawing"
    assert up.content_disposition("r\u00e9sum\u00e9 v2.pdf") == (
        "attachment; filename=\"r_sum_ v2.pdf\"; filename*=UTF-8''r%C3%A9sum%C3%A9%20v2.pdf")
    assert up.content_disposition('a";b\r\nc.pdf') == (
        "attachment; filename=\"a__bc.pdf\"; filename*=UTF-8''a%22%3Bbc.pdf")
    assert len(up.safe_name("y" * 500 + ".jpeg")) == 120 and up.safe_name("y" * 500 + ".jpeg").endswith(".jpeg")
    assert up.type_of_name("A.PDF") == "pdf" and up.type_of_name("x.jpeg") == "jpeg"
    assert up.type_of_name("x.svg") is None and up.type_of_name("pdf") is None


def test_the_stored_name_is_random_and_never_the_users(jenv):
    a = company(jenv, "c_a")
    ref = created_ref(create(a["owner"], PNG, "same.png"))
    add(a["owner"], ref, PNG, "same.png")
    paths = [r[0] for r in jenv.owner().execute("SELECT path FROM drawing")]
    assert len(set(paths)) == 2 and all("same" not in p for p in paths)
    assert all(Path(p).name not in ("same.png", "same") for p in paths)


# --- the minimum transfer rate (HLD section 13) ---------------------------------------------------

def _clock(monkeypatch, times):
    """uploads._now answers the given times one by one (the first call is the start of the receive
    loop, each later one follows a received message) and then repeats the last."""
    up = _mod("uploads")
    seq = iter(times)
    last = [times[-1]]

    def fake():
        last[0] = next(seq, last[0])
        return last[0]
    monkeypatch.setattr(up, "_now", fake)


def _slots_free(up):
    assert up._companies == set()
    assert up.SLOTS.acquire(blocking=False) and up.SLOTS.acquire(blocking=False)
    up.SLOTS.release()
    up.SLOTS.release()


def test_one_byte_per_five_seconds_is_cut_after_the_grace_period(jenv, monkeypatch):
    up = _mod("uploads")
    a = company(jenv, "c_a")
    data = form(a["owner"].csrf, PDF + b"x" * 300000)
    head = data[:data.index(b"%PDF") + 20]  # the file part has started: a temporary file exists
    n = len(head)
    # start 0; head at 1; then one byte at 5 s steps: 6, 11, 16 (first violation), 21 ...
    _clock(monkeypatch, [0.0, 1.0, 6.0, 11.0, 16.0, 21.0, 26.0])
    msgs = [head] + [data[n + i:n + 1 + i] for i in range(6)]
    out = asgi("POST", "/jobs/upload", msgs, headers=upload_headers(a["owner"]))
    assert out.status == 408 and out.headers["connection"] == ["close"]
    assert b"too slowly" in out.body and b"smaller file" in out.body
    assert b"Nothing was stored" in out.body
    # 11 s: far fewer than 65536 * 1 bytes, so the cut is at the message that arrived at 11 s.
    assert out.receives == 3
    nothing_stored(jenv)
    _slots_free(up)


def test_a_client_at_exactly_the_minimum_rate_is_not_cut(jenv, monkeypatch):
    up = _mod("uploads")
    rate = up.MIN_BYTES_PER_SECOND
    a = company(jenv, "c_a")
    total = rate * 50
    base = len(form(a["owner"].csrf, b""))
    data = form(a["owner"].csrf, PDF + b"x" * (total - base - len(PDF)))
    assert len(data) == total
    # Cumulative bytes are rate * (t - grace) at every t after the grace period.
    msgs, times = [data[:10]], [0.0, 1.0]
    sent = 10
    for t in range(11, 61):
        end = rate * (t - 10)
        msgs.append(data[sent:end])
        times.append(float(t))
        sent = end
    _clock(monkeypatch, times)
    out = asgi("POST", "/jobs/upload", msgs, headers=upload_headers(a["owner"]))
    assert out.status == 303 and out.sent == total
    assert len(stored_files(jenv.files, "c_a")) == 1
    _slots_free(up)


def test_a_client_one_byte_below_the_minimum_rate_is_cut(jenv, monkeypatch):
    up = _mod("uploads")
    rate = up.MIN_BYTES_PER_SECOND
    a = company(jenv, "c_a")
    total = rate * 50 - 1
    base = len(form(a["owner"].csrf, b""))
    data = form(a["owner"].csrf, PDF + b"x" * (total - base - len(PDF)))
    assert len(data) == total
    msgs, times = [data[:10]], [0.0, 1.0]
    sent = 10
    for t in range(11, 61):
        end = min(rate * (t - 10) - 1, total)
        msgs.append(data[sent:end])
        times.append(float(t))
        sent = end
    _clock(monkeypatch, times)
    out = asgi("POST", "/jobs/upload", msgs, headers=upload_headers(a["owner"]))
    assert out.status == 408 and out.receives == 2  # the head, then the message at 11 s
    nothing_stored(jenv)
    _slots_free(up)


def test_before_the_grace_period_ends_even_one_byte_in_total_is_not_cut(jenv, monkeypatch):
    up = _mod("uploads")
    a = company(jenv, "c_a")
    data = form(a["owner"].csrf, PDF + b"x" * 1000)
    msgs = [data[:1]] + [data[i:i + 1] for i in range(1, 5)] + [data[5:]]
    _clock(monkeypatch, [0.0, 1.0, 5.0, 9.0, 9.99, 10.0, 10.0])  # 10.0 is not over the grace
    out = asgi("POST", "/jobs/upload", msgs, headers=upload_headers(a["owner"]))
    assert out.status == 303
    _slots_free(up)


def test_just_over_the_grace_period_with_just_enough_bytes_passes(jenv, monkeypatch):
    up = _mod("uploads")
    a = company(jenv, "c_a")
    data = form(a["owner"].csrf, PDF + b"x" * 100000)
    need = up.MIN_BYTES_PER_SECOND // 2  # at 10.5 s: 0.5 s over the grace
    _clock(monkeypatch, [0.0, 1.0, 10.5])
    out = asgi("POST", "/jobs/upload", [data[:10], data[10:need], data[need:]],
               headers=upload_headers(a["owner"]))
    assert out.status == 303
    _clock(monkeypatch, [0.0, 1.0, 10.5])
    out = asgi("POST", "/jobs/upload", [data[:10], data[10:need - 1], data[need - 1:]],
               headers=upload_headers(a["owner"]))
    assert out.status == 408
    _slots_free(up)


def test_a_fast_client_then_silence_is_left_to_the_read_timeout(jenv, monkeypatch):
    up = _mod("uploads")
    monkeypatch.setattr(up, "READ_TIMEOUT_SECONDS", 0.3)
    a = company(jenv, "c_a")
    data = form(a["owner"].csrf, PDF + b"x" * 300000)
    _clock(monkeypatch, [0.0, 1.0, 30.0])  # the simulated 29 s of silence never reaches a rate check
    out = asgi("POST", "/jobs/upload", [data[:200000], "stall"], headers=upload_headers(a["owner"]))
    assert out.status == 408 and b"stopped arriving" in out.body
    assert out.receives == 2
    nothing_stored(jenv)
    _slots_free(up)


def test_a_fast_upload_of_the_maximum_size_is_never_cut(jenv):
    a = company(jenv, "c_a")
    data = form(a["owner"].csrf, PDF + b"x" * (25 * MB - 200000))
    start = time.monotonic()
    out = asgi("POST", "/jobs/upload", chunked(data), headers=upload_headers(a["owner"]))
    assert out.status == 303 and time.monotonic() - start < 20


def test_the_rate_constants_are_the_documented_ones():
    up = _mod("uploads")
    assert up.RATE_GRACE_SECONDS == 10.0 and up.MIN_BYTES_PER_SECOND == 65536


def test_a_real_time_drip_loses_the_slot_and_another_company_uploads_at_once(jenv, monkeypatch):
    up = _mod("uploads")
    monkeypatch.setattr(up, "RATE_GRACE_SECONDS", 0.3)
    monkeypatch.setattr(up, "MIN_BYTES_PER_SECOND", 1000)
    a, b = company(jenv, "c_a"), company(jenv, "c_b")
    data = form(a["owner"].csrf, PDF + b"x" * 300000)

    n = data.index(b"%PDF") + 20  # the file part has started: a temporary file exists

    def drip():
        yield data[:n]
        for i in range(100):
            time.sleep(0.05)
            yield data[n + i:n + 1 + i]
    start = time.monotonic()
    out = asgi("POST", "/jobs/upload", drip, headers=upload_headers(a["owner"]))
    assert time.monotonic() - start < 3
    assert out.status == 408 and out.receives < 30
    nothing_stored(jenv)
    _slots_free(up)
    assert created_ref(create(b["owner"])) == "J-1001"
