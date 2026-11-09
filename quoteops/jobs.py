"""Stage 3a: jobs and drawing upload (PRD F8, parts of F17; HLD section 13). Every route names its
action in quoteops.permissions. Every read and write runs in the signed-in user's tenant
transaction, so row-level security alone decides what exists: a job, a drawing or an id of
another company finds no row and the answer is the same 404 page."""
import hashlib
import logging
import math
import os
import re
import secrets
import unicodedata
import uuid
from datetime import date, datetime, timezone

from fastapi import APIRouter, Depends, Form, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import Response, StreamingResponse

from quoteops import uploads
from quoteops.auth import Principal, _origin_ok, _redirect, _refused, _same, session_csrf
from quoteops.config import MB, Settings, load_settings
from quoteops.dbconn import tenant_conn
from quoteops.guard import BodyTooLarge
from quoteops.pages import message, render
from quoteops.permissions import ROLE_REFUSAL, allowed, nav_for, require
from quoteops.team import _audit, _not_found

log = logging.getLogger("quoteops")
router = APIRouter()

JOBS_LOCK = 0x514F4A42          # first key of the per-company advisory lock (jobs and drawings)
REF_RE = re.compile(r"J-[0-9]{1,9}")
QTY_MAX = 1_000_000
CUSTOMER_MAX, PART_MAX, MATERIAL_MAX = 120, 120, 100
PAST_DATE = "This date has passed. Pick today or a later date."
FIELDS = ("customer", "part", "qty", "material", "due")


# --- plumbing -------------------------------------------------------------------------------------

def _lock(conn, company_id: str) -> None:
    """One company's job creations and drawing uploads at a time, so a quota is checked and used
    in one step. The two-key form never collides with the one-key sign-up lock, and the first
    key differs from the team lock's."""
    key = int.from_bytes(hashlib.sha256(company_id.encode("utf-8")).digest()[:4], "big", signed=True)
    conn.execute("SELECT pg_advisory_xact_lock(%s::int, %s::int)", (JOBS_LOCK, key))


def _uuid(value: str) -> uuid.UUID | None:
    try:
        return uuid.UUID(value)
    except ValueError:
        return None


def _today() -> date:
    """Today in UTC: the company's own view of the date in this stage."""
    return datetime.now(timezone.utc).date()


def _month_start() -> date:
    return _today().replace(day=1)


def _next_month() -> date:
    first = _month_start()
    return first.replace(year=first.year + 1, month=1) if first.month == 12 else \
        first.replace(month=first.month + 1)


def _mb(n: int) -> str:
    return f"{n / MB:.1f}".rstrip("0").rstrip(".")


def _job_by_ref(conn, ref: str):
    if not REF_RE.fullmatch(ref):
        return None
    return conn.execute("SELECT id, ref, customer, part, qty, material, due_date, status,"
                        " created_at FROM job WHERE ref = %s", (ref,)).fetchone()


def _job_dict(row) -> dict:
    return {"id": row[0], "ref": row[1], "customer": row[2], "part": row[3], "qty": row[4],
            "material": row[5] or "", "due": row[6].isoformat() if row[6] else "",
            "status": row[7], "created": row[8].astimezone(timezone.utc).strftime("%Y-%m-%d")}


# --- the fields -----------------------------------------------------------------------------------

def _text(raw: str, limit: int, label: str, required: bool) -> tuple[str, str | None]:
    """Trimmed, NFC, no control or other invisible character, at most `limit` characters."""
    value = unicodedata.normalize("NFC", raw).strip()
    if not value:
        return value, f"Enter the {label}." if required else None
    if len(value) > limit:
        return value, f"The {label} can have at most {limit} characters."
    if not value.isprintable():
        return value, f"The {label} contains a character that cannot be shown. Type it again."
    return value, None


def check_fields(form: dict, old_due: date | None = None) -> tuple[dict, dict, dict]:
    """(values to show again, clean values, errors). A due date must be today or later (UTC),
    except that editing a job may keep the date it already has."""
    values = {k: str(form.get(k, ""))[:1000] for k in FIELDS}
    errors, clean = {}, {}
    clean["customer"], errors["customer"] = _text(values["customer"], CUSTOMER_MAX, "customer", True)
    clean["part"], errors["part"] = _text(values["part"], PART_MAX, "part name", True)
    clean["material"], errors["material"] = _text(values["material"], MATERIAL_MAX, "material", False)
    qty = values["qty"].strip()
    if not re.fullmatch(r"[0-9]{1,7}", qty) or not 1 <= int(qty) <= QTY_MAX:
        errors["qty"] = f"Enter the quantity as a whole number from 1 to {QTY_MAX:,}."
    else:
        clean["qty"] = int(qty)
    due = values["due"].strip()
    clean["due"] = None
    if due:
        try:
            if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", due):
                raise ValueError
            day = date.fromisoformat(due)
        except ValueError:
            errors["due"] = "Enter the due date as a date, for example 2026-12-31."
        else:
            if day < _today() and day != old_due:
                errors["due"] = PAST_DATE
            clean["due"] = day
    clean["material"] = clean["material"] or None
    return values, clean, {k: v for k, v in errors.items() if v}


# --- pages ----------------------------------------------------------------------------------------

def _usage(conn, s: Settings) -> dict:
    jobs = conn.execute("SELECT count(*) FROM job WHERE created_at >= date_trunc('month', now(),"
                        " 'UTC')").fetchone()[0]
    used = conn.execute("SELECT coalesce(sum(bytes), 0) FROM drawing").fetchone()[0]
    return {"jobs": jobs, "max_jobs": s.max_jobs_per_month, "used_mb": _mb(used),
            "max_company_mb": s.max_company_mb, "max_file_mb": s.max_file_mb}


def _customers(conn) -> list[str]:
    return [r[0] for r in conn.execute("SELECT customer FROM job GROUP BY customer"
                                       " ORDER BY max(created_at) DESC, customer LIMIT 20")]


def _new_page(principal: Principal, s: Settings, status: int = 200, values=None, errors=None,
              banner: str | None = None) -> Response:
    with tenant_conn(principal.company_id) as conn:
        usage, customers = _usage(conn, s), _customers(conn)
    return render("job_new.html", status=status, title="New job",
                  nav=nav_for(principal, "new"), csrf=session_csrf(s, principal.session_hash),
                  values=values or {"qty": ""}, errors=errors or {}, banner=banner, usage=usage,
                  customers=customers, today=_today().isoformat(),
                  types=", ".join(t[2] for t in uploads.TYPES.values()))


def _job_page(principal: Principal, s: Settings, ref: str, status: int = 200, values=None,
              errors=None, banner: str | None = None) -> Response:
    with tenant_conn(principal.company_id) as conn:
        row = _job_by_ref(conn, ref)
        if row is None:
            return _not_found()
        drawings = conn.execute("SELECT id, file_name, mime, bytes, created_at FROM drawing"
                                " WHERE job_id = %s ORDER BY created_at, id", (row[0],)).fetchall()
        usage, customers = _usage(conn, s), _customers(conn)
    job = _job_dict(row)
    labels = {mime: label for mime, _, label in uploads.TYPES.values()}
    editor = allowed(principal.role, "edit_job") and job["status"] == "draft"
    return render(
        "job.html", status=status, title=job["ref"], nav=nav_for(principal, "jobs"), job=job,
        drawings=[{"id": d[0], "name": d[1], "type": labels.get(d[2], d[2]), "size": _mb(d[3]),
                   "at": d[4].astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}
                  for d in drawings],
        can_edit=editor, can_upload=editor and allowed(principal.role, "upload_drawing"),
        can_delete=editor and allowed(principal.role, "delete_drawing"),
        values=values or job, errors=errors or {}, banner=banner, usage=usage,
        customers=customers, today=_today().isoformat(),
        types=", ".join(t[2] for t in uploads.TYPES.values()),
        csrf=session_csrf(s, principal.session_hash))


@router.get("/jobs")
def job_list(principal: Principal = Depends(require("view_jobs"))):
    s = load_settings()
    with tenant_conn(principal.company_id) as conn:
        rows = conn.execute("SELECT j.id, j.ref, j.customer, j.part, j.qty, j.material,"
                            " j.due_date, j.status, j.created_at,"
                            " (SELECT count(*) FROM drawing d WHERE d.job_id = j.id)"
                            " FROM job j ORDER BY j.created_at DESC, j.ref DESC").fetchall()
        usage = _usage(conn, s)
    jobs = [{**_job_dict(r), "drawings": r[9]} for r in rows]
    return render("jobs.html", title="Quotes", nav=nav_for(principal, "jobs"), jobs=jobs,
                  usage=usage, can_create=allowed(principal.role, "create_job"))


@router.get("/jobs/new")
def job_new(principal: Principal = Depends(require("create_job"))):
    return _new_page(principal, load_settings())


# --- the upload: create a job with its first drawing, or add a drawing to a job -------------------

REFUSALS = {
    "csrf": None,  # the usual "Request refused" page
    "parts": "The form sent more parts than an upload has. Reload the page and try again.",
    "two_files": "Send one drawing at a time.",
    "malformed": "The upload could not be read. Reload the page and try again.",
    "fields": "The form fields are too long. Shorten them and try again.",
}


def _busy(which: str) -> Response:
    text = ("Another upload for your company is still running. Wait until it has finished,"
            " then try again." if which == "company" else
            "The service is busy with other uploads. Try again in a few seconds.")
    response = message("Service busy", text, status=503)
    response.headers["Retry-After"] = "5"
    return response


def _file_problem(s: Settings, got, file_name: str) -> str | None:
    """Why the received file cannot be a drawing, in plain words with the next step; None when it
    can. `file_name` is already made safe."""
    if got.tmp_path is None or (not file_name and got.size == 0):
        return "Choose a drawing to upload: a PDF, DXF, PNG or JPG file."
    if got.size == 0:
        return "The file is empty. Choose the drawing file again."
    kind = got.sniffer.result()
    if kind is None:
        return ("This file is not a PDF, DXF, PNG or JPG drawing. Export the drawing as one of"
                " these types and choose it again.")
    named = uploads.type_of_name(file_name)
    if named is None:
        return (f"The file is a {uploads.TYPES[kind][2]} file, but its name does not end in"
                f" {' or '.join(uploads.TYPES[kind][1])}. Rename the file and choose it again.")
    if named != kind:
        return (f"The file name ends in {os.path.splitext(file_name)[1]} but the file is a"
                f" {uploads.TYPES[kind][2]} file. Rename the file to end in"
                f" {uploads.TYPES[kind][1][0]}, or choose the right file.")
    return None


class _Quota(Exception):
    def __init__(self, text: str):
        super().__init__("quota")
        self.text = text


def _jobs_this_month(conn) -> int:
    return conn.execute("SELECT count(*) FROM job WHERE created_at >= date_trunc('month', now(),"
                        " 'UTC')").fetchone()[0]


def _company_bytes(conn) -> int:
    return conn.execute("SELECT coalesce(sum(bytes), 0) FROM drawing").fetchone()[0]


def _store(s: Settings, principal: Principal, got, kind: str, file_name: str, clean: dict | None,
           ref: str | None) -> str:
    """In one tenant transaction, under the company lock: the company is still active, the
    quotas, the job (when creating) and the drawing rows, the audit rows, then the rename of the
    temporary file to its random final name. The rename happens before the commit; if the commit
    fails, the final file is removed. Returns the job's ref."""
    folder = uploads.company_dir(s.files_dir, principal.company_id)
    uploads.sync_to_disk(got.tmp_path)
    stored = secrets.token_hex(16)
    final = os.path.join(folder, stored)
    renamed = False
    try:
        with tenant_conn(principal.company_id) as conn:
            _lock(conn, principal.company_id)
            status = conn.execute("SELECT status FROM company WHERE id = %s",
                                  (principal.company_id,)).fetchone()
            if status is None or status[0] != "active":
                raise _Quota("This company is not active. Nothing was stored.")
            if ref is None and _jobs_this_month(conn) >= s.max_jobs_per_month:
                raise _Quota(
                    f"Your company has created {s.max_jobs_per_month} jobs this month, the limit."
                    f" Nothing was stored. New jobs can be created again from"
                    f" {_next_month().isoformat()} (UTC); to raise the limit, contact QuoteOps"
                    " support.")
            used = _company_bytes(conn)
            if used + got.size > s.max_company_mb * MB:
                raise _Quota(
                    f"Your company has used {_mb(used)} MB of its {s.max_company_mb} MB for"
                    f" drawings, and this file needs {_mb(got.size)} MB. Nothing was stored."
                    " Delete drawings you no longer need, or contact QuoteOps support to raise"
                    " the limit.")
            if ref is None:
                n = conn.execute("UPDATE company SET job_next = job_next + 1 WHERE id = %s"
                                 " RETURNING job_next - 1", (principal.company_id,)).fetchone()[0]
                ref, job_id = f"J-{n}", uuid.uuid4()
                conn.execute("INSERT INTO job (id, company_id, ref, customer, part, qty, material,"
                             " due_date, status, created_by) VALUES (%s, %s, %s, %s, %s, %s, %s,"
                             " %s, 'draft', %s)",
                             (job_id, principal.company_id, ref, clean["customer"], clean["part"],
                              clean["qty"], clean["material"], clean["due"], principal.user_id))
                _audit(conn, principal, "job.create",
                       f"job {job_id} fields customer,part,qty,material,due_date")
            else:
                row = conn.execute("SELECT id, status FROM job WHERE ref = %s FOR UPDATE",
                                   (ref,)).fetchone()
                if row is None or row[1] != "draft":
                    raise _Quota("This job can no longer take drawings. Nothing was stored.")
                job_id = row[0]
            drawing_id = uuid.uuid4()
            conn.execute("INSERT INTO drawing (id, company_id, job_id, file_name, mime, bytes,"
                         " sha256, path, created_by) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
                         (drawing_id, principal.company_id, job_id, file_name,
                          uploads.TYPES[kind][0], got.size, got.sha256.digest(),
                          f"{principal.company_id}/{stored}", principal.user_id))
            _audit(conn, principal, "drawing.upload", f"drawing {drawing_id} job {job_id}")
            os.rename(got.tmp_path, final)
            renamed = True
    except BaseException:
        if renamed:  # the rows were not committed: nothing may point at the file, so it goes
            uploads.remove_quietly(final, "drawing after a failed commit",
                                   f"company {principal.company_id}")
        raise
    return ref


@router.post("/jobs/upload")
async def job_upload(request: Request, principal: Principal = Depends(require("upload_drawing"))):
    """Before any byte of the body is read: the session, the role, the verified address and the
    active company (the dependency), the Origin, the job (when adding to one), the request type
    and an upload slot. The csrf field must be the first thing the form sends before the file:
    it is checked as soon as its part ends, and a file part that starts before a valid token is
    refused before a byte of it is written. The guard answers with Connection: close whenever the
    body was not read to its end."""
    s = load_settings()
    if not _origin_ok(request, s):
        return _refused()
    ref = request.query_params.get("job")
    if ref is not None:
        def _target():
            with tenant_conn(principal.company_id) as conn:
                return _job_by_ref(conn, ref)
        row = await run_in_threadpool(_target)
        if row is None:
            return _not_found()
        if row[7] != "draft":
            return message("Job closed", "Drawings can be added only while the job is a draft.",
                           status=409)
    elif not allowed(principal.role, "create_job"):
        return message("Not allowed", ROLE_REFUSAL, status=403)
    boundary = uploads.boundary_of(request.headers.get("content-type", ""))
    if boundary is None:
        return message("Upload not understood", REFUSALS["malformed"], status=400)
    left = uploads.cooldown_left(principal.company_id)
    if left > 0:  # before a slot is taken or a byte is read
        seconds = math.ceil(left)
        response = message("Uploads paused", f"Uploads from your company are paused for {seconds}"
                           " seconds because the last upload arrived too slowly. Nothing was"
                           " stored. Wait, then try again, or use a faster connection or a smaller"
                           " file.", status=429)
        response.headers["Retry-After"] = str(seconds)
        return response
    try:
        async with uploads.upload_slot(principal.company_id):
            return await _receive_and_store(request, s, principal, boundary, ref)
    except uploads.Busy as exc:
        return _busy(exc.which)


async def _receive_and_store(request: Request, s: Settings, principal: Principal, boundary: bytes,
                             ref: str | None) -> Response:
    try:
        folder = await run_in_threadpool(uploads.tmp_dir, s.files_dir, principal.company_id)
    except (OSError, ValueError) as exc:
        log.error("upload folder not usable: %s company %s", type(exc).__name__,
                  principal.company_id)
        return _store_failed()
    stream = uploads.Stream(session_csrf(s, principal.session_hash), folder,
                            s.max_file_mb * MB, _same)

    def again(status: int, banner: str, errors=None) -> Response:
        """The form again with what was typed, the cause and the next step."""
        form = stream.out.fields
        if ref is None:
            values, _, _ = check_fields(form)
            return _new_page(principal, s, status=status, values=values, errors=errors or {},
                             banner=banner)
        return _job_page(principal, s, ref, status=status, banner=banner)

    try:
        try:
            got = await uploads.receive_upload(stream, request.receive, boundary)
        except uploads.Refused as exc:
            if exc.key == "csrf":
                return _refused()
            if exc.key == "file":
                return await run_in_threadpool(
                    again, 413, f"The file is larger than {s.max_file_mb} MB, the limit for one"
                    " drawing. Nothing was stored. Make the file smaller (for example, export the"
                    " drawing at a lower resolution) and choose it again.")
            return message("Upload not understood", REFUSALS[exc.key], status=exc.status)
        except BodyTooLarge:
            return await run_in_threadpool(
                again, 413, f"The upload is larger than {s.max_file_mb} MB, the limit for one"
                " drawing. Nothing was stored. Choose a smaller file.")
        except TimeoutError:
            await run_in_threadpool(stream.discard)
            uploads.start_cooldown(principal.company_id)
            return message("Upload stopped", "The upload stopped arriving or arrived too slowly, so"
                           " it was cancelled. Nothing was stored. Check the connection and try"
                           " again, or upload a smaller file.", status=408)
        except uploads.ClientGone:
            return Response(status_code=400)  # nobody is listening any more
        except OSError as exc:
            log.error("upload could not be written: %s company %s", type(exc).__name__,
                      principal.company_id)
            return _store_failed()

        file_name = uploads.safe_name(got.file_name or "")
        problem = _file_problem(s, got, file_name)
        clean, errors = None, {}
        if ref is None:
            _, clean, errors = check_fields(got.fields)
        if problem or errors:
            if problem:
                errors["file"] = problem
            return await run_in_threadpool(
                again, 400, problem or "Check the fields marked below. The drawing was not"
                " stored: choose it again after correcting them.", errors)
        try:
            ref = await run_in_threadpool(_store, s, principal, got, got.sniffer.result(),
                                          file_name, clean, ref)
        except _Quota as exc:
            return await run_in_threadpool(again, 403, exc.text)
        except OSError as exc:
            log.error("drawing could not be stored: %s company %s", type(exc).__name__,
                      principal.company_id)
            return _store_failed()
        return _redirect(f"/jobs/{ref}")
    finally:
        await run_in_threadpool(stream.discard)


def _store_failed() -> Response:
    return message("Upload failed", "The drawing could not be stored. Nothing was saved. Try"
                   " again in a few minutes; if it keeps failing, contact QuoteOps support.",
                   status=500)


# --- one job --------------------------------------------------------------------------------------

@router.get("/jobs/{ref}")
def job_view(ref: str, principal: Principal = Depends(require("view_jobs"))):
    return _job_page(principal, load_settings(), ref)


@router.post("/jobs/{ref}")
def job_edit(request: Request, ref: str, principal: Principal = Depends(require("edit_job")),
             csrf: str = Form(""), customer: str = Form(""), part: str = Form(""),
             qty: str = Form(""), material: str = Form(""), due: str = Form("")):
    s = load_settings()
    if not (_origin_ok(request, s) and _same(csrf, session_csrf(s, principal.session_hash))):
        return _refused()
    form = {"customer": customer, "part": part, "qty": qty, "material": material, "due": due}
    with tenant_conn(principal.company_id) as conn:
        row = _job_by_ref(conn, ref)
        if row is None:
            return _not_found()
        if row[7] != "draft":
            return message("Job closed", "A job can be changed only while it is a draft.",
                           status=409)
        values, clean, errors = check_fields(form, old_due=row[6])
        if not errors:
            old = {"customer": row[2], "part": row[3], "qty": row[4], "material": row[5],
                   "due_date": row[6]}
            new = {"customer": clean["customer"], "part": clean["part"], "qty": clean["qty"],
                   "material": clean["material"], "due_date": clean["due"]}
            changed = [k for k in old if old[k] != new[k]]
            if changed:
                conn.execute("UPDATE job SET customer = %s, part = %s, qty = %s, material = %s,"
                             " due_date = %s WHERE id = %s",
                             (new["customer"], new["part"], new["qty"], new["material"],
                              new["due_date"], row[0]))
                _audit(conn, principal, "job.update", f"job {row[0]} fields {','.join(changed)}")
    if errors:
        return _job_page(principal, s, ref, status=400, values={**_job_dict(row), **values},
                         errors=errors, banner="Check the fields marked below. Nothing was changed.")
    return _redirect(f"/jobs/{ref}")


# --- drawings: download and delete ----------------------------------------------------------------

def _drawing(conn, ref: str, drawing: str):
    drawing_id = _uuid(drawing)
    if drawing_id is None or not REF_RE.fullmatch(ref):
        return None
    return conn.execute("SELECT d.id, d.job_id, d.file_name, d.path, d.bytes, j.status"
                        " FROM drawing d JOIN job j ON j.id = d.job_id"
                        " WHERE d.id = %s AND j.ref = %s", (drawing_id, ref)).fetchone()


def _chunks(fd: int):
    try:
        while True:
            data = os.read(fd, 65536)
            if not data:
                break
            yield data
    finally:
        os.close(fd)


@router.get("/jobs/{ref}/drawings/{drawing}")
def drawing_download(ref: str, drawing: str, principal: Principal = Depends(require("view_jobs"))):
    """Only ever as an attachment of type application/octet-stream, never inline: the file is
    not rendered by the server or, with nosniff and the sandbox policy, by the browser."""
    s = load_settings()
    with tenant_conn(principal.company_id) as conn:
        row = _drawing(conn, ref, drawing)
    if row is None:
        return _not_found()
    real = uploads.resolve(s.files_dir, principal.company_id, row[3])
    if real is None:
        log.error("drawing path outside its company folder: drawing %s company %s", row[0],
                  principal.company_id)
        return _not_found()
    try:
        fd = os.open(real, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as exc:
        log.error("drawing file not readable: %s drawing %s", type(exc).__name__, row[0])
        return _not_found()
    size = os.fstat(fd).st_size
    return StreamingResponse(_chunks(fd), media_type="application/octet-stream", headers={
        "content-disposition": uploads.content_disposition(row[2]),
        "content-length": str(size),
        "x-content-type-options": "nosniff",
        "cache-control": "no-store",
        "content-security-policy": "sandbox; default-src 'none'",
    })


@router.post("/jobs/{ref}/drawings/{drawing}/delete")
def drawing_delete(request: Request, ref: str, drawing: str,
                   principal: Principal = Depends(require("delete_drawing")), csrf: str = Form("")):
    """The row goes in the transaction, then the file. A file that cannot be removed is logged by
    class name and ids and stays as an orphan that no row points at."""
    s = load_settings()
    if not (_origin_ok(request, s) and _same(csrf, session_csrf(s, principal.session_hash))):
        return _refused()
    with tenant_conn(principal.company_id) as conn:
        row = _drawing(conn, ref, drawing)
        if row is None:
            return _not_found()
        if row[5] != "draft":
            return message("Job closed", "Drawings can be deleted only while the job is a draft.",
                           status=409)
        _lock(conn, principal.company_id)
        conn.execute("DELETE FROM drawing WHERE id = %s", (row[0],))
        _audit(conn, principal, "drawing.delete", f"drawing {row[0]} job {row[1]}")
    real = uploads.resolve(s.files_dir, principal.company_id, row[3])
    if real is None:
        log.error("drawing path outside its company folder: drawing %s company %s", row[0],
                  principal.company_id)
    else:
        uploads.remove_quietly(real, "drawing file", f"drawing {row[0]}")
    return _redirect(f"/jobs/{ref}")
