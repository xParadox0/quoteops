"""Stage 3a: jobs and drawings (PRD F8, parts of F17; HLD section 13). The permission table for
every job route and role, company A against company B on every route, inactive companies, the
quotas with their exact boundaries and under parallel requests, the job fields, editing,
deleting, the audit trail, the logs, and every page escaping what users typed."""
import logging
import os
import re
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from tests.stage2a_support import adb, env  # noqa: F401  (fixtures)
from tests.stage3a_support import (  # noqa: F401  (jenv is a fixture)
    DXF, EDITORS, FIELDS, JPEG, MB, PDF, PNG, READERS, ROLES, add, company, create, created_ref,
    form, jenv, post_upload, stored_files, tmp_files, tree,
)

PAST = "This date has passed. Pick today or a later date."
NOT_FOUND = "There is no page at this address."
ROLE_TEXT = "Your role can see jobs but not change them."
HOSTILE = "<img src=x onerror=alert(1)>"
HOSTILE_FILE = '"><script>alert(1).pdf'


def _mod(name):
    import importlib
    return importlib.import_module(f"quoteops.{name}")


def state(env):
    """Everything a job route may change, and the files."""
    with env.owner() as c:
        return (c.execute("SELECT id, company_id, ref, customer, part, qty, material, due_date,"
                          " status FROM job ORDER BY company_id, ref").fetchall(),
                c.execute("SELECT id, company_id, job_id, file_name, mime, bytes, sha256, path"
                          " FROM drawing ORDER BY id").fetchall(),
                c.execute("SELECT count(*) FROM audit_event").fetchone()[0],
                c.execute("SELECT id, job_next, status FROM company ORDER BY id").fetchall(),
                tree(env.files))


def drawing_id(env, ref, cid="c_a"):
    with env.owner() as c:
        row = c.execute("SELECT d.id FROM drawing d JOIN job j ON j.id = d.job_id"
                        " WHERE j.ref = %s AND j.company_id = %s ORDER BY d.created_at LIMIT 1",
                        (ref, cid)).fetchone()
    return row[0] if row else None


@pytest.fixture
def two(jenv):
    """Company A with one job J-1001 and its drawing, and company B; both active, all roles."""
    a, b = company(jenv, "c_a"), company(jenv, "c_b")
    ref = created_ref(create(a["owner"]))
    assert ref == "J-1001"
    return a, b, ref, drawing_id(jenv, ref)


# --- the permission table -------------------------------------------------------------------------

def test_the_permission_table_is_one_dict_with_exactly_these_actions():
    p = _mod("permissions")
    assert p.ACTIONS == {
        "view_jobs": ("owner", "estimator", "accountant", "viewer"),
        "create_job": ("owner", "estimator"),
        "edit_job": ("owner", "estimator"),
        "upload_drawing": ("owner", "estimator"),
        "delete_drawing": ("owner", "estimator"),
    }
    for later in ("confirm_value", "approve_price", "set_rates"):
        assert later not in p.ACTIONS
    with pytest.raises(KeyError):
        p.require("approve_price")


def test_every_job_route_uses_the_permission_dependency():
    from quoteops import auth, jobs, team
    found = {}
    for other in (auth.router, team.router):  # no job route lives anywhere else
        assert not [r for r in other.routes if r.path.startswith("/jobs")]
    for r in jobs.router.routes:
        if r.path.startswith("/jobs"):
            calls = [d.call for d in r.dependant.dependencies]
            names = [getattr(c, "__qualname__", "") for c in calls]
            found[(r.path, tuple(sorted(r.methods)))] = names
            assert any(n == "require.<locals>.dependency" and c.__module__ == "quoteops.permissions"
                       for n, c in zip(names, calls)), r.path
    assert set(found) == {
        ("/jobs", ("GET",)), ("/jobs/new", ("GET",)), ("/jobs/upload", ("POST",)),
        ("/jobs/{ref}", ("GET",)), ("/jobs/{ref}", ("POST",)),
        ("/jobs/{ref}/drawings/{drawing}", ("GET",)),
        ("/jobs/{ref}/drawings/{drawing}/delete", ("POST",))}


def _routes(ref, did):
    """(name, method, path, data or None, multipart body maker or None)."""
    return [
        ("list", "GET", "/jobs", None),
        ("new form", "GET", "/jobs/new", None),
        ("view", "GET", f"/jobs/{ref}", None),
        ("edit", "POST", f"/jobs/{ref}", "edit"),
        ("create", "POST", "/jobs/upload", "create"),
        ("upload", "POST", f"/jobs/upload?job={ref}", "upload"),
        ("download", "GET", f"/jobs/{ref}/drawings/{did}", None),
        ("delete", "POST", f"/jobs/{ref}/drawings/{did}/delete", "delete"),
    ]


def _send(user, method, path, kind):
    if method == "GET":
        return user.client.get(path)
    if kind == "edit":
        return user.client.post(path, data={"csrf": user.csrf, **{**FIELDS, "qty": "7"}})
    if kind == "delete":
        return user.client.post(path, data={"csrf": user.csrf})
    job = path.split("job=", 1)[1] if "job=" in path else None
    return post_upload(user.client, form(user.csrf, PNG, "extra.png",
                                         fields={} if job else FIELDS), job=job)


WRITES = {"new form", "edit", "create", "upload", "delete"}
EXPECT_OK = {"list": 200, "new form": 200, "view": 200, "edit": 303, "create": 303,
             "upload": 303, "download": 200, "delete": 303}


@pytest.mark.parametrize("route", [r[0] for r in _routes("J-1", "x")])
def test_permission_table_for_every_role_on_every_route(jenv, two, route):
    a, _, ref, did = two
    name, method, path, kind = next(r for r in _routes(ref, did) if r[0] == route)
    # Readers first: they must change nothing.
    for role in READERS:
        before = state(jenv)
        r = _send(a[role], method, path, kind)
        if name in WRITES:
            assert r.status_code == 403, (role, name, r.status_code)
            assert ROLE_TEXT in r.text
            assert state(jenv) == before, (role, name)
        else:
            assert r.status_code == 200, (role, name, r.status_code)
    for role in EDITORS:
        r = _send(a[role], method, path, kind)
        assert r.status_code == EXPECT_OK[name], (role, name, r.status_code, r.text[:500])
        if name == "delete":  # the drawing is gone now; give the next editor a new one
            assert drawing_id(jenv, ref) is None
            add(a["owner"], ref, PDF, "again.pdf")
            did = drawing_id(jenv, ref)
            path = f"/jobs/{ref}/drawings/{did}/delete"


@pytest.mark.parametrize("route", [r[0] for r in _routes("J-1", "x")])
def test_every_job_route_redirects_without_a_session(jenv, two, route):
    _, _, ref, did = two
    name, method, path, kind = next(r for r in _routes(ref, did) if r[0] == route)
    before = state(jenv)
    anon = jenv.client()
    if method == "GET":
        r = anon.get(path)
    elif kind in ("create", "upload"):
        r = post_upload(anon, form("x", PDF), job=ref if kind == "upload" else None)
    else:
        r = anon.post(path, data={"csrf": "x", **FIELDS})
    assert r.status_code == 303 and r.headers["location"] == "/login", name
    assert state(jenv) == before


# --- company A against company B ------------------------------------------------------------------

def test_company_b_cannot_see_a_job_of_company_a_in_the_list(jenv, two):
    a, b, ref, _ = two
    page = b["owner"].client.get("/jobs")
    assert page.status_code == 200
    assert FIELDS["customer"] not in page.text and ref not in page.text
    assert "No jobs yet." in page.text
    assert FIELDS["customer"] in a["viewer"].client.get("/jobs").text


@pytest.mark.parametrize("role", ROLES)
def test_company_b_gets_404_on_every_route_of_company_a_and_nothing_changes(jenv, two, role):
    a, b, ref, did = two
    user = b[role]
    before = state(jenv)
    pages = []
    for name, method, path, kind in _routes(ref, did):
        if name in ("list", "new form", "create"):
            continue
        r = _send(user, method, path, kind)
        if role in READERS and name in WRITES:
            assert r.status_code == 403, (role, name)
        else:
            assert r.status_code == 404, (role, name, r.status_code)
            pages.append(r.content)
        assert state(jenv) == before, (role, name)
    assert len(set(pages)) == 1  # the same 404 page every time


def test_company_b_creates_its_own_j1001_and_a_is_untouched(jenv, two):
    a, b, ref, did = two
    a_rows = [r for r in state(jenv)[0] if r[1] == "c_a"]
    a_files = stored_files(jenv.files, "c_a")
    assert created_ref(create(b["estimator"], PNG, "b.png")) == "J-1001"
    assert [r for r in state(jenv)[0] if r[1] == "c_a"] == a_rows
    assert stored_files(jenv.files, "c_a") == a_files
    assert len(stored_files(jenv.files, "c_b")) == 1
    # B's J-1001 is B's: adding a drawing goes to B's job, and A's drawing id under B's ref is 404.
    assert add(b["owner"], "J-1001", DXF, "b.dxf").status_code == 303
    assert jenv.scalar("SELECT count(*) FROM drawing WHERE company_id = 'c_a'") == 1
    assert jenv.scalar("SELECT count(*) FROM drawing WHERE company_id = 'c_b'") == 2
    for path in (f"/jobs/J-1001/drawings/{did}", f"/jobs/J-1001/drawings/{did}/delete"):
        r = (b["owner"].client.get(path) if not path.endswith("delete")
             else b["owner"].client.post(path, data={"csrf": b["owner"].csrf}))
        assert r.status_code == 404
    assert stored_files(jenv.files, "c_a") == a_files
    a_page = a["owner"].client.get(f"/jobs/{ref}").text
    assert "b.dxf" not in a_page and "b.png" not in a_page


def test_upload_to_a_job_of_another_company_reads_no_body_and_writes_no_file(jenv, two):
    _, b, ref, _ = two
    from tests.stage3a_support import asgi, upload_headers
    out = asgi("POST", "/jobs/upload", [form(b["owner"].csrf, PDF, fields={})],
               headers=upload_headers(b["owner"]), query=f"job={ref}")
    assert out.status == 404 and out.receives == 0
    assert out.headers["connection"] == ["close"]
    assert not (jenv.files / "c_b").exists() or not tmp_files(jenv.files)


@pytest.mark.parametrize("bad", ["not-a-uuid", str(uuid.uuid4()), "../../etc/passwd", "1"])
def test_download_of_unknown_or_malformed_ids_is_the_same_404(jenv, two, bad):
    a, _, ref, did = two
    r = a["owner"].client.get(f"/jobs/{ref}/drawings/{bad}")
    ref404 = a["owner"].client.get(f"/jobs/J-9999/drawings/{did}")
    assert r.status_code == ref404.status_code == 404
    assert r.content == ref404.content and NOT_FOUND in r.text


# --- inactive companies and users -----------------------------------------------------------------

@pytest.mark.parametrize("status", ["unverified", "suspended", "deleting"])
def test_an_inactive_company_is_refused_on_every_route(jenv, two, status):
    a, _, ref, did = two
    with jenv.owner() as c:
        c.execute("UPDATE company SET status = %s WHERE id = 'c_a'", (status,))
    before = state(jenv)
    for role in EDITORS:
        for name, method, path, kind in _routes(ref, did):
            r = _send(a[role], method, path, kind)
            if status == "unverified":
                assert r.status_code == 403, (name, r.status_code)
                assert "not active" in r.text
            else:  # the session lookup refuses a suspended or deleting company outright
                assert r.status_code == 303 and r.headers["location"] == "/login", name
            assert state(jenv) == before, name
    assert not tmp_files(jenv.files)


def test_a_user_whose_address_is_not_verified_is_refused(jenv, two):
    a, _, ref, did = two
    with jenv.owner() as c:
        c.execute("UPDATE app_user SET email_verified_at = NULL WHERE id = %s",
                  (a["estimator"].id,))
    before = state(jenv)
    for name, method, path, kind in _routes(ref, did):
        r = _send(a["estimator"], method, path, kind)
        assert r.status_code == 403 and "Verify your email" in r.text, name
    assert state(jenv) == before


def test_a_company_suspended_between_the_check_and_the_store_stores_nothing(jenv, monkeypatch):
    a = company(jenv, "c_a")
    jobs = _mod("jobs")
    real = jobs._jobs_this_month

    def suspend_then_count(conn):
        with jenv.owner() as c:  # another session suspends the company meanwhile
            c.execute("UPDATE company SET status = 'unverified' WHERE id = 'c_a'")
        return real(conn)
    monkeypatch.setattr(jobs, "_lock", lambda conn, cid: (suspend_then_count(conn), None)[1])
    r = create(a["owner"])
    assert r.status_code == 403 and "not active" in r.text
    assert jenv.scalar("SELECT count(*) FROM job") == 0
    assert stored_files(jenv.files, "c_a") == [] and not tmp_files(jenv.files)


# --- job references -------------------------------------------------------------------------------

def test_refs_count_up_from_1001_per_company(jenv):
    a, b = company(jenv, "c_a"), company(jenv, "c_b")
    assert [created_ref(create(a["owner"])) for _ in range(3)] == ["J-1001", "J-1002", "J-1003"]
    assert created_ref(create(b["owner"])) == "J-1001"
    assert jenv.scalar("SELECT job_next FROM company WHERE id = 'c_a'") == 1004


def _no_company_slot(monkeypatch):
    """Parallel requests of one company pass the in-process company slot, so the database lock
    is what is tested."""
    up = _mod("uploads")
    monkeypatch.setattr(up, "_claim", lambda cid: True)
    monkeypatch.setattr(up, "_release", lambda cid: None)


def _slow(monkeypatch, name, seconds=0.6):
    jobs = _mod("jobs")
    real = getattr(jobs, name)

    def slow(conn):
        value = real(conn)
        time.sleep(seconds)  # widen the window between the check and the insert
        return value
    monkeypatch.setattr(jobs, name, slow)


def _parallel(*calls):
    out, gate = [None] * len(calls), threading.Barrier(len(calls))

    def run(i, fn):
        gate.wait()
        out[i] = fn()
    threads = [threading.Thread(target=run, args=(i, fn)) for i, fn in enumerate(calls)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(60)
    return out


def test_two_parallel_creations_get_different_refs(jenv, monkeypatch):
    a = company(jenv, "c_a")
    _no_company_slot(monkeypatch)
    _slow(monkeypatch, "_company_bytes", 0.3)
    r1, r2 = _parallel(lambda: create(a["owner"]), lambda: create(a["estimator"], PNG, "x.png"))
    assert sorted([created_ref(r1), created_ref(r2)]) == ["J-1001", "J-1002"]


# --- quotas ---------------------------------------------------------------------------------------

def test_jobs_per_month_boundary(jenv, monkeypatch):
    monkeypatch.setenv("QO_MAX_JOBS_PER_MONTH", "2")
    a = company(jenv, "c_a")
    created_ref(create(a["owner"]))
    created_ref(create(a["owner"]))
    before = state(jenv)
    r = create(a["owner"], fields={**FIELDS, "customer": "Typed Customer"})
    assert r.status_code == 403
    assert "created 2 jobs this month, the limit" in r.text and "Nothing was stored" in r.text
    assert 'value="Typed Customer"' in r.text  # the typed fields are kept
    assert state(jenv) == before and not tmp_files(jenv.files)
    # Adding a drawing to an existing job is not a new job.
    assert add(a["owner"], "J-1001").status_code == 303
    # A job of last month does not count.
    with jenv.owner() as c:
        c.execute("UPDATE job SET created_at = date_trunc('month', now(), 'UTC')"
                  " - interval '1 second' WHERE ref = 'J-1001'")
    assert created_ref(create(a["owner"])) == "J-1003"


def test_parallel_creation_at_the_last_allowed_job(jenv, monkeypatch):
    monkeypatch.setenv("QO_MAX_JOBS_PER_MONTH", "2")
    a = company(jenv, "c_a")
    created_ref(create(a["owner"]))
    _no_company_slot(monkeypatch)
    _slow(monkeypatch, "_jobs_this_month")
    r1, r2 = _parallel(lambda: create(a["owner"]), lambda: create(a["estimator"], PNG, "x.png"))
    assert sorted([r1.status_code, r2.status_code]) == [303, 403]
    assert jenv.scalar("SELECT count(*) FROM job") == 2
    assert len(stored_files(jenv.files, "c_a")) == 2 and not tmp_files(jenv.files)


def _pdf_of(size: int) -> bytes:
    return (PDF + b"%" * size)[:size]


def test_company_bytes_boundary(jenv, monkeypatch):
    monkeypatch.setenv("QO_MAX_COMPANY_MB", "1")
    monkeypatch.setenv("QO_MAX_FILE_MB", "1")
    a = company(jenv, "c_a")
    ref = created_ref(create(a["owner"], _pdf_of(MB // 2)))
    assert add(a["owner"], ref, _pdf_of(MB // 2)).status_code == 303  # exactly the limit in total
    before = state(jenv)
    r = add(a["owner"], ref, _pdf_of(len(PDF) + 1))
    assert r.status_code == 403
    assert "used 1 MB of its 1 MB for drawings" in r.text and "Delete drawings" in r.text
    assert state(jenv) == before and not tmp_files(jenv.files)
    # Deleting a drawing frees its bytes.
    did = drawing_id(jenv, ref)
    assert a["owner"].client.post(f"/jobs/{ref}/drawings/{did}/delete",
                                  data={"csrf": a["owner"].csrf}).status_code == 303
    assert add(a["owner"], ref, _pdf_of(MB // 2)).status_code == 303


def test_one_file_of_exactly_the_company_limit_passes_and_one_byte_more_is_refused(jenv, monkeypatch):
    monkeypatch.setenv("QO_MAX_COMPANY_MB", "1")
    monkeypatch.setenv("QO_MAX_FILE_MB", "2")
    a = company(jenv, "c_a")
    r = create(a["owner"], _pdf_of(MB + 1))
    assert r.status_code == 403 and "Nothing was stored" in r.text
    assert jenv.scalar("SELECT count(*) FROM job") == 0
    assert created_ref(create(a["owner"], _pdf_of(MB))) == "J-1001"


@pytest.mark.parametrize("size,admitted", [(700 * 1024, 1), (MB // 2, 2)])
def test_parallel_uploads_at_the_last_megabyte_admit_exactly_the_free_amount(jenv, monkeypatch,
                                                                             size, admitted):
    monkeypatch.setenv("QO_MAX_COMPANY_MB", "2")
    a = company(jenv, "c_a")
    ref = created_ref(create(a["owner"], _pdf_of(MB)))  # 1 MB of 2 is free
    _no_company_slot(monkeypatch)
    _slow(monkeypatch, "_company_bytes")
    r1, r2 = _parallel(lambda: add(a["owner"], ref, _pdf_of(size)),
                       lambda: add(a["estimator"], ref, _pdf_of(size)))
    assert sorted([r1.status_code, r2.status_code]) == sorted([303] * admitted + [403] * (2 - admitted))
    total = jenv.scalar("SELECT sum(bytes) FROM drawing")
    assert total == MB + admitted * size <= 2 * MB
    assert len(stored_files(jenv.files, "c_a")) == 1 + admitted and not tmp_files(jenv.files)


# --- the job fields -------------------------------------------------------------------------------

def test_create_stores_the_fields_and_the_drawing(jenv):
    a = company(jenv, "c_a")
    fields = {"customer": "  PT Cahaya\u0301  ", "part": "Valve seat ring", "qty": "120",
              "material": "SUS304", "due": (datetime.now(timezone.utc).date()).isoformat()}
    ref = created_ref(create(a["estimator"], PNG, "Valve.PNG", fields=fields))
    with jenv.owner() as c:
        job = c.execute("SELECT customer, part, qty, material, due_date, status, created_by"
                        " FROM job").fetchone()
        d = c.execute("SELECT file_name, mime, bytes, sha256, path, created_by FROM drawing"
                      ).fetchone()
    assert job[:6] == ("PT Cahay\u00e1", "Valve seat ring", 120, "SUS304",
                       datetime.now(timezone.utc).date(), "draft")  # trimmed and NFC
    assert job[6] == d[5] == a["estimator"].id
    import hashlib
    assert d[:4] == ("Valve.PNG", "image/png", len(PNG), hashlib.sha256(PNG).digest())
    assert re.fullmatch(r"c_a/[0-9a-f]{32}", d[4])
    assert (jenv.files / d[4]).read_bytes() == PNG
    assert ref == "J-1001"


@pytest.mark.parametrize("field,value,text", [
    ("customer", "", "Enter the customer."),
    ("customer", "   ", "Enter the customer."),
    ("customer", "x" * 121, "at most 120 characters"),
    ("customer", "A\x07B", "cannot be shown"),
    ("customer", "A\u202eB", "cannot be shown"),
    ("part", "", "Enter the part name."),
    ("part", "p" * 121, "at most 120 characters"),
    ("material", "m" * 101, "at most 100 characters"),
    ("qty", "0", "whole number from 1 to 1,000,000"),
    ("qty", "1000001", "whole number from 1 to 1,000,000"),
    ("qty", "1.5", "whole number"),
    ("qty", "+3", "whole number"),
    ("qty", "\u0663", "whole number"),
    ("qty", "", "whole number"),
    ("due", "2020-01-01", PAST),
    ("due", "yesterday", "Enter the due date as a date"),
    ("due", "2026-02-30", "Enter the due date as a date"),
])
def test_create_refuses_bad_fields_keeps_what_was_typed_and_stores_nothing(jenv, field, value, text):
    a = company(jenv, "c_a")
    fields = {**FIELDS, field: value}
    r = create(a["owner"], fields=fields)
    assert r.status_code == 400, r.text[:500]
    assert text in r.text
    if field != "customer":
        assert f'value="{FIELDS["customer"]}"' in r.text  # the other fields are kept
    assert jenv.scalar("SELECT count(*) FROM job") == 0
    assert stored_files(jenv.files, "c_a") == [] and not tmp_files(jenv.files)


def test_yesterday_in_utc_is_past_and_today_is_not(jenv):
    a = company(jenv, "c_a")
    today = datetime.now(timezone.utc).date()
    r = create(a["owner"], fields={**FIELDS, "due": (today - timedelta(days=1)).isoformat()})
    assert r.status_code == 400 and PAST in r.text
    assert created_ref(create(a["owner"], fields={**FIELDS, "due": today.isoformat()}))


def test_the_quantity_bounds_are_accepted(jenv):
    a = company(jenv, "c_a")
    for qty in ("1", "1000000", " 42 "):
        created_ref(create(a["owner"], fields={**FIELDS, "qty": qty}))
    assert sorted(r[0] for r in jenv.owner().execute("SELECT qty FROM job")) == [1, 42, 1000000]


def test_the_new_job_form_offers_up_to_20_customers_of_this_company_only(jenv):
    a, b = company(jenv, "c_a"), company(jenv, "c_b")
    with jenv.owner() as c:
        for i in range(25):
            c.execute("INSERT INTO job (id, company_id, ref, customer, part, qty, status,"
                      " created_by, created_at) VALUES (%s, 'c_a', %s, %s, 'p', 1, 'draft', %s,"
                      " now() - make_interval(mins => %s))",
                      (uuid.uuid4(), f"J-{i}", f"Customer {i:02d}", a["owner"].id, i))
        c.execute("INSERT INTO job (id, company_id, ref, customer, part, qty, status, created_by)"
                  " VALUES (%s, 'c_b', 'J-1', 'Secret B customer', 'p', 1, 'draft', %s)",
                  (uuid.uuid4(), b["owner"].id))
    page = a["owner"].client.get("/jobs/new").text
    options = re.findall(r'<option value="([^"]*)">', page)
    assert options == [f"Customer {i:02d}" for i in range(20)]  # the newest first
    assert "Secret B customer" not in page
    assert 'list="customers"' in page and '<datalist id="customers">' in page


# --- editing --------------------------------------------------------------------------------------

def test_edit_changes_the_fields_and_audits_their_names_only(jenv, two):
    a, _, ref, _ = two
    r = a["estimator"].client.post(f"/jobs/{ref}", data={
        "csrf": a["estimator"].csrf, **FIELDS, "customer": "New Customer Name", "qty": "9"})
    assert r.status_code == 303 and r.headers["location"] == f"/jobs/{ref}"
    with jenv.owner() as c:
        assert c.execute("SELECT customer, qty FROM job WHERE ref = %s", (ref,)).fetchone() == (
            "New Customer Name", 9)
        what, subject, actor = c.execute("SELECT what, subject, actor FROM audit_event"
                                         " ORDER BY id DESC LIMIT 1").fetchone()
    job_id = jenv.scalar("SELECT id FROM job WHERE ref = %s", (ref,))
    assert (what, subject, actor) == ("job.update", f"job {job_id} fields customer,qty",
                                      a["estimator"].id)
    # Nothing changed: no audit row.
    n = jenv.scalar("SELECT count(*) FROM audit_event")
    a["estimator"].client.post(f"/jobs/{ref}", data={
        "csrf": a["estimator"].csrf, **FIELDS, "customer": "New Customer Name", "qty": "9"})
    assert jenv.scalar("SELECT count(*) FROM audit_event") == n


def test_edit_may_keep_an_old_due_date_but_not_set_a_new_past_one(jenv, two):
    a, _, ref, _ = two
    with jenv.owner() as c:
        c.execute("UPDATE job SET due_date = '2025-03-01' WHERE ref = %s", (ref,))
    u = a["owner"]
    ok = u.client.post(f"/jobs/{ref}", data={"csrf": u.csrf, **FIELDS, "due": "2025-03-01",
                                             "part": "Renamed part"})
    assert ok.status_code == 303
    bad = u.client.post(f"/jobs/{ref}", data={"csrf": u.csrf, **FIELDS, "due": "2025-03-02"})
    assert bad.status_code == 400 and PAST in bad.text and "Nothing was changed" in bad.text
    assert str(jenv.scalar("SELECT due_date FROM job WHERE ref = %s", (ref,))) == "2025-03-01"
    assert jenv.scalar("SELECT part FROM job WHERE ref = %s", (ref,)) == "Renamed part"


def test_edit_needs_the_csrf_token_and_the_origin(jenv, two):
    a, b, ref, _ = two
    u = a["owner"]
    before = state(jenv)
    for data, headers in (({"csrf": "wrong", **FIELDS}, {}),
                          ({"csrf": b["owner"].csrf, **FIELDS}, {}),
                          ({**FIELDS}, {}),
                          ({"csrf": u.csrf, **FIELDS}, {"Origin": "https://evil.example"})):
        r = u.client.post(f"/jobs/{ref}", data={**data, "qty": "77"}, headers=headers)
        assert r.status_code == 403 and "Request refused" in r.text
    assert state(jenv) == before


def test_a_job_that_is_not_a_draft_cannot_be_changed(jenv, two):
    a, _, ref, did = two
    with jenv.owner() as c:
        c.execute("UPDATE job SET status = 'review' WHERE ref = %s", (ref,))
    before = state(jenv)
    u = a["owner"]
    assert u.client.post(f"/jobs/{ref}", data={"csrf": u.csrf, **FIELDS}).status_code == 409
    assert u.client.post(f"/jobs/{ref}/drawings/{did}/delete",
                         data={"csrf": u.csrf}).status_code == 409
    assert add(u, ref).status_code == 409
    assert state(jenv) == before
    page = u.client.get(f"/jobs/{ref}").text
    assert 'action="/jobs/upload' not in page and "/delete" not in page


# --- deleting -------------------------------------------------------------------------------------

def test_delete_removes_the_row_then_the_file_and_audits(jenv, two):
    a, _, ref, did = two
    path = jenv.scalar("SELECT path FROM drawing WHERE id = %s", (did,))
    assert (jenv.files / path).exists()
    r = a["estimator"].client.post(f"/jobs/{ref}/drawings/{did}/delete",
                                   data={"csrf": a["estimator"].csrf})
    assert r.status_code == 303 and r.headers["location"] == f"/jobs/{ref}"
    assert jenv.scalar("SELECT count(*) FROM drawing") == 0
    assert not (jenv.files / path).exists()
    with jenv.owner() as c:
        row = c.execute("SELECT what, subject FROM audit_event ORDER BY id DESC LIMIT 1").fetchone()
    job_id = jenv.scalar("SELECT id FROM job WHERE ref = %s", (ref,))
    assert row == ("drawing.delete", f"drawing {did} job {job_id}")


def test_delete_needs_the_csrf_token(jenv, two):
    a, b, ref, did = two
    before = state(jenv)
    for csrf in ("", "wrong", b["owner"].csrf, a["viewer"].csrf):
        r = a["owner"].client.post(f"/jobs/{ref}/drawings/{did}/delete", data={"csrf": csrf})
        assert r.status_code == 403
    assert state(jenv) == before


def test_a_failed_file_removal_is_logged_by_class_and_ids_and_leaves_an_orphan(jenv, two,
                                                                               monkeypatch, caplog):
    a, _, ref, did = two
    path = jenv.scalar("SELECT path FROM drawing WHERE id = %s", (did,))
    real_unlink = os.unlink

    def refuse(p, *args, **kw):
        if str(p).endswith(path.split("/")[1]):
            raise PermissionError("no")
        return real_unlink(p, *args, **kw)
    monkeypatch.setattr(os, "unlink", refuse)
    with caplog.at_level(logging.INFO, logger="quoteops"):
        r = a["owner"].client.post(f"/jobs/{ref}/drawings/{did}/delete",
                                   data={"csrf": a["owner"].csrf})
    assert r.status_code == 303
    assert jenv.scalar("SELECT count(*) FROM drawing") == 0
    assert (jenv.files / path).exists()  # the orphan nothing references
    lines = [x.getMessage() for x in caplog.records]
    assert any("PermissionError" in m and str(did) in m for m in lines), lines
    assert not any("part.pdf" in m or FIELDS["customer"] in m for m in lines)


# --- the audit trail and the logs -----------------------------------------------------------------

def test_create_and_upload_write_audit_rows_with_ids_and_field_names_only(jenv):
    a = company(jenv, "c_a")
    ref = created_ref(create(a["owner"], PDF, HOSTILE_FILE.replace('"', "'"),
                             fields={**FIELDS, "customer": HOSTILE}))
    add(a["owner"], ref, PNG, "second-secret-name.png")
    with jenv.owner() as c:
        rows = c.execute("SELECT company_id, actor, what, subject FROM audit_event ORDER BY id"
                         ).fetchall()
        job_id = c.execute("SELECT id FROM job").fetchone()[0]
        ids = [r[0] for r in c.execute("SELECT id FROM drawing ORDER BY created_at, id")]
    assert [r[2] for r in rows] == ["job.create", "drawing.upload", "drawing.upload"]
    assert rows[0][3] == f"job {job_id} fields customer,part,qty,material,due_date"
    assert {r[3] for r in rows[1:]} == {f"drawing {i} job {job_id}" for i in ids}
    assert all(r[0] == "c_a" and r[1] == a["owner"].id for r in rows)
    text = " ".join(str(v) for r in rows for v in r)
    for secret in (HOSTILE, "second-secret-name", "script", FIELDS["part"], "S45C"):
        assert secret not in text


def test_no_file_name_customer_text_or_content_reaches_the_log(jenv, monkeypatch, caplog):
    a = company(jenv, "c_a")
    monkeypatch.setenv("QO_MAX_FILE_MB", "1")
    names = ["Rahasia-Pelanggan.pdf", "Rahasia-Dua.png", "Rahasia-Tiga.pdf"]
    customer = "Rahasia Customer Name"
    with caplog.at_level(logging.DEBUG):
        created_ref(create(a["owner"], PDF, names[0], fields={**FIELDS, "customer": customer}))
        create(a["owner"], PDF, names[1], fields={**FIELDS, "customer": customer})  # mismatch
        create(a["owner"], b"%PDF-" + b"Rahasia" * (MB // 7 + 10), names[2],
               fields={**FIELDS, "customer": customer})  # too large
        create(a["owner"], b"<html>Rahasia</html>", "x.png", fields={**FIELDS, "customer": customer})
    text = " ".join(f"{x.getMessage()} {x.args!r}" for x in caplog.records)
    assert "Rahasia" not in text


# --- pages ----------------------------------------------------------------------------------------

def test_every_page_escapes_the_customer_and_the_file_name(jenv):
    a = company(jenv, "c_a")
    ref = created_ref(create(a["owner"], PDF, '\\"><script>alert(1).pdf',
                             fields={**FIELDS, "customer": HOSTILE, "part": HOSTILE,
                                     "material": HOSTILE}))
    did = drawing_id(jenv, ref)
    stored = jenv.scalar("SELECT file_name FROM drawing")
    assert stored == '"><script>alert(1).pdf'
    pages = [a["viewer"].client.get("/jobs"), a["owner"].client.get(f"/jobs/{ref}"),
             a["viewer"].client.get(f"/jobs/{ref}"), a["owner"].client.get("/jobs/new"),
             create(a["owner"], fields={**FIELDS, "customer": HOSTILE, "due": "2020-01-01"}),
             add(a["owner"], ref, PNG, '\\"><script>x</script>.pdf')]
    for r in pages:
        assert r.status_code in (200, 400), r.status_code
        assert HOSTILE not in r.text and "<script>" not in r.text.lower()
        assert "<script" not in r.text.lower()
    assert "&lt;img src=x onerror=alert(1)&gt;" in pages[0].text
    assert "&#34;&gt;&lt;script&gt;alert(1).pdf" in pages[1].text
    d = a["owner"].client.get(f"/jobs/{ref}/drawings/{did}")
    header = d.headers["content-disposition"]
    assert "<" not in header and '"><' not in header and "\r" not in header and "\n" not in header
    assert header == ("attachment; filename=\"___script_alert(1).pdf\";"
                      " filename*=UTF-8''%22%3E%3Cscript%3Ealert%281%29.pdf")


def test_the_pages_show_the_configured_limits(jenv, monkeypatch):
    monkeypatch.setenv("QO_MAX_FILE_MB", "7")
    monkeypatch.setenv("QO_MAX_COMPANY_MB", "300")
    monkeypatch.setenv("QO_MAX_JOBS_PER_MONTH", "12")
    a = company(jenv, "c_a")
    new = a["owner"].client.get("/jobs/new").text
    assert "PDF, DXF, PNG, JPG, one file, up to 7 MB." in new
    assert "50 MB" not in new and "25 MB" not in new
    assert "0 of 12 jobs this month" in new and "of 300 MB used" in new
    ref = created_ref(create(a["owner"]))
    listing = a["owner"].client.get("/jobs").text
    assert "1 of 12 jobs this month" in listing and "of 300 MB used" in listing
    assert "up to 7 MB" in a["owner"].client.get(f"/jobs/{ref}").text


def test_the_new_job_form_sends_the_token_first_and_the_file_last(jenv):
    a = company(jenv, "c_a")
    page = a["owner"].client.get("/jobs/new").text
    f = re.search(r'<form[^>]*action="/jobs/upload"[^>]*>(.*?)</form>', page, re.S)
    assert f and 'enctype="multipart/form-data"' in f.group(0)
    names = re.findall(r'name="([a-z]+)"', f.group(1))
    assert names[0] == "csrf" and names[-1] == "file"
    assert names == ["csrf", "customer", "part", "qty", "material", "due", "file"]
    assert re.search(r'<input id="file" name="file" type="file" required', page)
    for name in ("customer", "part", "qty"):
        assert re.search(rf'id="{name}" name="{name}"[^>]* required', page), name
    assert f'min="{datetime.now(timezone.utc).date().isoformat()}"' in page


def test_navigation_shows_only_what_works(jenv, two):
    a, _, ref, _ = two
    expected = {"owner": ["/jobs", "/jobs/new", "/team"], "estimator": ["/jobs", "/jobs/new"],
                "accountant": ["/jobs"], "viewer": ["/jobs"]}
    for role, links in expected.items():
        for path in ("/jobs", f"/jobs/{ref}", "/app"):
            page = a[role].client.get(path).text
            nav = re.search(r'<nav class="side"[^>]*>(.*?)</nav>', page, re.S).group(1)
            assert re.findall(r'href="([^"]+)"', nav) == links, (role, path)
            for dead in ("Overview", "Rates", "Company", "Roles"):
                assert dead not in nav
    assert 'href="/jobs"' in a["viewer"].client.get("/app").text
    assert "Jobs arrive in the next stage" not in a["viewer"].client.get("/app").text
    assert "/team" in re.search(r'<nav class="side"[^>]*>(.*?)</nav>',
                                a["owner"].client.get("/team").text, re.S).group(1)


def test_job_pages_have_no_script_and_every_input_has_a_label(jenv, two):
    a, _, ref, _ = two
    for path in ("/jobs", "/jobs/new", f"/jobs/{ref}"):
        page = a["owner"].client.get(path).text
        assert "<script" not in page.lower() and " style=" not in page and "<style" not in page
        assert not re.search(r'(src|href|action)="(https?:)?//', page)
        for tag in re.findall(r"<input[^>]*>", page):
            if 'type="hidden"' in tag:
                continue
            ident = re.search(r'\bid="([^"]+)"', tag)
            assert ident and f'<label for="{ident.group(1)}"' in page, (path, tag)


def test_the_job_page_lists_the_drawings_with_download_links(jenv, two):
    a, _, ref, did = two
    add(a["owner"], ref, DXF, "plan.DXF")
    page = a["viewer"].client.get(f"/jobs/{ref}").text
    assert f'href="/jobs/{ref}/drawings/{did}"' in page and "plan.DXF" in page
    assert "DXF" in page and "PDF" in page
    assert "/delete" not in page and 'action="/jobs/upload' not in page  # a viewer changes nothing
    owner_page = a["owner"].client.get(f"/jobs/{ref}").text
    assert f'action="/jobs/{ref}/drawings/{did}/delete"' in owner_page
    assert f'action="/jobs/upload?job={ref}"' in owner_page


# --- the download ---------------------------------------------------------------------------------

@pytest.mark.parametrize("kind", ["pdf", "png", "jpeg", "dxf"])
def test_download_is_an_attachment_of_octet_stream_with_the_safety_headers(jenv, kind):
    from tests.stage3a_support import SAMPLES
    a = company(jenv, "c_a")
    data, name, _ = SAMPLES[kind]
    ref = created_ref(create(a["owner"], data, name))
    did = drawing_id(jenv, ref)
    for role in ROLES:
        r = a[role].client.get(f"/jobs/{ref}/drawings/{did}")
        assert r.status_code == 200 and r.content == data
        h = r.headers
        assert h["content-type"] == "application/octet-stream"
        assert h["content-disposition"].startswith("attachment;")
        assert "inline" not in h["content-disposition"]
        assert h["x-content-type-options"] == "nosniff"
        assert h["cache-control"] == "no-store"
        assert "sandbox; default-src 'none'" in h.get_list("content-security-policy")
        assert h["content-length"] == str(len(data))


def test_a_stored_path_outside_the_company_folder_is_a_404_and_a_log_line(jenv, two, caplog):
    a, b, ref, did = two
    b_ref = created_ref(create(b["owner"], PNG, "b-secret.png"))
    b_path = jenv.scalar("SELECT path FROM drawing WHERE company_id = 'c_b'")
    outside = jenv.files.parent / "outside.txt"
    outside.write_bytes(b"outside")
    link = jenv.files / "c_a" / ("0" * 32)
    link.symlink_to(outside)
    for path in (b_path, f"c_a/../{b_path}", "../outside.txt", str(outside), "c_a/" + "0" * 32,
                 "c_a/.tmp/x", "c_a"):
        with jenv.owner() as c:
            c.execute("UPDATE drawing SET path = %s WHERE id = %s", (path, did))
        caplog.clear()
        with caplog.at_level(logging.INFO, logger="quoteops"):
            r = a["owner"].client.get(f"/jobs/{ref}/drawings/{did}")
        assert r.status_code == 404 and NOT_FOUND in r.text, path
        assert b"outside" not in r.content and PNG not in r.content
        lines = [x.getMessage() for x in caplog.records]
        assert any(str(did) in m for m in lines), (path, lines)
        assert not any("outside.txt" in m or "b-secret" in m or "part.pdf" in m for m in lines)
    assert b_ref == "J-1001"


def test_a_commit_that_fails_after_the_rename_removes_the_final_file(jenv, monkeypatch):
    """The rename is the last step inside the transaction; a commit failure after it (simulated
    by a deferred constraint) must leave no file behind."""
    a = company(jenv, "c_a")
    with jenv.owner() as c:
        c.execute("CREATE FUNCTION fail_later() RETURNS trigger LANGUAGE plpgsql AS"
                  " $$ BEGIN RAISE EXCEPTION 'commit refused'; END $$")
        c.execute("CREATE CONSTRAINT TRIGGER fail_on_commit AFTER INSERT ON drawing"
                  " DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION fail_later()")
    client = jenv.client(raise_server_exceptions=False)
    client.cookies.set("qo_session", a["owner"].token)
    r = post_upload(client, form(a["owner"].csrf, PDF))
    assert r.status_code == 500
    assert jenv.scalar("SELECT count(*) FROM job") == 0
    assert stored_files(jenv.files, "c_a") == [] and not tmp_files(jenv.files)


def test_company_b_usage_and_storage_quota_count_only_its_own_drawings(jenv, monkeypatch):
    """Every page hides A's drawings through the job join; the usage line and the storage
    quota read drawing alone, so they rely on the drawing table's own row-level security."""
    monkeypatch.setenv("QO_MAX_COMPANY_MB", "1")
    a, b = company(jenv, "c_a"), company(jenv, "c_b")
    created_ref(create(a["owner"], (PDF + b"%" * MB)[:MB]))  # A is full
    page = b["owner"].client.get("/jobs").text
    assert "0 MB of 1 MB used by drawings" in page
    assert "0 MB of 1 MB used" in b["owner"].client.get("/jobs/new").text
    assert created_ref(create(b["owner"], PDF)) == "J-1001"  # B's quota is untouched by A's


def test_a_create_refused_by_the_create_job_row_names_the_role_and_reads_no_body(jenv,
                                                                                 monkeypatch):
    from tests.stage3a_support import asgi, upload_headers
    p = _mod("permissions")
    monkeypatch.setitem(p.ACTIONS, "create_job", ("owner",))
    a = company(jenv, "c_a")
    out = asgi("POST", "/jobs/upload", [form(a["estimator"].csrf, PDF)],
               headers=upload_headers(a["estimator"]))
    assert out.status == 403 and out.receives == 0
    assert ROLE_TEXT.encode() in out.body and b"Request refused" not in out.body
    assert jenv.scalar("SELECT count(*) FROM job") == 0
