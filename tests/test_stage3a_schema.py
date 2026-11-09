"""Stage 3a: the schema (job number series, drawing columns, CHECKs, the composite foreign key),
the minimal privileges of qo_web on job, drawing and audit_event, no new SECURITY DEFINER
function, the migration over the stage 2b database (snapshot of main at 848cb17), the files
volume in compose, the new settings, and the documents."""
import re
import uuid
from pathlib import Path

import psycopg
import pytest
import yaml

from tests.conftest import Db
from tests.stage2a_support import adb  # noqa: F401  (fixture)

ROOT = Path(__file__).resolve().parent.parent
SNAPSHOT = Path(__file__).resolve().parent / "data" / "schema_848cb17.sql"
PRIVS = ["SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"]
DEFINER_FUNCTIONS = {
    "qo_login_lookup", "qo_session_create", "qo_session_lookup", "qo_session_delete",
    "qo_invite_lookup", "qo_throttle_check", "qo_throttle_reset", "qo_company_count",
    "qo_session_delete_user", "qo_purge_unverified", "qo_admin_login_lookup", "qo_admin_totp_use",
    "qo_admin_session_create", "qo_admin_session_lookup", "qo_admin_session_delete",
    "qo_admin_session_delete_user"}
MIMES = ["application/pdf", "image/vnd.dxf", "image/png", "image/jpeg"]
STATUSES = ["draft", "review", "approved", "quoted", "won", "lost", "invoiced"]


def _privs(c, role, table):
    return {p for p in PRIVS
            if c.execute("SELECT has_table_privilege(%s, %s, %s)", (role, table, p)).fetchone()[0]}


def _seed(c):
    for cid in ("c_a", "c_b"):
        c.execute("INSERT INTO company (id, name, status) VALUES (%s, %s, 'active')", (cid, cid))
    uid = uuid.uuid4()
    c.execute("INSERT INTO app_user (id, company_id, email, pw_hash, pw_salt, role, consent_version,"
              " consent_at) VALUES (%s, 'c_a', 'o@a.test', '\\x00', '\\x00', 'owner', 'v', now())",
              (uid,))
    ja, jb = uuid.uuid4(), uuid.uuid4()
    for jid, cid in ((ja, "c_a"), (jb, "c_b")):
        c.execute("INSERT INTO job (id, company_id, ref, customer, part, qty, status, created_by)"
                  " VALUES (%s, %s, 'J-1001', 'c', 'p', 1, 'draft', %s)", (jid, cid, uid))
    return uid, ja, jb


def _drawing(c, cid, job, mime="application/pdf", nbytes=1):
    c.execute("INSERT INTO drawing (id, company_id, job_id, file_name, mime, bytes, sha256, path)"
              " VALUES (%s, %s, %s, 'a.pdf', %s, %s, '\\x00', %s)",
              (uuid.uuid4(), cid, job, mime, nbytes, f"{cid}/{'0' * 32}"))


# --- columns and constraints ----------------------------------------------------------------------

def test_the_new_columns(adb):
    with adb.connect() as c:
        cols = {(t, n): (dt, null, d) for t, n, dt, null, d in c.execute(
            "SELECT table_name, column_name, data_type, is_nullable, column_default"
            " FROM information_schema.columns WHERE table_schema = 'public'"
            " AND table_name IN ('company', 'drawing')")}
    assert cols[("company", "job_next")] == ("integer", "NO", "1001")
    assert cols[("drawing", "created_at")] == ("timestamp with time zone", "NO", "now()")
    assert cols[("drawing", "created_by")][:2] == ("uuid", "YES")


def test_refs_are_unique_per_company_only(adb):
    with adb.connect() as c:
        _, ja, _ = _seed(c)  # both companies have a J-1001
        with pytest.raises(psycopg.errors.UniqueViolation):
            c.execute("INSERT INTO job (id, company_id, ref, customer, part, qty, status,"
                      " created_by) VALUES (%s, 'c_a', 'J-1001', 'c', 'p', 1, 'draft', %s)",
                      (uuid.uuid4(), uuid.uuid4()))


def test_job_status_and_drawing_mime_are_checked(adb):
    with adb.connect(autocommit=True) as c:
        uid, ja, _ = _seed(c)
        for s in STATUSES:
            c.execute("INSERT INTO job (id, company_id, ref, customer, part, qty, status,"
                      " created_by) VALUES (%s, 'c_a', %s, 'c', 'p', 1, %s, %s)",
                      (uuid.uuid4(), f"J-{s}", s, uid))
        for bad in ("Draft", "deleted", "", "draft "):
            with pytest.raises(psycopg.errors.CheckViolation):
                c.execute("INSERT INTO job (id, company_id, ref, customer, part, qty, status,"
                          " created_by) VALUES (%s, 'c_a', 'J-x', 'c', 'p', 1, %s, %s)",
                          (uuid.uuid4(), bad, uid))
        for m in MIMES:
            _drawing(c, "c_a", ja, m)
        for bad in ("image/svg+xml", "text/html", "application/zip", "application/octet-stream",
                    "IMAGE/PNG"):
            with pytest.raises(psycopg.errors.CheckViolation):
                _drawing(c, "c_a", ja, bad)
        with pytest.raises(psycopg.errors.CheckViolation):
            _drawing(c, "c_a", ja, nbytes=0)
        with pytest.raises(psycopg.errors.CheckViolation):
            c.execute("UPDATE job SET status = 'gone' WHERE id = %s", (ja,))


def test_a_drawing_can_never_point_at_another_companys_job(adb):
    with adb.connect(autocommit=True) as c:  # the owner login, which row-level security does not bind
        _, ja, jb = _seed(c)
        _drawing(c, "c_a", ja)
        with pytest.raises(psycopg.errors.ForeignKeyViolation):
            _drawing(c, "c_b", ja)
        with pytest.raises(psycopg.errors.ForeignKeyViolation):
            c.execute("UPDATE drawing SET company_id = 'c_b' WHERE job_id = %s", (ja,))
        with pytest.raises(psycopg.errors.ForeignKeyViolation):
            c.execute("UPDATE drawing SET job_id = %s", (jb,))
    with adb.connect() as c:
        fks = [r[0] for r in c.execute("SELECT pg_get_constraintdef(oid) FROM pg_constraint"
                                       " WHERE conrelid = 'drawing'::regclass AND contype = 'f'")]
    assert "FOREIGN KEY (company_id, job_id) REFERENCES job(company_id, id) NOT VALID" in fks


@pytest.mark.parametrize("table", ["job", "drawing", "audit_event", "company"])
def test_rls_stays_forced_and_the_web_role_owns_nothing(adb, table):
    with adb.connect() as c:
        assert c.execute("SELECT relrowsecurity, relforcerowsecurity FROM pg_class"
                         " WHERE oid = %s::regclass", (table,)).fetchone() == (True, True)
        owner = c.execute("SELECT r.rolname FROM pg_class cl JOIN pg_roles r ON r.oid = cl.relowner"
                          " WHERE cl.oid = %s::regclass", (table,)).fetchone()[0]
        assert owner not in ("qo_web", "qo_admin", "qo_definer")
        assert c.execute("SELECT count(*) FROM pg_class WHERE relowner ="
                         " (SELECT oid FROM pg_roles WHERE rolname = 'qo_web')").fetchone()[0] == 0


# --- privileges -----------------------------------------------------------------------------------

def test_qo_web_has_the_minimum_on_job_drawing_and_audit_event(adb):
    with adb.connect() as c:
        assert _privs(c, "qo_web", "job") == {"SELECT", "INSERT", "UPDATE"}
        assert _privs(c, "qo_web", "drawing") == {"SELECT", "INSERT", "DELETE"}
        assert _privs(c, "qo_web", "audit_event") == {"INSERT"}
        assert c.execute("SELECT has_sequence_privilege('qo_web', 'audit_event_id_seq', 'USAGE')"
                         ).fetchone()[0]
        # The admin role gets nothing new: still no content, still only reading the trail.
        assert _privs(c, "qo_admin", "job") == _privs(c, "qo_admin", "drawing") == set()
        assert _privs(c, "qo_admin", "audit_event") == {"SELECT"}
        assert _privs(c, "qo_definer", "job") == _privs(c, "qo_definer", "drawing") == set()


def test_qo_web_can_append_to_the_audit_trail_but_not_read_or_rewrite_it(adb):
    with adb.connect() as c:
        c.execute("INSERT INTO company (id, name) VALUES ('c_a', 'A')")
    with adb.connect("qo_web") as c:
        c.execute("SELECT set_config('app.company_id', 'c_a', true)")
        c.execute("INSERT INTO audit_event (company_id, what, subject) VALUES ('c_a', 'x', 'y')")
    for stmt in ("SELECT count(*) FROM audit_event", "UPDATE audit_event SET what = 'z'",
                 "DELETE FROM audit_event",
                 "DELETE FROM job", "UPDATE drawing SET bytes = 2"):
        with adb.connect("qo_web") as c:
            c.execute("SELECT set_config('app.company_id', 'c_a', true)")
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                c.execute(stmt)
    with adb.connect() as c:
        assert c.execute("SELECT what FROM audit_event").fetchall() == [("x",)]


def test_no_new_security_definer_function(adb):
    with adb.connect() as c:
        names = {r[0] for r in c.execute("SELECT proname FROM pg_proc p JOIN pg_namespace n"
                                         " ON n.oid = p.pronamespace WHERE n.nspname = 'public'"
                                         " AND p.prosecdef")}
    assert names == DEFINER_FUNCTIONS


# --- the migration --------------------------------------------------------------------------------

def test_the_snapshot_is_the_schema_of_main():
    text = SNAPSHOT.read_text(encoding="ascii")
    assert "job_next" not in text and "drawing_mime_known" not in text
    assert "GRANT SELECT, INSERT, UPDATE, DELETE ON\n  company, app_user, invite, job, drawing" in text


def test_migration_applies_twice_and_over_a_stage2b_database(empty_db):
    with empty_db.connect(autocommit=True) as c:
        c.execute(SNAPSHOT.read_text(encoding="ascii"))
        assert c.execute("SELECT count(*) FROM information_schema.columns WHERE"
                         " table_name = 'company' AND column_name = 'job_next'").fetchone()[0] == 0
        uid, ja, jb = _seed(c)
        _drawing(c, "c_a", ja)
        c.execute("INSERT INTO audit_event (company_id, actor, what, subject)"
                  " VALUES ('c_a', %s, 'user.role', 'x')", (uid,))
        before = {t: c.execute(f"SELECT count(*) FROM public.{t}").fetchone()[0]
                  for t in ("company", "app_user", "job", "drawing", "audit_event")}
    try:
        for _ in range(2):
            empty_db.migrate()
            with empty_db.connect() as c:
                after = {t: c.execute(f"SELECT count(*) FROM public.{t}").fetchone()[0]
                         for t in before}
                assert after == before
                assert c.execute("SELECT job_next FROM company ORDER BY id").fetchall() == [
                    (1001,), (1001,)]
                assert c.execute("SELECT created_at IS NOT NULL FROM drawing").fetchone() == (True,)
                cons = {r[0] for r in c.execute("SELECT conname FROM pg_constraint WHERE conrelid"
                                                " IN ('job'::regclass, 'drawing'::regclass)")}
                assert {"job_status_known", "drawing_mime_known", "drawing_bytes_positive",
                        "drawing_same_company_job"} <= cons
                idx = {r[0] for r in c.execute("SELECT indexname FROM pg_indexes"
                                               " WHERE tablename IN ('job', 'drawing')")}
                assert {"job_company_ref_key", "job_company_id_key"} <= idx
                assert _privs(c, "qo_web", "audit_event") == {"INSERT"}
                assert _privs(c, "qo_web", "job") == {"SELECT", "INSERT", "UPDATE"}
                assert c.execute("SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON"
                                 " n.oid = p.pronamespace WHERE n.nspname = 'public'"
                                 " AND p.prosecdef").fetchone()[0] == len(DEFINER_FUNCTIONS)
            with empty_db.connect("qo_web") as c:
                c.execute("SELECT set_config('app.company_id', 'c_a', true)")
                assert c.execute("SELECT count(*) FROM job").fetchone()[0] == 1
                assert c.execute("SELECT count(*) FROM drawing").fetchone()[0] == 1
    finally:
        with Db(empty_db.port, "postgres").connect(autocommit=True) as c:
            c.execute(f'DROP DATABASE IF EXISTS "{empty_db.dbname}" WITH (FORCE)')


# --- compose and the image ------------------------------------------------------------------------

def _compose():
    return yaml.safe_load((ROOT / "deploy" / "compose.yaml").read_text(encoding="ascii"))


def test_only_web_mounts_the_files_volume_and_stays_read_only():
    doc = _compose()
    services = doc["services"]
    web = services["web"]
    assert web["volumes"] == ["qofiles:/var/qo-files"]
    assert web["read_only"] is True
    assert "/var/qo-files" not in " ".join(str(t) for t in web["tmpfs"])
    for name in ("admin", "migrate", "db"):
        assert "/var/qo-files" not in str(services[name]), name
        assert "qofiles" not in str(services[name]), name
    assert services["admin"]["read_only"] is True and services["migrate"]["read_only"] is True
    assert doc["volumes"] == {"dbdata": {}, "qofiles": {}}


def test_web_gets_the_upload_settings():
    env = _compose()["services"]["web"]["environment"]
    assert env["QO_FILES_DIR"] == "/var/qo-files"
    assert env["QO_MAX_FILE_MB"] == "${QO_MAX_FILE_MB:-25}"
    assert env["QO_MAX_COMPANY_MB"] == "${QO_MAX_COMPANY_MB:-500}"
    assert env["QO_MAX_JOBS_PER_MONTH"] == "${QO_MAX_JOBS_PER_MONTH:-50}"
    for name in ("admin", "migrate"):
        other = _compose()["services"][name]["environment"]
        assert not [k for k in other if k.startswith(("QO_MAX_FILE", "QO_MAX_COMPANY_MB",
                                                      "QO_MAX_JOBS", "QO_FILES"))]


def test_the_image_creates_the_files_folder_for_the_container_user():
    text = (ROOT / "Dockerfile").read_text(encoding="ascii")
    assert "install -d -m 0700 -o 10001 -g 10001 /var/qo-files" in text
    assert "USER 10001" in text


# --- settings -------------------------------------------------------------------------------------

@pytest.fixture
def clean(monkeypatch):
    for k in ("QO_MAX_FILE_MB", "QO_MAX_COMPANY_MB", "QO_MAX_JOBS_PER_MONTH", "QO_FILES_DIR",
              "QO_MAIL", "QO_SCRYPT_CONCURRENCY", "QO_SCRYPT_WAIT_SECONDS"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("QO_SECRET", "s" * 40)
    monkeypatch.setenv("QO_BASE_URL", "https://qo.example")
    return monkeypatch


def test_upload_settings_defaults(clean):
    from quoteops import config
    s = config.load_settings()
    assert (s.max_file_mb, s.max_company_mb, s.max_jobs_per_month, s.files_dir) == (
        25, 500, 50, "/var/qo-files")
    assert config.max_file_bytes() == 25 * 1024 * 1024


@pytest.mark.parametrize("name,value,text", [
    ("QO_MAX_FILE_MB", "0", "QO_MAX_FILE_MB must be at least 1"),
    ("QO_MAX_FILE_MB", "201", "QO_MAX_FILE_MB must be at most 200"),
    ("QO_MAX_FILE_MB", "2.5", "QO_MAX_FILE_MB must be a whole number"),
    ("QO_MAX_FILE_MB", "x", "QO_MAX_FILE_MB must be a whole number"),
    ("QO_MAX_COMPANY_MB", "0", "QO_MAX_COMPANY_MB must be at least 1"),
    ("QO_MAX_COMPANY_MB", "100001", "QO_MAX_COMPANY_MB must be at most 100000"),
    ("QO_MAX_JOBS_PER_MONTH", "0", "QO_MAX_JOBS_PER_MONTH must be at least 1"),
    ("QO_MAX_JOBS_PER_MONTH", "100001", "QO_MAX_JOBS_PER_MONTH must be at most 100000"),
    ("QO_MAX_JOBS_PER_MONTH", "-3", "QO_MAX_JOBS_PER_MONTH must be at least 1"),
    ("QO_FILES_DIR", "relative/files", "QO_FILES_DIR must be an absolute path"),
])
def test_upload_settings_are_validated(clean, name, value, text):
    from quoteops import config
    clean.setenv(name, value)
    with pytest.raises(config.ConfigError) as exc:
        config.load_settings()
    assert str(exc.value).startswith(text)
    assert value not in str(exc.value) or value in ("0",)


@pytest.mark.parametrize("name,value,field,expected", [
    ("QO_MAX_FILE_MB", "1", "max_file_mb", 1), ("QO_MAX_FILE_MB", "200", "max_file_mb", 200),
    ("QO_MAX_COMPANY_MB", "1", "max_company_mb", 1),
    ("QO_MAX_COMPANY_MB", "100000", "max_company_mb", 100000),
    ("QO_MAX_JOBS_PER_MONTH", "100000", "max_jobs_per_month", 100000),
    ("QO_FILES_DIR", "/srv/files/", "files_dir", "/srv/files"),
])
def test_upload_settings_accept_their_bounds(clean, name, value, field, expected):
    from quoteops import config
    clean.setenv(name, value)
    assert getattr(config.load_settings(), field) == expected


# --- documents ------------------------------------------------------------------------------------

def test_the_hld_has_the_stage_3a_section():
    hld = (ROOT / "docs" / "HLD.md").read_text(encoding="utf-8")
    head = "## 13. Stage 3a: jobs and drawing upload"
    assert head in hld
    text = hld.split(head, 1)[1]
    for needle in ("ROUTE_BODY_LIMITS", "/jobs/upload", "16384", "X-CSRF-Token", "csrf",
                   "Connection: close", "advisory lock", "/var/qo-files", "qofiles",
                   "25 MB", "50 MB", "1048576", "UTC", "J-1001", "job_next", "sandbox",
                   "nosniff", "realpath", "orphan", "Accepted limits", "Not checked",
                   "Cloudflare", "100 MB", "tracemalloc", "permissions.py", "MAX_PARALLEL",
                   "30 seconds", "one hour", "503", "Retry-After"):
        assert needle in text, needle
    assert "there is deliberately no exemption mechanism until then" not in hld
    row = re.search(r"^\| 3a \|.*$", hld, re.M)
    assert row and "drawing upload" in row.group(0)


def test_the_hld_states_the_minimum_upload_rate_and_its_residual_limit():
    hld = (ROOT / "docs" / "HLD.md").read_text(encoding="utf-8")
    text = hld.split("## 13. Stage 3a: jobs and drawing upload", 1)[1]
    for needle in ("RATE_GRACE_SECONDS", "MIN_BYTES_PER_SECOND", "10 seconds", "64 KiB/s",
                   "burst-and-drip bound", "too slowly", "per-IP throttle",
                   "20 verified companies"):
        assert needle in text, needle
    assert "can hold an upload slot for a long time" not in text
    assert "Two such clients make every other upload answer 503 until they end" not in text


def test_the_readme_names_the_volume_and_the_settings():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for needle in ("qofiles", "/var/qo-files", "QO_MAX_FILE_MB", "QO_MAX_COMPANY_MB",
                   "QO_MAX_JOBS_PER_MONTH", "down -v"):
        assert needle in readme, needle
