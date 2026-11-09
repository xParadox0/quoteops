"""Stage 1 fix 4: /healthz does not disclose internals, plus exhaustive privilege and input tests."""
import logging
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psycopg
import pytest
import yaml

from tests.test_app import _client

COMPOSE = Path(__file__).resolve().parent.parent / "deploy" / "compose.yaml"


# 1. healthz -----------------------------------------------------------------------------------

def test_healthz_503_body_is_constant_and_failure_is_logged(db, monkeypatch, caplog):
    caplog.set_level(logging.ERROR, logger="quoteops")
    r = _client(monkeypatch, db, port="1").get("/healthz")
    assert r.status_code == 503
    assert r.json() == {"detail": "database check failed"}
    assert "Error" not in r.text and "OperationalError" not in r.text
    records = [x for x in caplog.records if x.name == "quoteops" and x.levelno == logging.ERROR]
    assert records, "the failure must be logged at error level on the quoteops logger"
    assert any("OperationalError" in x.getMessage() for x in records)
    assert not any("127.0.0.1" in x.getMessage() for x in records)


# 2. qo_admin matrix ---------------------------------------------------------------------------

APP_USER_READABLE = {"id", "company_id", "email", "role", "email_verified_at", "disabled_at",
                     "consent_version", "consent_at"}
FULL_READ = {"company", "audit_event", "support_grant", "company_usage"}


def test_qo_admin_privilege_matrix_is_exact(db):
    with db.connect() as c:
        rows = c.execute(
            "SELECT cl.relname, a.attname FROM pg_class cl"
            " JOIN pg_namespace n ON n.oid = cl.relnamespace"
            " JOIN information_schema.columns ic ON ic.table_schema = n.nspname"
            "   AND ic.table_name = cl.relname"
            " JOIN pg_attribute a ON a.attrelid = cl.oid AND a.attname = ic.column_name"
            " WHERE n.nspname = 'public' AND cl.relkind IN ('r', 'v', 'p')"
            "   AND cl.relname NOT LIKE 'pg\\_%' ORDER BY 1, 2").fetchall()
        assert rows
        tables = sorted({t for t, _ in rows})
        assert FULL_READ | {"app_user", "session", "invite", "job"} <= set(tables)
        readable, problems = set(), []
        for t, col in rows:
            for priv in ("INSERT", "UPDATE", "REFERENCES"):
                if c.execute("SELECT has_column_privilege('qo_admin', %s, %s, %s)",
                             (f"public.{t}", col, priv)).fetchone()[0]:
                    problems.append((t, col, priv))
            if c.execute("SELECT has_column_privilege('qo_admin', %s, %s, 'SELECT')",
                         (f"public.{t}", col)).fetchone()[0]:
                readable.add((t, col))
        for t in tables:
            for priv in ("DELETE", "TRUNCATE", "TRIGGER"):
                if c.execute("SELECT has_table_privilege('qo_admin', %s, %s)",
                             (f"public.{t}", priv)).fetchone()[0]:
                    problems.append((t, None, priv))
        assert problems == []
        expected = {(t, col) for t, col in rows if t in FULL_READ}
        expected |= {("app_user", col) for col in APP_USER_READABLE}
        assert readable == expected
        usage_cols = {col for t, col in rows if t == "company_usage"}
        assert usage_cols == {"company_id", "status", "created_at", "users", "jobs", "drawings",
                              "documents", "audit_events"}


# 3. qo_* functions with hostile input ---------------------------------------------------------

HOSTILE = ["'", "'; DROP TABLE session; --", "%", "%s%(x)s", "\\", "\\x00ff", "a" * 10000,
           "\u00e9\u4e2d\u6587\U0001f600\u202e"]
FUTURE = datetime.now(timezone.utc) + timedelta(hours=1)


def _session_count(db):
    with db.connect() as c:
        return c.execute("SELECT count(*) FROM session").fetchone()[0]


def test_lookups_return_no_rows_for_null_and_hostile_input(db):
    with db.connect("qo_web") as c:
        assert c.execute("SELECT * FROM qo_login_lookup(NULL)").fetchall() == []
        for fn in ("qo_session_lookup", "qo_invite_lookup"):
            assert c.execute(f"SELECT * FROM {fn}(NULL)").fetchall() == []
        for s in HOSTILE:
            assert c.execute("SELECT * FROM qo_login_lookup(%s)", (s,)).fetchall() == []
            for fn in ("qo_session_lookup", "qo_invite_lookup"):
                assert c.execute(f"SELECT * FROM {fn}(%s)", (s.encode("utf-8"),)).fetchall() == []


def test_session_delete_null_and_hostile_do_nothing(db):
    with db.connect() as c:
        uid = c.execute("SELECT id FROM app_user LIMIT 1").fetchone()[0]
    with db.connect("qo_web", autocommit=True) as c:
        c.execute("SELECT qo_session_create(%s, %s, %s, NULL)", (b"keep", uid, FUTURE))
    before = _session_count(db)
    with db.connect("qo_web", autocommit=True) as c:
        assert c.execute("SELECT qo_session_delete(NULL)").fetchone() == (None,)
        for s in HOSTILE:
            c.execute("SELECT qo_session_delete(%s)", (s.encode("utf-8"),))
    assert _session_count(db) == before == 1


def test_session_create_rejects_null_hash_and_null_or_unknown_user(db):
    with db.connect() as c:
        uid = c.execute("SELECT id FROM app_user LIMIT 1").fetchone()[0]
    before = _session_count(db)
    with db.connect("qo_web", autocommit=True) as c:
        with pytest.raises(psycopg.errors.NotNullViolation):
            c.execute("SELECT qo_session_create(NULL, %s, %s, NULL)", (uid, FUTURE))
        with pytest.raises(psycopg.errors.NotNullViolation):
            c.execute("SELECT qo_session_create(%s, NULL, %s, NULL)", (b"h", FUTURE))
        with pytest.raises(psycopg.errors.ForeignKeyViolation):
            c.execute("SELECT qo_session_create(%s, %s, %s, NULL)", (b"h", uuid.uuid4(), FUTURE))
    assert _session_count(db) == before


# 4. DDL as qo_web -----------------------------------------------------------------------------

def test_qo_web_cannot_create_a_table(db):
    with db.connect("qo_web", autocommit=True) as c:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute("CREATE TABLE evil(i int)")


# 5. compose environment separation ------------------------------------------------------------

def test_compose_environment_separation():
    services = yaml.safe_load(COMPOSE.read_text())["services"]
    web, dbs, migrate = (services[k] for k in ("web", "db", "migrate"))
    web_env, db_env, mig_env = set(web["environment"]), set(dbs["environment"]), set(migrate["environment"])
    assert "QO_WEB_PASSWORD" in web_env
    assert not web_env & {"QO_OWNER_PASSWORD", "QO_ADMIN_PASSWORD", "POSTGRES_PASSWORD"}
    assert "env_file" not in web
    assert "POSTGRES_PASSWORD" in db_env
    assert not db_env & {"QO_OWNER_PASSWORD", "QO_ADMIN_PASSWORD", "QO_WEB_PASSWORD"}
    assert {"QO_OWNER_PASSWORD", "QO_WEB_PASSWORD", "QO_ADMIN_PASSWORD"} <= mig_env
