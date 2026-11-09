"""Stage 1 fix 3: applying the schema again over a database with data keeps the lookup functions
intact, a database still holding the pre-D6 qo_login_lookup is migrated, and a session whose
company row is missing does not resolve."""
import uuid

import pytest

from tests.conftest import Db

FUNCTIONS = {
    "qo_login_lookup": "qo_login_lookup(citext)",
    "qo_session_create": "qo_session_create(bytea, uuid, timestamptz, inet)",
    "qo_session_lookup": "qo_session_lookup(bytea)",
    "qo_session_delete": "qo_session_delete(bytea)",
    "qo_invite_lookup": "qo_invite_lookup(bytea)",
}
TABLES = ["company", "app_user", "session", "invite", "job", "drawing", "job_value", "rate",
          "cost_line", "document", "audit_event", "support_grant"]
LOGIN_COLUMNS = ["id", "company_id", "pw_hash", "pw_salt", "role", "email_verified_at",
                 "disabled_at", "company_status"]

LIVE_A, LIVE_B = b"\x0a", b"\x0b"

# qo_login_lookup as the schema before D6 created it: no company_status column.
PRE_D6_LOGIN_LOOKUP = """
DROP FUNCTION public.qo_login_lookup(citext);
CREATE FUNCTION public.qo_login_lookup(p_email citext)
RETURNS TABLE (id uuid, company_id text, pw_hash bytea, pw_salt bytea, role text,
               email_verified_at timestamptz, disabled_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
  SELECT u.id, u.company_id, u.pw_hash, u.pw_salt, u.role, u.email_verified_at, u.disabled_at
  FROM public.app_user u WHERE u.email = p_email LIMIT 1
$$;
ALTER FUNCTION public.qo_login_lookup(citext) OWNER TO qo_definer;
REVOKE ALL ON FUNCTION public.qo_login_lookup(citext) FROM PUBLIC, qo_admin;
GRANT EXECUTE ON FUNCTION public.qo_login_lookup(citext) TO qo_web;
"""


@pytest.fixture
def db(db):
    """The shared fixture, plus a drop afterwards (see tests/test_stage1_fix.py)."""
    yield db
    with Db(db.port, "postgres").connect(autocommit=True) as c:
        c.execute(f'DROP DATABASE IF EXISTS "{db.dbname}" WITH (FORCE)')


@pytest.fixture
def seeded(db):
    """Two companies with users (from the shared fixture) and a live session for each."""
    with db.connect() as c:
        ua = c.execute("SELECT id FROM public.app_user WHERE email = 'u1@c_a.test'").fetchone()[0]
        ub = c.execute("SELECT id FROM public.app_user WHERE email = 'u1@c_b.test'").fetchone()[0]
        for h, uid in ((LIVE_A, ua), (LIVE_B, ub)):
            c.execute("INSERT INTO public.session (id_hash, user_id, expires_at)"
                      " VALUES (%s, %s, now() + interval '1 day')", (h, uid))
    return {"db": db, "ua": ua, "ub": ub}


def _counts(db):
    with db.connect() as c:
        return {t: c.execute(f"SELECT count(*) FROM public.{t}").fetchone()[0] for t in TABLES}


def _assert_functions_intact(db):
    with db.connect() as c:
        for sig in FUNCTIONS.values():
            row = c.execute(
                "SELECT r.rolname, p.prosecdef, p.proconfig,"
                "       has_function_privilege('qo_web', p.oid, 'EXECUTE'),"
                "       has_function_privilege('qo_admin', p.oid, 'EXECUTE'),"
                "       has_function_privilege('public', p.oid, 'EXECUTE')"
                " FROM pg_proc p JOIN pg_roles r ON r.oid = p.proowner"
                " WHERE p.oid = to_regprocedure(%s)", (sig,)).fetchone()
            assert row is not None, sig
            assert row == ("qo_definer", True, ["search_path=pg_catalog, public, pg_temp"],
                           True, False, False), sig
            grantees = {r[0] for r in c.execute(
                "SELECT a.grantee::regrole::text FROM pg_proc p, aclexplode(p.proacl) a"
                " WHERE p.oid = to_regprocedure(%s) AND a.grantee <> p.proowner", (sig,))}
            assert grantees == {"qo_web"}, sig


def _assert_login_works(seeded):
    with seeded["db"].connect("qo_web") as c:
        cur = c.execute("SELECT * FROM qo_login_lookup('U1@c_a.test')")
        cols = [d.name for d in cur.description]
        rows = cur.fetchall()
        assert cols == LOGIN_COLUMNS
        assert len(rows) == 1
        assert (rows[0][0], rows[0][1], rows[0][7]) == (seeded["ua"], "c_a", "unverified")
        rows = c.execute("SELECT user_id, company_id FROM qo_session_lookup(%s)",
                         (LIVE_B,)).fetchall()
        assert rows == [(seeded["ub"], "c_b")]


def test_schema_applies_again_over_data(seeded):
    db = seeded["db"]
    before = _counts(db)
    assert before["company"] == 2 and before["app_user"] == 4 and before["session"] == 2
    for _ in range(2):
        db.migrate()
        _assert_functions_intact(db)
        assert _counts(db) == before
        _assert_login_works(seeded)


def test_schema_replaces_pre_d6_login_lookup(seeded):
    """A database migrated before company_status existed: CREATE OR REPLACE cannot change the
    output columns, so the migration must drop that version and restore owner and grants."""
    db = seeded["db"]
    with db.connect() as c:
        c.execute(PRE_D6_LOGIN_LOOKUP)
    before = _counts(db)
    for _ in range(2):
        db.migrate()
        _assert_functions_intact(db)
        assert _counts(db) == before
        _assert_login_works(seeded)


def test_session_lookup_fails_closed_without_company_row(seeded):
    """A non-sysadmin user whose company row is gone has no session. The foreign key normally
    prevents this; the owner bypasses it here to prove the lookup does not depend on it."""
    db = seeded["db"]
    with db.connect() as c:
        c.execute("SET session_replication_role = replica")
        c.execute("DELETE FROM public.company WHERE id = 'c_a'")
    with db.connect() as c:
        assert c.execute("SELECT count(*) FROM public.app_user WHERE company_id = 'c_a'"
                         ).fetchone()[0] == 2
    with db.connect("qo_web") as c:
        assert c.execute("SELECT * FROM qo_session_lookup(%s)", (LIVE_A,)).fetchall() == []
        assert len(c.execute("SELECT * FROM qo_session_lookup(%s)", (LIVE_B,)).fetchall()) == 1
        rows = c.execute("SELECT company_id, company_status FROM qo_login_lookup('u1@c_a.test')"
                         ).fetchall()
        assert rows == [("c_a", None)]
