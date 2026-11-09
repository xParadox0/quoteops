"""Stage 1 fix: password material and sessions are out of reach of qo_web and qo_admin, and
the pre-company lookups (sign-in, session cookie, invite) go through SECURITY DEFINER functions."""
import uuid

import psycopg
import pytest

from tests.conftest import Db

FUNCTIONS = {
    "qo_login_lookup": "qo_login_lookup(citext)",
    "qo_session_create": "qo_session_create(bytea, uuid, timestamptz, inet)",
    "qo_session_lookup": "qo_session_lookup(bytea)",
    "qo_session_delete": "qo_session_delete(bytea)",
    "qo_invite_lookup": "qo_invite_lookup(bytea)",
}
ADMIN_USER_COLUMNS = ["id", "company_id", "email", "role", "email_verified_at", "disabled_at",
                      "consent_version", "consent_at"]
NOT_FOR_DEFINER = ["job", "rate", "document", "drawing", "job_value", "cost_line", "audit_event",
                   "support_grant", "company_usage"]

LIVE_A, LIVE_B, EXPIRED, DISABLED = b"\x0a", b"\x0b", b"\x0e", b"\x0d"
INV_OK, INV_USED, INV_EXPIRED = b"\x1a", b"\x1b", b"\x1c"


@pytest.fixture
def db(db):
    """The shared fixture, plus a drop afterwards: the test container keeps its data on a tmpfs
    inside a 256 MB limit, and this file creates enough databases to exhaust it."""
    yield db
    with Db(db.port, "postgres").connect(autocommit=True) as c:
        c.execute(f'DROP DATABASE IF EXISTS "{db.dbname}" WITH (FORCE)')


@pytest.fixture
def seeded(db):
    """Sessions for company A and B, an expired one, one of a disabled user, and three invites."""
    with db.connect() as c:
        ua = c.execute("SELECT id FROM app_user WHERE email = 'u1@c_a.test'").fetchone()[0]
        ub = c.execute("SELECT id FROM app_user WHERE email = 'u1@c_b.test'").fetchone()[0]
        ud = uuid.uuid4()
        c.execute("INSERT INTO app_user (id, company_id, email, pw_hash, pw_salt, role,"
                  " disabled_at, consent_version, consent_at)"
                  " VALUES (%s,'c_a','gone@c_a.test','\\x00','\\x00','viewer',now(),'v1',now())",
                  (ud,))
        for h, uid, exp in ((LIVE_A, ua, "1 day"), (LIVE_B, ub, "1 day"),
                            (EXPIRED, ua, "-1 minute"), (DISABLED, ud, "1 day")):
            c.execute("INSERT INTO session (id_hash, user_id, expires_at)"
                      " VALUES (%s, %s, now() + %s::interval)", (h, uid, exp))
        # One unused invite per company and address (stage 2b), so the expired one has its own.
        for h, email, exp, used in ((INV_OK, "new@c_a.test", "1 day", None),
                                    (INV_USED, "new@c_a.test", "1 day", "now"),
                                    (INV_EXPIRED, "expired@c_a.test", "-1 minute", None)):
            c.execute("INSERT INTO invite (id_hash, company_id, email, role, expires_at, used_at)"
                      " VALUES (%s,'c_a',%s,'estimator', now() + %s::interval,"
                      " %s::timestamptz)", (h, email, exp, used))
    return {"db": db, "ua": ua, "ub": ub, "ud": ud}


# --- qo_admin -------------------------------------------------------------------------------

@pytest.mark.parametrize("col", ["pw_hash", "pw_salt"])
def test_admin_denied_on_password_columns(db, col):
    with db.connect("qo_admin") as c:
        with pytest.raises(psycopg.errors.InsufficientPrivilege, match="permission denied"):
            c.execute(f"SELECT {col} FROM app_user")
    with db.connect("qo_admin") as c:
        with pytest.raises(psycopg.errors.InsufficientPrivilege, match="permission denied"):
            c.execute("SELECT * FROM app_user")


def test_admin_reads_allowed_user_columns(db):
    with db.connect("qo_admin") as c:
        rows = c.execute(f"SELECT {', '.join(ADMIN_USER_COLUMNS)} FROM app_user").fetchall()
    assert len(rows) == 4
    assert {r[1] for r in rows} == {"c_a", "c_b"}


def test_admin_denied_on_session(seeded):
    with seeded["db"].connect("qo_admin") as c:
        with pytest.raises(psycopg.errors.InsufficientPrivilege, match="permission denied"):
            c.execute("SELECT count(*) FROM session")


def test_admin_cannot_call_functions(seeded):
    for name in FUNCTIONS:
        with seeded["db"].connect("qo_admin") as c:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                c.execute(f"SELECT * FROM {name}(NULL)" if name != "qo_session_create"
                          else "SELECT qo_session_create(NULL, NULL, NULL, NULL)")


# --- qo_web on the session table --------------------------------------------------------------

@pytest.mark.parametrize("stmt", [
    "SELECT count(*) FROM session",
    "INSERT INTO session (id_hash, user_id, expires_at) VALUES ('\\xff', gen_random_uuid(), now())",
    "UPDATE session SET expires_at = now()",
    "DELETE FROM session",
])
def test_web_denied_on_session(seeded, stmt):
    with seeded["db"].connect("qo_web") as c:
        c.execute("SELECT set_config('app.company_id', 'c_a', false)")
        with pytest.raises(psycopg.errors.InsufficientPrivilege, match="permission denied"):
            c.execute(stmt)


def test_session_rls_forced_and_without_policy(db):
    with db.connect() as c:
        row = c.execute("SELECT relrowsecurity, relforcerowsecurity FROM pg_class"
                        " WHERE oid = 'session'::regclass").fetchone()
        assert row == (True, True)
        assert c.execute("SELECT count(*) FROM pg_policies WHERE tablename = 'session'"
                         ).fetchone()[0] == 0


def test_company_b_cannot_reach_company_a_session(seeded):
    db = seeded["db"]
    with db.connect("qo_web") as c:
        c.execute("SELECT set_config('app.company_id', 'c_b', false)")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute("SELECT * FROM session")
    with db.connect("qo_web") as c:
        c.execute("SELECT set_config('app.company_id', 'c_b', false)")
        # Without the cookie value there is no hash to ask for, and no function lists sessions.
        assert c.execute("SELECT * FROM qo_session_lookup(%s)", (b"\x0c",)).fetchall() == []
        c.execute("SELECT qo_session_delete(%s)", (b"\x0c",))
        callable_fns = {r[0] for r in c.execute(
            "SELECT p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace"
            " WHERE n.nspname = 'public' AND has_function_privilege(p.oid, 'EXECUTE')"
            " AND NOT EXISTS (SELECT 1 FROM pg_depend d"  # citext's own functions
            "                 WHERE d.objid = p.oid AND d.deptype = 'e')")}
    # Stage 2a adds the throttle, company-count, sign-out-everywhere and unverified-purge
    # functions; none lists sessions or takes a hash it was not given.
    assert callable_fns == set(FUNCTIONS) | {"qo_throttle_check", "qo_throttle_reset",
                                             "qo_company_count", "qo_session_delete_user",
                                             "qo_purge_unverified"}
    with db.connect() as c:
        assert c.execute("SELECT count(*) FROM session WHERE id_hash = %s",
                         (LIVE_A,)).fetchone()[0] == 1


# --- the functions ----------------------------------------------------------------------------

def test_login_lookup_returns_one_row_without_company(db):
    """Replaces reviewer test M: sign-in happens before any company is known."""
    with db.connect("qo_web") as c:
        cur = c.execute("SELECT * FROM qo_login_lookup(%s)", ("U1@c_a.test",))
        cols = [d.name for d in cur.description]
        rows = cur.fetchall()
    assert cols == ["id", "company_id", "pw_hash", "pw_salt", "role", "email_verified_at",
                    "disabled_at", "company_status"]
    assert len(rows) == 1
    assert rows[0][1] == "c_a" and rows[0][2] == b"\x00" and rows[0][4] == "owner"


def test_login_lookup_reports_disabled_user(seeded):
    with seeded["db"].connect("qo_web") as c:
        rows = c.execute("SELECT id, disabled_at FROM qo_login_lookup('gone@c_a.test')").fetchall()
    assert len(rows) == 1 and rows[0][0] == seeded["ud"] and rows[0][1] is not None


@pytest.mark.parametrize("email", [
    "nobody@c_a.test", "u1@c_a.test' OR '1'='1", "%", "u%@c_a.test", "%@%", "",
    "u1@c_a.test\u00e9", "\u2603@\u00fc.test", "' ; DELETE FROM app_user; --",
])
def test_login_lookup_unknown_or_hostile_returns_nothing(db, email):
    with db.connect("qo_web") as c:
        assert c.execute("SELECT * FROM qo_login_lookup(%s)", (email,)).fetchall() == []
    with db.connect() as c:
        assert c.execute("SELECT count(*) FROM app_user").fetchone()[0] == 4


def test_session_create_then_lookup_then_delete(seeded):
    db, ua = seeded["db"], seeded["ua"]
    h = b"\x42" * 32
    with db.connect("qo_web") as c:
        c.execute("SELECT qo_session_create(%s, %s, now() + interval '1 hour', %s)",
                  (h, ua, "192.0.2.7"))
    with db.connect() as c:
        row = c.execute("SELECT user_id, host(created_ip) FROM session WHERE id_hash = %s",
                        (h,)).fetchone()
        assert row == (ua, "192.0.2.7")
    with db.connect("qo_web") as c:
        rows = c.execute("SELECT user_id, company_id, role FROM qo_session_lookup(%s)",
                         (h,)).fetchall()
        assert rows == [(ua, "c_a", "owner")]
        c.execute("SELECT qo_session_delete(%s)", (h,))
        assert c.execute("SELECT * FROM qo_session_lookup(%s)", (h,)).fetchall() == []
    with db.connect() as c:
        assert c.execute("SELECT count(*) FROM session WHERE id_hash = %s", (h,)).fetchone()[0] == 0
        assert c.execute("SELECT count(*) FROM session").fetchone()[0] == 4


def test_session_lookup_live_row(seeded):
    with seeded["db"].connect("qo_web") as c:
        cur = c.execute("SELECT * FROM qo_session_lookup(%s)", (LIVE_B,))
        cols = [d.name for d in cur.description]
        rows = cur.fetchall()
    assert cols == ["user_id", "company_id", "role", "expires_at"]
    assert len(rows) == 1 and rows[0][:3] == (seeded["ub"], "c_b", "owner")


@pytest.mark.parametrize("h", [b"\x99", EXPIRED, DISABLED], ids=["unknown", "expired", "disabled"])
def test_session_lookup_refuses(seeded, h):
    with seeded["db"].connect("qo_web") as c:
        assert c.execute("SELECT * FROM qo_session_lookup(%s)", (h,)).fetchall() == []


def test_invite_lookup_valid(seeded):
    with seeded["db"].connect("qo_web") as c:
        cur = c.execute("SELECT * FROM qo_invite_lookup(%s)", (INV_OK,))
        cols = [d.name for d in cur.description]
        rows = cur.fetchall()
    assert cols == ["company_id", "email", "role", "expires_at"]
    assert len(rows) == 1 and rows[0][:3] == ("c_a", "new@c_a.test", "estimator")


@pytest.mark.parametrize("h", [b"\x99", INV_USED, INV_EXPIRED], ids=["unknown", "used", "expired"])
def test_invite_lookup_refuses(seeded, h):
    with seeded["db"].connect("qo_web") as c:
        assert c.execute("SELECT * FROM qo_invite_lookup(%s)", (h,)).fetchall() == []


# --- function properties ----------------------------------------------------------------------

@pytest.mark.parametrize("sig", FUNCTIONS.values())
def test_function_execute_only_for_web(db, sig):
    with db.connect() as c:
        got = c.execute(
            "SELECT has_function_privilege('qo_web', %s, 'EXECUTE'),"
            "       has_function_privilege('qo_admin', %s, 'EXECUTE'),"
            "       has_function_privilege('public', %s, 'EXECUTE')", (sig, sig, sig)).fetchone()
    assert got == (True, False, False)


@pytest.mark.parametrize("sig", FUNCTIONS.values())
def test_function_is_definer_with_pinned_search_path(db, sig):
    with db.connect() as c:
        row = c.execute("SELECT p.prosecdef, p.proconfig, r.rolname, r.rolsuper"
                        " FROM pg_proc p JOIN pg_roles r ON r.oid = p.proowner"
                        " WHERE p.oid = %s::regprocedure", (sig,)).fetchone()
    assert row[0] is True
    assert row[1] == ["search_path=pg_catalog, public, pg_temp"]
    assert row[2] == "qo_definer" and row[3] is False


# --- qo_definer -------------------------------------------------------------------------------

def test_definer_role_attributes(db):
    with db.connect() as c:
        row = c.execute("SELECT rolcanlogin, rolbypassrls, rolsuper, rolcreaterole, rolcreatedb"
                        " FROM pg_roles WHERE rolname = 'qo_definer'").fetchone()
        assert row == (False, True, False, False, False)
        assert c.execute("SELECT count(*) FROM pg_auth_members m JOIN pg_roles r"
                         " ON r.oid = m.roleid WHERE r.rolname = 'qo_definer'").fetchone()[0] == 0
    with db.connect("qo_web") as c:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute("SET ROLE qo_definer")


@pytest.mark.parametrize("table", NOT_FOR_DEFINER)
def test_definer_has_nothing_on_other_tables(db, table):
    with db.connect() as c:
        got = c.execute(
            "SELECT bool_or(has_table_privilege('qo_definer', %s, p))"
            " FROM unnest(ARRAY['SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES',"
            "'TRIGGER']) p", (table,)).fetchone()[0]
        assert got is False
        assert c.execute("SELECT has_any_column_privilege('qo_definer', %s, 'SELECT,INSERT,UPDATE')",
                         (table,)).fetchone()[0] is False


def test_definer_reads_only_id_and_status_of_company(db):
    """qo_session_lookup and qo_login_lookup read a company's status (D6); qo_purge_unverified
    also reads created_at and deletes unverified companies (owner decision 2026-11-08); nothing
    else of it."""
    with db.connect() as c:
        got = {p for p in ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES",
                           "TRIGGER")
               if c.execute("SELECT has_table_privilege('qo_definer', 'company', %s)",
                            (p,)).fetchone()[0]}
        assert got == {"DELETE"}
        cols = [r[0] for r in c.execute(
            "SELECT attname FROM pg_attribute WHERE attrelid = 'company'::regclass"
            " AND attnum > 0 AND NOT attisdropped")]
        assert {"id", "status", "created_at"} < set(cols)
        for col in cols:
            assert c.execute("SELECT has_column_privilege('qo_definer', 'company', %s, 'SELECT')",
                             (col,)).fetchone()[0] is (col in ("id", "status", "created_at")), col
            assert c.execute("SELECT has_column_privilege('qo_definer', 'company', %s,"
                             " 'INSERT,UPDATE,REFERENCES')", (col,)).fetchone()[0] is False, col


def test_definer_privileges_are_exactly_the_listed_ones(db):
    with db.connect() as c:
        table_level = set(c.execute(
            "SELECT c.relname, a.privilege_type FROM pg_class c"
            " JOIN pg_namespace n ON n.oid = c.relnamespace, aclexplode(c.relacl) a"
            " WHERE n.nspname = 'public' AND a.grantee = 'qo_definer'::regrole"))
        column_level = set(c.execute(
            "SELECT c.relname, t.attname, a.privilege_type FROM pg_attribute t"
            " JOIN pg_class c ON c.oid = t.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace,"
            " aclexplode(t.attacl) a"
            " WHERE n.nspname = 'public' AND a.grantee = 'qo_definer'::regrole"))
    # DELETE on company and app_user: qo_purge_unverified (owner decision 2026-11-08).
    # INSERT and DELETE on admin_session: the qo_admin_session_* functions (stage 2b part 2).
    assert table_level == {("session", "INSERT"), ("session", "DELETE"), ("company", "DELETE"),
                           ("app_user", "DELETE"), ("admin_session", "INSERT"),
                           ("admin_session", "DELETE")} | {
        ("auth_throttle", p) for p in ("SELECT", "INSERT", "UPDATE", "DELETE")}
    expected = {("app_user", col, "SELECT") for col in
                ("id", "company_id", "email", "pw_hash", "pw_salt", "role", "email_verified_at",
                 "disabled_at")}
    expected |= {("session", col, "SELECT") for col in ("id_hash", "user_id", "expires_at")}
    expected |= {("invite", col, "SELECT") for col in
                 ("id_hash", "company_id", "email", "role", "expires_at", "used_at")}
    expected |= {("company", col, "SELECT") for col in ("id", "status", "created_at")}
    # Stage 2b part 2: qo_admin_login_lookup and qo_admin_totp_use read the factor and set the
    # last used counter; the admin session functions read these three columns.
    expected |= {("admin_factor", col, "SELECT") for col in
                 ("user_id", "totp_secret", "last_counter")}
    expected |= {("admin_factor", "last_counter", "UPDATE")}
    expected |= {("admin_session", col, "SELECT") for col in ("id_hash", "user_id", "expires_at")}
    assert column_level == expected
