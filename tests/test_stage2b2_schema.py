"""Stage 2b part 2 schema: admin_factor and admin_session, the six qo_admin_* SECURITY DEFINER
functions (callable by qo_admin only), the two throttle functions also granted to qo_admin, the
hardening of qo_login_lookup (never a sysadmin row), and the migration over a stage 2b part 1
database."""
import re
import threading
import uuid
from pathlib import Path

import psycopg
import pytest

from tests.conftest import Db
from tests.stage2a_support import adb  # noqa: F401  (fixture)

ADMIN_FUNCTIONS = {
    "qo_admin_login_lookup": "qo_admin_login_lookup(citext)",
    "qo_admin_totp_use": "qo_admin_totp_use(uuid, bigint)",
    "qo_admin_session_create": "qo_admin_session_create(bytea, uuid, timestamptz, inet)",
    "qo_admin_session_lookup": "qo_admin_session_lookup(bytea)",
    "qo_admin_session_delete": "qo_admin_session_delete(bytea)",
    "qo_admin_session_delete_user": "qo_admin_session_delete_user(uuid)",
}
THROTTLE = {"qo_throttle_check": "qo_throttle_check(bytea, text, integer, integer, integer)",
            "qo_throttle_reset": "qo_throttle_reset(bytea, text)"}
WEB_FUNCTIONS = {"qo_login_lookup", "qo_session_create", "qo_session_lookup", "qo_session_delete",
                 "qo_invite_lookup", "qo_throttle_check", "qo_throttle_reset", "qo_company_count",
                 "qo_session_delete_user", "qo_purge_unverified"}
ADMIN_TABLES = ["admin_factor", "admin_session"]
PRIVS = ["SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"]
STAGE2B1_SCHEMA = Path(__file__).resolve().parent / "data" / "schema_903b975.sql"
TABLES = ["company", "app_user", "session", "invite", "job", "drawing", "job_value", "rate",
          "cost_line", "document", "audit_event", "support_grant", "auth_throttle"]
ROOT_ID, OWNER_ID = uuid.UUID(int=1), uuid.UUID(int=2)
SECRET = bytes(range(20))


def _calls():
    """One call of each admin function with harmless arguments."""
    return ["SELECT * FROM qo_admin_login_lookup('x@y.test')",
            "SELECT qo_admin_totp_use(gen_random_uuid(), 1)",
            "SELECT qo_admin_session_create('\\x01', gen_random_uuid(), now(), NULL)",
            "SELECT * FROM qo_admin_session_lookup('\\x01')",
            "SELECT qo_admin_session_delete('\\x01')",
            "SELECT qo_admin_session_delete_user(gen_random_uuid())"]


def _admin(c, uid=ROOT_ID, email="root@ops.test", factor=True, disabled=False, verified=True,
           counter=0):
    c.execute("INSERT INTO app_user (id, company_id, email, pw_hash, pw_salt, role,"
              " email_verified_at, disabled_at, consent_version, consent_at)"
              " VALUES (%s, NULL, %s, '\\x0a', '\\x0b', 'sysadmin', %s, %s, 'admin', now())",
              (uid, email, "now" if verified else None, "now" if disabled else None))
    if factor:
        c.execute("INSERT INTO admin_factor (user_id, totp_secret, last_counter)"
                  " VALUES (%s, %s, %s)", (uid, SECRET, counter))


def _owner(c, uid=OWNER_ID, email="owner@shop.test", cid="c_one"):
    c.execute("INSERT INTO company (id, name, status) VALUES (%s, 'One', 'active')"
              " ON CONFLICT (id) DO NOTHING", (cid,))
    c.execute("INSERT INTO app_user (id, company_id, email, pw_hash, pw_salt, role,"
              " email_verified_at, consent_version, consent_at)"
              " VALUES (%s, %s, %s, '\\x0c', '\\x0d', 'owner', now(), 'v1', now())",
              (uid, cid, email))


@pytest.fixture
def seeded(adb):
    with adb.connect() as c:
        _admin(c)
        _owner(c)
    return adb


# --- the tables -----------------------------------------------------------------------------------

def test_admin_factor_columns_and_keys(adb):
    with adb.connect() as c:
        cols = c.execute("SELECT column_name, data_type, is_nullable, column_default"
                         " FROM information_schema.columns WHERE table_name = 'admin_factor'"
                         " ORDER BY ordinal_position").fetchall()
        fk = c.execute("SELECT pg_get_constraintdef(oid) FROM pg_constraint"
                       " WHERE conrelid = 'admin_factor'::regclass AND contype = 'f'").fetchall()
        pk = c.execute("SELECT pg_get_constraintdef(oid) FROM pg_constraint"
                       " WHERE conrelid = 'admin_factor'::regclass AND contype = 'p'").fetchall()
    assert [(n, t, null) for n, t, null, _ in cols] == [
        ("user_id", "uuid", "NO"), ("totp_secret", "bytea", "NO"), ("last_counter", "bigint", "NO"),
        ("created_at", "timestamp with time zone", "YES")]
    assert cols[2][3] == "0" and cols[3][3] == "now()"
    assert pk == [("PRIMARY KEY (user_id)",)]
    assert fk == [("FOREIGN KEY (user_id) REFERENCES app_user(id) ON DELETE CASCADE",)]


def test_admin_session_columns_and_keys(adb):
    with adb.connect() as c:
        cols = c.execute("SELECT column_name, data_type, is_nullable FROM information_schema.columns"
                         " WHERE table_name = 'admin_session' ORDER BY ordinal_position").fetchall()
        fk = c.execute("SELECT pg_get_constraintdef(oid) FROM pg_constraint"
                       " WHERE conrelid = 'admin_session'::regclass AND contype = 'f'").fetchall()
        pk = c.execute("SELECT pg_get_constraintdef(oid) FROM pg_constraint"
                       " WHERE conrelid = 'admin_session'::regclass AND contype = 'p'").fetchall()
    assert cols == [("id_hash", "bytea", "NO"), ("user_id", "uuid", "NO"),
                    ("expires_at", "timestamp with time zone", "NO"), ("created_ip", "inet", "YES")]
    assert pk == [("PRIMARY KEY (id_hash)",)]
    assert fk == [("FOREIGN KEY (user_id) REFERENCES app_user(id) ON DELETE CASCADE",)]


@pytest.mark.parametrize("table", ADMIN_TABLES)
def test_admin_tables_force_rls_without_policy(adb, table):
    with adb.connect() as c:
        assert c.execute("SELECT relrowsecurity, relforcerowsecurity FROM pg_class"
                         " WHERE oid = %s::regclass", (table,)).fetchone() == (True, True)
        assert c.execute("SELECT count(*) FROM pg_policies WHERE tablename = %s",
                         (table,)).fetchone()[0] == 0
        owner = c.execute("SELECT r.rolname FROM pg_class cl JOIN pg_roles r"
                          " ON r.oid = cl.relowner WHERE cl.oid = %s::regclass", (table,)).fetchone()[0]
    assert owner == "qo_owner"


@pytest.mark.parametrize("table", ADMIN_TABLES)
@pytest.mark.parametrize("role", ["qo_web", "qo_admin", "public"])
def test_no_grant_on_admin_tables_for_app_roles(adb, table, role):
    with adb.connect() as c:
        assert c.execute("SELECT bool_or(has_table_privilege(%s, %s, p)) FROM unnest(%s::text[]) p",
                         (role, table, PRIVS)).fetchone()[0] is False
        assert c.execute("SELECT has_any_column_privilege(%s, %s, 'SELECT,INSERT,UPDATE,REFERENCES')",
                         (role, table)).fetchone()[0] is False


@pytest.mark.parametrize("table", ADMIN_TABLES)
@pytest.mark.parametrize("role", ["qo_web", "qo_admin"])
def test_app_roles_are_refused_on_admin_tables(seeded, table, role):
    stmts = [f"SELECT count(*) FROM {table}", f"DELETE FROM {table}",
             f"UPDATE {table} SET user_id = user_id",
             "INSERT INTO admin_factor (user_id, totp_secret) VALUES (gen_random_uuid(), '\\x00')"
             if table == "admin_factor" else
             "INSERT INTO admin_session (id_hash, user_id, expires_at)"
             " VALUES ('\\x00', gen_random_uuid(), now())"]
    for stmt in stmts:
        with seeded.connect(role) as c:
            if role == "qo_web":
                c.execute("SELECT set_config('app.company_id', 'c_one', false)")
            with pytest.raises(psycopg.errors.InsufficientPrivilege, match="permission denied"):
                c.execute(stmt)


def test_definer_privileges_on_admin_tables_are_exact(adb):
    with adb.connect() as c:
        table_level = set(c.execute(
            "SELECT cl.relname, a.privilege_type FROM pg_class cl, aclexplode(cl.relacl) a"
            " WHERE cl.relname = ANY(%s) AND a.grantee = 'qo_definer'::regrole", (ADMIN_TABLES,)))
        column_level = set(c.execute(
            "SELECT cl.relname, t.attname, a.privilege_type FROM pg_attribute t"
            " JOIN pg_class cl ON cl.oid = t.attrelid, aclexplode(t.attacl) a"
            " WHERE cl.relname = ANY(%s) AND a.grantee = 'qo_definer'::regrole", (ADMIN_TABLES,)))
        others = c.execute(
            "SELECT count(*) FROM pg_class cl, aclexplode(cl.relacl) a"
            " WHERE cl.relname = ANY(%s) AND a.grantee NOT IN ('qo_definer'::regrole, cl.relowner)",
            (ADMIN_TABLES,)).fetchone()[0]
        other_cols = c.execute(
            "SELECT count(*) FROM pg_attribute t JOIN pg_class cl ON cl.oid = t.attrelid,"
            " aclexplode(t.attacl) a WHERE cl.relname = ANY(%s) AND a.grantee <> 'qo_definer'::regrole",
            (ADMIN_TABLES,)).fetchone()[0]
    assert table_level == {("admin_session", "INSERT"), ("admin_session", "DELETE")}
    assert column_level == {
        ("admin_factor", "user_id", "SELECT"), ("admin_factor", "totp_secret", "SELECT"),
        ("admin_factor", "last_counter", "SELECT"), ("admin_factor", "last_counter", "UPDATE"),
        ("admin_session", "id_hash", "SELECT"), ("admin_session", "user_id", "SELECT"),
        ("admin_session", "expires_at", "SELECT")}
    assert others == 0 and other_cols == 0


# --- function properties --------------------------------------------------------------------------

@pytest.mark.parametrize("sig", ADMIN_FUNCTIONS.values())
def test_admin_function_definer_owner_search_path(adb, sig):
    with adb.connect() as c:
        row = c.execute("SELECT p.prosecdef, p.proconfig, r.rolname, r.rolsuper"
                        " FROM pg_proc p JOIN pg_roles r ON r.oid = p.proowner"
                        " WHERE p.oid = to_regprocedure(%s)", (sig,)).fetchone()
    assert row is not None, sig
    assert row == (True, ["search_path=pg_catalog, public, pg_temp"], "qo_definer", False)


@pytest.mark.parametrize("sig", ADMIN_FUNCTIONS.values())
def test_admin_function_execute_for_qo_admin_only(adb, sig):
    with adb.connect() as c:
        got = c.execute(
            "SELECT has_function_privilege('qo_web', %s, 'EXECUTE'),"
            "       has_function_privilege('qo_admin', %s, 'EXECUTE'),"
            "       has_function_privilege('public', %s, 'EXECUTE')", (sig, sig, sig)).fetchone()
        grantees = {r[0] for r in c.execute(
            "SELECT a.grantee::regrole::text FROM pg_proc p, aclexplode(p.proacl) a"
            " WHERE p.oid = to_regprocedure(%s) AND a.grantee <> p.proowner", (sig,))}
    assert got == (False, True, False)
    assert grantees == {"qo_admin"}


@pytest.mark.parametrize("sig", THROTTLE.values())
def test_throttle_functions_for_web_and_admin(adb, sig):
    with adb.connect() as c:
        grantees = {r[0] for r in c.execute(
            "SELECT a.grantee::regrole::text FROM pg_proc p, aclexplode(p.proacl) a"
            " WHERE p.oid = to_regprocedure(%s) AND a.grantee <> p.proowner", (sig,))}
        public = c.execute("SELECT has_function_privilege('public', %s, 'EXECUTE')",
                           (sig,)).fetchone()[0]
    assert grantees == {"qo_web", "qo_admin"} and public is False


@pytest.mark.parametrize("sig", ADMIN_FUNCTIONS.values())
def test_admin_function_body_qualifies_every_table(adb, sig):
    with adb.connect() as c:
        src = c.execute("SELECT prosrc FROM pg_proc WHERE oid = to_regprocedure(%s)",
                        (sig,)).fetchone()[0]
    names = re.findall(r"\b(?:FROM|JOIN|INTO|UPDATE)\s+(?!SET\b)([A-Za-z_][\w.]*)", src,
                       re.IGNORECASE)
    assert names
    assert all(n.startswith("public.") for n in names), names


def _callable(db, role):
    with db.connect(role) as c:
        return {r[0] for r in c.execute(
            "SELECT p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace"
            " WHERE n.nspname = 'public' AND has_function_privilege(p.oid, 'EXECUTE')"
            " AND NOT EXISTS (SELECT 1 FROM pg_depend d"
            "                 WHERE d.objid = p.oid AND d.deptype = 'e')")}


def test_callable_function_sets_per_role(adb):
    assert _callable(adb, "qo_admin") == set(ADMIN_FUNCTIONS) | set(THROTTLE)
    assert _callable(adb, "qo_web") == WEB_FUNCTIONS


def test_web_cannot_call_any_admin_function(seeded):
    for call in _calls():
        with seeded.connect("qo_web") as c:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                c.execute(call)


@pytest.mark.parametrize("call", [
    "SELECT * FROM qo_login_lookup('root@ops.test')", "SELECT * FROM qo_session_lookup('\\x01')",
    "SELECT qo_session_create('\\x01', gen_random_uuid(), now(), NULL)",
    "SELECT qo_session_delete('\\x01')", "SELECT * FROM qo_invite_lookup('\\x01')",
    "SELECT qo_company_count()", "SELECT qo_session_delete_user(gen_random_uuid())",
    "SELECT qo_purge_unverified(100000, 500)"])
def test_admin_cannot_call_the_web_functions(seeded, call):
    with seeded.connect("qo_admin") as c:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute(call)


def test_admin_calls_the_throttle_functions(seeded):
    with seeded.connect("qo_admin", autocommit=True) as c:
        assert c.execute("SELECT qo_throttle_check('\\x01', 'admin_login_ip', 5, 60, 60)"
                         ).fetchone()[0] is True
        c.execute("SELECT qo_throttle_reset('\\x01', 'admin_login_ip')")


@pytest.mark.parametrize("stmt", ["SELECT pw_hash FROM app_user", "SELECT pw_salt FROM app_user",
                                  "SELECT * FROM app_user", "SELECT count(*) FROM session",
                                  "SELECT count(*) FROM invite", "SELECT count(*) FROM auth_throttle"])
def test_admin_still_has_no_hashes_sessions_or_invites(seeded, stmt):
    with seeded.connect("qo_admin") as c:
        with pytest.raises(psycopg.errors.InsufficientPrivilege, match="permission denied"):
            c.execute(stmt)


def test_public_cannot_call_admin_functions(adb):
    with adb.connect() as c:
        for sig in ADMIN_FUNCTIONS.values():
            assert c.execute("SELECT has_function_privilege('public', %s, 'EXECUTE')",
                             (sig,)).fetchone()[0] is False


# --- qo_admin_login_lookup ------------------------------------------------------------------------

def test_admin_login_lookup_returns_the_admin_row(seeded):
    with seeded.connect("qo_admin") as c:
        cur = c.execute("SELECT * FROM qo_admin_login_lookup('ROOT@ops.test')")
        cols = [d.name for d in cur.description]
        rows = cur.fetchall()
    assert cols == ["user_id", "pw_hash", "pw_salt", "totp_secret", "last_counter"]
    assert rows == [(ROOT_ID, b"\x0a", b"\x0b", SECRET, 0)]


@pytest.mark.parametrize("case", ["owner", "disabled", "unverified", "no_factor", "unknown"])
def test_admin_login_lookup_refuses(seeded, case):
    with seeded.connect() as c:
        if case == "disabled":
            _admin(c, uuid.uuid4(), "case@ops.test", disabled=True)
        elif case == "unverified":
            _admin(c, uuid.uuid4(), "case@ops.test", verified=False)
        elif case == "no_factor":
            _admin(c, uuid.uuid4(), "case@ops.test", factor=False)
    email = {"owner": "owner@shop.test", "unknown": "nobody@ops.test"}.get(case, "case@ops.test")
    with seeded.connect("qo_admin") as c:
        assert c.execute("SELECT * FROM qo_admin_login_lookup(%s)", (email,)).fetchall() == []


def test_admin_login_lookup_owner_with_a_factor_row_is_still_refused(seeded):
    """Even a factor row planted for a company account does not make it an administrator."""
    with seeded.connect() as c:
        c.execute("INSERT INTO admin_factor (user_id, totp_secret) VALUES (%s, %s)",
                  (OWNER_ID, SECRET))
    with seeded.connect("qo_admin") as c:
        assert c.execute("SELECT * FROM qo_admin_login_lookup('owner@shop.test')").fetchall() == []


@pytest.mark.parametrize("email", [None, "", "%", "root@ops.test' OR '1'='1", "%@%", "root%"])
def test_admin_login_lookup_hostile_input(seeded, email):
    with seeded.connect("qo_admin") as c:
        assert c.execute("SELECT * FROM qo_admin_login_lookup(%s)", (email,)).fetchall() == []


# --- qo_admin_totp_use: the replay guard ----------------------------------------------------------

def _use(db, counter, uid=ROOT_ID):
    with db.connect("qo_admin", autocommit=True) as c:
        return c.execute("SELECT qo_admin_totp_use(%s, %s)", (uid, counter)).fetchone()[0]


def _last(db, uid=ROOT_ID):
    with db.connect() as c:
        return c.execute("SELECT last_counter FROM admin_factor WHERE user_id = %s",
                         (uid,)).fetchone()[0]


def test_totp_use_is_compare_and_set(seeded):
    assert _use(seeded, 100) is True and _last(seeded) == 100
    assert _use(seeded, 100) is False and _last(seeded) == 100
    assert _use(seeded, 99) is False and _last(seeded) == 100
    assert _use(seeded, 101) is True and _last(seeded) == 101
    assert _use(seeded, 5, uid=uuid.uuid4()) is False
    assert _use(seeded, None) is False and _last(seeded) == 101


def test_totp_use_counts_once_under_concurrency(seeded):
    """The second caller waits for the first one's row lock and then finds the counter used."""
    first = seeded.connect("qo_admin")
    try:
        assert first.execute("SELECT qo_admin_totp_use(%s, 7)", (ROOT_ID,)).fetchone()[0] is True
        result = []
        t = threading.Thread(target=lambda: result.append(_use(seeded, 7)))
        t.start()
        t.join(1.0)
        assert t.is_alive(), "the second call must wait for the first one's lock"
        first.commit()
        t.join(10)
        assert result == [False]
    finally:
        first.close()
    assert _last(seeded) == 7


# --- the admin sessions ---------------------------------------------------------------------------

def _create(db, h, uid=ROOT_ID, expires="1 hour", ip=None):
    with db.connect("qo_admin", autocommit=True) as c:
        c.execute("SELECT qo_admin_session_create(%s, %s, now() + %s::interval, %s)",
                  (h, uid, expires, ip))


def _lookup(db, h):
    with db.connect("qo_admin") as c:
        cur = c.execute("SELECT * FROM qo_admin_session_lookup(%s)", (h,))
        return [d.name for d in cur.description], cur.fetchall()


def test_admin_session_create_lookup_delete(seeded):
    _create(seeded, b"\x01" * 32, ip="192.0.2.9")
    with seeded.connect() as c:
        assert c.execute("SELECT user_id, host(created_ip) FROM admin_session").fetchall() == [
            (ROOT_ID, "192.0.2.9")]
    cols, rows = _lookup(seeded, b"\x01" * 32)
    assert cols == ["user_id", "email", "expires_at"]
    assert [r[:2] for r in rows] == [(ROOT_ID, "root@ops.test")]
    with seeded.connect("qo_admin", autocommit=True) as c:
        c.execute("SELECT qo_admin_session_delete(%s)", (b"\x01" * 32,))
    assert _lookup(seeded, b"\x01" * 32)[1] == []


@pytest.mark.parametrize("case", ["expired", "disabled", "now_owner", "unknown"])
def test_admin_session_lookup_refuses(seeded, case):
    _create(seeded, b"\x02", expires="-1 second" if case == "expired" else "1 hour")
    with seeded.connect() as c:
        if case == "disabled":
            c.execute("UPDATE app_user SET disabled_at = now() WHERE id = %s", (ROOT_ID,))
        elif case == "now_owner":
            c.execute("UPDATE app_user SET role = 'owner', company_id = 'c_one' WHERE id = %s",
                      (ROOT_ID,))
    assert _lookup(seeded, b"\x99" if case == "unknown" else b"\x02")[1] == []


def test_admin_session_cannot_be_made_for_a_company_account(seeded):
    """The create function stores whatever user id it is given, but the lookup only ever
    answers for a sysadmin."""
    _create(seeded, b"\x03", uid=OWNER_ID)
    assert _lookup(seeded, b"\x03")[1] == []


def test_admin_session_delete_user_only_that_user(seeded):
    other = uuid.uuid4()
    with seeded.connect() as c:
        _admin(c, other, "two@ops.test")
    for n, uid in ((1, ROOT_ID), (2, ROOT_ID), (3, other)):
        _create(seeded, bytes([n]), uid=uid)
    with seeded.connect("qo_admin", autocommit=True) as c:
        c.execute("SELECT qo_admin_session_delete_user(%s)", (ROOT_ID,))
        c.execute("SELECT qo_admin_session_delete_user(NULL)")
    with seeded.connect() as c:
        assert c.execute("SELECT user_id FROM admin_session").fetchall() == [(other,)]


def test_deleting_a_user_deletes_factor_and_sessions(seeded):
    _create(seeded, b"\x04")
    with seeded.connect() as c:
        c.execute("DELETE FROM app_user WHERE id = %s", (ROOT_ID,))
        assert c.execute("SELECT count(*) FROM admin_factor").fetchone()[0] == 0
        assert c.execute("SELECT count(*) FROM admin_session").fetchone()[0] == 0


# --- hardening of the public sign-in lookup -------------------------------------------------------

def test_web_login_lookup_never_returns_a_sysadmin(seeded):
    with seeded.connect("qo_web") as c:
        assert c.execute("SELECT * FROM qo_login_lookup('root@ops.test')").fetchall() == []
        assert c.execute("SELECT * FROM qo_login_lookup('ROOT@OPS.TEST')").fetchall() == []
        assert len(c.execute("SELECT * FROM qo_login_lookup('owner@shop.test')").fetchall()) == 1
    with seeded.connect() as c:
        src = c.execute("SELECT prosrc FROM pg_proc WHERE oid = to_regprocedure("
                        "'qo_login_lookup(citext)')").fetchone()[0]
    assert "role <> 'sysadmin'" in src


# --- planted temporary tables ---------------------------------------------------------------------

def test_admin_functions_ignore_planted_temp_tables(seeded):
    """The owner may create temporary tables: shadows of app_user, admin_factor and admin_session
    in the calling session must not change what the admin functions read or write."""
    evil = uuid.uuid4()
    _create(seeded, b"\x05")
    with seeded.connect(autocommit=True) as c:
        for t in ("app_user", "admin_factor", "admin_session", "company"):
            c.execute(f"CREATE TEMP TABLE {t} (LIKE public.{t} INCLUDING DEFAULTS)")
        c.execute("INSERT INTO pg_temp.app_user (id, company_id, email, pw_hash, pw_salt, role,"
                  " email_verified_at, consent_version, consent_at) VALUES"
                  " (%s, NULL, 'evil@x.test', '\\xee', '\\xee', 'sysadmin', now(), 'v', now()),"
                  " (%s, NULL, 'root@ops.test', '\\xee', '\\xee', 'sysadmin', now(), 'v', now())",
                  (evil, ROOT_ID))
        c.execute("INSERT INTO pg_temp.admin_factor (user_id, totp_secret, last_counter)"
                  " VALUES (%s, '\\xee', 0), (%s, '\\xee', 999999)", (evil, ROOT_ID))
        c.execute("INSERT INTO pg_temp.admin_session (id_hash, user_id, expires_at)"
                  " VALUES ('\\x06', %s, now() + interval '1 day'),"
                  " ('\\x05', %s, now() - interval '1 day')", (evil, ROOT_ID))

        assert c.execute("SELECT * FROM qo_admin_login_lookup('evil@x.test')").fetchall() == []
        assert c.execute("SELECT pw_hash, totp_secret, last_counter FROM"
                         " qo_admin_login_lookup('root@ops.test')").fetchall() == [
            (b"\x0a", SECRET, 0)]
        assert c.execute("SELECT qo_admin_totp_use(%s, 5)", (ROOT_ID,)).fetchone()[0] is True
        assert c.execute("SELECT qo_admin_totp_use(%s, 5)", (evil,)).fetchone()[0] is False
        assert c.execute("SELECT last_counter FROM public.admin_factor").fetchone()[0] == 5
        assert c.execute("SELECT last_counter FROM pg_temp.admin_factor WHERE user_id = %s",
                         (ROOT_ID,)).fetchone()[0] == 999999

        assert c.execute("SELECT * FROM qo_admin_session_lookup('\\x06')").fetchall() == []
        assert [r[0] for r in c.execute("SELECT user_id FROM qo_admin_session_lookup('\\x05')")
                ] == [ROOT_ID]
        c.execute("SELECT qo_admin_session_create('\\x07', %s, now() + interval '1 hour', NULL)",
                  (ROOT_ID,))
        assert c.execute("SELECT count(*) FROM public.admin_session WHERE id_hash = '\\x07'"
                         ).fetchone()[0] == 1
        assert c.execute("SELECT count(*) FROM pg_temp.admin_session WHERE id_hash = '\\x07'"
                         ).fetchone()[0] == 0
        c.execute("SELECT qo_admin_session_delete('\\x05')")
        assert c.execute("SELECT count(*) FROM pg_temp.admin_session WHERE id_hash = '\\x05'"
                         ).fetchone()[0] == 1
        c.execute("SELECT qo_admin_session_delete_user(%s)", (ROOT_ID,))
        assert c.execute("SELECT count(*) FROM public.admin_session").fetchone()[0] == 0
        assert c.execute("SELECT count(*) FROM pg_temp.admin_session").fetchone()[0] == 2
        # The public sign-in lookup keeps ignoring a planted sysadmin as well.
        assert c.execute("SELECT * FROM qo_login_lookup('evil@x.test')").fetchall() == []


# --- migration ------------------------------------------------------------------------------------

def _inventory(c):
    out = {}
    for sig in list(ADMIN_FUNCTIONS.values()) + list(THROTTLE.values()):
        out[sig] = c.execute(
            "SELECT r.rolname, p.prosecdef, has_function_privilege('qo_web', p.oid, 'EXECUTE'),"
            " has_function_privilege('qo_admin', p.oid, 'EXECUTE'),"
            " has_function_privilege('public', p.oid, 'EXECUTE')"
            " FROM pg_proc p JOIN pg_roles r ON r.oid = p.proowner"
            " WHERE p.oid = to_regprocedure(%s)", (sig,)).fetchone()
    return out


def _assert_inventory(c):
    inv = _inventory(c)
    for sig in ADMIN_FUNCTIONS.values():
        assert inv[sig] == ("qo_definer", True, False, True, False), sig
    for sig in THROTTLE.values():
        assert inv[sig] == ("qo_definer", True, True, True, False), sig


def test_migration_applies_twice(adb):
    adb.migrate()
    adb.migrate()
    with adb.connect() as c:
        _assert_inventory(c)


def test_migration_applies_over_a_stage2b1_database(empty_db):
    with empty_db.connect(autocommit=True) as c:
        c.execute(STAGE2B1_SCHEMA.read_text(encoding="ascii"))
        assert c.execute("SELECT to_regclass('public.admin_factor')").fetchone()[0] is None
        c.execute("INSERT INTO company (id, name, status) VALUES ('c_old', 'Old', 'active')")
        owner = uuid.uuid4()
        c.execute("INSERT INTO app_user (id, company_id, email, pw_hash, pw_salt, role,"
                  " email_verified_at, consent_version, consent_at) VALUES (%s, 'c_old',"
                  " 'old@x.test', '\\x01', '\\x02', 'owner', now(), 'v1', now())", (owner,))
        c.execute("INSERT INTO app_user (id, company_id, email, pw_hash, pw_salt, role,"
                  " email_verified_at, consent_version, consent_at) VALUES (%s, NULL,"
                  " 'root@x.test', '\\x01', '\\x02', 'sysadmin', now(), 'v1', now())", (ROOT_ID,))
        c.execute("INSERT INTO session (id_hash, user_id, expires_at)"
                  " VALUES ('\\x0a', %s, now() + interval '1 day')", (owner,))
        c.execute("INSERT INTO invite (id_hash, company_id, email, role, expires_at)"
                  " VALUES ('\\x0b', 'c_old', 'new@x.test', 'viewer', now() + interval '1 day')")
        c.execute("INSERT INTO auth_throttle VALUES ('\\x0c', 'login_ip', now(), 1, NULL)")
        before = {t: c.execute(f"SELECT count(*) FROM public.{t}").fetchone()[0] for t in TABLES}
        # The stage 2b part 1 lookup still returned the sysadmin's row.
        assert len(c.execute("SELECT * FROM qo_login_lookup('root@x.test')").fetchall()) == 1
    try:
        for _ in range(2):
            empty_db.migrate()
            with empty_db.connect() as c:
                after = {t: c.execute(f"SELECT count(*) FROM public.{t}").fetchone()[0]
                         for t in TABLES}
                assert after == before
                _assert_inventory(c)
                assert c.execute("SELECT count(*) FROM admin_factor").fetchone()[0] == 0
            with empty_db.connect("qo_web") as c:
                assert c.execute("SELECT * FROM qo_login_lookup('root@x.test')").fetchall() == []
                assert c.execute("SELECT id FROM qo_login_lookup('old@x.test')").fetchall() == [
                    (owner,)]
                assert c.execute("SELECT user_id FROM qo_session_lookup('\\x0a')").fetchone() == (
                    owner,)
            with empty_db.connect("qo_admin") as c:
                # The sysadmin of the old database has no factor yet: no admin sign-in until
                # reset-admin gives it one.
                assert c.execute("SELECT * FROM qo_admin_login_lookup('root@x.test')"
                                 ).fetchall() == []
    finally:
        with Db(empty_db.port, "postgres").connect(autocommit=True) as c:
            c.execute(f'DROP DATABASE IF EXISTS "{empty_db.dbname}" WITH (FORCE)')
