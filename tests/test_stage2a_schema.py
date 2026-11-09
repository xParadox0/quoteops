"""Stage 2a schema: the auth_throttle table and the four new SECURITY DEFINER functions follow the
stage 1 pattern, behave as specified, and the migration applies over a stage 1 (6b9b987) database."""
import re
import uuid
from pathlib import Path

import psycopg
import pytest

from tests.conftest import Db
from tests.stage2a_support import adb  # noqa: F401  (fixture)

OLD_FUNCTIONS = {
    "qo_login_lookup": "qo_login_lookup(citext)",
    "qo_session_create": "qo_session_create(bytea, uuid, timestamptz, inet)",
    "qo_session_lookup": "qo_session_lookup(bytea)",
    "qo_session_delete": "qo_session_delete(bytea)",
    "qo_invite_lookup": "qo_invite_lookup(bytea)",
}
NEW_FUNCTIONS = {
    "qo_throttle_check": "qo_throttle_check(bytea, text, integer, integer, integer)",
    "qo_throttle_reset": "qo_throttle_reset(bytea, text)",
    "qo_company_count": "qo_company_count()",
    "qo_session_delete_user": "qo_session_delete_user(uuid)",
}
STAGE1_SCHEMA = Path(__file__).resolve().parent / "data" / "schema_6b9b987.sql"
TABLES = ["company", "app_user", "session", "invite", "job", "drawing", "job_value", "rate",
          "cost_line", "document", "audit_event", "support_grant"]


@pytest.fixture
def db(db):
    yield db
    with Db(db.port, "postgres").connect(autocommit=True) as c:
        c.execute(f'DROP DATABASE IF EXISTS "{db.dbname}" WITH (FORCE)')


def _check(c, key=b"k", kind="t", limit=3, window=900, block=900):
    return c.execute("SELECT qo_throttle_check(%s, %s, %s, %s, %s)",
                     (key, kind, limit, window, block)).fetchone()[0]


def _row(db, key=b"k", kind="t"):
    with db.connect() as c:
        return c.execute("SELECT hits, window_start, blocked_until,"
                         " blocked_until - now() AS left FROM auth_throttle"
                         " WHERE key = %s AND kind = %s", (key, kind)).fetchone()


# --- the table ----------------------------------------------------------------------------------

def test_auth_throttle_columns_and_key(adb):
    with adb.connect() as c:
        cols = c.execute("SELECT column_name, data_type FROM information_schema.columns"
                         " WHERE table_name = 'auth_throttle' ORDER BY ordinal_position").fetchall()
        pk = c.execute("SELECT array_agg(a.attname ORDER BY a.attname) FROM pg_index i"
                       " JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey)"
                       " WHERE i.indrelid = 'auth_throttle'::regclass AND i.indisprimary"
                       ).fetchone()[0]
    assert cols == [("key", "bytea"), ("kind", "text"),
                    ("window_start", "timestamp with time zone"), ("hits", "integer"),
                    ("blocked_until", "timestamp with time zone")]
    assert sorted(pk) == ["key", "kind"]


def test_auth_throttle_rls_forced_without_policy(adb):
    with adb.connect() as c:
        assert c.execute("SELECT relrowsecurity, relforcerowsecurity FROM pg_class"
                         " WHERE oid = 'auth_throttle'::regclass").fetchone() == (True, True)
        assert c.execute("SELECT count(*) FROM pg_policies WHERE tablename = 'auth_throttle'"
                         ).fetchone()[0] == 0


@pytest.mark.parametrize("role", ["qo_web", "qo_admin"])
def test_auth_throttle_no_privilege_for_app_roles(adb, role):
    with adb.connect() as c:
        got = c.execute(
            "SELECT bool_or(has_table_privilege(%s, 'auth_throttle', p))"
            " FROM unnest(ARRAY['SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES',"
            "'TRIGGER']) p", (role,)).fetchone()[0]
        assert got is False
        assert c.execute("SELECT has_any_column_privilege(%s, 'auth_throttle',"
                         " 'SELECT,INSERT,UPDATE,REFERENCES')", (role,)).fetchone()[0] is False
    for stmt in ("SELECT count(*) FROM auth_throttle", "DELETE FROM auth_throttle",
                 "INSERT INTO auth_throttle VALUES ('\\x00', 'x', now(), 1, NULL)"):
        with adb.connect(role) as c:
            with pytest.raises(psycopg.errors.InsufficientPrivilege, match="permission denied"):
                c.execute(stmt)


def test_definer_privileges_on_auth_throttle(adb):
    with adb.connect() as c:
        privs = {r[0] for r in c.execute(
            "SELECT a.privilege_type FROM pg_class cl, aclexplode(cl.relacl) a"
            " WHERE cl.oid = 'auth_throttle'::regclass AND a.grantee = 'qo_definer'::regrole")}
    assert privs == {"SELECT", "INSERT", "UPDATE", "DELETE"}


# --- function properties (the stage 1 pattern) ----------------------------------------------------

@pytest.mark.parametrize("sig", NEW_FUNCTIONS.values())
def test_new_function_definer_owner_search_path(adb, sig):
    with adb.connect() as c:
        row = c.execute("SELECT p.prosecdef, p.proconfig, r.rolname, r.rolsuper"
                        " FROM pg_proc p JOIN pg_roles r ON r.oid = p.proowner"
                        " WHERE p.oid = to_regprocedure(%s)", (sig,)).fetchone()
    assert row is not None, sig
    assert row == (True, ["search_path=pg_catalog, public, pg_temp"], "qo_definer", False)


@pytest.mark.parametrize("sig", NEW_FUNCTIONS.values())
def test_new_function_execute_only_for_web(adb, sig):
    with adb.connect() as c:
        got = c.execute(
            "SELECT has_function_privilege('qo_web', %s, 'EXECUTE'),"
            "       has_function_privilege('qo_admin', %s, 'EXECUTE'),"
            "       has_function_privilege('public', %s, 'EXECUTE')", (sig, sig, sig)).fetchone()
        grantees = {r[0] for r in c.execute(
            "SELECT a.grantee::regrole::text FROM pg_proc p, aclexplode(p.proacl) a"
            " WHERE p.oid = to_regprocedure(%s) AND a.grantee <> p.proowner", (sig,))}
    # Stage 2b part 2: the admin service rate-limits its sign-in with the two throttle
    # functions, so qo_admin may call those two and no other function of this list.
    for_admin = sig.startswith("qo_throttle_")
    assert got == (True, for_admin, False)
    assert grantees == ({"qo_web", "qo_admin"} if for_admin else {"qo_web"})


@pytest.mark.parametrize("sig", NEW_FUNCTIONS.values())
def test_new_function_body_qualifies_every_table(adb, sig):
    with adb.connect() as c:
        src = c.execute("SELECT prosrc FROM pg_proc WHERE oid = to_regprocedure(%s)",
                        (sig,)).fetchone()[0]
    # "ON CONFLICT ... DO UPDATE SET" names no table.
    names = re.findall(r"\b(?:FROM|JOIN|INTO|UPDATE)\s+(?!SET\b)([A-Za-z_][\w.]*)", src,
                       re.IGNORECASE)
    assert names
    assert all(n.startswith("public.") for n in names), names


def test_admin_cannot_call_new_functions(adb):
    calls = ["SELECT qo_company_count()", "SELECT qo_session_delete_user(gen_random_uuid())"]
    for call in calls:
        with adb.connect("qo_admin") as c:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                c.execute(call)
    # Stage 2b part 2: the admin service's sign-in throttle.
    with adb.connect("qo_admin") as c:
        assert c.execute("SELECT qo_throttle_check('\\x00', 'x', 1, 1, 1)").fetchone()[0] is True
        c.execute("SELECT qo_throttle_reset('\\x00', 'x')")


def test_new_functions_ignore_planted_temp_tables(db):
    """The owner may create temporary tables; shadows of company, session and auth_throttle in the
    calling session must not change what the functions count, delete or write."""
    with db.connect() as c:
        ua = c.execute("SELECT id FROM public.app_user WHERE email = 'u1@c_a.test'").fetchone()[0]
        c.execute("INSERT INTO public.session (id_hash, user_id, expires_at)"
                  " VALUES ('\\x0a', %s, now() + interval '1 day')", (ua,))
        c.execute("UPDATE public.company SET status = 'active'")  # only verified ones count
    with db.connect(autocommit=True) as c:
        for t in ("company", "session", "auth_throttle"):
            c.execute(f"CREATE TEMP TABLE {t} (LIKE public.{t} INCLUDING DEFAULTS)")
        c.execute("INSERT INTO pg_temp.company (id, name, status)"
                  " SELECT 'x' || g, 'x', 'active' FROM generate_series(1, 9) g")
        c.execute("INSERT INTO pg_temp.session (id_hash, user_id, expires_at)"
                  " VALUES ('\\x0b', %s, now() + interval '1 day')", (ua,))
        assert c.execute("SELECT qo_company_count()").fetchone()[0] == 2
        assert _check(c, key=b"p", limit=1) is True
        assert c.execute("SELECT count(*) FROM public.auth_throttle").fetchone()[0] == 1
        assert c.execute("SELECT count(*) FROM pg_temp.auth_throttle").fetchone()[0] == 0
        c.execute("SELECT qo_session_delete_user(%s)", (ua,))
        assert c.execute("SELECT count(*) FROM public.session").fetchone()[0] == 0
        assert c.execute("SELECT count(*) FROM pg_temp.session").fetchone()[0] == 1


# --- qo_throttle_check / qo_throttle_reset --------------------------------------------------------

def test_throttle_allows_up_to_limit_then_blocks(adb):
    with adb.connect("qo_web", autocommit=True) as c:
        assert [_check(c) for _ in range(3)] == [True, True, True]
        assert _check(c) is False
        assert _check(c) is False
    hits, _, blocked_until, left = _row(adb)
    assert blocked_until is not None
    assert 890 <= left.total_seconds() <= 900


def test_throttle_block_does_not_extend_while_blocked(adb):
    with adb.connect("qo_web", autocommit=True) as c:
        for _ in range(4):
            _check(c)
    first = _row(adb)[2]
    with adb.connect("qo_web", autocommit=True) as c:
        assert _check(c) is False
    assert _row(adb)[2] == first


def test_throttle_block_expires(adb):
    with adb.connect("qo_web", autocommit=True) as c:
        for _ in range(4):
            _check(c)
    with adb.connect() as c:  # the clock: move the block and the window into the past
        c.execute("UPDATE auth_throttle SET blocked_until = now() - interval '1 second',"
                  " window_start = now() - interval '16 minutes'")
    with adb.connect("qo_web", autocommit=True) as c:
        assert _check(c) is True
    hits, _, blocked_until, _ = _row(adb)
    assert (hits, blocked_until) == (1, None)


def test_throttle_window_expires_without_block(adb):
    with adb.connect("qo_web", autocommit=True) as c:
        assert _check(c) and _check(c) and _check(c)
    with adb.connect() as c:
        c.execute("UPDATE auth_throttle SET window_start = now() - interval '901 seconds'")
    with adb.connect("qo_web", autocommit=True) as c:
        assert _check(c) is True
        assert _check(c) is True
    assert _row(adb)[0] == 2


def test_throttle_keys_and_kinds_are_separate(adb):
    with adb.connect("qo_web", autocommit=True) as c:
        for _ in range(4):
            _check(c, key=b"a", kind="x", limit=3)
        assert _check(c, key=b"a", kind="x", limit=3) is False
        assert _check(c, key=b"a", kind="y", limit=3) is True
        assert _check(c, key=b"b", kind="x", limit=3) is True


def test_throttle_reset_deletes_row(adb):
    with adb.connect("qo_web", autocommit=True) as c:
        for _ in range(4):
            _check(c)
        c.execute("SELECT qo_throttle_reset(%s, %s)", (b"k", "t"))
        assert _check(c) is True
    assert _row(adb)[0] == 1


@pytest.mark.parametrize("call", ["check", "reset"])
def test_throttle_functions_delete_rows_older_than_one_day(adb, call):
    with adb.connect() as c:
        c.execute("INSERT INTO auth_throttle VALUES ('\\x01', 'old', now() - interval '25 hours', 9, NULL),"
                  " ('\\x02', 'old', now() - interval '25 hours', 9, now() - interval '20 hours'),"
                  " ('\\x03', 'recent', now() - interval '23 hours', 9, NULL)")
    with adb.connect("qo_web", autocommit=True) as c:
        if call == "check":
            _check(c, key=b"z")
        else:
            c.execute("SELECT qo_throttle_reset(%s, %s)", (b"z", "t"))
    with adb.connect() as c:
        kinds = sorted(r[0] for r in c.execute("SELECT kind FROM auth_throttle WHERE key <> '\\x7a'"))
    assert kinds == ["recent"]


def test_throttle_null_key_is_refused(adb):
    with adb.connect("qo_web", autocommit=True) as c:
        with pytest.raises(psycopg.errors.NotNullViolation):
            _check(c, key=None)


# --- qo_company_count / qo_session_delete_user -----------------------------------------------------

def test_company_count_ignores_rls(db):
    """The count is of verified companies only; the fixture's two start unverified."""
    with db.connect("qo_web") as c:
        assert c.execute("SELECT qo_company_count()").fetchone()[0] == 0
    with db.connect() as c:
        c.execute("UPDATE company SET status = 'active'")
    with db.connect("qo_web") as c:
        assert c.execute("SELECT count(*) FROM company").fetchone()[0] == 0
        assert c.execute("SELECT qo_company_count()").fetchone()[0] == 2
        c.execute("SELECT set_config('app.company_id', 'c_a', false)")
        assert c.execute("SELECT qo_company_count()").fetchone()[0] == 2


def test_session_delete_user_deletes_only_that_user(db):
    with db.connect() as c:
        ids = [r[0] for r in c.execute("SELECT id FROM app_user ORDER BY email")]
        for n, uid in enumerate(ids):
            for k in range(2):
                c.execute("INSERT INTO session (id_hash, user_id, expires_at)"
                          " VALUES (%s, %s, now() + interval '1 day')", (bytes([n, k]), uid))
    with db.connect("qo_web", autocommit=True) as c:
        c.execute("SELECT qo_session_delete_user(%s)", (ids[0],))
        c.execute("SELECT qo_session_delete_user(NULL)")
        c.execute("SELECT qo_session_delete_user(%s)", (uuid.uuid4(),))
    with db.connect() as c:
        left = {r[0] for r in c.execute("SELECT user_id FROM session")}
        assert c.execute("SELECT count(*) FROM session").fetchone()[0] == 6
    assert left == set(ids[1:])


# --- migration over a stage 1 database ------------------------------------------------------------

def test_migration_applies_over_a_stage1_database(empty_db):
    with empty_db.connect(autocommit=True) as c:
        c.execute(STAGE1_SCHEMA.read_text(encoding="ascii"))
        c.execute("INSERT INTO company (id, name, status) VALUES ('c_old', 'Old', 'active')")
        uid = uuid.uuid4()
        c.execute("INSERT INTO app_user (id, company_id, email, pw_hash, pw_salt, role,"
                  " consent_version, consent_at) VALUES (%s, 'c_old', 'old@x.test', '\\x01',"
                  " '\\x02', 'owner', 'v1', now())", (uid,))
        c.execute("INSERT INTO session (id_hash, user_id, expires_at)"
                  " VALUES ('\\x0a', %s, now() + interval '1 day')", (uid,))
        assert c.execute("SELECT to_regclass('public.auth_throttle')").fetchone()[0] is None
        before = {t: c.execute(f"SELECT count(*) FROM public.{t}").fetchone()[0] for t in TABLES}
    try:
        for _ in range(2):
            empty_db.migrate()
            with empty_db.connect() as c:
                after = {t: c.execute(f"SELECT count(*) FROM public.{t}").fetchone()[0]
                         for t in TABLES}
                assert after == before
                for sig in list(OLD_FUNCTIONS.values()) + list(NEW_FUNCTIONS.values()):
                    row = c.execute(
                        "SELECT r.rolname, p.prosecdef, has_function_privilege('qo_web', p.oid,"
                        " 'EXECUTE'), has_function_privilege('qo_admin', p.oid, 'EXECUTE'),"
                        " has_function_privilege('public', p.oid, 'EXECUTE')"
                        " FROM pg_proc p JOIN pg_roles r ON r.oid = p.proowner"
                        " WHERE p.oid = to_regprocedure(%s)", (sig,)).fetchone()
                    # Stage 2b part 2: qo_admin also executes the two throttle functions.
                    for_admin = sig.startswith("qo_throttle_")
                    assert row == ("qo_definer", True, True, for_admin, False), sig
            with empty_db.connect("qo_web") as c:
                assert c.execute("SELECT user_id FROM qo_session_lookup('\\x0a')").fetchone() == (uid,)
                assert c.execute("SELECT qo_company_count()").fetchone()[0] == 1
                assert c.execute("SELECT qo_throttle_check('\\x01', 'm', 5, 60, 60)").fetchone()[0]
    finally:
        with Db(empty_db.port, "postgres").connect(autocommit=True) as c:
            c.execute(f'DROP DATABASE IF EXISTS "{empty_db.dbname}" WITH (FORCE)')
