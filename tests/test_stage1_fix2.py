"""Stage 1 fix 2: the SECURITY DEFINER lookups cannot be redirected to a temporary table, and a
suspended or deleting company's sessions stop resolving."""
import re
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
TABLES = ["company", "app_user", "session", "invite"]

LIVE_A, LIVE_B, LIVE_SYS = b"\x0a", b"\x0b", b"\x05"
PLANTED = b"\x77"


@pytest.fixture
def db(db):
    """The shared fixture, plus a drop afterwards (see tests/test_stage1_fix.py)."""
    yield db
    with Db(db.port, "postgres").connect(autocommit=True) as c:
        c.execute(f'DROP DATABASE IF EXISTS "{db.dbname}" WITH (FORCE)')


@pytest.fixture
def seeded(db):
    """Live sessions for a user of company A, of company B, and of a sysadmin."""
    with db.connect() as c:
        ua = c.execute("SELECT id FROM public.app_user WHERE email = 'u1@c_a.test'").fetchone()[0]
        ub = c.execute("SELECT id FROM public.app_user WHERE email = 'u1@c_b.test'").fetchone()[0]
        us = uuid.uuid4()
        c.execute("INSERT INTO public.app_user (id, company_id, email, pw_hash, pw_salt, role,"
                  " consent_version, consent_at)"
                  " VALUES (%s, NULL, 'root@ops.test', '\\x00', '\\x00', 'sysadmin', 'v1', now())",
                  (us,))
        for h, uid in ((LIVE_A, ua), (LIVE_B, ub), (LIVE_SYS, us)):
            c.execute("INSERT INTO public.session (id_hash, user_id, expires_at)"
                      " VALUES (%s, %s, now() + interval '1 day')", (h, uid))
    return {"db": db, "ua": ua, "ub": ub, "us": us}


# --- D5: no temporary tables for the application roles ------------------------------------------

@pytest.mark.parametrize("role", ["qo_web", "qo_admin"])
def test_role_cannot_create_temp_table(db, role):
    with db.connect(role) as c:
        with pytest.raises(psycopg.errors.InsufficientPrivilege, match="permission denied"):
            c.execute("CREATE TEMP TABLE t (x int)")


def test_temporary_revoked_on_database(db):
    with db.connect() as c:
        got = c.execute(
            "SELECT has_database_privilege('public', current_database(), 'TEMPORARY'),"
            "       has_database_privilege('qo_web', current_database(), 'TEMPORARY'),"
            "       has_database_privilege('qo_admin', current_database(), 'TEMPORARY')"
        ).fetchone()
    assert got == (False, False, False)


def test_web_cannot_plant_temp_app_user(db):
    """The reviewer's replay: qo_web shadows app_user with a temporary table of its own."""
    with db.connect("qo_web") as c:
        with pytest.raises(psycopg.errors.InsufficientPrivilege, match="permission denied"):
            c.execute("CREATE TEMP TABLE app_user (id uuid, company_id text, email citext,"
                      " pw_hash bytea, pw_salt bytea, role text, email_verified_at timestamptz,"
                      " disabled_at timestamptz)")
    with db.connect("qo_web") as c:
        assert c.execute("SELECT * FROM qo_login_lookup('evil@x.test')").fetchall() == []


def test_functions_ignore_planted_temp_tables(seeded):
    """Independent of the TEMPORARY revoke: the owner, who may create temporary tables, plants
    shadows of every table the functions read, in the same session that calls them. The
    functions run as qo_definer and must still read and write the public tables only."""
    db, ua, ub = seeded["db"], seeded["ua"], seeded["ub"]
    evil = uuid.uuid4()
    new_hash = b"\x42" * 32
    with db.connect(autocommit=True) as c:
        for t in TABLES:
            c.execute(f"CREATE TEMP TABLE {t} (LIKE public.{t} INCLUDING DEFAULTS)")
            c.execute(f"GRANT ALL ON pg_temp.{t} TO PUBLIC")
        c.execute("INSERT INTO pg_temp.company (id, name, status, created_at)"
                  " VALUES ('c_a', 'planted', 'suspended', now()), ('c_evil', 'planted', 'active', now())")
        for uid, cid, email in ((evil, "c_evil", "evil@x.test"), (ua, "c_evil", "u1@c_a.test")):
            c.execute("INSERT INTO pg_temp.app_user (id, company_id, email, pw_hash, pw_salt, role,"
                      " consent_version, consent_at)"
                      " VALUES (%s, %s, %s, '\\xee', '\\xee', 'owner', 'v1', now())", (uid, cid, email))
        for h, uid in ((PLANTED, evil), (LIVE_A, evil), (LIVE_B, ub)):
            c.execute("INSERT INTO pg_temp.session (id_hash, user_id, expires_at)"
                      " VALUES (%s, %s, now() + interval '1 day')", (h, uid))
        c.execute("INSERT INTO pg_temp.invite (id_hash, company_id, email, role, expires_at)"
                  " VALUES (%s, 'c_evil', 'evil@x.test', 'owner', now() + interval '1 day')",
                  (PLANTED,))

        assert c.execute("SELECT * FROM qo_login_lookup('evil@x.test')").fetchall() == []
        rows = c.execute("SELECT company_id, pw_hash FROM qo_login_lookup('u1@c_a.test')").fetchall()
        assert rows == [("c_a", b"\x00")]

        assert c.execute("SELECT * FROM qo_session_lookup(%s)", (PLANTED,)).fetchall() == []
        rows = c.execute("SELECT user_id, company_id FROM qo_session_lookup(%s)", (LIVE_A,)).fetchall()
        assert rows == [(ua, "c_a")]
        assert c.execute("SELECT * FROM qo_invite_lookup(%s)", (PLANTED,)).fetchall() == []

        c.execute("SELECT qo_session_create(%s, %s, now() + interval '1 hour', NULL)", (new_hash, ua))
        assert c.execute("SELECT count(*) FROM public.session WHERE id_hash = %s",
                         (new_hash,)).fetchone()[0] == 1
        assert c.execute("SELECT count(*) FROM pg_temp.session WHERE id_hash = %s",
                         (new_hash,)).fetchone()[0] == 0

        c.execute("SELECT qo_session_delete(%s)", (LIVE_B,))
        assert c.execute("SELECT count(*) FROM public.session WHERE id_hash = %s",
                         (LIVE_B,)).fetchone()[0] == 0
        assert c.execute("SELECT count(*) FROM pg_temp.session WHERE id_hash = %s",
                         (LIVE_B,)).fetchone()[0] == 1


@pytest.mark.parametrize("sig", FUNCTIONS.values())
def test_function_search_path_ends_with_pg_temp(db, sig):
    with db.connect() as c:
        config = c.execute("SELECT proconfig FROM pg_proc WHERE oid = %s::regprocedure",
                           (sig,)).fetchone()[0]
    paths = [e for e in config if e.startswith("search_path=")]
    assert len(paths) == 1
    elements = [p.strip() for p in paths[0].split("=", 1)[1].split(",")]
    assert elements[0] == "pg_catalog"
    assert elements[-1] == "pg_temp"


@pytest.mark.parametrize("sig", FUNCTIONS.values())
def test_function_body_qualifies_every_table(db, sig):
    with db.connect() as c:
        src = c.execute("SELECT prosrc FROM pg_proc WHERE oid = %s::regprocedure",
                        (sig,)).fetchone()[0]
    names = re.findall(r"\b(?:FROM|JOIN|INTO|UPDATE)\s+([A-Za-z_][\w.]*)", src, re.IGNORECASE)
    assert names
    assert all(n.startswith("public.") for n in names), names


# --- D6: a suspended or deleting company's sessions do not resolve -----------------------------

@pytest.mark.parametrize("status,expected", [
    ("active", 1), ("unverified", 1), ("suspended", 0), ("deleting", 0),
])
def test_session_lookup_follows_company_status(seeded, status, expected):
    db = seeded["db"]
    with db.connect() as c:
        c.execute("UPDATE public.company SET status = %s WHERE id = 'c_a'", (status,))
    with db.connect("qo_web") as c:
        rows = c.execute("SELECT user_id, company_id FROM qo_session_lookup(%s)", (LIVE_A,)).fetchall()
        assert len(rows) == expected
        if expected:
            assert rows == [(seeded["ua"], "c_a")]
        # Company B is untouched by A's status.
        assert len(c.execute("SELECT * FROM qo_session_lookup(%s)", (LIVE_B,)).fetchall()) == 1


def test_sysadmin_session_resolves_while_companies_suspended(seeded):
    db = seeded["db"]
    with db.connect() as c:
        c.execute("UPDATE public.company SET status = 'suspended'")
    with db.connect("qo_web") as c:
        rows = c.execute("SELECT user_id, company_id, role FROM qo_session_lookup(%s)",
                         (LIVE_SYS,)).fetchall()
    assert rows == [(seeded["us"], None, "sysadmin")]


def test_login_lookup_reports_company_status(seeded):
    db = seeded["db"]
    with db.connect() as c:
        c.execute("UPDATE public.company SET status = 'suspended' WHERE id = 'c_a'")
    with db.connect("qo_web") as c:
        cur = c.execute("SELECT * FROM qo_login_lookup('u1@c_a.test')")
        cols = [d.name for d in cur.description]
        rows = cur.fetchall()
        assert "company_status" in cols
        status = cols.index("company_status")
        assert len(rows) == 1 and rows[0][status] == "suspended"
        rows = c.execute("SELECT company_status FROM qo_login_lookup('u1@c_b.test')").fetchall()
        assert rows == [("unverified",)]
        # Stage 2b part 2: the public sign-in lookup never returns a sysadmin row.
        rows = c.execute("SELECT company_id, company_status FROM qo_login_lookup('root@ops.test')"
                         ).fetchall()
        assert rows == []
