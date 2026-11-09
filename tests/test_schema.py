import uuid

import psycopg
import pytest

TABLES = ["company", "app_user", "session", "invite", "job", "drawing", "job_value", "rate",
          "cost_line", "document", "audit_event", "support_grant"]
CONTENT_TABLES = ["job", "drawing", "job_value", "cost_line", "document", "rate"]


def test_schema_loads_twice(empty_db):
    empty_db.migrate()
    empty_db.migrate()
    with empty_db.connect() as c:
        have = {r[0] for r in c.execute(
            "SELECT tablename FROM pg_tables WHERE schemaname = 'public'")}
    assert set(TABLES) <= have


def test_rls_enabled_and_forced_on_every_company_id_table(db):
    with db.connect() as c:
        tenant = {r[0] for r in c.execute(
            "SELECT c.table_name FROM information_schema.columns c"
            " JOIN information_schema.tables t USING (table_schema, table_name)"
            " WHERE c.table_schema='public' AND c.column_name='company_id'"
            " AND t.table_type='BASE TABLE'")}
        tenant.add("company")
        assert tenant >= set(TABLES) - {"session"}
        for t in tenant:
            row = c.execute("SELECT relrowsecurity, relforcerowsecurity FROM pg_class"
                            " WHERE oid = %s::regclass", (t,)).fetchone()
            assert row == (True, True), f"{t}: RLS enabled/forced = {row}"


def test_web_without_company_sees_zero_rows(db):
    with db.connect() as c:  # the owner proves rows exist for both companies
        assert c.execute("SELECT count(*) FROM job").fetchone()[0] == 4
    with db.connect("qo_web") as c:
        assert c.execute("SELECT count(*) FROM job").fetchone()[0] == 0
        assert c.execute("SELECT count(*) FROM app_user").fetchone()[0] == 0


def test_web_with_company_sees_only_that_company_and_cannot_write_to_another(db):
    with db.connect("qo_web") as c:
        c.execute("SELECT set_config('app.company_id', 'c_a', true)")
        rows = c.execute("SELECT DISTINCT company_id FROM job").fetchall()
        assert rows == [("c_a",)]
        assert c.execute("SELECT count(*) FROM job").fetchone()[0] == 2
        with pytest.raises(psycopg.errors.InsufficientPrivilege, match="row-level security"):
            c.execute(
                "INSERT INTO job (id, company_id, ref, customer, part, qty, status, created_by)"
                " VALUES (%s,'c_b','J-9','x','x',1,'draft',%s)", (uuid.uuid4(), uuid.uuid4()))
    with db.connect("qo_web") as c:
        c.execute("SELECT set_config('app.company_id', 'c_a', true)")
        n = c.execute("UPDATE job SET customer = 'hacked' WHERE company_id = 'c_b'").rowcount
        assert n == 0
    with db.connect() as c:
        assert c.execute("SELECT count(*) FROM job WHERE customer='hacked'").fetchone()[0] == 0


def test_tenant_setting_does_not_leak_across_transactions(db):
    from quoteops.app import tenant_conn
    with tenant_conn("c_a", db.conninfo("qo_web")) as c:
        assert c.execute("SELECT count(*) FROM job").fetchone()[0] == 2
    with db.connect("qo_web") as c:
        assert c.execute("SELECT count(*) FROM job").fetchone()[0] == 0


def test_web_role_cannot_alter_or_drop_and_has_no_bypassrls(db):
    with db.connect() as c:
        row = c.execute("SELECT rolbypassrls, rolsuper, rolcanlogin FROM pg_roles"
                        " WHERE rolname = 'qo_web'").fetchone()
        assert row == (False, False, True)
        owner = c.execute("SELECT tableowner FROM pg_tables WHERE tablename = 'job'").fetchone()[0]
        assert owner != "qo_web"
    for stmt in ("ALTER TABLE job ADD COLUMN x int", "DROP TABLE job", "TRUNCATE job",
                 "CREATE TABLE evil (id int)", "ALTER TABLE job DISABLE ROW LEVEL SECURITY"):
        with db.connect("qo_web") as c:
            with pytest.raises((psycopg.errors.InsufficientPrivilege,
                                psycopg.errors.UndefinedTable)):
                c.execute(stmt)


def test_admin_role_has_no_bypassrls(db):
    with db.connect() as c:
        row = c.execute("SELECT rolbypassrls, rolsuper FROM pg_roles"
                        " WHERE rolname = 'qo_admin'").fetchone()
        assert row == (False, False)


def test_admin_reads_usage_and_users_across_companies(db):
    with db.connect("qo_admin") as c:
        usage = c.execute("SELECT * FROM company_usage ORDER BY company_id").fetchall()
        cols = [d.name for d in c.execute("SELECT * FROM company_usage").description]
        assert [r[0] for r in usage] == ["c_a", "c_b"]
        assert "jobs" in cols and "users" in cols
        assert not {"customer", "part", "name", "email", "ref"} & set(cols)
        jobs_ix, users_ix = cols.index("jobs"), cols.index("users")
        assert all(r[jobs_ix] == 2 and r[users_ix] == 2 for r in usage)
        assert c.execute("SELECT count(*) FROM app_user").fetchone()[0] == 4
        assert c.execute("SELECT count(*) FROM company").fetchone()[0] == 2


@pytest.mark.parametrize("table", CONTENT_TABLES)
def test_admin_denied_on_content_tables(db, table):
    with db.connect("qo_admin") as c:
        with pytest.raises(psycopg.errors.InsufficientPrivilege, match="permission denied"):
            c.execute(f"SELECT 1 FROM {table} LIMIT 1")


def test_sysadmin_with_company_id_fails(db):
    with db.connect() as c:
        with pytest.raises(psycopg.errors.CheckViolation):
            c.execute(
                "INSERT INTO app_user (id, company_id, email, pw_hash, pw_salt, role,"
                " consent_version, consent_at) VALUES (%s,'c_a','s@x.test','\\x00','\\x00',"
                "'sysadmin','v1',now())", (uuid.uuid4(),))


def test_owner_without_company_id_fails(db):
    with db.connect() as c:
        with pytest.raises(psycopg.errors.CheckViolation):
            c.execute(
                "INSERT INTO app_user (id, company_id, email, pw_hash, pw_salt, role,"
                " consent_version, consent_at) VALUES (%s,NULL,'o@x.test','\\x00','\\x00',"
                "'owner','v1',now())", (uuid.uuid4(),))


def test_check_accepts_the_valid_combinations(db):
    with db.connect() as c:
        c.execute("INSERT INTO app_user (id, company_id, email, pw_hash, pw_salt, role,"
                  " consent_version, consent_at) VALUES (%s,NULL,'s@x.test','\\x00','\\x00',"
                  "'sysadmin','v1',now())", (uuid.uuid4(),))
