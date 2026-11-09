"""Fixtures: a throwaway PostgreSQL container on a random loopback port, removed after the run."""
import secrets
import shutil
import subprocess
import time
import uuid

import psycopg
import pytest

from quoteops.migrate import migrate

OWNER = "qo_owner"
OWNER_PW = secrets.token_hex(8)
WEB_PW = secrets.token_hex(8)
ADMIN_PW = secrets.token_hex(8)
PASSWORDS = {OWNER: OWNER_PW, "qo_web": WEB_PW, "qo_admin": ADMIN_PW}


def _docker_ok() -> bool:
    if not shutil.which("docker"):
        return False
    return subprocess.run(["docker", "info"], capture_output=True).returncode == 0


@pytest.fixture(scope="session")
def pg_server():
    if not _docker_ok():
        pytest.skip("SKIPPED: docker is not available, so the PostgreSQL tests cannot run")
    name = f"quoteops-test-{uuid.uuid4().hex[:8]}"
    run = subprocess.run(
        ["docker", "run", "-d", "--name", name, "--memory", "256m",
         "-e", f"POSTGRES_USER={OWNER}", "-e", f"POSTGRES_PASSWORD={OWNER_PW}",
         "-p", "127.0.0.1::5432", "--tmpfs", "/var/lib/postgresql/data",
         "postgres:16"],
        capture_output=True, text=True,
    )
    if run.returncode != 0:
        pytest.fail(f"could not start the test PostgreSQL container: {run.stderr.strip()}")
    try:
        port = subprocess.run(["docker", "port", name, "5432/tcp"], capture_output=True,
                              text=True, check=True).stdout.split()[0].rsplit(":", 1)[1]
        deadline = time.time() + 60
        while True:
            try:
                psycopg.connect(host="127.0.0.1", port=port, user=OWNER, password=OWNER_PW,
                                dbname="postgres", connect_timeout=2).close()
                break
            except psycopg.OperationalError:
                if time.time() > deadline:
                    pytest.fail("test PostgreSQL container did not become ready in 60 s")
                time.sleep(1)
        yield {"port": port}
    finally:
        subprocess.run(["docker", "rm", "-f", "-v", name], capture_output=True)


class Db:
    def __init__(self, port: str, dbname: str):
        self.port, self.dbname = port, dbname

    def conninfo(self, user: str = OWNER) -> str:
        return psycopg.conninfo.make_conninfo(
            host="127.0.0.1", port=self.port, dbname=self.dbname, user=user,
            password=PASSWORDS[user])

    def connect(self, user: str = OWNER, **kw) -> psycopg.Connection:
        return psycopg.connect(self.conninfo(user), **kw)

    def migrate(self) -> None:
        import os
        os.environ["QO_WEB_PASSWORD"], os.environ["QO_ADMIN_PASSWORD"] = WEB_PW, ADMIN_PW
        migrate(self.conninfo(OWNER))


@pytest.fixture
def empty_db(pg_server):
    """A fresh database, schema not yet applied."""
    dbname = f"t_{uuid.uuid4().hex[:10]}"
    with psycopg.connect(host="127.0.0.1", port=pg_server["port"], user=OWNER,
                         password=OWNER_PW, dbname="postgres", autocommit=True) as c:
        c.execute(f'CREATE DATABASE "{dbname}"')
    return Db(pg_server["port"], dbname)


@pytest.fixture
def db(empty_db):
    """A fresh database with the schema applied and two companies, A and B, with data."""
    empty_db.migrate()
    with empty_db.connect() as c:
        for cid in ("c_a", "c_b"):
            c.execute("INSERT INTO company (id, name) VALUES (%s, %s)", (cid, f"Company {cid}"))
            for n in (1, 2):
                uid = uuid.uuid4()
                c.execute(
                    "INSERT INTO app_user (id, company_id, email, pw_hash, pw_salt, role,"
                    " consent_version, consent_at) VALUES (%s,%s,%s,'\\x00','\\x00','owner','v1',now())",
                    (uid, cid, f"u{n}@{cid}.test"))
                c.execute(
                    "INSERT INTO job (id, company_id, ref, customer, part, qty, status, created_by)"
                    " VALUES (%s,%s,%s,'cust','part',1,'draft',%s)",
                    (uuid.uuid4(), cid, f"J-{n}", uid))
    return empty_db
