"""Database connections for the web role."""
from contextlib import contextmanager

import psycopg

from quoteops.config import web_conninfo


@contextmanager
def tenant_conn(company_id: str, conninfo: str | None = None):
    """One transaction scoped to a company. The setting dies with the transaction."""
    with psycopg.connect(conninfo or web_conninfo()) as conn:
        with conn.transaction():
            conn.execute("SELECT set_config('app.company_id', %s, true)", (company_id,))
            yield conn


def lookup_conn() -> psycopg.Connection:
    """A connection with no company, for the qo_* functions that run before one is known."""
    return psycopg.connect(web_conninfo(), autocommit=True)
