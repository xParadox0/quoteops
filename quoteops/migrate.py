"""Apply schema.sql as the owner role. Safe to run repeatedly."""
import os
from importlib import resources

import psycopg
from psycopg import sql

from quoteops.config import owner_conninfo

# Role passwords come from the environment; the SQL file never holds a secret.
_ROLE_PASSWORDS = {"qo_web": "QO_WEB_PASSWORD", "qo_admin": "QO_ADMIN_PASSWORD"}


def migrate(conninfo: str | None = None) -> None:
    ddl = resources.files("quoteops").joinpath("db/schema.sql").read_text(encoding="ascii")
    with psycopg.connect(conninfo or owner_conninfo(), autocommit=True) as conn:
        conn.execute(ddl)
        for role, var in _ROLE_PASSWORDS.items():
            password = os.environ.get(var)
            if password:
                conn.execute(
                    sql.SQL("ALTER ROLE {} PASSWORD {}").format(
                        sql.Identifier(role), sql.Literal(password)
                    )
                )
