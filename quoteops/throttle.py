"""Rate limits kept in PostgreSQL (auth_throttle), so they hold across restarts and workers.
The stored key is sha256(kind|value|secret): never the raw email or address."""
import hashlib

import psycopg


def key(kind: str, value: str, secret: bytes) -> bytes:
    return hashlib.sha256(f"{kind}|{value}|".encode("utf-8") + secret).digest()


def hit(conn: psycopg.Connection, kind: str, value: str, secret: bytes, limit: int,
        window_seconds: int, block_seconds: int) -> bool:
    """Count one attempt; True when the caller may go on."""
    return conn.execute("SELECT qo_throttle_check(%s, %s, %s, %s, %s)",
                        (key(kind, value, secret), kind, limit, window_seconds, block_seconds)
                        ).fetchone()[0]


def reset(conn: psycopg.Connection, kind: str, value: str, secret: bytes) -> None:
    conn.execute("SELECT qo_throttle_reset(%s, %s)", (key(kind, value, secret), kind))
