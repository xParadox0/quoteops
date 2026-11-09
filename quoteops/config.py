"""Settings, read from the environment. Passwords and the secret never leave this module's callers,
and no error message repeats a value."""
import math
import os
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import psycopg


def _conninfo(user: str, password: str) -> str:
    return psycopg.conninfo.make_conninfo(
        host=os.environ.get("QO_DB_HOST", "localhost"),
        port=os.environ.get("QO_DB_PORT", "5432"),
        dbname=os.environ.get("QO_DB_NAME", "quoteops"),
        user=user,
        password=password,
    )


def web_conninfo() -> str:
    return _conninfo("qo_web", os.environ["QO_WEB_PASSWORD"])


def admin_conninfo() -> str:
    """The admin service's only database login (stage 2b part 2); never the web role."""
    return _conninfo("qo_admin", os.environ["QO_ADMIN_PASSWORD"])


def owner_conninfo() -> str:
    return _conninfo(os.environ.get("QO_OWNER_USER", "qo_owner"), os.environ["QO_OWNER_PASSWORD"])


class ConfigError(Exception):
    """A setting is missing or invalid. The message names the variable, never its value."""


@dataclass(frozen=True)
class Settings:
    secret: bytes               # QO_SECRET: HMAC key for mail tokens, CSRF tokens, throttle keys
    base_url: str               # QO_BASE_URL without a trailing slash; every mail link starts here
    base_origin: str            # scheme://host[:port] of base_url, for the Origin check
    mail: str                   # QO_MAIL: "file" (default) or "graph"
    mail_dir: str
    cookie_secure: bool
    client_ip_header: str | None  # None: the socket address is the client
    max_companies: int
    login_fails_per_email: int
    login_fails_per_ip: int
    login_window_seconds: int
    login_block_seconds: int
    forgot_per_email: int       # per hour
    forgot_per_ip: int          # per hour
    signup_per_ip: int          # per hour
    signup_per_email: int       # per hour
    scrypt_concurrency: int     # scrypt computations at once in this process
    scrypt_wait_seconds: float  # how long a request waits for one before the answer is 503
    unverified_max_age_hours: int  # an unverified company is deleted after this
    unverified_keep: int        # and beyond this many newest unverified companies
    max_users_per_company: int  # users plus pending invitations of one company
    invites_per_day: int        # invitations per company per day
    invites_per_address_per_day: int  # invitations per recipient address per day, all companies
    # Stage 2b part 3, read only when QO_MAIL=graph; "" otherwise. The secret is kept out of repr.
    graph_tenant: str = ""      # QO_GRAPH_TENANT (a GUID)
    graph_client_id: str = ""   # QO_GRAPH_CLIENT_ID (a GUID)
    graph_client_secret: str = field(default="", repr=False)  # QO_GRAPH_CLIENT_SECRET
    mail_from: str = ""         # QO_MAIL_FROM: the sender's user principal name
    # Stage 3a: drawing uploads (PRD section 6). One MB is 1048576 bytes.
    max_file_mb: int = 25       # QO_MAX_FILE_MB: one drawing
    max_company_mb: int = 500   # QO_MAX_COMPANY_MB: all drawings of one company
    max_jobs_per_month: int = 50  # QO_MAX_JOBS_PER_MONTH: jobs created per calendar month (UTC)
    files_dir: str = "/var/qo-files"  # QO_FILES_DIR: the files volume, one folder per company


@dataclass(frozen=True)
class AdminSettings:
    """The admin service's settings (stage 2b part 2). It reads neither QO_WEB_PASSWORD nor
    QO_SECRET: its database login is qo_admin and its HMAC key is QO_ADMIN_SECRET, so the two
    services share no password and no key."""
    secret: bytes               # QO_ADMIN_SECRET: HMAC key for admin CSRF tokens and throttle keys
    base_url: str               # QO_ADMIN_BASE_URL without a trailing slash
    base_origin: str            # scheme://host[:port] of base_url, for the Origin check
    cookie_secure: bool
    client_ip_header: str | None
    session_hours: int          # absolute lifetime of an admin session, never extended
    login_fails_per_email: int
    login_fails_per_ip: int
    login_window_seconds: int
    login_block_seconds: int


# An unverified account must outlive its 48-hour verification link (auth.VERIFY_SECONDS), so a
# link that still works never points at a deleted account.
UNVERIFIED_MIN_AGE_HOURS = 49

_BOOLEANS = {"true": True, "1": True, "yes": True, "false": False, "0": False, "no": False}


def _positive_int(name: str, default: int, maximum: int | None = None, minimum: int = 1) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ConfigError(f"{name} must be a whole number") from None
    if value < minimum:
        raise ConfigError(f"{name} must be at least {minimum}")
    if maximum is not None and value > maximum:
        raise ConfigError(f"{name} must be at most {maximum}")
    return value


def _positive_number(name: str, default: float, maximum: float) -> float:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        raise ConfigError(f"{name} must be a number") from None
    if not math.isfinite(value) or value <= 0:
        raise ConfigError(f"{name} must be a positive number")
    if value > maximum:  # a huge finite wait passes the checks above but overflows the timeout
        raise ConfigError(f"{name} must be at most {maximum:g}")
    return value


def scrypt_limits() -> tuple[int, float]:
    """QO_SCRYPT_CONCURRENCY (1 to 64) and QO_SCRYPT_WAIT_SECONDS (above 0, at most 3600). One
    scrypt needs 32 MiB, so the default of 3 at once is about 100 MB of a web container limited
    to 512 MiB."""
    return (_positive_int("QO_SCRYPT_CONCURRENCY", 3, maximum=64),
            _positive_number("QO_SCRYPT_WAIT_SECONDS", 8.0, maximum=3600))


MB = 1024 * 1024


def max_file_bytes() -> int:
    """QO_MAX_FILE_MB (1 to 200, default 25) in bytes. Read on every upload request by the
    request size guard, which runs before the route and so before load_settings."""
    return _positive_int("QO_MAX_FILE_MB", 25, maximum=200) * MB


def _files_dir() -> str:
    raw = os.environ.get("QO_FILES_DIR", "").strip() or "/var/qo-files"
    if not os.path.isabs(raw) or "\0" in raw:
        raise ConfigError("QO_FILES_DIR must be an absolute path such as /var/qo-files")
    return os.path.normpath(raw)


def _secret(name: str) -> bytes:
    secret = os.environ.get(name, "")
    if not secret:
        raise ConfigError(f"{name} is required: set it to a random value of at least 32 characters")
    if len(secret) < 32:
        raise ConfigError(f"{name} is too short: it needs at least 32 characters")
    return secret.encode("utf-8")


def _cookie_secure() -> bool:
    raw_secure = os.environ.get("QO_COOKIE_SECURE", "").strip().lower() or "true"
    if raw_secure not in _BOOLEANS:
        raise ConfigError("QO_COOKIE_SECURE must be true or false")
    return _BOOLEANS[raw_secure]


def _base_url(name: str, example: str, cookie_secure: bool) -> tuple[str, str]:
    """(base URL without a trailing slash, its lower-case origin)."""
    base = os.environ.get(name, "").strip()
    if not base:
        raise ConfigError(f"{name} is required, for example {example}")
    parts = urlsplit(base)
    if (parts.scheme not in ("https", "http") or not parts.hostname or parts.query
            or parts.fragment or "@" in parts.netloc):
        raise ConfigError(f"{name} must be an absolute URL such as {example}")
    if parts.scheme != "https" and cookie_secure:
        raise ConfigError(f"{name} must use https; http is accepted only with"
                          " QO_COOKIE_SECURE=false, for local development")
    return base.rstrip("/"), f"{parts.scheme}://{parts.netloc}".lower()


_GUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
GRAPH_SECRET_MAX = 256


def _guid(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise ConfigError(f"{name} is required: the GUID from the Entra app registration")
    if not _GUID.fullmatch(value):
        raise ConfigError(f"{name} must be a GUID such as 00000000-0000-0000-0000-000000000000")
    return value


def _graph_secret(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise ConfigError(f"{name} is required: the client secret of the Entra app")
    if len(value) > GRAPH_SECRET_MAX:
        raise ConfigError(f"{name} is too long: at most {GRAPH_SECRET_MAX} characters")
    if any(c.isspace() or not c.isprintable() for c in value):
        raise ConfigError(f"{name} must not contain whitespace or control characters")
    return value


def _graph_settings() -> dict:
    """The four Graph settings (QO_MAIL=graph); no error message repeats a value."""
    from quoteops.guard import valid_email  # guard imports this module, so not at the top
    tenant, client_id = _guid("QO_GRAPH_TENANT"), _guid("QO_GRAPH_CLIENT_ID")
    secret = _graph_secret("QO_GRAPH_CLIENT_SECRET")
    sender = os.environ.get("QO_MAIL_FROM", "")
    if not sender:
        raise ConfigError("QO_MAIL_FROM is required: the sender's address (the shared mailbox)")
    if not valid_email(sender):
        raise ConfigError("QO_MAIL_FROM must be one email address of at most 254 characters")
    return dict(graph_tenant=tenant, graph_client_id=client_id, graph_client_secret=secret,
                mail_from=sender)


def load_settings() -> Settings:
    """Read and check every setting. Raises ConfigError naming the first problem."""
    secret = _secret("QO_SECRET")
    cookie_secure = _cookie_secure()
    base_url, base_origin = _base_url("QO_BASE_URL", "https://quoteops.example.com", cookie_secure)

    scrypt_concurrency, scrypt_wait_seconds = scrypt_limits()

    mail = os.environ.get("QO_MAIL", "").strip() or "file"
    if mail not in ("file", "graph"):
        raise ConfigError("QO_MAIL: this mail backend is not available in this stage;"
                          " use QO_MAIL=file or QO_MAIL=graph")
    graph = _graph_settings() if mail == "graph" else {}

    return Settings(
        secret=secret,
        base_url=base_url,
        base_origin=base_origin,
        mail=mail,
        mail_dir=os.environ.get("QO_MAIL_DIR", "").strip() or "/tmp/qo-mail",
        cookie_secure=cookie_secure,
        client_ip_header=os.environ.get("QO_CLIENT_IP_HEADER", "").strip() or None,
        max_companies=_positive_int("QO_MAX_COMPANIES", 20),
        login_fails_per_email=_positive_int("QO_LOGIN_FAILS_PER_EMAIL", 5),
        login_fails_per_ip=_positive_int("QO_LOGIN_FAILS_PER_IP", 30),
        login_window_seconds=_positive_int("QO_LOGIN_WINDOW_SECONDS", 900),
        login_block_seconds=_positive_int("QO_LOGIN_BLOCK_SECONDS", 900),
        forgot_per_email=_positive_int("QO_FORGOT_PER_EMAIL", 3),
        forgot_per_ip=_positive_int("QO_FORGOT_PER_IP", 10),
        signup_per_ip=_positive_int("QO_SIGNUP_PER_IP", 5),
        signup_per_email=_positive_int("QO_SIGNUP_PER_EMAIL", 3),
        scrypt_concurrency=scrypt_concurrency,
        scrypt_wait_seconds=scrypt_wait_seconds,
        # The upper bounds keep the purge's seconds and count inside a PostgreSQL integer.
        unverified_max_age_hours=_positive_int("QO_UNVERIFIED_MAX_AGE_HOURS", 72, maximum=8760,
                                               minimum=UNVERIFIED_MIN_AGE_HOURS),
        unverified_keep=_positive_int("QO_UNVERIFIED_KEEP", 500, maximum=1000000, minimum=10),
        max_users_per_company=_positive_int("QO_MAX_USERS_PER_COMPANY", 5, maximum=100),
        invites_per_day=_positive_int("QO_INVITES_PER_DAY", 20, maximum=1000),
        invites_per_address_per_day=_positive_int("QO_INVITES_PER_ADDRESS_PER_DAY", 3, maximum=100),
        max_file_mb=max_file_bytes() // MB,
        max_company_mb=_positive_int("QO_MAX_COMPANY_MB", 500, maximum=100000),
        max_jobs_per_month=_positive_int("QO_MAX_JOBS_PER_MONTH", 50, maximum=100000),
        files_dir=_files_dir(),
        **graph,
    )


def load_admin_settings() -> AdminSettings:
    """The admin service's settings. Requires QO_ADMIN_PASSWORD (checked here, read only by
    admin_conninfo), QO_ADMIN_SECRET and QO_ADMIN_BASE_URL; never reads QO_WEB_PASSWORD or
    QO_SECRET. Raises ConfigError naming the first problem."""
    if not os.environ.get("QO_ADMIN_PASSWORD", ""):
        raise ConfigError("QO_ADMIN_PASSWORD is required: the password of the qo_admin database role")
    secret = _secret("QO_ADMIN_SECRET")
    cookie_secure = _cookie_secure()
    base_url, base_origin = _base_url("QO_ADMIN_BASE_URL", "https://admin.quoteops.example.com",
                                      cookie_secure)
    scrypt_limits()  # the admin sign-in hashes too; refuse bad values at start, not at sign-in
    return AdminSettings(
        secret=secret,
        base_url=base_url,
        base_origin=base_origin,
        cookie_secure=cookie_secure,
        client_ip_header=os.environ.get("QO_CLIENT_IP_HEADER", "").strip() or None,
        session_hours=_positive_int("QO_ADMIN_SESSION_HOURS", 8, maximum=24),
        login_fails_per_email=_positive_int("QO_ADMIN_LOGIN_FAILS_PER_EMAIL", 5, maximum=1000),
        login_fails_per_ip=_positive_int("QO_ADMIN_LOGIN_FAILS_PER_IP", 20, maximum=10000),
        login_window_seconds=_positive_int("QO_LOGIN_WINDOW_SECONDS", 900),
        login_block_seconds=_positive_int("QO_LOGIN_BLOCK_SECONDS", 900),
    )
