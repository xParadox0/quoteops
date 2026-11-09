"""Stage 2b part 2: the admin service's settings, its compose service and environment, and the
documented command for the CLI."""
import os
from pathlib import Path

import pytest
import yaml

from tests.stage2b2_support import mod

ROOT = Path(__file__).resolve().parent.parent
COMPOSE = ROOT / "deploy" / "compose.yaml"
ADMIN_SECRET = "admin-config-test-secret-0123456789abcd"
ADMIN_BASE = "https://admin.qo.example"
CLI_COMMAND = ("docker compose -p quoteops -f deploy/compose.yaml run --rm migrate"
               " python -m quoteops create-admin")


def _services():
    return yaml.safe_load(COMPOSE.read_text())["services"]


@pytest.fixture
def clean_env(monkeypatch):
    for k in list(os.environ):
        if k.startswith("QO_"):
            monkeypatch.delenv(k)
    monkeypatch.setenv("QO_ADMIN_PASSWORD", "admin-db-password")
    monkeypatch.setenv("QO_ADMIN_SECRET", ADMIN_SECRET)
    monkeypatch.setenv("QO_ADMIN_BASE_URL", ADMIN_BASE)
    return monkeypatch


# --- settings -------------------------------------------------------------------------------------

def test_admin_settings_defaults(clean_env):
    s = mod("config").load_admin_settings()
    assert s.secret == ADMIN_SECRET.encode()
    assert (s.base_url, s.base_origin) == (ADMIN_BASE, ADMIN_BASE)
    assert s.cookie_secure is True and s.client_ip_header is None
    assert s.session_hours == 8
    assert (s.login_fails_per_email, s.login_fails_per_ip) == (5, 20)
    assert (s.login_window_seconds, s.login_block_seconds) == (900, 900)
    assert not hasattr(s, "password") and "admin-db-password" not in repr(s)


def test_admin_settings_read_their_variables(clean_env):
    for k, v in (("QO_ADMIN_SESSION_HOURS", "24"), ("QO_ADMIN_LOGIN_FAILS_PER_EMAIL", "3"),
                 ("QO_ADMIN_LOGIN_FAILS_PER_IP", "7"), ("QO_LOGIN_WINDOW_SECONDS", "60"),
                 ("QO_LOGIN_BLOCK_SECONDS", "120"), ("QO_CLIENT_IP_HEADER", "CF-Connecting-IP"),
                 ("QO_ADMIN_BASE_URL", "https://Admin.Qo.Example:8443/")):
        clean_env.setenv(k, v)
    s = mod("config").load_admin_settings()
    assert s.session_hours == 24
    assert (s.login_fails_per_email, s.login_fails_per_ip) == (3, 7)
    assert (s.login_window_seconds, s.login_block_seconds) == (60, 120)
    assert s.client_ip_header == "CF-Connecting-IP"
    assert s.base_url == "https://Admin.Qo.Example:8443"
    assert s.base_origin == "https://admin.qo.example:8443"


@pytest.mark.parametrize("var,bad", [
    ("QO_ADMIN_SESSION_HOURS", "0"), ("QO_ADMIN_SESSION_HOURS", "25"),
    ("QO_ADMIN_SESSION_HOURS", "eight"), ("QO_ADMIN_SESSION_HOURS", "1.5"),
    ("QO_ADMIN_LOGIN_FAILS_PER_EMAIL", "0"), ("QO_ADMIN_LOGIN_FAILS_PER_EMAIL", "x"),
    ("QO_ADMIN_LOGIN_FAILS_PER_IP", "0"), ("QO_ADMIN_LOGIN_FAILS_PER_IP", "-3"),
    ("QO_ADMIN_SECRET", ""), ("QO_ADMIN_SECRET", "short-secret"),
    ("QO_ADMIN_BASE_URL", ""), ("QO_ADMIN_BASE_URL", "http://admin.qo.example"),
    ("QO_ADMIN_BASE_URL", "admin.qo.example"), ("QO_ADMIN_BASE_URL", "https://u@admin.qo.example"),
    ("QO_ADMIN_BASE_URL", "https://admin.qo.example/?x=1"), ("QO_ADMIN_BASE_URL", "ftp://admin.x"),
    ("QO_ADMIN_PASSWORD", ""), ("QO_COOKIE_SECURE", "maybe")])
def test_admin_settings_refusals_name_the_variable_not_the_value(clean_env, var, bad):
    clean_env.setenv(var, bad)
    config = mod("config")
    with pytest.raises(config.ConfigError) as exc:
        config.load_admin_settings()
    assert var in str(exc.value)
    if len(bad) > 3:
        assert bad not in str(exc.value)


@pytest.mark.parametrize("var", ["QO_ADMIN_PASSWORD", "QO_ADMIN_SECRET", "QO_ADMIN_BASE_URL"])
def test_admin_settings_require(clean_env, var):
    clean_env.delenv(var)
    config = mod("config")
    with pytest.raises(config.ConfigError, match=var):
        config.load_admin_settings()


def test_admin_settings_bounds_accepted(clean_env):
    for hours in ("1", "24"):
        clean_env.setenv("QO_ADMIN_SESSION_HOURS", hours)
        assert mod("config").load_admin_settings().session_hours == int(hours)


def test_http_admin_url_only_without_secure_cookies(clean_env):
    clean_env.setenv("QO_ADMIN_BASE_URL", "http://localhost:8092")
    clean_env.setenv("QO_COOKIE_SECURE", "false")
    s = mod("config").load_admin_settings()
    assert s.base_origin == "http://localhost:8092" and s.cookie_secure is False


def test_admin_settings_do_not_need_the_web_settings(clean_env):
    for k in ("QO_WEB_PASSWORD", "QO_SECRET", "QO_BASE_URL", "QO_MAIL"):
        assert k not in os.environ
    mod("config").load_admin_settings()


def test_web_settings_do_not_need_the_admin_settings(clean_env):
    for k in ("QO_ADMIN_PASSWORD", "QO_ADMIN_SECRET", "QO_ADMIN_BASE_URL"):
        clean_env.delenv(k)
    clean_env.setenv("QO_SECRET", "web-secret-0123456789abcdefghijklmnop")
    clean_env.setenv("QO_BASE_URL", "https://qo.example")
    mod("config").load_settings()


def test_web_base_url_messages_unchanged(clean_env):
    clean_env.setenv("QO_SECRET", "web-secret-0123456789abcdefghijklmnop")
    config = mod("config")
    for bad, text in (("", "QO_BASE_URL is required, for example https://quoteops.example.com"),
                      ("x", "QO_BASE_URL must be an absolute URL such as"
                            " https://quoteops.example.com"),
                      ("http://qo.example", "QO_BASE_URL must use https; http is accepted only"
                                            " with QO_COOKIE_SECURE=false, for local development")):
        clean_env.setenv("QO_BASE_URL", bad)
        with pytest.raises(config.ConfigError) as exc:
            config.load_settings()
        assert str(exc.value) == text


def test_admin_conninfo_is_the_admin_role(clean_env):
    info = mod("config").admin_conninfo()
    import psycopg
    d = psycopg.conninfo.conninfo_to_dict(info)
    assert d["user"] == "qo_admin" and d["password"] == "admin-db-password"


# --- compose --------------------------------------------------------------------------------------

ADMIN_ENV = {"QO_DB_HOST", "QO_DB_NAME", "QO_ADMIN_PASSWORD", "QO_ADMIN_BASE_URL",
             "QO_ADMIN_SECRET", "QO_ADMIN_SESSION_HOURS", "QO_ADMIN_LOGIN_FAILS_PER_EMAIL",
             "QO_ADMIN_LOGIN_FAILS_PER_IP", "QO_LOGIN_WINDOW_SECONDS", "QO_LOGIN_BLOCK_SECONDS",
             "QO_COOKIE_SECURE", "QO_CLIENT_IP_HEADER", "QO_SCRYPT_CONCURRENCY",
             "QO_SCRYPT_WAIT_SECONDS"}


def test_compose_admin_service():
    services = _services()
    admin, web = services["admin"], services["web"]
    assert admin["build"] == web["build"] and admin["image"] == web["image"]
    assert admin["command"] == ["uvicorn", "quoteops.admin_app:app", "--host", "0.0.0.0",
                                "--port", "8092", "--no-access-log"]
    assert admin["read_only"] is True and "/tmp" in admin["tmpfs"]
    assert admin["security_opt"] == web["security_opt"]
    assert admin["mem_limit"] == web["mem_limit"] == "512m"
    assert set(admin["networks"]) == {"internal", "edge"}
    assert admin.get("user") == web.get("user")
    assert "ports" not in admin and "expose" not in admin and "env_file" not in admin
    assert "http://127.0.0.1:8092/healthz" in " ".join(admin["healthcheck"]["test"])
    assert admin["depends_on"] == {"migrate": {"condition": "service_completed_successfully"}}
    assert admin["restart"] == web["restart"]


def test_compose_admin_environment_is_exactly_its_own():
    env = _services()["admin"]["environment"]
    assert set(env) == ADMIN_ENV
    assert env["QO_ADMIN_PASSWORD"] == "${QO_ADMIN_PASSWORD:?set it in deploy/.env}"
    assert env["QO_ADMIN_SECRET"] == "${QO_ADMIN_SECRET:?set it in deploy/.env}"
    assert env["QO_ADMIN_BASE_URL"] == "${QO_ADMIN_BASE_URL:?set it in deploy/.env}"
    for k in ("QO_WEB_PASSWORD", "QO_OWNER_PASSWORD", "QO_OWNER_USER", "POSTGRES_PASSWORD",
              "QO_SECRET", "QO_BASE_URL", "QO_MAIL", "QO_MAIL_DIR"):
        assert k not in env, k
    assert not any("WEB_PASSWORD" in str(v) or "POSTGRES" in str(v) or "${QO_SECRET" in str(v)
                   for v in env.values())


def test_compose_web_gets_nothing_of_the_admin_service():
    web = _services()["web"]
    assert not [k for k in web["environment"] if k.startswith("QO_ADMIN")]
    assert not any("QO_ADMIN" in str(v) for v in web["environment"].values())
    assert "8092" not in str(web)


def test_compose_migrate_has_what_the_cli_needs():
    mig = _services()["migrate"]
    env = mig["environment"]
    assert mig["command"] == ["python", "-m", "quoteops", "migrate"]
    assert {"QO_DB_HOST", "QO_DB_NAME", "QO_OWNER_USER", "QO_OWNER_PASSWORD"} <= set(env)
    # The role passwords are there for migrate itself (it sets them); the CLI does not read
    # them, and no signing key or mail setting is given to this service.
    assert set(env) == {"QO_DB_HOST", "QO_DB_NAME", "QO_OWNER_USER", "QO_OWNER_PASSWORD",
                        "QO_WEB_PASSWORD", "QO_ADMIN_PASSWORD"}


def test_env_example_has_the_admin_variables():
    text = (ROOT / "deploy" / ".env.example").read_text(encoding="ascii")
    lines = dict(line.split("=", 1) for line in text.splitlines()
                 if line and not line.startswith("#"))
    assert lines["QO_ADMIN_PASSWORD"].startswith("change-me")
    assert lines["QO_ADMIN_SECRET"].startswith("change-me") and len(lines["QO_ADMIN_SECRET"]) < 32
    assert lines["QO_ADMIN_BASE_URL"].startswith("https://")
    for k in ("QO_ADMIN_SESSION_HOURS", "QO_ADMIN_LOGIN_FAILS_PER_EMAIL",
              "QO_ADMIN_LOGIN_FAILS_PER_IP"):
        assert k in text


def test_cli_command_documented():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    hld = (ROOT / "docs" / "HLD.md").read_text(encoding="utf-8")
    for doc in (readme, hld):
        assert CLI_COMMAND in doc
        assert CLI_COMMAND.replace("create-admin", "reset-admin") in doc


def test_hld_has_the_stage_section_and_the_hardened_limit():
    hld = (ROOT / "docs" / "HLD.md").read_text(encoding="utf-8")
    assert "## 11. Stage 2b part 2: administrator identity and second factor" in hld
    assert "`qo_login_lookup` returns the password hash to the web role" not in hld or \
        "never a `sysadmin`" in hld
    prd = (ROOT / "docs" / "PRD.md").read_text(encoding="utf-8")
    assert "Q5: Second factor for the administrator: an authenticator-app code (recommended," \
           " no mail needed) or none in version 1." not in prd
