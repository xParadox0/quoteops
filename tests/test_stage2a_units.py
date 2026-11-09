"""Stage 2a units without a database: configuration, password policy and hashing, signed tokens,
the file mail backend."""
import hashlib
import importlib
import os
import stat
import time

import pytest

from tests.stage2a_support import BASE, SECRET


def _mod(name):
    return importlib.import_module(f"quoteops.{name}")


@pytest.fixture
def cfg_env(monkeypatch):
    for k in list(os.environ):
        if k.startswith("QO_"):
            monkeypatch.delenv(k)
    monkeypatch.setenv("QO_SECRET", SECRET)
    monkeypatch.setenv("QO_BASE_URL", BASE)
    return monkeypatch


# --- configuration --------------------------------------------------------------------------------

def test_config_defaults(cfg_env):
    s = _mod("config").load_settings()
    assert s.base_url == BASE and s.base_origin == BASE
    assert s.mail == "file" and s.mail_dir == "/tmp/qo-mail"
    assert s.cookie_secure is True and s.client_ip_header is None and s.max_companies == 20
    assert (s.login_fails_per_email, s.login_fails_per_ip, s.login_window_seconds,
            s.login_block_seconds) == (5, 30, 900, 900)
    assert (s.forgot_per_email, s.forgot_per_ip, s.signup_per_ip) == (3, 10, 5)


def test_config_reads_overrides(cfg_env):
    cfg_env.setenv("QO_BASE_URL", BASE + "/")
    cfg_env.setenv("QO_MAIL_DIR", "/x/mail")
    cfg_env.setenv("QO_COOKIE_SECURE", "false")
    cfg_env.setenv("QO_CLIENT_IP_HEADER", "CF-Connecting-IP")
    cfg_env.setenv("QO_MAX_COMPANIES", "3")
    cfg_env.setenv("QO_LOGIN_FAILS_PER_EMAIL", "7")
    s = _mod("config").load_settings()
    assert s.base_url == BASE and s.mail_dir == "/x/mail" and s.cookie_secure is False
    assert s.client_ip_header == "CF-Connecting-IP" and s.max_companies == 3
    assert s.login_fails_per_email == 7


@pytest.mark.parametrize("var,value,needle", [
    ("QO_SECRET", None, "QO_SECRET"),
    ("QO_SECRET", "x" * 31, "QO_SECRET"),
    ("QO_BASE_URL", None, "QO_BASE_URL"),
    ("QO_BASE_URL", "qo.example", "QO_BASE_URL"),
    ("QO_BASE_URL", "http://qo.example", "https"),
    ("QO_MAIL", "smtp", "not available in this stage"),
    ("QO_MAX_COMPANIES", "lots", "QO_MAX_COMPANIES"),
    ("QO_MAX_COMPANIES", "0", "QO_MAX_COMPANIES"),
    ("QO_COOKIE_SECURE", "maybe", "QO_COOKIE_SECURE"),
])
def test_config_refuses(cfg_env, var, value, needle):
    if value is None:
        cfg_env.delenv(var)
    else:
        cfg_env.setenv(var, value)
    config = _mod("config")
    with pytest.raises(config.ConfigError) as exc:
        config.load_settings()
    assert needle in str(exc.value)
    if var == "QO_SECRET" and value:
        assert value not in str(exc.value)


def test_config_accepts_32_char_secret_and_http_only_without_secure_cookie(cfg_env):
    cfg_env.setenv("QO_SECRET", "y" * 32)
    cfg_env.setenv("QO_BASE_URL", "http://localhost:8091")
    cfg_env.setenv("QO_COOKIE_SECURE", "false")
    s = _mod("config").load_settings()
    assert s.base_origin == "http://localhost:8091"


def test_app_refuses_to_start_without_secret(cfg_env):
    from fastapi.testclient import TestClient
    cfg_env.delenv("QO_SECRET")
    app = _mod("app").app
    config = _mod("config")
    with pytest.raises(config.ConfigError, match="QO_SECRET"):
        with TestClient(app):
            pass


# --- passwords ------------------------------------------------------------------------------------

@pytest.mark.parametrize("pw,ok", [
    ("a1b2c3d4e", False),            # 9
    ("k7m2p9x4w1", True),            # 10
    ("x" * 128, True),
    ("x" * 129, False),
    ("\ufb01" * 5, True),            # 5 ligatures, 10 characters after NFKC
    ("password123", False), ("PASSWORD123", False), ("qwertyuiop", False),
    ("1234567890", False), ("iloveyou12", False),
    ("owner.person@shop.test", False), ("OWNER.PERSON@SHOP.TEST", False),
    ("owner.person", False),
    ("milling cutter 7 bright", True),
])
def test_password_policy(pw, ok):
    err = _mod("passwords").policy_error(pw, "owner.person@shop.test")
    assert (err is None) is ok, (pw, err)


def test_common_password_list_is_long_and_ascii():
    common = _mod("passwords").COMMON_PASSWORDS
    assert len(common) >= 100
    assert all(p.isascii() and p == p.lower() for p in common)


def test_scrypt_parameters_and_salt(monkeypatch):
    passwords = _mod("passwords")
    calls, real = [], hashlib.scrypt

    def spy(password, **kw):
        calls.append(kw)
        return real(password, **kw)

    monkeypatch.setattr(hashlib, "scrypt", spy)
    h, salt = passwords.hash_password("milling cutter 7 bright")
    assert len(calls) == 1
    kw = calls[0]
    assert (kw["n"], kw["r"], kw["p"], kw["dklen"]) == (2 ** 15, 8, 1, 32)
    assert kw["maxmem"] >= 128 * 8 * 2 ** 15 and kw["salt"] == salt
    assert len(salt) == 16 and len(h) == 32
    h2, salt2 = passwords.hash_password("milling cutter 7 bright")
    assert salt2 != salt and h2 != h


def test_verify_password_and_nfkc():
    passwords = _mod("passwords")
    h, salt = passwords.hash_password("\ufb01" * 5)
    assert passwords.verify_password("fi" * 5, h, salt) is True
    assert passwords.verify_password("fi" * 4, h, salt) is False


def test_dummy_verify_runs_one_scrypt_and_fails(monkeypatch):
    passwords = _mod("passwords")
    calls, real = [], hashlib.scrypt
    monkeypatch.setattr(hashlib, "scrypt", lambda pw, **kw: calls.append(1) or real(pw, **kw))
    assert passwords.verify_dummy("anything at all") is False
    assert len(calls) == 1


# --- tokens ---------------------------------------------------------------------------------------

def test_token_round_trip_and_kind_bound():
    tokens = _mod("tokens")
    t = tokens.make("verify", "a@b.test", 60, SECRET.encode())
    assert tokens.check(t, "verify", SECRET.encode()) == "a@b.test"
    assert tokens.check(t, "reset", SECRET.encode()) is None
    assert tokens.check(t, "verify", b"another secret that is long enough!") is None


def test_token_expiry():
    tokens = _mod("tokens")
    t = tokens.make("verify", "a@b.test", 60, SECRET.encode(), now=time.time() - 61)
    assert tokens.check(t, "verify", SECRET.encode()) is None


def test_token_extra_is_signed():
    tokens = _mod("tokens")
    t = tokens.make("reset", "a@b.test", 60, SECRET.encode(), extra=b"fp1")
    assert tokens.check(t, "reset", SECRET.encode(), extra=b"fp1") == "a@b.test"
    assert tokens.check(t, "reset", SECRET.encode(), extra=b"fp2") is None
    assert tokens.check(t, "reset", SECRET.encode()) is None


@pytest.mark.parametrize("mangle", [
    lambda t: t[:-1], lambda t: t[:10], lambda t: "", lambda t: t.replace(".", ""),
    lambda t: t + "A", lambda t: "A" + t, lambda t: t.split(".")[0] + ".",
    lambda t: "." + t.split(".")[1], lambda t: t + ".x", lambda t: t.upper(),
    lambda t: "\u00e9" + t, lambda t: "%%%.***",
])
def test_token_mangled_is_refused(mangle):
    tokens = _mod("tokens")
    t = tokens.make("verify", "a@b.test", 60, SECRET.encode())
    assert tokens.check(mangle(t), "verify", SECRET.encode()) is None


# --- mail -----------------------------------------------------------------------------------------

def test_file_mailer_writes_one_private_file_per_mail(tmp_path):
    mail = _mod("mail")
    d = tmp_path / "box"
    m = mail.FileMailer(str(d))
    m.send("a@b.test", "Subject one", "Body one.")
    m.send("a@b.test", "Subject two", "Body two.")
    files = sorted(d.iterdir())
    assert len(files) == 2
    assert files[0].name != files[1].name and len(files[0].stem) >= 32
    for f in files:
        assert stat.S_IMODE(f.stat().st_mode) == 0o600
        assert f.read_text(encoding="utf-8").startswith("To: a@b.test\nSubject: ")
    assert stat.S_IMODE(d.stat().st_mode) & 0o077 == 0
