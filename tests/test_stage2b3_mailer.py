"""Stage 2b part 3: the Graph mail backend against a fake local server. Nothing here contacts
Microsoft."""
import importlib
import json
import logging
import threading
import time
import traceback
from urllib.parse import parse_qsl, quote

import pytest

from tests.stage2b3_support import (CLIENT_ID, CLIENT_SECRET, RECIPIENT, SENDER, SUBJECT, TENANT,
                                    TEXT, FakeGraph, Reply)


def _mail():
    return importlib.import_module("quoteops.mail")


@pytest.fixture
def fake():
    f = FakeGraph()
    yield f
    f.close()


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def make(fake, clock=None, timeout=5.0, **kw):
    extra = {"clock": clock} if clock else {}
    return _mail().GraphMailer(TENANT, CLIENT_ID, CLIENT_SECRET, SENDER, login_base=fake.base,
                               graph_base=fake.base + "/v1.0", timeout=timeout, **extra, **kw)


def send(m, to=RECIPIENT, subject=SUBJECT, text=TEXT):
    return m.send(to, subject, text)


# --- the requests ---------------------------------------------------------------------------------

def test_token_request_is_the_client_credentials_grant(fake):
    send(make(fake))
    [t] = fake.tokens()
    assert t.path == fake.token_path
    assert t.headers["Content-Type"] == "application/x-www-form-urlencoded"
    assert t.headers["User-Agent"] == "QuoteOps"
    assert parse_qsl(t.body.decode("ascii"), strict_parsing=True) == [
        ("client_id", CLIENT_ID), ("client_secret", CLIENT_SECRET),
        ("scope", "https://graph.microsoft.com/.default"),
        ("grant_type", "client_credentials")]
    assert "Authorization" not in t.headers


def test_send_request_is_exact(fake):
    send(make(fake))
    [r] = fake.sends()
    assert r.path == "/v1.0/users/quoteops%40masch.example/sendMail"
    assert r.headers["Authorization"] == "Bearer tok-1"
    assert r.headers["Content-Type"] == "application/json"
    assert r.headers["User-Agent"] == "QuoteOps"
    assert r.json == {"message": {
        "subject": SUBJECT, "body": {"contentType": "Text", "content": TEXT},
        "toRecipients": [{"emailAddress": {"address": RECIPIENT}}]}, "saveToSentItems": False}


def test_sender_is_percent_encoded_completely(fake):
    m = _mail().GraphMailer(TENANT, CLIENT_ID, CLIENT_SECRET, "a+b/c@masch.example",
                            login_base=fake.base, graph_base=fake.base + "/v1.0")
    send(m)
    assert fake.sends()[0].path == f"/v1.0/users/{quote('a+b/c@masch.example', safe='')}/sendMail"
    assert "%2F" in fake.sends()[0].path and "%2B" in fake.sends()[0].path


def test_non_ascii_text_is_sent_as_valid_json(fake):
    send(make(fake), subject="Tawaran \u00e9", text="Terima kasih \u2014 \u65e5\u672c")
    body = fake.sends()[0].json["message"]
    assert body["subject"] == "Tawaran \u00e9" and "\u65e5\u672c" in body["body"]["content"]


def test_default_urls_are_https_and_exact(monkeypatch):
    mail = _mail()
    assert mail.LOGIN_BASE == "https://login.microsoftonline.com"
    assert mail.GRAPH_BASE == "https://graph.microsoft.com/v1.0"
    seen = []

    class Resp:
        def __init__(self, status, body=b""):
            self.status, self._body = status, body

        def read(self, n=-1):
            return self._body

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    class Opener:
        def open(self, req, data=None, timeout=None):
            seen.append((req.full_url, timeout))
            if req.full_url.endswith("/token"):
                return Resp(200, json.dumps({"access_token": "t", "expires_in": 3600}).encode())
            return Resp(202)

    m = mail.GraphMailer(TENANT, CLIENT_ID, CLIENT_SECRET, SENDER)
    m._opener = Opener()
    send(m)
    assert seen == [
        (f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token", 10),
        ("https://graph.microsoft.com/v1.0/users/quoteops%40masch.example/sendMail", 10)]


def test_202_is_success_and_returns_none(fake):
    assert send(make(fake)) is None


# --- the token cache ------------------------------------------------------------------------------

def test_token_is_reused_until_five_minutes_before_expiry(fake):
    clock = Clock()
    m = make(fake, clock)
    send(m)
    clock.now += 3299
    send(m)
    assert len(fake.tokens()) == 1
    clock.now += 1  # 3300 s: five minutes before the 3600 s expiry
    send(m)
    assert len(fake.tokens()) == 2
    assert [r.headers["Authorization"] for r in fake.sends()] == [
        "Bearer tok-1", "Bearer tok-1", "Bearer tok-2"]


def test_a_failed_token_request_is_not_cached(fake):
    fake.token_plan = [Reply(500, b"{}")]
    m = make(fake)
    with pytest.raises(_mail().MailError):
        send(m)
    assert fake.sends() == []
    send(m)
    assert len(fake.tokens()) == 2 and len(fake.sends()) == 1


@pytest.mark.parametrize("body", [b"not json", b"{}", b'{"access_token": "", "expires_in": 3600}',
                                  b'{"access_token": "a b\\nc", "expires_in": 3600}',
                                  b'{"access_token": "t"}', b"[]"])
def test_a_token_answer_without_a_usable_token_fails_and_is_not_cached(fake, body):
    fake.token_plan = [Reply(200, body)]
    m = make(fake)
    with pytest.raises(_mail().MailError):
        send(m)
    assert fake.sends() == []
    send(m)
    assert len(fake.tokens()) == 2


def test_parallel_sends_fetch_one_token(fake):
    fake.token_delay = 0.4  # every thread is waiting when the first answer comes
    m = make(fake)
    errors = []

    def run():
        try:
            send(m)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=run) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(20)
    assert errors == []
    assert len(fake.tokens()) == 1 and len(fake.sends()) == 8


def test_parallel_sends_after_expiry_refresh_once(fake):
    clock = Clock()
    m = make(fake, clock)
    send(m)
    clock.now += 4000
    fake.token_delay = 0.4
    threads = [threading.Thread(target=send, args=(m,)) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(20)
    assert len(fake.tokens()) == 2


# --- failures -------------------------------------------------------------------------------------

def test_401_drops_the_token_and_retries_exactly_once(fake):
    fake.send_plan = [Reply(401, b"{}")]
    m = make(fake)
    send(m)
    assert len(fake.tokens()) == 2 and len(fake.sends()) == 2
    assert [r.headers["Authorization"] for r in fake.sends()] == ["Bearer tok-1", "Bearer tok-2"]
    send(m)  # the new token is the cached one
    assert len(fake.tokens()) == 2 and fake.sends()[-1].headers["Authorization"] == "Bearer tok-2"


def test_a_second_401_is_a_failure_without_a_third_try(fake):
    fake.send_plan = [Reply(401), Reply(401), Reply(401)]
    with pytest.raises(_mail().MailError) as exc:
        send(make(fake))
    assert "401" in str(exc.value)
    assert len(fake.sends()) == 2 and len(fake.tokens()) == 2


@pytest.mark.parametrize("status", [400, 403, 404, 429, 500, 502, 503])
def test_other_statuses_fail_without_a_retry(fake, status):
    fake.send_plan = [Reply(status, b'{"error": "x"}'), Reply(202)]
    with pytest.raises(_mail().MailError) as exc:
        send(make(fake))
    assert str(exc.value) == f"send failed with status {status}"
    assert len(fake.sends()) == 1 and len(fake.tokens()) == 1


@pytest.mark.parametrize("status", [200, 204])
def test_only_202_is_success(fake, status):
    fake.send_plan = [Reply(status)]
    with pytest.raises(_mail().MailError):
        send(make(fake))


@pytest.mark.parametrize("status", [400, 401, 403, 429, 500, 503])
def test_token_endpoint_failures_fail_without_a_retry_and_send_nothing(fake, status):
    fake.token_plan = [Reply(status, b"{}"), Reply(200)]
    with pytest.raises(_mail().MailError) as exc:
        send(make(fake))
    assert str(exc.value) == f"token request failed with status {status}"
    assert len(fake.tokens()) == 1 and fake.sends() == []


def test_mail_error_is_a_plain_exception():
    assert issubclass(_mail().MailError, Exception)
    assert not issubclass(_mail().MailError, (OSError, ValueError))


@pytest.mark.parametrize("where", ["token", "send"])
def test_a_redirect_is_a_failure_and_is_not_followed(fake, where):
    plan = [Reply(302, headers={"Location": fake.base + "/never"})]
    setattr(fake, f"{where}_plan", plan)
    with pytest.raises(_mail().MailError) as exc:
        send(make(fake))
    assert "302" in str(exc.value)
    assert fake.of("other") == [] and not [r for r in fake.requests if r.path == "/never"]


@pytest.mark.parametrize("status", [301, 303, 307, 308])
def test_every_redirect_status_fails(fake, status):
    fake.send_plan = [Reply(status, headers={"Location": fake.base + "/never"})]
    with pytest.raises(_mail().MailError):
        send(make(fake))
    assert fake.of("other") == []


@pytest.mark.parametrize("where", ["token", "send"])
def test_a_slow_endpoint_fails_fast_at_the_timeout(fake, where):
    setattr(fake, f"{where}_plan", [Reply(202 if where == "send" else 200, b"{}", delay=3.0)])
    m = make(fake, timeout=0.3)
    started = time.monotonic()
    with pytest.raises(_mail().MailError):
        send(m)
    assert time.monotonic() - started < 2.0


def test_the_default_timeout_is_ten_seconds():
    assert _mail().GraphMailer(TENANT, CLIENT_ID, CLIENT_SECRET, SENDER).timeout == 10


def test_a_closed_port_is_a_mail_error():
    m = _mail().GraphMailer(TENANT, CLIENT_ID, CLIENT_SECRET, SENDER,
                            login_base="http://127.0.0.1:9", graph_base="http://127.0.0.1:9/v1.0",
                            timeout=1)
    with pytest.raises(_mail().MailError):
        send(m)


# --- what an error and a log may hold -------------------------------------------------------------

@pytest.mark.parametrize("where,status", [("token", 400), ("token", 500), ("send", 400),
                                          ("send", 401), ("send", 500), ("send", 302)])
def test_errors_and_logs_hold_no_body_secret_token_recipient_or_subject(fake, caplog, where, status):
    secrets_in_body = [CLIENT_SECRET, "tok-1", RECIPIENT, SUBJECT, "GRAPH-ERROR-TEXT"]
    body = json.dumps({"error": {"message": " ".join(secrets_in_body)}}).encode()
    if where == "send":
        fake.send_plan = [Reply(status, body, headers={"Location": fake.base + "/never"}),
                          Reply(status, body)]
    else:
        fake.token_plan = [Reply(status, body)]
    caplog.set_level(logging.DEBUG)
    with pytest.raises(_mail().MailError) as exc:
        send(make(fake))
    shown = [str(exc.value), repr(exc.value), "".join(traceback.format_exception(exc.value))]
    shown += [r.getMessage() for r in caplog.records]
    shown += [str(r.__dict__) for r in caplog.records]
    for text in shown:
        for secret in secrets_in_body + ["customer", "verification link"]:
            assert secret not in text, (secret, text)
    assert str(exc.value) in (f"{where} failed with status {status}",
                              f"token request failed with status {status}",
                              f"send failed with status {status}")
    assert not [r for r in caplog.records if r.levelno >= logging.INFO]


def test_a_successful_send_logs_nothing(fake, caplog):
    caplog.set_level(logging.DEBUG)
    send(make(fake))
    assert [r for r in caplog.records if r.name.startswith(("quoteops", "urllib"))] == []


def test_the_mailer_repr_holds_no_secret(fake):
    assert CLIENT_SECRET not in repr(make(fake)) and CLIENT_SECRET not in str(make(fake))


# --- refusals before any network call -------------------------------------------------------------

@pytest.mark.parametrize("to,subject", [
    ("a@b.cc\nBcc: x@y.zz", SUBJECT), ("a@b.cc\r", SUBJECT), (RECIPIENT, "Hi\nBcc: x@y.zz"),
    (RECIPIENT, "Hi\r\n"), (RECIPIENT, "\rHi")])
def test_line_breaks_are_refused_before_any_network_call(fake, to, subject):
    with pytest.raises(ValueError):
        send(make(fake), to, subject)
    assert fake.requests == []


@pytest.mark.parametrize("to", ["", "nobody", "a@b", "a b@c.dd", "a@b.cc, d@e.ff", "a@b.cc;d@e.ff",
                                "x@y.zz|w", "@b.cc", "a@" + "b" * 260 + ".cc"])
def test_an_implausible_recipient_is_refused_before_any_network_call(fake, to):
    with pytest.raises(ValueError):
        send(make(fake), to)
    assert fake.requests == []


# --- mailer() -------------------------------------------------------------------------------------

def _settings(**over):
    config = importlib.import_module("quoteops.config")
    base = dict(secret=b"x" * 32, base_url="https://qo.example", base_origin="https://qo.example",
                mail="graph", mail_dir="/nonexistent", cookie_secure=True, client_ip_header=None,
                max_companies=1, login_fails_per_email=1, login_fails_per_ip=1,
                login_window_seconds=1, login_block_seconds=1, forgot_per_email=1,
                forgot_per_ip=1, signup_per_ip=1, signup_per_email=1, scrypt_concurrency=1,
                scrypt_wait_seconds=1.0, unverified_max_age_hours=72, unverified_keep=10,
                max_users_per_company=1, invites_per_day=1, invites_per_address_per_day=1,
                graph_tenant=TENANT, graph_client_id=CLIENT_ID,
                graph_client_secret=CLIENT_SECRET, mail_from=SENDER)
    base.update(over)
    return config.Settings(**base)


@pytest.fixture(autouse=True)
def _clear_cache():
    mail = _mail()
    getattr(mail, "_GRAPH_MAILERS", {}).clear()
    yield
    getattr(mail, "_GRAPH_MAILERS", {}).clear()


def test_mailer_returns_the_file_backend_by_default(tmp_path):
    m = _mail().mailer(_settings(mail="file", mail_dir=str(tmp_path), graph_tenant="",
                                 graph_client_id="", graph_client_secret="", mail_from=""))
    assert isinstance(m, _mail().FileMailer) and m.directory == str(tmp_path)


def test_mailer_returns_one_graph_mailer_per_process_and_settings():
    mail = _mail()
    a, b = mail.mailer(_settings()), mail.mailer(_settings())
    assert isinstance(a, mail.GraphMailer) and a is b
    assert mail.mailer(_settings(mail_from="other@masch.example")) is not a
    assert mail.mailer(_settings(graph_client_secret="another-secret-value")) is not a


def test_mailer_cache_is_cleared_by_the_test_hook():
    mail = _mail()
    a = mail.mailer(_settings())
    mail._GRAPH_MAILERS.clear()
    assert mail.mailer(_settings()) is not a


def test_token_cache_works_across_calls_through_mailer(fake, monkeypatch):
    mail = _mail()
    monkeypatch.setattr(mail, "LOGIN_BASE", fake.base)
    monkeypatch.setattr(mail, "GRAPH_BASE", fake.base + "/v1.0")
    for _ in range(3):
        mail.mailer(_settings()).send(RECIPIENT, SUBJECT, TEXT)
    assert len(fake.tokens()) == 1 and len(fake.sends()) == 3


def test_no_environment_variable_changes_the_endpoints(fake, monkeypatch):
    for name in ("QO_GRAPH_LOGIN_BASE", "QO_GRAPH_BASE", "QO_GRAPH_URL", "QO_LOGIN_BASE"):
        monkeypatch.setenv(name, fake.base)
    m = _mail().GraphMailer(TENANT, CLIENT_ID, CLIENT_SECRET, SENDER)
    assert m.login_base == "https://login.microsoftonline.com"
    assert m.graph_base == "https://graph.microsoft.com/v1.0"
