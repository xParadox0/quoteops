"""Stage 2b part 3, fix 1: the password-changed notice is a background task. It is queued only
after the password change committed, on the success path only, and it never changes the answer."""
import hashlib
import importlib
import logging
import time

import pytest

from tests.stage2a_support import (  # noqa: F401  (adb and env are fixtures)
    NEW_PASSWORD, SECRET, account, adb, csrf_from, env, forgot, reset_link, signed_up, token_of,
)
from tests.stage2b3_support import FakeGraph
from tests.test_stage2a_fix3 import (
    _asgi_post, _assert_busy, _blocked, _form_cookie, _slow_mailer,
)
from tests.test_stage2a_fix5 import CLOSED
from tests.test_stage2b3_app import sent_links, use_graph

EMAIL = "owner@shop.test"


def _mod(name):
    return importlib.import_module(f"quoteops.{name}")


@pytest.fixture
def fake():
    f = FakeGraph()
    yield f
    f.close()


def notices(env, email=EMAIL):
    return [m for m in env.mails_to(email) if "password was changed" in m.subject]


def reset_data(env, email=EMAIL, password=NEW_PASSWORD):
    forgot(env.client(), email)
    token = token_of(reset_link(env, email))
    c = env.client()
    form = c.get("/reset", params={"token": token})
    return c, {"csrf": csrf_from(form.text), "token": token, "password": password}


def test_the_notice_is_sent_after_the_answer_and_the_answer_is_fast(env, monkeypatch):
    account(env, EMAIL)
    c, data = reset_data(env)
    order = []
    sent = _slow_mailer(monkeypatch, order, delay=2.0)
    csrf, cookie = _form_cookie(env, f"/reset?token={data['token']}")
    out = _asgi_post("/reset", {**data, "csrf": csrf}, cookie, order)
    assert out["status"] == 200
    assert out["answered"] - out["start"] < 1.0, out
    deadline = time.monotonic() + 10
    while not notices(env) and time.monotonic() < deadline:
        time.sleep(0.05)
    assert len(notices(env)) == 1 and order == ["response", "mail"]
    assert sent[0] > out["answered"]


def test_a_slow_graph_token_endpoint_does_not_delay_the_answer(env, fake):
    account(env, EMAIL)
    use_graph(env, fake)
    forgot(env.client(), EMAIL)
    [link] = sent_links(fake, "/reset")
    token = link.split("?token=", 1)[1]
    _mod("mail")._GRAPH_MAILERS.clear()  # no cached token: the notice must ask for one
    fake.token_delay = 2.0
    csrf, cookie = _form_cookie(env, f"/reset?token={token}")
    out = _asgi_post("/reset", {"csrf": csrf, "token": token, "password": NEW_PASSWORD}, cookie, [])
    assert out["status"] == 200 and out["answered"] - out["start"] < 1.0, out
    deadline = time.monotonic() + 10
    while len(fake.sends()) < 2 and time.monotonic() < deadline:
        time.sleep(0.05)
    assert len(fake.sends()) == 2
    assert fake.sends()[1].json["message"]["toRecipients"] == [
        {"emailAddress": {"address": EMAIL}}]


def test_one_successful_reset_sends_one_notice_and_a_replay_sends_none(env):
    account(env, EMAIL)
    c, data = reset_data(env)
    assert c.post("/reset", data=data).status_code == 200
    assert len(notices(env)) == 1
    assert c.post("/reset", data=data).status_code == 400
    assert len(notices(env)) == 1


def test_the_notice_goes_to_the_account_with_the_text_of_changed_mail(env, monkeypatch):
    auth = _mod("auth")
    account(env, EMAIL)
    c, data = reset_data(env)
    calls = []

    class Recorder:
        def send(self, to, subject, text):
            calls.append((to, subject, text))

    monkeypatch.setattr(auth, "mailer", lambda s: Recorder())
    assert c.post("/reset", data=data).status_code == 200
    assert calls == [(EMAIL, *auth._changed_mail(EMAIL))]


def test_the_notice_is_queued_after_the_commit(env, monkeypatch):
    account(env, EMAIL)
    c, data = reset_data(env)
    seen = []

    class Looker:
        def send(self, to, subject, text):
            with env.owner() as o:
                seen.append(bytes(o.execute("SELECT pw_hash FROM app_user").fetchone()[0]))
                seen.append(o.execute("SELECT count(*) FROM session").fetchone()[0])

    with env.owner() as o:
        before = bytes(o.execute("SELECT pw_hash FROM app_user").fetchone()[0])
    monkeypatch.setattr(_mod("auth"), "mailer", lambda s: Looker())
    assert c.post("/reset", data=data).status_code == 200
    assert seen[0] != before and seen[1] == 0


def _refused(env, name):
    """A reset POST that must be refused, for the named reason; returns the response."""
    tokens = _mod("tokens")
    if name == "weak":
        c, data = reset_data(env)
        return c.post("/reset", data={**data, "password": "password123"})
    if name == "bad":
        c, data = reset_data(env)
        return c.post("/reset", data={**data, "token": data["token"][:-3]})
    if name == "expired":
        c, data = reset_data(env)
        with env.owner() as o:
            pw_hash = bytes(o.execute("SELECT pw_hash FROM app_user").fetchone()[0])
        old = tokens.make("reset", EMAIL, 3600, SECRET.encode(),
                          extra=hashlib.sha256(b"pw-fingerprint|" + pw_hash).digest(),
                          now=time.time() - 3605)
        return c.post("/reset", data={**data, "token": old})
    if name == "replayed":
        c, data = reset_data(env)
        assert c.post("/reset", data=data).status_code == 200
        return c.post("/reset", data=data)
    raise AssertionError(name)


@pytest.mark.parametrize("name,status", [("weak", 400), ("bad", 400), ("expired", 400),
                                         ("replayed", 400)])
def test_a_refused_reset_sends_no_notice(env, name, status):
    account(env, EMAIL)
    expected = 1 if name == "replayed" else 0
    r = _refused(env, name)
    assert r.status_code == status
    assert len(notices(env)) == expected


def test_a_busy_reset_sends_no_notice(env):
    account(env, EMAIL)
    c, data = reset_data(env)
    with _blocked(env):
        _assert_busy(c.post("/reset", data=data))
    assert notices(env) == []


def test_a_cap_closed_reset_sends_no_notice(env):
    env.monkeypatch.setenv("QO_MAX_COMPANIES", "1")
    signed_up(env, "late@shop.test")
    account(env, "first@shop.test")
    c, data = reset_data(env, "late@shop.test")
    r = c.post("/reset", data=data)
    assert r.status_code == 403 and CLOSED in r.text
    assert notices(env, "late@shop.test") == []


@pytest.mark.parametrize("exc", [_mod("mail").MailError, OSError, RuntimeError])
def test_a_failing_mailer_leaves_the_answer_and_the_password_and_logs_the_class(
        env, monkeypatch, caplog, exc):
    account(env, EMAIL)
    account(env, "other@shop.test")
    c, data = reset_data(env, "other@shop.test")
    good = c.post("/reset", data=data)
    assert good.status_code == 200 and "Password changed" in good.text
    c, data = reset_data(env)

    def boom(self, to, subject, text):
        raise exc(f"SECRET-TEXT {to} {subject}")

    monkeypatch.setattr(_mod("mail").FileMailer, "send", boom)
    caplog.set_level(logging.DEBUG)
    r = c.post("/reset", data=data)
    assert (r.status_code, r.content) == (good.status_code, good.content)
    errors = [x.getMessage() for x in caplog.records if x.levelno >= logging.ERROR]
    assert errors == [f"mail could not be sent: {exc.__name__}"], errors
    assert "SECRET-TEXT" not in caplog.text and EMAIL not in caplog.text
    from tests.stage2a_support import login
    assert login(env.client(), EMAIL, NEW_PASSWORD).status_code == 303
