"""Stage 2b part 3: the Graph backend end to end through the web app, against a fake local
server; the admin service and the compose file without any mail setting."""
import importlib
import logging
import re
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from tests.stage2a_support import (  # noqa: F401  (adb and env are fixtures)
    BASE, PASSWORD, SECRET, account, adb, csrf_from, env, finish_signup, forgot, form_csrf,
    path_of, signup,
)
from tests.stage2b2_support import (  # noqa: F401  (aenv is a fixture)
    ADMIN_BASE, aenv, admin_login, mod, page_csrf,
)
from tests.stage2b3_support import CLIENT_ID, CLIENT_SECRET, SENDER, TENANT, FakeGraph, Reply
from tests.test_stage2b_team import invite, team_csrf

ROOT = Path(__file__).resolve().parent.parent
GRAPH_ENV = {"QO_MAIL": "graph", "QO_GRAPH_TENANT": TENANT, "QO_GRAPH_CLIENT_ID": CLIENT_ID,
             "QO_GRAPH_CLIENT_SECRET": CLIENT_SECRET, "QO_MAIL_FROM": SENDER}


@pytest.fixture
def fake():
    f = FakeGraph()
    yield f
    f.close()


def use_graph(env, fake):
    """Switch the web app to the Graph backend, pointed at the fake server."""
    mail = importlib.import_module("quoteops.mail")
    for k, v in GRAPH_ENV.items():
        env.monkeypatch.setenv(k, v)
    env.monkeypatch.delenv("QO_MAIL_DIR", raising=False)
    env.monkeypatch.setattr(mail, "LOGIN_BASE", fake.base)
    env.monkeypatch.setattr(mail, "GRAPH_BASE", fake.base + "/v1.0")
    getattr(mail, "_GRAPH_MAILERS", {}).clear()


def sent_links(fake, route):
    out = []
    for r in fake.sends():
        content = r.json["message"]["body"]["content"]
        out += [x for x in re.findall(r"https?://\S+", content) if f"{route}?token=" in x]
    return out


def class_only(caplog, *forbidden):
    errors = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert errors and all("MailError" in r.getMessage() for r in errors), caplog.text
    for r in caplog.records:
        for word in (CLIENT_SECRET, "tok-1", "GRAPH-ERROR-TEXT") + forbidden:
            assert word not in r.getMessage() and word not in str(r.__dict__)


def test_signup_mail_goes_to_graph_with_the_link_from_the_base_url(env, fake):
    use_graph(env, fake)
    c = env.client()
    assert signup(c, "new@shop.test").status_code == 200
    [r] = fake.sends()
    message = r.json["message"]
    assert message["toRecipients"] == [{"emailAddress": {"address": "new@shop.test"}}]
    assert r.path == fake.send_path
    [link] = sent_links(fake, "/verify")
    assert link.startswith(BASE + "/verify?token=")
    assert env.mails() == []
    done = finish_signup(c, link)
    assert done.status_code == 200 and "/login" in done.text


def test_a_graph_failure_leaves_the_signup_answer_unchanged_and_logs_only_the_class(env, fake, caplog):
    use_graph(env, fake)
    ok = signup(env.client(), "first@shop.test")
    fake.send_plan = [Reply(500, b"GRAPH-ERROR-TEXT second@shop.test " + CLIENT_SECRET.encode())]
    caplog.set_level(logging.DEBUG)
    failed = signup(env.client(), "second@shop.test")
    assert (failed.status_code, failed.content) == (ok.status_code, ok.content)
    class_only(caplog, "second@shop.test")
    assert len(fake.sends()) == 2


def test_a_graph_outage_is_the_same_for_a_known_address(env, fake, caplog):
    use_graph(env, fake)
    fake.send_plan = [Reply(503)]
    caplog.set_level(logging.DEBUG)
    r = signup(env.client(), "down@shop.test")
    assert r.status_code == 200
    class_only(caplog, "down@shop.test")


def test_invitation_mail_goes_to_graph_with_the_link(env, fake):
    owner = account(env, "owner@shop.test")
    use_graph(env, fake)
    assert invite(owner, "new@shop.test").status_code in (200, 303)
    [link] = sent_links(fake, "/invite")
    assert link.startswith(BASE + "/invite?token=")
    assert fake.sends()[0].json["message"]["toRecipients"] == [
        {"emailAddress": {"address": "new@shop.test"}}]
    assert env.mails_to("new@shop.test") == []


def test_an_invitation_mail_failure_is_not_shown_and_logs_the_class(env, fake, caplog):
    owner = account(env, "owner@shop.test")
    use_graph(env, fake)
    first = invite(owner, "one@shop.test")
    fake.send_plan = [Reply(500, b"GRAPH-ERROR-TEXT")]
    caplog.set_level(logging.DEBUG)
    second = invite(owner, "two@shop.test")
    assert second.status_code == first.status_code
    class_only(caplog, "two@shop.test")
    with env.owner() as o:
        assert o.execute("SELECT count(*) FROM invite WHERE email = 'two@shop.test'"
                         ).fetchone()[0] == 1


def test_the_reset_mail_and_the_password_changed_notice_go_to_graph(env, fake):
    account(env, "owner@shop.test")
    use_graph(env, fake)
    assert forgot(env.client(), "owner@shop.test").status_code == 200
    [link] = sent_links(fake, "/reset")
    c = env.client()
    form = c.get(path_of(link))
    token = link.split("?token=", 1)[1]
    done = c.post("/reset", data={"csrf": csrf_from(form.text), "token": token,
                                  "password": "another long phrase 42"})
    assert done.status_code == 200 and "Password changed" in done.text
    assert len(fake.sends()) == 2


def test_a_failing_changed_notice_does_not_break_the_password_reset(env, fake, caplog):
    account(env, "owner@shop.test")
    use_graph(env, fake)
    forgot(env.client(), "owner@shop.test")
    [link] = sent_links(fake, "/reset")
    c = env.client()
    form = c.get(path_of(link))
    fake.send_plan = [Reply(500, b"GRAPH-ERROR-TEXT")]
    caplog.set_level(logging.DEBUG)
    done = c.post("/reset", data={"csrf": csrf_from(form.text),
                                  "token": link.split("?token=", 1)[1],
                                  "password": "another long phrase 42"})
    assert done.status_code == 200 and "Password changed" in done.text
    class_only(caplog, "owner@shop.test")


def test_the_web_app_refuses_to_start_in_graph_mode_without_its_variables(env):
    env.monkeypatch.setenv("QO_MAIL", "graph")
    config = importlib.import_module("quoteops.config")
    with pytest.raises(config.ConfigError, match="QO_GRAPH_TENANT"):
        with TestClient(importlib.import_module("quoteops.app").app):
            pass


def test_the_admin_service_starts_with_no_mail_setting_even_a_broken_one(aenv, monkeypatch):
    for k in ("QO_MAIL", "QO_MAIL_DIR", "QO_MAIL_FROM", *GRAPH_ENV):
        monkeypatch.delenv(k, raising=False)
    app = mod("admin_app").app
    with TestClient(app, base_url=ADMIN_BASE, headers={"Origin": ADMIN_BASE}) as c:
        assert c.get("/healthz").status_code == 200
    monkeypatch.setenv("QO_MAIL", "graph")
    monkeypatch.setenv("QO_GRAPH_CLIENT_SECRET", "bad secret")
    monkeypatch.setenv("QO_MAIL_FROM", "bad")
    with TestClient(app, base_url=ADMIN_BASE, headers={"Origin": ADMIN_BASE}) as c:
        assert c.get("/healthz").status_code == 200


# --- compose and the example ----------------------------------------------------------------------

GRAPH_VARS = ("QO_GRAPH_TENANT", "QO_GRAPH_CLIENT_ID", "QO_GRAPH_CLIENT_SECRET", "QO_MAIL_FROM")


def _services():
    return yaml.safe_load((ROOT / "deploy" / "compose.yaml").read_text())["services"]


def test_compose_web_has_all_four_graph_variables_as_pass_through():
    env = _services()["web"]["environment"]
    for k in GRAPH_VARS:
        assert env[k] == f"${{{k}:-}}", k
    assert env["QO_MAIL"] == "${QO_MAIL:-file}"
    assert env["QO_MAIL_DIR"] == "/var/qo-mail"


@pytest.mark.parametrize("service", ["admin", "migrate", "db"])
def test_compose_other_services_have_no_graph_or_mail_variable(service):
    doc = _services()[service]
    env = doc.get("environment", {})
    for k in (*GRAPH_VARS, "QO_MAIL", "QO_MAIL_DIR"):
        assert k not in env, (service, k)
    assert not any("GRAPH" in str(v) or "QO_MAIL" in str(v) for v in env.values())
    assert "env_file" not in doc


def test_no_compose_service_or_example_holds_a_real_looking_secret():
    text = (ROOT / "deploy" / "compose.yaml").read_text()
    for line in text.splitlines():
        if "GRAPH_CLIENT_SECRET" in line:
            assert line.strip() == "QO_GRAPH_CLIENT_SECRET: ${QO_GRAPH_CLIENT_SECRET:-}"
    example = (ROOT / "deploy" / ".env.example").read_text()
    values = dict(line.split("=", 1) for line in example.splitlines()
                  if line and not line.startswith("#") and "=" in line)
    assert values["QO_MAIL"] == "file"
    assert values["QO_GRAPH_TENANT"] == "" or values["QO_GRAPH_TENANT"].startswith("change-me")
    assert values["QO_GRAPH_CLIENT_SECRET"].startswith("change-me")
    assert "graph.env" in example and "QO_MAIL=graph" in example
    for k in GRAPH_VARS:
        assert k in values
        assert not re.search(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                             values[k], re.I)
