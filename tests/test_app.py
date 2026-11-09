from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from tests.conftest import WEB_PW

COMPOSE = Path(__file__).resolve().parent.parent / "deploy" / "compose.yaml"


def _client(monkeypatch, db, port=None):
    from quoteops.app import app
    monkeypatch.setenv("QO_DB_HOST", "127.0.0.1")
    monkeypatch.setenv("QO_DB_PORT", port or db.port)
    monkeypatch.setenv("QO_DB_NAME", db.dbname)
    monkeypatch.setenv("QO_WEB_PASSWORD", WEB_PW)
    return TestClient(app)


def test_healthz_ok_through_web_role(db, monkeypatch):
    r = _client(monkeypatch, db).get("/healthz")
    assert r.status_code == 200 and r.text == "ok"


def test_healthz_fails_loudly_when_database_unreachable(db, monkeypatch):
    r = _client(monkeypatch, db, port="1").get("/healthz")
    assert r.status_code == 503 and "database check failed" in r.text


def test_anonymous_index_redirects_to_login(db, monkeypatch):
    r = _client(monkeypatch, db).get("/", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"


def _keys(node):
    if isinstance(node, dict):
        for k, v in node.items():
            yield k
            yield from _keys(v)
    elif isinstance(node, list):
        for v in node:
            yield from _keys(v)


def test_compose_has_no_ports_key():
    doc = yaml.safe_load(COMPOSE.read_text())
    assert "ports" not in set(_keys(doc))
    assert {"web", "db"} <= set(doc["services"])


def test_compose_hardening():
    doc = yaml.safe_load(COMPOSE.read_text())
    web, db = doc["services"]["web"], doc["services"]["db"]
    assert web["read_only"] is True and "/tmp" in web["tmpfs"]
    assert "no-new-privileges:true" in web["security_opt"]
    assert web["mem_limit"] == "512m" and db["mem_limit"] == "512m"
    assert set(web["networks"]) == {"internal", "edge"} and db["networks"] == ["internal"]
    assert "healthcheck" in web and "healthcheck" in db
