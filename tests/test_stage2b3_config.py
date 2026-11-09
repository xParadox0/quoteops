"""Stage 2b part 3: the Microsoft Graph settings. No database."""
import importlib
import os

import pytest

from tests.stage2a_support import BASE, SECRET
from tests.stage2b3_support import CLIENT_ID, CLIENT_SECRET, SENDER, TENANT


def _config():
    return importlib.import_module("quoteops.config")


@pytest.fixture
def cfg(monkeypatch):
    for k in list(os.environ):
        if k.startswith("QO_"):
            monkeypatch.delenv(k)
    monkeypatch.setenv("QO_SECRET", SECRET)
    monkeypatch.setenv("QO_BASE_URL", BASE)
    return monkeypatch


@pytest.fixture
def graph(cfg):
    cfg.setenv("QO_MAIL", "graph")
    cfg.setenv("QO_GRAPH_TENANT", TENANT)
    cfg.setenv("QO_GRAPH_CLIENT_ID", CLIENT_ID)
    cfg.setenv("QO_GRAPH_CLIENT_SECRET", CLIENT_SECRET)
    cfg.setenv("QO_MAIL_FROM", SENDER)
    return cfg


def test_graph_settings_are_read(graph):
    s = _config().load_settings()
    assert s.mail == "graph"
    assert (s.graph_tenant, s.graph_client_id) == (TENANT, CLIENT_ID)
    assert s.graph_client_secret == CLIENT_SECRET and s.mail_from == SENDER


def test_graph_mode_does_not_need_the_mail_directory(graph):
    assert "QO_MAIL_DIR" not in os.environ
    assert _config().load_settings().mail == "graph"


def test_file_is_the_default_and_reads_no_graph_value(cfg):
    s = _config().load_settings()
    assert s.mail == "file"
    assert (s.graph_tenant, s.graph_client_id, s.graph_client_secret, s.mail_from) == ("",) * 4


def test_file_mode_ignores_even_invalid_graph_values(cfg):
    cfg.setenv("QO_MAIL", "file")
    cfg.setenv("QO_GRAPH_TENANT", "not a guid")
    cfg.setenv("QO_GRAPH_CLIENT_ID", "x")
    cfg.setenv("QO_GRAPH_CLIENT_SECRET", "bad secret \n with space")
    cfg.setenv("QO_MAIL_FROM", "nonsense")
    s = _config().load_settings()
    assert s.mail == "file"
    assert (s.graph_tenant, s.graph_client_id, s.graph_client_secret, s.mail_from) == ("",) * 4


def test_unknown_mail_backend_is_refused(cfg):
    cfg.setenv("QO_MAIL", "smtp")
    with pytest.raises(_config().ConfigError, match="QO_MAIL"):
        _config().load_settings()


GUID_CASES = ["", "not-a-guid", TENANT[:-1], TENANT + "0", TENANT.replace("-", ""),
              " " + TENANT, TENANT + "\n", "g" + TENANT[1:]]


@pytest.mark.parametrize("var", ["QO_GRAPH_TENANT", "QO_GRAPH_CLIENT_ID"])
@pytest.mark.parametrize("value", [None] + GUID_CASES)
def test_graph_guid_variables_are_required_and_checked(graph, var, value):
    if value is None:
        graph.delenv(var)
    else:
        graph.setenv(var, value)
    with pytest.raises(_config().ConfigError) as exc:
        _config().load_settings()
    assert var in str(exc.value)
    if value:
        assert value.strip() not in str(exc.value)


def test_graph_guid_in_upper_case_is_accepted(graph):
    graph.setenv("QO_GRAPH_TENANT", TENANT.upper().replace("1", "A"))
    assert _config().load_settings().graph_tenant


BAD_SECRETS = ["with space", "tab\there", "new\nline", "cr\rhere", "del\x7fhere",
               "bell\x07here", " leading", "trailing ", "x" * 257, "uni\u00a0space", "uni\u2028sep"]


@pytest.mark.parametrize("value", [None, ""] + BAD_SECRETS)
def test_graph_secret_is_required_and_checked_and_never_echoed(graph, value):
    if value is None:
        graph.delenv("QO_GRAPH_CLIENT_SECRET")
    else:
        graph.setenv("QO_GRAPH_CLIENT_SECRET", value)
    with pytest.raises(_config().ConfigError) as exc:
        _config().load_settings()
    message = str(exc.value)
    assert "QO_GRAPH_CLIENT_SECRET" in message
    if value:
        for fragment in (value, value.strip(), value[:8]):
            assert fragment not in message
            assert fragment not in repr(exc.value)


def test_graph_secret_of_256_characters_is_accepted(graph):
    graph.setenv("QO_GRAPH_CLIENT_SECRET", "s" * 256)
    assert len(_config().load_settings().graph_client_secret) == 256


@pytest.mark.parametrize("value", [None, "", "nope", "a@b", "a b@c.d", "a@@b.c", "x@y.z|w",
                                   "a@" + "b" * 250 + ".cc", "a@b.cc\nBcc: x@y.zz"])
def test_sender_is_required_and_must_be_an_address(graph, value):
    if value is None:
        graph.delenv("QO_MAIL_FROM")
    else:
        graph.setenv("QO_MAIL_FROM", value)
    with pytest.raises(_config().ConfigError) as exc:
        _config().load_settings()
    assert "QO_MAIL_FROM" in str(exc.value)


def test_sender_of_254_characters_is_accepted(graph):
    address = "a" * (254 - len("@b.cc")) + "@b.cc"
    graph.setenv("QO_MAIL_FROM", address)
    assert _config().load_settings().mail_from == address


def test_the_secret_is_in_no_repr_or_str_of_the_settings(graph):
    s = _config().load_settings()
    assert CLIENT_SECRET not in repr(s) and CLIENT_SECRET not in str(s)
    assert "graph_client_secret" not in repr(s)


def test_admin_settings_read_no_mail_setting(cfg):
    cfg.setenv("QO_ADMIN_PASSWORD", "admin-db-password")
    cfg.setenv("QO_ADMIN_SECRET", "admin-config-test-secret-0123456789abcd")
    cfg.setenv("QO_ADMIN_BASE_URL", "https://admin.qo.example")
    base = _config().load_admin_settings()
    cfg.setenv("QO_MAIL", "graph")  # graph with every variable missing or invalid
    cfg.setenv("QO_GRAPH_TENANT", "bad")
    cfg.setenv("QO_GRAPH_CLIENT_SECRET", "bad secret")
    cfg.setenv("QO_MAIL_FROM", "bad")
    assert _config().load_admin_settings() == base
    cfg.setenv("QO_MAIL", "smtp")
    assert _config().load_admin_settings() == base
    assert not any(f.startswith(("graph", "mail")) for f in base.__dataclass_fields__)
