"""Stage 2b part 3: the HLD, the README and the PRD say what the code does."""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HLD = (ROOT / "docs" / "HLD.md").read_text(encoding="utf-8")
README = (ROOT / "README.md").read_text(encoding="utf-8")
VARIABLES = ("QO_MAIL", "QO_GRAPH_TENANT", "QO_GRAPH_CLIENT_ID", "QO_GRAPH_CLIENT_SECRET",
             "QO_MAIL_FROM")


def _section() -> str:
    head = "## 12. Stage 2b part 3: the Microsoft Graph mail backend"
    assert head in HLD
    return HLD.split(head, 1)[1]


def test_hld_has_the_stage_section_with_what_it_must_say():
    text = _section()
    for needle in ("client-credentials", "Mail.Send", "application access policy",
                   "user principal name", "quoteops@chronyxlabs.com", "five minutes",
                   "202", "queued", "not delivered", "10 seconds", "background",
                   "401", "429", "redirect", "MailError", "class name", "DKIM", "DMARC",
                   "chronyxlabs.com", "shared mailbox", "QuoteOps", "restart", "retried",
                   "saveToSentItems", "QO_GRAPH_CLIENT_SECRET", "admin"):
        assert needle in text, needle


def test_hld_no_longer_says_only_the_file_backend_exists():
    assert "`QO_MAIL` accepts only `file` in this stage" not in HLD
    assert "Both mails go through the file mailer." not in HLD
    assert "`QO_MAIL` accepts `file` (the default" in HLD


def test_readme_names_the_variables():
    for name in VARIABLES:
        assert name in README, name
    assert "Stage 2a writes mail as files" not in README
