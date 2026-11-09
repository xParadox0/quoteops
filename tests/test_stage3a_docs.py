"""Stage 3a: the documents must say what the code allows (pass 2 of the independent review).
The bound on the time one upload can hold a slot is computed from the constants of uploads.py, so
the HLD cannot drift from them again."""
from pathlib import Path

from quoteops import guard, uploads

ROOT = Path(__file__).resolve().parent.parent
HEAD = "## 13. Stage 3a: jobs and drawing upload"


def _hld13() -> str:
    return (ROOT / "docs" / "HLD.md").read_text(encoding="utf-8").split(HEAD, 1)[1]


def burst_and_drip_bound(grace=None) -> int:
    """Seconds: the credit of the bytes sent in a burst, the grace, and one more read."""
    grace = uploads.RATE_GRACE_SECONDS if grace is None else grace
    body = 25 * 1048576 + guard.UPLOAD_OVERHEAD  # the default 25 MB limit and the framing
    return round(grace + body / uploads.MIN_BYTES_PER_SECOND + uploads.READ_TIMEOUT_SECONDS)


def _without_allowance() -> int:
    """Seconds with the file alone (no multipart allowance), from the constants."""
    return round(uploads.RATE_GRACE_SECONDS + 25 * 1048576 / uploads.MIN_BYTES_PER_SECOND
                 + uploads.READ_TIMEOUT_SECONDS)


def test_the_hld_gives_the_burst_and_drip_bound():
    text = _hld13()
    for needle in ("burst-and-drip bound", "441 seconds", "X/65536 + 10 + 30 seconds"):
        assert needle in text, needle
    assert "at most about 400 seconds" not in text
    assert "at most the file size over the rate plus the grace" not in text


def test_the_hld_says_four_companies_can_fill_all_four_slots():
    text = _hld13()
    assert "four attacker companies can occupy all four process slots" in text
    assert "does not stop a client that sends at or above the minimum rate" in text
    assert "every other company then sees 503" in text
    assert "part of the time" not in text
    assert "many accounts" not in text


def test_the_hld_says_what_is_not_built():
    text = _hld13()
    for needle in ("There is no per-IP throttle", "no per-company limit on upload attempts",
                   "no cooldown after an upload that ended in a refusal",
                   "no total deadline shorter than the file needs at the minimum rate",
                   "writes no log line for a cut upload or a 503 answer",
                   "tightening options", "the owner's decision", "none is built"):
        assert needle in text, needle


def test_the_readme_says_four_uploads_at_once():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert ("At most four uploads run at once in the web process, one per company; the fifth is"
            " the first one answered \"busy\", after it has waited up to 5 seconds.") in readme
    assert "At most two uploads run at once" not in readme
    assert "a third waits up to 5 seconds" not in readme


def test_the_hld_number_is_the_one_the_constants_give():
    text = _hld13()
    assert uploads.MIN_BYTES_PER_SECOND == 65536 and uploads.READ_TIMEOUT_SECONDS == 30
    assert uploads.RATE_GRACE_SECONDS == 10
    bound = burst_and_drip_bound()
    assert bound == 441
    assert f"about {bound} seconds for a 25 MB file" in text
    assert f"X/{uploads.MIN_BYTES_PER_SECOND} + {uploads.RATE_GRACE_SECONDS:g} +" \
           f" {uploads.READ_TIMEOUT_SECONDS:g} seconds" in text


def test_the_hld_gives_the_bound_without_the_allowance():
    text = _hld13()
    without = _without_allowance()
    assert without == 440 and burst_and_drip_bound() == without + 1
    assert f"about {without} seconds without the allowance" in text
    assert "435" not in text
