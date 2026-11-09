"""Stage 3a: the cooldown of a company whose upload was cut for stalling or for being too slow, and
the four process slots (HLD section 13). The clock is faked by patching uploads._now; only the
real-time test and the stall test wait, and only a fraction of a second or one second."""
import importlib
import re
import threading
import time
from pathlib import Path

import pytest

from tests.stage2a_support import adb, env  # noqa: F401  (fixtures)
from tests.stage3a_support import (  # noqa: F401  (jenv is a fixture)
    MB, PDF, add, asgi, chunked, company, create, created_ref, form, jenv, post_upload,
    stored_files, tmp_files, tree, upload_headers,
)

ROOT = Path(__file__).resolve().parent.parent
PAUSED = ("Uploads from your company are paused for {n} seconds because the last upload arrived"
          " too slowly. Nothing was stored. Wait, then try again, or use a faster connection or a"
          " smaller file.")


def _up():
    return importlib.import_module("quoteops.uploads")


class Clock:
    def __init__(self, t=100.0):
        self.t = t

    def __call__(self):
        return self.t


@pytest.fixture
def clock(monkeypatch):
    c = Clock()
    monkeypatch.setattr(_up(), "_now", c)
    return c


def nothing_stored(env):
    assert [k for k in tree(env.files) if "/.tmp/" not in "/" + k] == []
    assert tmp_files(env.files) == []


def cut_slow(user, clock, query="", ref=None):
    """An upload whose file part has started and whose clock then jumps 20 s with one more byte:
    the rate rule cuts it at the first message."""
    data = form(user.csrf, PDF + b"x" * 300000, fields={} if ref else None)
    n = data.index(b"%PDF") + 20
    t0 = clock.t

    def gen():
        yield data[:n]
        clock.t = t0 + 20
        yield data[n:n + 1]
        yield data[n + 1:]
    out = asgi("POST", "/jobs/upload", gen, headers=upload_headers(user), query=query)
    assert out.status == 408 and out.receives == 1, (out.status, out.receives)
    clock.t = t0 + 20
    return out


def hold_all_slots(up):
    for _ in range(up.MAX_PARALLEL):
        assert up.SLOTS.acquire(blocking=False)


def free_all_slots(up):
    for _ in range(up.MAX_PARALLEL):
        up.SLOTS.release()


def refused(user, up, retry_after, seconds, query="", drawings_before=None):
    """The next upload of a company in cooldown: 429, no slot, no body byte, no file. Every
    process slot is held meanwhile, so an answer other than 429 would be a 503 or a read."""
    hold_all_slots(up)
    try:
        data = form(user.csrf, PDF + b"x" * 1000, fields={} if query else None)
        out = asgi("POST", "/jobs/upload", chunked(data), headers=upload_headers(user), query=query)
    finally:
        free_all_slots(up)
    assert out.status == 429, out.status
    assert out.headers["retry-after"] == [retry_after]
    assert out.headers["connection"] == ["close"]
    assert out.receives == 0 and out.sent == 0
    assert PAUSED.format(n=seconds).encode() in out.body
    assert up.SLOTS._value == up.MAX_PARALLEL and up._companies == set()
    return out


def test_the_constants_are_the_documented_ones():
    up = _up()
    assert up.COOLDOWN_SECONDS == 60.0 and up.MAX_PARALLEL == 4


def test_after_a_too_slow_cut_the_next_upload_of_the_company_is_429_without_a_slot(jenv, clock):
    up = _up()
    a = company(jenv, "c_a")
    cut_slow(a["owner"], clock)
    nothing_stored(jenv)
    clock.t += 0.25  # 59.75 s left, rounded up
    refused(a["owner"], up, "60", 60)
    nothing_stored(jenv)
    assert up.cooldown_left("c_a") == pytest.approx(59.75)


def test_after_a_per_read_stall_the_cooldown_starts_too(jenv, clock, monkeypatch):
    up = _up()
    monkeypatch.setattr(up, "READ_TIMEOUT_SECONDS", 0.3)
    a = company(jenv, "c_a")
    data = form(a["owner"].csrf, PDF + b"x" * 300000)
    out = asgi("POST", "/jobs/upload", [data[:200000], "stall"], headers=upload_headers(a["owner"]))
    assert out.status == 408 and b"stopped arriving" in out.body
    nothing_stored(jenv)
    assert up.cooldown_left("c_a") == 60.0
    refused(a["owner"], up, "60", 60)


def test_the_cooldown_belongs_to_the_whole_company_and_to_no_other(jenv, clock):
    up = _up()
    a, b = company(jenv, "c_a"), company(jenv, "c_b")
    cut_slow(a["owner"], clock)
    refused(a["estimator"], up, "60", 60)  # another user of the same company
    assert created_ref(create(b["owner"])) == "J-1001"  # another company is not affected
    assert up.cooldown_left("c_b") == 0.0 and set(up._cooldown) == {"c_a"}


def test_after_the_cooldown_the_company_can_upload_again(jenv, clock):
    a = company(jenv, "c_a")
    cut_slow(a["owner"], clock)
    assert create(a["owner"]).status_code == 429
    clock.t += 61
    assert created_ref(create(a["owner"])) == "J-1001"


def test_one_second_before_the_end_it_is_refused_and_at_the_end_it_is_allowed(jenv, clock):
    up = _up()
    a = company(jenv, "c_a")
    cut_slow(a["owner"], clock)
    clock.t += 59
    refused(a["owner"], up, "1", 1)
    clock.t += 1
    assert up.cooldown_left("c_a") == 0.0
    assert created_ref(create(a["owner"])) == "J-1001"


def test_a_cooldown_of_a_fraction_of_a_second_is_announced_as_one_second(jenv, clock):
    up = _up()
    a = company(jenv, "c_a")
    cut_slow(a["owner"], clock)
    clock.t += 59.5
    refused(a["owner"], up, "1", 1)


@pytest.mark.parametrize("case", ["too large", "file part too large", "chunked too large", "wrong type", "quota", "csrf", "busy", "gone"])
def test_no_other_refusal_starts_a_cooldown(jenv, clock, monkeypatch, case):
    up = _up()
    a = company(jenv, "c_a")
    u = a["owner"]
    if case == "too large":
        monkeypatch.setenv("QO_MAX_FILE_MB", "1")
        assert create(u, PDF + b"x" * (2 * MB)).status_code == 413
    elif case == "file part too large":  # inside the body limit, over the file limit
        monkeypatch.setenv("QO_MAX_FILE_MB", "1")
        assert create(u, PDF + b"x" * (MB + 1000)).status_code == 413
    elif case == "chunked too large":  # no declared length: the guard cuts the body
        monkeypatch.setenv("QO_MAX_FILE_MB", "1")
        out = asgi("POST", "/jobs/upload", chunked(form(u.csrf, PDF + b"x" * (2 * MB))),
                   headers=upload_headers(u))
        assert out.status == 413
    elif case == "wrong type":
        assert create(u, b"<html>", "x.png").status_code == 400
    elif case == "quota":
        monkeypatch.setenv("QO_MAX_JOBS_PER_MONTH", "1")
        created_ref(create(u))
        assert create(u).status_code == 403
    elif case == "csrf":
        r = post_upload(u.client, form("wrong", PDF))
        assert r.status_code == 403
    elif case == "busy":
        monkeypatch.setattr(up, "SLOT_WAIT_SECONDS", 0.3)
        assert up._claim("c_a")
        try:
            assert create(u).status_code == 503
        finally:
            up._release("c_a")
    else:
        data = form(u.csrf, PDF + b"x" * 300000)
        asgi("POST", "/jobs/upload", [data[:200000], "disconnect"], headers=upload_headers(u))
    assert up._cooldown == {} and up.cooldown_left("c_a") == 0.0
    assert u.client.get("/jobs").status_code == 200
    if case != "quota":  # the quota refusal is the monthly limit itself, which stays
        assert created_ref(create(u)) in ("J-1001", "J-1002")


def test_the_dict_is_purged_of_expired_entries_by_any_call(jenv, clock):
    up = _up()
    up.start_cooldown("c_a")
    up.start_cooldown("c_b")
    clock.t += 30
    up.start_cooldown("c_c")
    assert len(up._cooldown) == 3
    clock.t += 31  # c_a and c_b ended 1 s ago, c_c has 29 s left
    assert up.cooldown_left("c_z") == 0.0
    assert set(up._cooldown) == {"c_c"}
    assert up.cooldown_left("c_c") == pytest.approx(29.0)
    clock.t += 29
    assert up.cooldown_left("c_c") == 0.0 and len(up._cooldown) == 0


def test_the_dict_never_holds_more_than_the_companies_in_cooldown(clock):
    up = _up()
    for i in range(200):
        clock.t += 1
        up.start_cooldown(f"c_{i}")
        up.cooldown_left("c_none")
        assert len(up._cooldown) <= 60


def test_the_cooldown_applies_to_adding_a_drawing_to_a_job_too(jenv, clock):
    up = _up()
    a = company(jenv, "c_a")
    ref = created_ref(create(a["owner"]))
    cut_slow(a["owner"], clock, query=f"job={ref}", ref=ref)
    assert add(a["owner"], ref).status_code == 429
    refused(a["owner"], up, "60", 60, query=f"job={ref}")
    assert len(stored_files(jenv.files, "c_a")) == 1
    clock.t += 60
    assert add(a["owner"], ref).status_code == 303


def test_session_role_origin_and_job_checks_still_come_first(jenv, clock):
    up = _up()
    a = company(jenv, "c_a")
    ref = created_ref(create(a["owner"]))
    cut_slow(a["owner"], clock)
    assert up.cooldown_left("c_a") > 0
    data = form(a["viewer"].csrf, PDF)
    viewer = asgi("POST", "/jobs/upload", chunked(data), headers=upload_headers(a["viewer"]))
    assert viewer.status == 403 and viewer.receives == 0
    assert b"paused" not in viewer.body
    data = form(a["owner"].csrf, PDF)
    bad = asgi("POST", "/jobs/upload", chunked(data),
               headers=upload_headers(a["owner"], origin="https://evil.example"))
    assert bad.status == 403 and b"paused" not in bad.body
    missing = asgi("POST", "/jobs/upload", chunked(data), headers=upload_headers(a["owner"]),
                   query="job=J-9999")
    assert missing.status == 404
    anonymous = asgi("POST", "/jobs/upload", chunked(data),
                     headers={"content-type": upload_headers(a["owner"])["content-type"]})
    assert anonymous.status != 429
    assert ref


def test_with_four_slots_the_fifth_concurrent_upload_gets_503_and_the_first_four_proceed(
        jenv, monkeypatch):
    up = _up()
    monkeypatch.setattr(up, "SLOT_WAIT_SECONDS", 0.3)
    assert up.MAX_PARALLEL == 4
    cs = [company(jenv, f"c_{n}") for n in "abcde"]
    go, results = threading.Event(), {}

    def run(c):
        data = form(c["owner"].csrf, PDF + b"x" * 1000)
        n = data.index(b"%PDF") + 20

        def gen():
            yield data[:n]
            go.wait(15)
            yield data[n:]
        results[c["owner"].csrf] = asgi("POST", "/jobs/upload", gen,
                                        headers=upload_headers(c["owner"]))
    threads = [threading.Thread(target=run, args=(c,)) for c in cs[:4]]
    for t in threads:
        t.start()
    try:
        deadline = time.monotonic() + 10
        while up.SLOTS._value != 0 and time.monotonic() < deadline:
            time.sleep(0.02)
        assert up.SLOTS._value == 0
        fifth = asgi("POST", "/jobs/upload", chunked(form(cs[4]["owner"].csrf, PDF)),
                     headers=upload_headers(cs[4]["owner"]))
        assert fifth.status == 503 and fifth.headers["retry-after"] == ["5"]
        assert fifth.receives == 0
    finally:
        go.set()
        for t in threads:
            t.join(20)
    assert sorted(r.status for r in results.values()) == [303] * 4
    assert up.SLOTS._value == up.MAX_PARALLEL


def test_real_time_a_drip_is_cut_the_retry_is_paused_and_it_ends(jenv, monkeypatch):
    up = _up()
    monkeypatch.setattr(up, "RATE_GRACE_SECONDS", 0.3)
    monkeypatch.setattr(up, "MIN_BYTES_PER_SECOND", 1000)
    monkeypatch.setattr(up, "COOLDOWN_SECONDS", 1.0)
    a, b = company(jenv, "c_a"), company(jenv, "c_b")
    data = form(a["owner"].csrf, PDF + b"x" * 300000)
    n = data.index(b"%PDF") + 20

    def drip():
        yield data[:n]
        for i in range(100):
            time.sleep(0.05)
            yield data[n + i:n + 1 + i]
    cut_at = None
    out = asgi("POST", "/jobs/upload", drip, headers=upload_headers(a["owner"]))
    cut_at = time.monotonic()
    assert out.status == 408
    retry = asgi("POST", "/jobs/upload", chunked(form(a["owner"].csrf, PDF)),
                 headers=upload_headers(a["owner"]))
    assert retry.status == 429 and retry.headers["retry-after"] == ["1"] and retry.receives == 0
    assert created_ref(create(b["owner"])) == "J-1001"  # another company at once
    time.sleep(max(0.0, 1.05 - (time.monotonic() - cut_at)))
    assert created_ref(create(a["owner"])) == "J-1001"  # the cut upload stored nothing


# --- the HLD says what is true --------------------------------------------------------------------

def test_the_hld_states_the_cooldown_the_four_slots_and_the_residual_limit():
    hld = (ROOT / "docs" / "HLD.md").read_text(encoding="utf-8")
    text = hld.split("## 13. Stage 3a: jobs and drawing upload", 1)[1]
    for needle in (
            "`uploads.COOLDOWN_SECONDS` (60 seconds)", "429", "`Retry-After`",
            "`uploads.MAX_PARALLEL` (4)", "at most one per company",
            "a 25 MB upload held the server at 70 to 71 MB",
            "in memory", "a restart clears it", "each keeps its own",
            "all users of the company", "started only by an upload that stalled or arrived too slowly",
            "several verified company accounts", "about 12 seconds per account per 72 seconds",
            "a below-rate account is cut after about 12 seconds",
            "There is no per-IP throttle", "Cloudflare client-IP header is not configured",
            "20 verified companies", "honest users for 60 seconds"):
        assert needle in text, needle
    assert "the two process slots, the single slot per company" not in text
    assert re.search(r"MAX_PARALLEL`? \(2\)", text) is None
