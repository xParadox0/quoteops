"""Stage 2a fix 5, from the third independent review (owner decision 2026-11-08).
A: only verified companies count toward the cap; the cap bites where an account becomes real, at
   POST /verify and at the reset of an unverified account, under the sign-up advisory lock.
B: unverified companies and their never-verified owners are deleted after
   QO_UNVERIFIED_MAX_AGE_HOURS (72), and beyond the QO_UNVERIFIED_KEEP (500) newest, by
   qo_purge_unverified, which the sign-up background task calls.
C: verification ends every session of the user, even one that should not exist."""
import importlib
import logging
import os
import re
import threading
import time
import uuid
from pathlib import Path

import psycopg
import pytest
import yaml

from tests.stage2a_support import (  # noqa: F401  (adb and env are fixtures)
    ENV_DEFAULTS_TO_CLEAR, NEW_PASSWORD, PASSWORD, SECRET, account, adb, csrf_from, env,
    finish_signup, forgot, login, path_of, reset_link, signed_up, signup, verify_link,
)
from tests.test_stage2a_fix3 import SIGNUP_DONE

ROOT = Path(__file__).resolve().parent.parent
PURGE = "qo_purge_unverified(integer, integer)"
CLOSED = "Sign-up is closed for now"
NOT_VALID = "This link is not valid or has expired."
VERIFIED = "Your email address is verified"
H72 = 72 * 3600


def _mod(name):
    return importlib.import_module(f"quoteops.{name}")


def _company(c, cid, status="unverified", hours=0.0, verified=False, sessions=0, users=1):
    """A company created `hours` ago with its owner (and more users), through the owner
    connection."""
    c.execute("INSERT INTO company (id, name, status, created_at)"
              " VALUES (%s, %s, %s, now() - make_interval(secs => %s))",
              (cid, f"Name {cid}", status, hours * 3600))
    for n in range(users):
        uid = uuid.uuid4()
        c.execute("INSERT INTO app_user (id, company_id, email, pw_hash, pw_salt, role,"
                  " email_verified_at, consent_version, consent_at)"
                  " VALUES (%s, %s, %s, '\\x00', '\\x00', %s, %s, 'v1', now())",
                  (uid, cid, f"u{n}@{cid}.test", "owner" if n == 0 else "viewer",
                   "now" if verified else None))
        for k in range(sessions):
            c.execute("INSERT INTO session (id_hash, user_id, expires_at)"
                      " VALUES (%s, %s, now() + interval '1 day')",
                      (f"{cid}-{n}-{k}".encode(), uid))


def _purge(db, older=H72, keep=500):
    with db.connect("qo_web", autocommit=True) as c:
        return c.execute("SELECT qo_purge_unverified(%s::int, %s::int)", (older, keep)).fetchone()[0]


def _ids(db, table="company", col="id"):
    with db.connect() as c:
        return {r[0] for r in c.execute(f"SELECT {col} FROM {table}")}


def _sessions(db):
    with db.connect() as c:
        return c.execute("SELECT count(*) FROM session").fetchone()[0]


# --- B: qo_purge_unverified ---------------------------------------------------------------------

def test_purge_deletes_exactly_the_doomed_rows(adb):
    with adb.connect() as c:
        _company(c, "c_old_unv", hours=73, sessions=2, users=2)
        _company(c, "c_old_nousers", hours=100, users=0)
        _company(c, "c_new_unv", hours=1, sessions=1)
        _company(c, "c_old_active", status="active", hours=500, verified=True, sessions=1)
        _company(c, "c_old_active_unv_user", status="active", hours=500)
        _company(c, "c_old_suspended", status="suspended", hours=500, verified=True)
        _company(c, "c_old_deleting", status="deleting", hours=500, verified=True)
        _company(c, "c_old_inconsistent", hours=500, verified=True, sessions=1)
    assert _purge(adb) == 2
    assert _ids(adb) == {"c_new_unv", "c_old_active", "c_old_active_unv_user",
                         "c_old_suspended", "c_old_deleting", "c_old_inconsistent"}
    assert _ids(adb, "app_user", "company_id") == _ids(adb)
    assert _sessions(adb) == 3  # c_new_unv, c_old_active, c_old_inconsistent


def test_purge_is_idempotent(adb):
    with adb.connect() as c:
        _company(c, "c_old", hours=80, sessions=1)
        _company(c, "c_new", hours=2)
    assert _purge(adb) == 1
    assert _purge(adb) == 0
    assert _ids(adb) == {"c_new"}


def test_purge_deletes_at_most_500_companies_a_call_oldest_first(adb):
    with adb.connect() as c:
        for n in range(520):
            _company(c, f"c_{n:03d}", hours=100 + n, sessions=1 if n % 50 == 0 else 0)
    assert _purge(adb) == 500
    assert _ids(adb) == {f"c_{n:03d}" for n in range(20)}  # the 20 newest are left
    assert _purge(adb) == 20
    assert _ids(adb) == set() and _ids(adb, "app_user") == set() and _sessions(adb) == 0


def test_purge_keeps_only_the_newest_unverified_beyond_keep(adb):
    with adb.connect() as c:
        for n in range(15):
            _company(c, f"c_{n:02d}", hours=1 + n)  # c_00 is the newest
        _company(c, "c_active", status="active", hours=30, verified=True)
        _company(c, "c_inconsistent", hours=40, verified=True)
    # 16 unverified by status, the newest 10 are kept; c_inconsistent is beyond them but has a
    # verified user, so only c_10 to c_14 go.
    assert _purge(adb, keep=10) == 5
    assert _ids(adb) == {f"c_{n:02d}" for n in range(10)} | {"c_active", "c_inconsistent"}
    assert _purge(adb, keep=10) == 0


def test_purge_never_deletes_a_verified_company_or_user(adb):
    with adb.connect() as c:
        for status in ("active", "suspended", "deleting"):
            _company(c, f"c_{status}", status=status, hours=1000, verified=True, sessions=1)
            _company(c, f"c_{status}_new", status=status, hours=1, sessions=1)
        _company(c, "c_inconsistent", hours=1000, verified=True, users=2)
        _company(c, "c_unv", hours=1000)
    before_users = _ids(adb, "app_user")
    assert _purge(adb, older=1, keep=0) == 1
    assert _ids(adb) == {"c_active", "c_active_new", "c_suspended", "c_suspended_new",
                         "c_deleting", "c_deleting_new", "c_inconsistent"}
    assert len(before_users - _ids(adb, "app_user")) == 1 and _sessions(adb) == 6


def test_purge_ignores_planted_temp_tables(adb):
    with adb.connect() as c:
        _company(c, "c_old", hours=100)
        _company(c, "c_keep", status="active", hours=100, verified=True)
    with adb.connect(autocommit=True) as c:
        for t in ("company", "app_user", "session"):
            c.execute(f"CREATE TEMP TABLE {t} (LIKE public.{t} INCLUDING DEFAULTS)")
        c.execute("INSERT INTO pg_temp.company (id, name, status, created_at)"
                  " VALUES ('c_keep', 'x', 'unverified', now() - interval '1000 hours'),"
                  " ('c_temp', 'x', 'unverified', now() - interval '1000 hours')")
        assert c.execute("SELECT qo_purge_unverified(%s, 500)", (H72,)).fetchone()[0] == 1
        assert c.execute("SELECT count(*) FROM pg_temp.company").fetchone()[0] == 2
        assert {r[0] for r in c.execute("SELECT id FROM public.company")} == {"c_keep"}


def test_web_can_call_the_purge_but_cannot_delete_other_companies_itself(adb):
    """qo_web keeps its stage 1 tenant grant on company and app_user; row-level security limits
    a direct DELETE to the company in app.company_id, so with none set it deletes nothing."""
    with adb.connect() as c:
        _company(c, "c_x", hours=100, sessions=1)
    with adb.connect("qo_web", autocommit=True) as c:
        assert c.execute("DELETE FROM company").rowcount == 0
        assert c.execute("DELETE FROM app_user").rowcount == 0
        c.execute("SELECT set_config('app.company_id', 'c_other', false)")
        assert c.execute("DELETE FROM app_user WHERE company_id = 'c_x'").rowcount == 0
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute("DELETE FROM session")
    assert _ids(adb) == {"c_x"} and _sessions(adb) == 1
    assert _purge(adb) == 1


def test_admin_and_public_cannot_call_the_purge(adb):
    with adb.connect() as c:
        _company(c, "c_x", hours=100)
        got = c.execute("SELECT has_function_privilege('qo_web', %s, 'EXECUTE'),"
                        " has_function_privilege('qo_admin', %s, 'EXECUTE'),"
                        " has_function_privilege('public', %s, 'EXECUTE')",
                        (PURGE, PURGE, PURGE)).fetchone()
        grantees = {r[0] for r in c.execute(
            "SELECT a.grantee::regrole::text FROM pg_proc p, aclexplode(p.proacl) a"
            " WHERE p.oid = to_regprocedure(%s) AND a.grantee <> p.proowner", (PURGE,))}
    assert got == (True, False, False) and grantees == {"qo_web"}
    with adb.connect("qo_admin") as c:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute("SELECT qo_purge_unverified(1, 10)")
    assert _ids(adb) == {"c_x"}


def _purge_properties(db):
    with db.connect() as c:
        return c.execute("SELECT p.prosecdef, p.proconfig, r.rolname, r.rolsuper, p.provolatile,"
                         " pg_get_function_result(p.oid)"
                         " FROM pg_proc p JOIN pg_roles r ON r.oid = p.proowner"
                         " WHERE p.oid = to_regprocedure(%s)", (PURGE,)).fetchone()


def test_purge_is_a_definer_function_with_a_pinned_search_path(adb):
    expected = (True, ["search_path=pg_catalog, public, pg_temp"], "qo_definer", False, "v",
                "integer")
    assert _purge_properties(adb) == expected
    adb.migrate()  # idempotent: applying the schema again keeps every property
    assert _purge_properties(adb) == expected


def test_purge_body_qualifies_every_table(adb):
    with adb.connect() as c:
        src = c.execute("SELECT prosrc FROM pg_proc WHERE oid = to_regprocedure(%s)",
                        (PURGE,)).fetchone()[0]
    ctes = set(re.findall(r"\b([A-Za-z_]\w*)\s+AS\s+(?:MATERIALIZED\s+)?\(", src, re.IGNORECASE))
    names = re.findall(r"\b(?:FROM|JOIN|INTO|UPDATE|USING)\s+(?!SET\b)([A-Za-z_][\w.]*)", src,
                       re.IGNORECASE)
    tables = [n for n in names if n not in ctes]
    assert {"public.company", "public.app_user", "public.session"} <= set(tables)
    assert all(n.startswith("public.") for n in tables), tables


def test_company_count_counts_verified_companies_only(adb):
    with adb.connect() as c:
        for status in ("unverified", "active", "suspended", "deleting"):
            _company(c, f"c_{status}", status=status)
    with adb.connect("qo_web") as c:
        assert c.execute("SELECT qo_company_count()").fetchone()[0] == 3


# --- A: the cap counts verified companies and bites at the link -----------------------------------

def _state(env, email):
    with env.owner() as c:
        row = c.execute("SELECT u.pw_hash, u.pw_salt, u.email_verified_at, u.consent_at, c.name,"
                        " c.status FROM app_user u JOIN company c ON c.id = u.company_id"
                        " WHERE u.email = %s", (email,)).fetchone()
    return None if row is None else (bytes(row[0]), bytes(row[1])) + tuple(row[2:])


def _verified_companies(env):
    return env.scalar("SELECT count(*) FROM company WHERE status <> 'unverified'")


def test_unverified_signups_do_not_close_signup(env):
    env.monkeypatch.setenv("QO_MAX_COMPANIES", "3")
    for n in range(6):
        signed_up(env, f"s{n}@shop.test", ip=f"198.51.100.{n // 5 + 1}")
    r = signup(env.client(ip="198.51.100.9"), "seventh@shop.test")
    assert r.status_code == 200 and SIGNUP_DONE in r.text
    assert env.scalar("SELECT count(*) FROM company") == 7
    assert len(env.mails_to("seventh@shop.test")) == 1


def test_signup_answers_stay_identical_with_unverified_companies_beyond_the_cap(env):
    env.monkeypatch.setenv("QO_MAX_COMPANIES", "2")
    for n in range(3):
        signed_up(env, f"s{n}@shop.test")
    for _ in range(3):
        signed_up(env, "busy@shop.test", ip="198.51.100.20")
    answers = [signup(env.client(ip="198.51.100.30"), "new@shop.test"),
               signup(env.client(ip="198.51.100.31"), "s0@shop.test"),
               signup(env.client(ip="198.51.100.32"), "busy@shop.test")]  # over its address limit
    assert [r.status_code for r in answers] == [200, 200, 200]
    assert answers[0].content == answers[1].content == answers[2].content
    assert SIGNUP_DONE in answers[0].text


def test_verifying_beyond_the_cap_shows_the_closed_page_and_changes_nothing(env):
    env.monkeypatch.setenv("QO_MAX_COMPANIES", "1")
    signed_up(env, "late@shop.test", company="Late Name")  # while the form is still open
    account(env, "first@shop.test")
    link = verify_link(env, "late@shop.test")
    before, mails = _state(env, "late@shop.test"), len(env.mails())
    c = env.client()
    r = c.get(path_of(link))  # the form is still shown; only the POST refuses
    assert r.status_code == 200 and 'action="/verify"' in r.text
    r = finish_signup(c, link, company="New Name")
    assert r.status_code == 403 and CLOSED in r.text
    assert _state(env, "late@shop.test") == before and len(env.mails()) == mails
    assert login(env.client(), "late@shop.test").status_code == 400
    env.monkeypatch.setenv("QO_MAX_COMPANIES", "2")  # a raised cap lets the same link work
    r = finish_signup(env.client(), link, company="New Name")
    assert r.status_code == 200 and VERIFIED in r.text
    assert _state(env, "late@shop.test")[4:] == ("New Name", "active")


def test_reset_of_an_unverified_account_at_the_cap_shows_the_closed_page(env):
    env.monkeypatch.setenv("QO_MAX_COMPANIES", "1")
    signed_up(env, "late@shop.test")  # while the form is still open
    account(env, "first@shop.test")
    forgot(env.client(), "late@shop.test")
    token = reset_link(env, "late@shop.test").split("?token=", 1)[1]
    c = env.client()
    data = {"csrf": csrf_from(c.get("/reset", params={"token": token}).text), "token": token,
            "password": NEW_PASSWORD}
    before, mails = _state(env, "late@shop.test"), len(env.mails())
    r = c.post("/reset", data=data)
    assert r.status_code == 403 and CLOSED in r.text
    assert _state(env, "late@shop.test") == before and len(env.mails()) == mails
    env.monkeypatch.setenv("QO_MAX_COMPANIES", "2")
    assert c.post("/reset", data=data).status_code == 200  # the token is still good
    assert _state(env, "late@shop.test")[5] == "active"
    assert login(env.client(), "late@shop.test", NEW_PASSWORD).status_code == 303


def test_reset_of_a_verified_account_is_not_affected_by_the_cap(env):
    env.monkeypatch.setenv("QO_MAX_COMPANIES", "1")
    account(env, "first@shop.test")
    forgot(env.client(), "first@shop.test")
    token = reset_link(env, "first@shop.test").split("?token=", 1)[1]
    c = env.client()
    data = {"csrf": csrf_from(c.get("/reset", params={"token": token}).text), "token": token,
            "password": NEW_PASSWORD}
    assert c.post("/reset", data=data).status_code == 200
    assert login(env.client(), "first@shop.test", NEW_PASSWORD).status_code == 303


@pytest.mark.parametrize("status", ["suspended", "deleting"])
def test_a_suspended_company_is_not_affected_by_the_cap_check(env, status):
    env.monkeypatch.setenv("QO_MAX_COMPANIES", "2")
    signed_up(env, "late@shop.test", company="Old Name")
    with env.owner() as o:
        o.execute("UPDATE company SET status = %s WHERE name = 'Old Name'", (status,))
    account(env, "first@shop.test")  # with the suspended one, the cap is full now
    assert _verified_companies(env) == 2
    r = finish_signup(env.client(), verify_link(env, "late@shop.test"), company="New Name")
    assert r.status_code == 200 and VERIFIED in r.text
    state = _state(env, "late@shop.test")
    assert state[2] is not None and state[4:] == ("Old Name", status)


def test_two_verifications_at_the_last_place_admit_exactly_one(env):
    """At count = max - 1 two links are sent at once. The check is held open in each request
    until the other arrives or 3 s pass: with the advisory lock the second request waits for the
    first to commit and then sees the cap reached; without it both pass."""
    env.monkeypatch.setenv("QO_MAX_COMPANIES", "2")
    account(env, "first@shop.test")
    emails = ["b@shop.test", "c@shop.test"]
    for e in emails:
        signed_up(env, e)
    clients = [env.client(), env.client()]
    datas = []
    for cl, e in zip(clients, emails):
        link = verify_link(env, e)
        r = cl.get(path_of(link))
        datas.append({"csrf": csrf_from(r.text), "token": link.split("?token=", 1)[1],
                      "password": PASSWORD, "company": "Bengkel Maju", "terms": "yes"})
    auth, together = _mod("auth"), threading.Barrier(2)
    real = auth._cap_closed

    def held_open(*a, **kw):
        result = real(*a, **kw)
        try:
            together.wait(3)
        except threading.BrokenBarrierError:
            pass
        return result

    env.monkeypatch.setattr(auth, "_cap_closed", held_open)
    results = [None, None]

    def run(i):
        results[i] = clients[i].post("/verify", data=datas[i])

    threads = [threading.Thread(target=run, args=(i,)) for i in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    codes = sorted(r.status_code for r in results)
    assert codes == [200, 403], [r.text for r in results]
    assert sum(CLOSED in r.text for r in results) == 1
    assert _verified_companies(env) == 2
    assert env.scalar("SELECT count(*) FROM app_user WHERE email_verified_at IS NULL") == 1


# --- B: the purge runs from the sign-up background task -------------------------------------------

def test_signup_purges_an_old_unverified_company(env):
    with env.owner() as c:
        _company(c, "c_abandoned", hours=73, sessions=1)
        _company(c, "c_recent", hours=1)
        _company(c, "c_live", status="active", hours=1000, verified=True)
    signed_up(env, "new@shop.test")
    ids = _ids(env.db)
    assert "c_abandoned" not in ids and {"c_recent", "c_live"} <= ids and len(ids) == 3
    assert env.scalar("SELECT count(*) FROM app_user WHERE email = 'new@shop.test'") == 1
    assert env.scalar("SELECT count(*) FROM session") == 0


def test_signup_purge_uses_the_age_setting(env):
    env.monkeypatch.setenv("QO_UNVERIFIED_MAX_AGE_HOURS", "100")
    with env.owner() as c:
        _company(c, "c_80h", hours=80)
        _company(c, "c_101h", hours=101)
    signed_up(env, "new@shop.test")
    assert "c_80h" in _ids(env.db) and "c_101h" not in _ids(env.db)


class PurgeBoom(Exception):
    pass


def test_a_failing_purge_does_not_stop_the_signup(env, monkeypatch, caplog):
    def boom(*a, **kw):
        raise PurgeBoom("detail-that-must-not-leak new@shop.test")

    monkeypatch.setattr(_mod("auth"), "_purge_unverified", boom)
    caplog.set_level(logging.DEBUG)
    with env.owner() as c:
        _company(c, "c_abandoned", hours=73)
    r = signup(env.client(), "new@shop.test")
    assert r.status_code == 200 and SIGNUP_DONE in r.text
    assert env.scalar("SELECT count(*) FROM app_user WHERE email = 'new@shop.test'") == 1
    assert len(env.mails_to("new@shop.test")) == 1
    assert "c_abandoned" in _ids(env.db)
    texts = [f"{x.getMessage()} {x.args!r} {x.exc_text or ''}" for x in caplog.records
             if not x.name.startswith(("httpx", "httpcore"))]
    assert any("PurgeBoom" in t for t in texts)
    assert not any("detail-that-must-not-leak" in t or "new@shop.test" in t for t in texts)
    assert not any(x.exc_info for x in caplog.records)


def test_keep_evicts_the_oldest_unverified_through_signup(env):
    env.monkeypatch.setenv("QO_UNVERIFIED_KEEP", "10")
    with env.owner() as c:
        _company(c, "c_live", status="active", hours=1000, verified=True)
    emails = [f"s{n:02d}@shop.test" for n in range(12)]
    for n, e in enumerate(emails):
        signed_up(env, e, ip=f"198.51.100.{n // 5 + 1}")
        time.sleep(0.01)  # distinct creation times
    # Each sign-up purges before it creates: 10 kept + the new one.
    left = _ids(env.db, "app_user", "email")
    assert left == set(emails[1:]) | {"u0@c_live.test"}
    r = env.client().get(path_of(verify_link(env, emails[0])))
    assert r.status_code == 400 and NOT_VALID in r.text


def test_a_purged_account_has_no_valid_link(env):
    signed_up(env, "gone@shop.test")
    link = verify_link(env, "gone@shop.test")
    with env.owner() as o:
        o.execute("UPDATE company SET created_at = now() - interval '73 hours'")
    signed_up(env, "other@shop.test")  # its background task purges
    assert env.scalar("SELECT count(*) FROM app_user WHERE email = 'gone@shop.test'") == 0
    c = env.client()
    r = c.get(path_of(link))
    assert r.status_code == 400 and NOT_VALID in r.text
    data = {"csrf": csrf_from(c.get("/signup").text), "token": link.split("?token=", 1)[1],
            "password": PASSWORD, "company": "X", "terms": "yes"}
    r = c.post("/verify", data=data)
    assert r.status_code == 400 and NOT_VALID in r.text


def test_a_verification_link_expires_before_the_purge(env):
    """The link lasts 48 hours, the account 72: a link older than 48 hours is not valid even
    though the account still exists."""
    auth, tokens = _mod("auth"), _mod("tokens")
    signed_up(env, "late@shop.test")
    token = tokens.make("verify", "late@shop.test", auth.VERIFY_SECONDS, SECRET.encode(),
                        now=time.time() - auth.VERIFY_SECONDS - 60)
    r = env.client().get("/verify", params={"token": token})
    assert r.status_code == 400 and NOT_VALID in r.text
    assert env.scalar("SELECT count(*) FROM app_user WHERE email = 'late@shop.test'") == 1
    config = _mod("config")
    assert config.UNVERIFIED_MIN_AGE_HOURS * 3600 > auth.VERIFY_SECONDS


# --- settings ------------------------------------------------------------------------------------

@pytest.fixture
def cfg(monkeypatch):
    for k in list(os.environ):
        if k.startswith("QO_"):
            monkeypatch.delenv(k)
    monkeypatch.setenv("QO_SECRET", SECRET)
    monkeypatch.setenv("QO_BASE_URL", "https://qo.example")
    return monkeypatch


def test_unverified_settings_defaults(cfg):
    s = _mod("config").load_settings()
    assert (s.unverified_max_age_hours, s.unverified_keep) == (72, 500)


@pytest.mark.parametrize("var,value,ok", [
    ("QO_UNVERIFIED_MAX_AGE_HOURS", "0", False),
    ("QO_UNVERIFIED_MAX_AGE_HOURS", "1", False),
    ("QO_UNVERIFIED_MAX_AGE_HOURS", "48", False),
    ("QO_UNVERIFIED_MAX_AGE_HOURS", "-72", False),
    ("QO_UNVERIFIED_MAX_AGE_HOURS", "soon", False),
    ("QO_UNVERIFIED_MAX_AGE_HOURS", "8761", False),
    ("QO_UNVERIFIED_MAX_AGE_HOURS", "49", True),
    ("QO_UNVERIFIED_MAX_AGE_HOURS", "72", True),
    ("QO_UNVERIFIED_MAX_AGE_HOURS", "8760", True),
    ("QO_UNVERIFIED_KEEP", "9", False),
    ("QO_UNVERIFIED_KEEP", "many", False),
    ("QO_UNVERIFIED_KEEP", "1000001", False),
    ("QO_UNVERIFIED_KEEP", "10", True),
    ("QO_UNVERIFIED_KEEP", "500", True),
])
def test_unverified_settings_are_checked(cfg, var, value, ok):
    config = _mod("config")
    cfg.setenv(var, value)
    if ok:
        s = config.load_settings()
        got = s.unverified_max_age_hours if var == "QO_UNVERIFIED_MAX_AGE_HOURS" else s.unverified_keep
        assert got == int(value)
        return
    with pytest.raises(config.ConfigError) as exc:
        config.load_settings()
    assert var in str(exc.value) and value not in str(exc.value)


def test_unverified_settings_reach_the_web_container_the_example_and_the_tests():
    web = yaml.safe_load((ROOT / "deploy" / "compose.yaml").read_text())["services"]["web"]
    assert web["environment"]["QO_UNVERIFIED_MAX_AGE_HOURS"] == "${QO_UNVERIFIED_MAX_AGE_HOURS:-72}"
    assert web["environment"]["QO_UNVERIFIED_KEEP"] == "${QO_UNVERIFIED_KEEP:-500}"
    example = (ROOT / "deploy" / ".env.example").read_text()
    assert "QO_UNVERIFIED_MAX_AGE_HOURS" in example and "QO_UNVERIFIED_KEEP" in example
    assert {"QO_UNVERIFIED_MAX_AGE_HOURS", "QO_UNVERIFIED_KEEP"} <= set(ENV_DEFAULTS_TO_CLEAR)


# --- C: verification ends every session of the user -----------------------------------------------

def test_verification_deletes_a_session_of_the_unverified_user(env):
    signed_up(env, "owner@shop.test")
    with env.owner() as o:  # artificial: the unusable credential cannot sign in
        uid = o.execute("SELECT id FROM app_user WHERE email = 'owner@shop.test'").fetchone()[0]
        o.execute("INSERT INTO session (id_hash, user_id, expires_at)"
                  " VALUES ('\\x77', %s, now() + interval '1 day')", (uid,))
    r = finish_signup(env.client(), verify_link(env, "owner@shop.test"))
    assert r.status_code == 200 and VERIFIED in r.text
    assert env.scalar("SELECT count(*) FROM session") == 0
