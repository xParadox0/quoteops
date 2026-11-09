"""Stage 2a fix 4, from the second independent review.
A: a request answered 503 (busy) changes nothing: sign-in, the verification form and reset take
   the scrypt slot first, before any throttle hit and any database connection.
B: no pre-hijacking: sign-up has no password; the mailbox owner chooses it when the verification
   link is opened, and until then the account has an unusable credential.
C: the scrypt settings have upper bounds."""
import hashlib
import importlib
import re
import threading
import time

import pytest
from markupsafe import escape

from tests.stage2a_support import (  # noqa: F401  (adb and env are fixtures)
    BASE, NEW_PASSWORD, PASSWORD, SECRET, account, adb, csrf_from, env, finish_signup, forgot,
    form_csrf, login, path_of, reset_link, session_cookie, signed_up, signup, token_of,
    verify_link,
)
from tests.test_stage2a_fix3 import (
    SIGNUP_DONE, _assert_busy, _blocked, _limit, _no_connection, _throttle_rows,
)

GENERIC = "The email or password is not correct."
ALREADY = "Already verified"
HOSTILE = "<script>x</script>\"'"


def _mod(name):
    return importlib.import_module(f"quoteops.{name}")


def _user(env, email):
    with env.owner() as c:
        row = c.execute("SELECT u.pw_hash, u.pw_salt, u.email_verified_at, u.consent_version,"
                        " u.consent_at, c.name, c.status FROM app_user u"
                        " JOIN company c ON c.id = u.company_id WHERE u.email = %s",
                        (email,)).fetchone()
    return None if row is None else (bytes(row[0]), bytes(row[1])) + tuple(row[2:])


def _verify_form(client, link):
    """GET the link; returns the form data a browser would send, without the user's fields."""
    r = client.get(path_of(link))
    assert r.status_code == 200 and 'action="/verify"' in r.text, r.text
    return {"csrf": csrf_from(r.text), "token": token_of(link)}


def _verify_data(client, link, password=PASSWORD, company="Bengkel Maju", terms=True):
    data = {**_verify_form(client, link), "password": password, "company": company}
    if terms:
        data["terms"] = "yes"
    return data


def _scrypt_of(password, salt):
    passwords = _mod("passwords")
    return passwords._scrypt(password, salt)


# --- A: a busy answer changes nothing ---------------------------------------------------------

def test_busy_reset_changes_nothing_and_opens_no_connection(env):
    account(env, "owner@shop.test")
    forgot(env.client(), "owner@shop.test")
    token = token_of(reset_link(env, "owner@shop.test"))
    c = env.client()
    data = {"csrf": csrf_from(c.get("/reset", params={"token": token}).text), "token": token,
            "password": NEW_PASSWORD}
    before, rows = _user(env, "owner@shop.test"), _throttle_rows(env)
    with _blocked(env):
        with _no_connection(env):
            r = c.post("/reset", data=data)
    _assert_busy(r)
    assert _user(env, "owner@shop.test") == before and _throttle_rows(env) == rows
    assert c.get("/reset", params={"token": token}).status_code == 200  # the token still works
    assert c.post("/reset", data=data).status_code == 200


def test_busy_verification_changes_nothing_and_opens_no_connection(env):
    signed_up(env, "owner@shop.test")
    c = env.client()
    link = verify_link(env, "owner@shop.test")
    data = _verify_data(c, link)
    before, rows, mails = _user(env, "owner@shop.test"), _throttle_rows(env), len(env.mails())
    with _blocked(env):
        with _no_connection(env):
            r = c.post("/verify", data=data)
    _assert_busy(r)
    assert _user(env, "owner@shop.test") == before and _throttle_rows(env) == rows
    assert len(env.mails()) == mails
    r = c.post("/verify", data=data)  # the same link still works
    assert r.status_code == 200 and ALREADY not in r.text
    assert login(env.client(), "owner@shop.test").status_code == 303


def test_five_busy_answers_do_not_lead_to_a_lockout(env):
    account(env, "owner@shop.test")
    c = env.client()
    csrf = form_csrf(c, "/login")
    with _blocked(env):
        for _ in range(5):
            _assert_busy(c.post("/login", data={"csrf": csrf, "email": "owner@shop.test",
                                                "password": "wrong password here"}))
    _limit(env, concurrency=3, wait=8)
    assert login(c, "owner@shop.test").status_code == 303


def test_one_slot_is_enough_for_every_route_that_hashes(env):
    """With QO_SCRYPT_CONCURRENCY=1 the outer slot of the request and the scrypt inside it share
    the one slot: nothing deadlocks or waits until busy."""
    _limit(env, concurrency=1, wait=2)
    account(env, "owner@shop.test")  # the verification POST and a sign-in
    assert login(env.client(), "owner@shop.test").status_code == 303
    assert login(env.client(), "nobody@shop.test", "wrong password here").status_code == 400
    forgot(env.client(), "owner@shop.test")
    token = token_of(reset_link(env, "owner@shop.test"))
    c = env.client()
    r = c.get("/reset", params={"token": token})
    r = c.post("/reset", data={"csrf": csrf_from(r.text), "token": token,
                               "password": NEW_PASSWORD})
    assert r.status_code == 200, r.text
    assert login(env.client(), "owner@shop.test", NEW_PASSWORD).status_code == 303


def test_scrypt_slot_is_reentrant_per_thread_and_released(env):
    passwords = _mod("passwords")
    _limit(env, concurrency=1, wait=0.05)
    with passwords.scrypt_slot():
        h, salt = passwords.hash_password("milling cutter 7 bright")  # no second acquire
        assert passwords.verify_password("milling cutter 7 bright", h, salt) is True
        with passwords.scrypt_slot():
            assert passwords.verify_dummy("milling cutter 7 bright") is False
        other = []

        def elsewhere():
            try:
                with passwords.scrypt_slot():
                    other.append("got it")
            except passwords.Busy:
                other.append("busy")

        t = threading.Thread(target=elsewhere)
        t.start()
        t.join(5)
        assert other == ["busy"]  # another thread still sees the one slot taken
    with pytest.raises(RuntimeError):
        with passwords.scrypt_slot():
            raise RuntimeError("inside")
    with passwords.scrypt_slot():  # released after the error, and after the nested use
        pass
    assert passwords.verify_password("milling cutter 7 bright", h, salt) is True


# --- B: sign-up without a password ------------------------------------------------------------

def test_signup_form_has_no_password_and_a_sent_one_is_ignored(env):
    c = env.client()
    page = c.get("/signup").text
    assert 'name="password"' not in page and 'type="password"' not in page
    r = c.post("/signup", data={"csrf": csrf_from(page), "email": "new@shop.test",
                                "password": PASSWORD, "company": "New", "terms": "yes"})
    assert r.status_code == 200 and SIGNUP_DONE in r.text
    pw_hash, pw_salt = _user(env, "new@shop.test")[:2]
    assert _scrypt_of(PASSWORD, pw_salt) != pw_hash
    assert login(env.client(), "new@shop.test").status_code == 400


def test_unusable_credential_is_random_per_account(env):
    signed_up(env, "one@shop.test")
    signed_up(env, "two@shop.test")
    one, two = _user(env, "one@shop.test"), _user(env, "two@shop.test")
    assert (len(one[0]), len(one[1])) == (len(two[0]), len(two[1])) == (32, 16)
    assert one[0] != two[0] and one[1] != two[1]
    assert one[0] != _scrypt_of("", one[1])


def test_signup_runs_no_scrypt_at_all(env, monkeypatch):
    calls, real = [], hashlib.scrypt
    monkeypatch.setattr(hashlib, "scrypt", lambda pw, **kw: calls.append(1) or real(pw, **kw))
    signed_up(env, "new@shop.test")
    signup(env.client(), "new@shop.test")  # an existing, unverified address
    assert calls == [] and len(env.mails_to("new@shop.test")) == 2


def test_signup_answers_are_identical_for_new_existing_and_throttled_addresses(env):
    signed_up(env, "unverified@shop.test", ip="192.0.2.1")
    account(env, "verified@shop.test", ip="192.0.2.2")
    for n in range(3):
        signed_up(env, "busy@shop.test", ip=f"192.0.2.{n + 3}")  # the address limit is reached
    answers = {e: signup(env.client(ip=f"198.51.100.{n + 1}"), e, company="Other")
               for n, e in enumerate(("new@shop.test", "unverified@shop.test",
                                      "verified@shop.test", "busy@shop.test"))}
    first = answers["new@shop.test"]
    assert first.status_code == 200 and SIGNUP_DONE in first.text
    for case, r in answers.items():
        assert (r.status_code, r.content) == (first.status_code, first.content), case
    assert len(env.mails_to("busy@shop.test")) == 3


def test_signup_again_for_an_unverified_address_mails_a_link_and_keeps_the_account(env):
    signed_up(env, "owner@shop.test", company="First Name")
    before = _user(env, "owner@shop.test")
    signup(env.client(ip="192.0.2.50"), "owner@shop.test", company="Second Name")
    mails = env.mails_to("owner@shop.test")
    assert len(mails) == 2 and all("/verify?token=" in m.body for m in mails)
    assert _user(env, "owner@shop.test") == before


# --- B: the verification link chooses the password ---------------------------------------------

def test_verification_form_is_shown_once_then_already_verified(env):
    signed_up(env, "owner@shop.test", company="Bengkel Maju")
    c = env.client()
    link = verify_link(env, "owner@shop.test")
    r = c.get(path_of(link))
    assert r.status_code == 200
    html = r.text
    assert 'action="/verify"' in html and 'name="password"' in html
    assert re.search(r'name="company"[^>]*value="Bengkel Maju"', html)
    assert 'name="terms"' in html and f'name="token" value="{token_of(link)}"' in html
    assert _user(env, "owner@shop.test")[2] is None  # opening the link changes nothing
    r = finish_signup(c, link)
    assert r.status_code == 200 and 'href="/login"' in r.text
    assert "qo_session=" not in r.headers.get("set-cookie", "")  # no sign-in by the link
    assert env.scalar("SELECT count(*) FROM session") == 0
    again = c.get(path_of(link))
    assert again.status_code == 200 and ALREADY in again.text
    assert 'name="password"' not in again.text and 'href="/login"' in again.text


def test_the_password_chosen_at_the_link_is_the_one_that_signs_in(env):
    signed_up(env, "owner@shop.test")
    for pw in (PASSWORD, NEW_PASSWORD, "", "x" * 12):  # sign-up never had a password
        assert login(env.client(), "owner@shop.test", pw).status_code == 400
    assert finish_signup(env.client(), verify_link(env, "owner@shop.test"),
                         password=NEW_PASSWORD).status_code == 200
    assert login(env.client(), "owner@shop.test", NEW_PASSWORD).status_code == 303
    assert login(env.client(), "owner@shop.test", PASSWORD).status_code == 400


def test_an_unverified_account_fails_sign_in_like_an_unknown_address(env, monkeypatch):
    signed_up(env, "owner@shop.test")
    c = env.client()
    csrf = form_csrf(c, "/login")
    calls, real = [], hashlib.scrypt
    monkeypatch.setattr(hashlib, "scrypt", lambda pw, **kw: calls.append(1) or real(pw, **kw))
    answers = {}
    for email in ("owner@shop.test", "nobody@shop.test"):
        calls.clear()
        answers[email] = c.post("/login", data={"csrf": csrf, "email": email,
                                                "password": PASSWORD})
        assert len(calls) == 1, email
    a = answers["owner@shop.test"]
    b = answers["nobody@shop.test"]
    assert a.status_code == b.status_code == 400 and GENERIC in a.text
    assert a.text.replace("owner@shop.test", "E") == b.text.replace("nobody@shop.test", "E")
    assert "verif" not in a.text.lower()


def test_pre_hijacking_the_attacker_cannot_sign_in(env):
    attacker = env.client(ip="203.0.113.66")
    assert signup(attacker, "victim@x.co", company="Evil Corp").status_code == 200
    signed_up_at = _user(env, "victim@x.co")[4]
    victim = env.client(ip="198.51.100.7")
    time.sleep(0.01)
    r = finish_signup(victim, verify_link(env, "victim@x.co"), password="victim chosen phrase 7",
                      company="Real Shop")
    assert r.status_code == 200
    pw_hash, _, verified_at, version, consent_at, name, status = _user(env, "victim@x.co")
    assert name == "Real Shop" and status == "active" and verified_at is not None
    assert version == "draft-0" and consent_at > signed_up_at
    for guess in (PASSWORD, "attacker phrase 123", "", "victim@x.co"):
        assert login(attacker, "victim@x.co", guess).status_code == 400, guess
    assert session_cookie(attacker) is None
    assert signup(attacker, "victim@x.co", company="Evil Corp").status_code == 200
    assert _user(env, "victim@x.co")[0] == pw_hash  # signing up again changes nothing
    assert "already exists" in env.mails_to("victim@x.co")[-1].body
    assert login(victim, "victim@x.co", "victim chosen phrase 7").status_code == 303


def test_a_second_submission_of_the_link_is_already_verified(env):
    signed_up(env, "owner@shop.test")
    link = verify_link(env, "owner@shop.test")
    tab1, tab2 = env.client(), env.client()
    data1, data2 = _verify_data(tab1, link), _verify_data(tab2, link, password=NEW_PASSWORD,
                                                          company="Other Name")
    assert tab1.post("/verify", data=data1).status_code == 200
    state = _user(env, "owner@shop.test")
    r = tab2.post("/verify", data=data2)
    assert r.status_code == 200 and ALREADY in r.text and 'name="password"' not in r.text
    assert _user(env, "owner@shop.test") == state
    assert login(env.client(), "owner@shop.test").status_code == 303
    assert login(env.client(), "owner@shop.test", NEW_PASSWORD).status_code == 400


def test_two_parallel_submissions_set_the_password_once(env):
    signed_up(env, "owner@shop.test")
    link = verify_link(env, "owner@shop.test")
    pws = ["first parallel phrase 1", "second parallel phrase 2"]
    clients = [env.client(), env.client()]
    datas = [_verify_data(c, link, password=pw) for c, pw in zip(clients, pws)]
    passwords, together = _mod("passwords"), threading.Barrier(2)
    real = passwords.hash_password

    def hash_after_both_checked(password):  # both requests have seen the account unverified
        together.wait(10)
        return real(password)

    env.monkeypatch.setattr(passwords, "hash_password", hash_after_both_checked)
    results = [None, None]

    def run(i):
        results[i] = clients[i].post("/verify", data=datas[i])

    threads = [threading.Thread(target=run, args=(i,)) for i in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    assert all(r.status_code == 200 for r in results)
    already = [ALREADY in r.text for r in results]
    assert sorted(already) == [False, True], [r.text for r in results]
    winner = pws[already.index(False)]
    pw_hash, pw_salt = _user(env, "owner@shop.test")[:2]
    assert _scrypt_of(winner, pw_salt) == pw_hash
    env.monkeypatch.setattr(passwords, "hash_password", real)
    assert login(env.client(), "owner@shop.test", winner).status_code == 303
    assert login(env.client(), "owner@shop.test", pws[already.index(True)]).status_code == 400


@pytest.mark.parametrize("status", ["suspended", "deleting"])
def test_verification_keeps_a_suspended_company_as_it_is(env, status):
    signed_up(env, "owner@shop.test", company="Old Name")
    with env.owner() as o:
        o.execute("UPDATE company SET status = %s", (status,))
    r = finish_signup(env.client(), verify_link(env, "owner@shop.test"), company="New Name")
    assert r.status_code == 200
    state = _user(env, "owner@shop.test")
    assert state[5:] == ("Old Name", status) and state[2] is not None


@pytest.mark.parametrize("change,field", [
    ({"terms": False}, "terms"),
    ({"password": "password123"}, "password"),
    ({"password": "short"}, "password"),
    ({"password": "correct\x00horse battery"}, "password"),
    ({"password": "owner@shop.test"}, "password"),
    ({"company": "   "}, "company"),
    ({"company": "x" * 81}, "company"),
    ({"company": "Bengkel\x1bMaju"}, "company"),
])
def test_verification_form_errors_change_nothing(env, change, field):
    signed_up(env, "owner@shop.test")
    before = _user(env, "owner@shop.test")
    c = env.client()
    link = verify_link(env, "owner@shop.test")
    r = c.post("/verify", data=_verify_data(c, link, **change))
    assert r.status_code == 400 and f'id="{field}-error"' in r.text
    assert 'action="/verify"' in r.text and f'value="{token_of(link)}"' in r.text
    assert _user(env, "owner@shop.test") == before
    assert env.scalar("SELECT count(*) FROM session") == 0


def _bad_tokens(good):
    tokens, key = _mod("tokens"), SECRET.encode()
    payload, sig = good.split(".")
    return {
        "expired": tokens.make("verify", "owner@shop.test", 48 * 3600, key,
                               now=time.time() - 48 * 3600 - 5),
        "tampered_sig": payload + "." + ("A" if sig[0] != "A" else "B") + sig[1:],
        "tampered_payload": tokens.make("verify", "other@shop.test", 60, key).split(".")[0]
        + "." + sig,
        "wrong_kind": tokens.make("reset", "owner@shop.test", 3600, key),
        "wrong_secret": tokens.make("verify", "owner@shop.test", 3600, b"z" * 40),
        "truncated": good[:-4],
        "empty": "",
        "unknown_email": tokens.make("verify", "nobody@shop.test", 3600, key),
    }


def test_verification_post_refuses_bad_tokens(env):
    signed_up(env, "owner@shop.test")
    signed_up(env, "other@shop.test", ip="192.0.2.9")
    before = [_user(env, e) for e in ("owner@shop.test", "other@shop.test")]
    c = env.client()
    link = verify_link(env, "owner@shop.test")
    for name, bad in _bad_tokens(token_of(link)).items():
        data = {**_verify_data(c, link), "token": bad}
        r = c.post("/verify", data=data)
        assert r.status_code == 400 and "not valid" in r.text, name
        assert [_user(env, e) for e in ("owner@shop.test", "other@shop.test")] == before, name


def test_reset_of_an_unverified_account_verifies_and_activates_it(env):
    signed_up(env, "owner@shop.test")
    before = _user(env, "owner@shop.test")
    forgot(env.client(), "owner@shop.test")
    c = env.client()
    token = token_of(reset_link(env, "owner@shop.test"))
    r = c.get("/reset", params={"token": token})
    r = c.post("/reset", data={"csrf": csrf_from(r.text), "token": token,
                               "password": NEW_PASSWORD})
    assert r.status_code == 200
    after = _user(env, "owner@shop.test")
    assert after[2] is not None and after[6] == "active"
    assert after[3:6] == before[3:6]  # consent and name stay as recorded at sign-up
    assert login(env.client(), "owner@shop.test", NEW_PASSWORD).status_code == 303
    again = env.client().get(path_of(verify_link(env, "owner@shop.test")))
    assert again.status_code == 200 and ALREADY in again.text


def test_reset_of_a_verified_account_keeps_its_verification_time(env):
    account(env, "owner@shop.test")
    verified_at = _user(env, "owner@shop.test")[2]
    forgot(env.client(), "owner@shop.test")
    c = env.client()
    token = token_of(reset_link(env, "owner@shop.test"))
    r = c.get("/reset", params={"token": token})
    c.post("/reset", data={"csrf": csrf_from(r.text), "token": token, "password": NEW_PASSWORD})
    assert _user(env, "owner@shop.test")[2] == verified_at


def test_verification_page_escapes_and_follows_the_page_rules(env):
    signed_up(env, "owner@shop.test", company=HOSTILE)
    r = env.client().get(path_of(verify_link(env, "owner@shop.test")))
    html = r.text
    assert r.status_code == 200 and HOSTILE not in html and str(escape(HOSTILE)) in html
    assert "<script" not in html.lower() and " style=" not in html
    assert not re.search(r'(src|href|action)="(https?:)?//', html)
    for m in re.finditer(r"<input([^>]*)>", html):
        if 'type="hidden"' in m.group(1):
            continue
        ident = re.search(r'id="([^"]+)"', m.group(1)).group(1)
        assert f'<label for="{ident}"' in html, ident
    assert r.headers.get("cache-control") == "no-store"


def test_verification_mail_and_signup_page_say_the_password_comes_with_the_link(env):
    page = env.client().get("/signup").text
    assert "password" in page.lower()  # it tells where the password is chosen
    signed_up(env, "owner@shop.test")
    body = env.mails_to("owner@shop.test")[0].body
    assert "choose your password" in body
    assert BASE + "/verify?token=" in body


# --- C: upper bounds of the scrypt settings ---------------------------------------------------

@pytest.mark.parametrize("var,value,ok", [
    ("QO_SCRYPT_WAIT_SECONDS", "1e100", False),
    ("QO_SCRYPT_WAIT_SECONDS", "1e308", False),
    ("QO_SCRYPT_WAIT_SECONDS", "3601", False),
    ("QO_SCRYPT_WAIT_SECONDS", "3600", True),
    ("QO_SCRYPT_WAIT_SECONDS", "0.001", True),
    ("QO_SCRYPT_CONCURRENCY", "65", False),
    ("QO_SCRYPT_CONCURRENCY", "100000", False),
    ("QO_SCRYPT_CONCURRENCY", "64", True),
])
def test_scrypt_settings_have_upper_bounds(monkeypatch, var, value, ok):
    config = _mod("config")
    for k in ("QO_SCRYPT_CONCURRENCY", "QO_SCRYPT_WAIT_SECONDS"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv(var, value)
    if ok:
        concurrency, wait = config.scrypt_limits()
        assert (concurrency if var == "QO_SCRYPT_CONCURRENCY" else wait) == float(value)
        return
    with pytest.raises(config.ConfigError) as exc:
        config.scrypt_limits()
    assert var in str(exc.value) and value not in str(exc.value)
