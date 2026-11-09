"""Stage 2a fix 2: a per-address limit on sign-up, so QuoteOps mail cannot flood an inbox."""
from tests.stage2a_support import account, adb, env, signup, throttle_key  # noqa: F401  (fixtures)

VICTIM = "victim@shop.test"


def _ips(n):
    return [f"203.0.113.{i}" for i in range(1, n + 1)]


def _expire(env):
    with env.owner() as o:
        o.execute("UPDATE auth_throttle SET blocked_until = now() - interval '1 second',"
                  " window_start = now() - interval '2 hours' WHERE kind = 'signup_email'")


def test_one_address_from_many_networks_gets_three_mails_and_identical_answers(env):
    answers = [signup(env.client(ip=ip), VICTIM) for ip in _ips(12)]
    assert len(env.mails_to(VICTIM)) == 3
    assert {(r.status_code, r.text) for r in answers} == {(answers[0].status_code, answers[0].text)}
    assert answers[0].status_code == 200 and "Check your email" in answers[0].text
    assert env.scalar("SELECT count(*) FROM company") == 1
    assert env.scalar("SELECT count(*) FROM app_user") == 1


def test_mail_flows_again_after_the_window(env):
    for ip in _ips(5):
        signup(env.client(ip=ip), VICTIM)
    assert len(env.mails_to(VICTIM)) == 3
    _expire(env)
    signup(env.client(ip="198.51.100.1"), VICTIM)
    assert len(env.mails_to(VICTIM)) == 4


def test_a_different_address_is_unaffected(env):
    for ip in _ips(5):
        signup(env.client(ip=ip), VICTIM)
    r = signup(env.client(ip="198.51.100.2"), "other@shop.test")
    assert r.status_code == 200 and len(env.mails_to("other@shop.test")) == 1


def test_stored_key_is_a_hash_not_the_address(env):
    signup(env.client(ip="192.0.2.77"), "Someone@Shop.test")
    with env.owner() as o:
        rows = {(bytes(r[0]), r[1]) for r in o.execute("SELECT key, kind FROM auth_throttle")}
    assert rows == {(throttle_key("signup_email", "someone@shop.test"), "signup_email"),
                    (throttle_key("signup_ip", "192.0.2.77"), "signup_ip")}


def test_an_existing_accounts_address_hits_the_limit_too(env):
    account(env, "owner@shop.test")  # one sign-up try, one verify mail
    before = len(env.mails_to("owner@shop.test"))
    for ip in _ips(6):
        signup(env.client(ip=ip), "owner@shop.test")
    assert len(env.mails_to("owner@shop.test")) == before + 2  # 3 per hour in all


def test_per_ip_limit_still_answers_429(env):
    c = env.client(ip="203.0.113.50")
    for n in range(5):
        assert signup(c, f"u{n}@shop.test").status_code == 200
    r = signup(c, "u5@shop.test")
    assert r.status_code == 429 and "Too many sign-ups" in r.text
    assert signup(env.client(ip="203.0.113.51"), "u5@shop.test").status_code == 200
