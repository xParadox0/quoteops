"""Stage 2b part 3, fix 2: a token reply whose expires_in is not a usable finite lifetime of at
most 24 hours fails like any unusable reply and caches nothing."""
import pytest

from tests.stage2b3_support import Reply
from tests.test_stage2b3_mailer import Clock, _mail, fake, make, send  # noqa: F401

FIXED = "token request failed with status 200"


def reply(lifetime: str) -> bytes:
    return b'{"access_token": "tok-x", "expires_in": ' + lifetime.encode() + b"}"


@pytest.mark.parametrize("lifetime", ["NaN", "Infinity", "-Infinity", "1e999", "-1e999", "86401",
                                      "86400.5", "1e300", "true", "false", '"3599"', "null", "[]",
                                      "[3600]", "{}", "1" + "0" * 400])
def test_an_unusable_lifetime_fails_with_the_fixed_text_and_caches_nothing(fake, lifetime):
    fake.token_plan = [Reply(200, reply(lifetime))]
    m = make(fake)
    with pytest.raises(_mail().MailError) as info:
        send(m)
    assert str(info.value) == FIXED
    assert "tok-x" not in str(info.value) and lifetime not in str(info.value)
    assert fake.sends() == []
    send(m)  # the next send asks for a token again
    assert len(fake.tokens()) == 2 and len(fake.sends()) == 1


@pytest.mark.parametrize("lifetime,reused", [("86400", True), ("3599", True), ("3600.5", True),
                                             ("0", False), ("1", False), ("-5", False),
                                             ("0.5", False)])
def test_a_finite_lifetime_up_to_24_hours_is_accepted(fake, lifetime, reused):
    fake.token_plan = [Reply(200, reply(lifetime))]
    clock = Clock()
    m = make(fake, clock)
    send(m)
    clock.now += 1
    send(m)
    assert len(fake.tokens()) == (1 if reused else 2)
    assert len(fake.sends()) == 2


def test_the_cache_ends_five_minutes_before_the_longest_lifetime(fake):
    fake.token_plan = [Reply(200, reply("86400"))]
    clock = Clock()
    m = make(fake, clock)
    send(m)
    clock.now += 86400 - 300 - 1
    send(m)
    assert len(fake.tokens()) == 1
    clock.now += 1
    send(m)
    assert len(fake.tokens()) == 2
