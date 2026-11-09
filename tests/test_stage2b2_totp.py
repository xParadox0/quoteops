"""Stage 2b part 2: quoteops/totp.py, RFC 6238 time-based codes on RFC 4226 HOTP, standard
library only. The product uses HMAC-SHA1, 6 digits, a 30-second step and one step either side."""
import hmac
from urllib.parse import parse_qs, urlsplit

import pytest

from tests.stage2b2_support import T0, mod

RFC_SECRET = b"12345678901234567890"
# RFC 4226 appendix D: HOTP values for counters 0 to 9.
RFC4226 = ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
           "399871", "520489"]
# RFC 6238 appendix B, SHA1 rows: (time, 8-digit code).
RFC6238 = [(59, "94287082"), (1111111109, "07081804"), (1111111111, "14050471"),
           (1234567890, "89005924"), (2000000000, "69279037"), (20000000000, "65353130")]
SECRET = bytes(range(20))


def totp():
    return mod("totp")


# --- vectors --------------------------------------------------------------------------------------

@pytest.mark.parametrize("counter", range(10))
def test_rfc4226_hotp_vectors(counter):
    assert totp().hotp(RFC_SECRET, counter) == RFC4226[counter]


@pytest.mark.parametrize("at,code", RFC6238)
def test_rfc6238_sha1_vectors_with_eight_digits(at, code):
    assert totp().totp(RFC_SECRET, at, digits=8) == code


@pytest.mark.parametrize("at,code", RFC6238)
def test_six_digit_codes_are_the_last_six_of_the_vectors(at, code):
    assert totp().totp(RFC_SECRET, at) == code[-6:]
    assert totp().match(RFC_SECRET, code[-6:], at) == int(at) // 30


def test_product_parameters():
    t = totp()
    assert (t.DIGITS, t.STEP, t.WINDOW, t.SECRET_BYTES) == (6, 30, 1, 20)
    a, b = t.new_secret(), t.new_secret()
    assert len(a) == 20 and len(b) == 20 and a != b


# --- the window -----------------------------------------------------------------------------------

@pytest.mark.parametrize("steps", [-1, 0, 1])
def test_previous_current_and_next_step_are_accepted(steps):
    t = totp()
    code = t.totp(SECRET, T0 + steps * 30)
    assert t.match(SECRET, code, T0) == int(T0) // 30 + steps


@pytest.mark.parametrize("steps", [-3, -2, 2, 3])
def test_two_steps_away_is_refused(steps):
    t = totp()
    code = t.totp(SECRET, T0 + steps * 30)
    # Make sure the code is not also, by chance, the code of a step inside the window.
    assert code not in {t.totp(SECRET, T0 + k * 30) for k in (-1, 0, 1)}
    assert t.match(SECRET, code, T0) is None


@pytest.mark.parametrize("offset", [0, 29.999])
def test_window_edges_inside_one_step(offset):
    """At the first and the last instant of a step the window is the same three counters."""
    t = totp()
    start = (int(T0) // 30) * 30
    for steps, ok in ((-2, False), (-1, True), (0, True), (1, True), (2, False)):
        code = t.totp(SECRET, start + steps * 30)
        assert (t.match(SECRET, code, start + offset) is not None) is ok, (steps, offset)


def test_another_secret_is_refused():
    t = totp()
    assert t.match(bytes(20), t.totp(SECRET, T0), T0) is None


# --- malformed input ------------------------------------------------------------------------------

def _variants(code: str) -> list[str]:
    fullwidth = "".join(chr(0xFF10 + int(c)) for c in code)
    arabic = "".join(chr(0x0660 + int(c)) for c in code)
    devanagari = "".join(chr(0x0966 + int(c)) for c in code)
    return ["", code[:5], code + "0", code + "00", code[:3] + " " + code[3:], " " + code,
            code + " ", code + "\n", code + "\r\n", "\t" + code, code + "\x00", fullwidth,
            arabic, devanagari, "abcdef", code[:5] + "a", "+" + code[:5], "-" + code[:5],
            code[:5] + "\u00b2", "1e+005", code[:2] + "_" + code[3:]]


def test_malformed_codes_are_refused_even_when_their_digits_are_right():
    t = totp()
    code = t.totp(SECRET, T0)
    for bad in _variants(code):
        assert t.well_formed(bad) is False, repr(bad)
        assert t.match(SECRET, bad, T0) is None, repr(bad)
    assert t.well_formed(code) is True


@pytest.mark.parametrize("bad", [None, 123456, b"123456"])
def test_non_text_codes_are_refused(bad):
    t = totp()
    assert t.well_formed(bad) is False
    assert t.match(SECRET, bad, T0) is None


# --- constant work --------------------------------------------------------------------------------

def _count(monkeypatch, module, name):
    calls = []
    real = getattr(module, name)

    def counting(*a, **kw):
        calls.append(a)
        return real(*a, **kw)
    monkeypatch.setattr(module, name, counting)
    return calls


def test_codes_are_compared_with_compare_digest(monkeypatch):
    t = totp()
    good = t.totp(SECRET, T0)
    calls = _count(monkeypatch, hmac, "compare_digest")
    assert t.match(SECRET, good, T0) is not None
    assert len(calls) == 3  # one comparison per step of the window, even after a match


@pytest.mark.parametrize("code", ["000000", "12345", "1234567", "abcdef", "", "\uff11" * 6])
def test_every_code_costs_three_hmacs_and_three_comparisons(monkeypatch, code):
    t = totp()
    compares = _count(monkeypatch, hmac, "compare_digest")
    hotps = _count(monkeypatch, t, "hotp")
    t.match(SECRET, code, T0)
    assert len(hotps) == 3 and len(compares) == 3


def test_equal_operator_is_not_what_decides(monkeypatch):
    """With compare_digest made to say no, even the right code is refused: the decision rests on
    it, not on ==."""
    t = totp()
    good = t.totp(SECRET, T0)
    monkeypatch.setattr(hmac, "compare_digest", lambda a, b: False)
    assert t.match(SECRET, good, T0) is None


# --- secret encoding and the otpauth URI ----------------------------------------------------------

def test_base32_without_padding():
    t = totp()
    assert t.encode_secret(RFC_SECRET) == "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    assert "=" not in t.encode_secret(bytes(range(20)))


def test_otpauth_uri():
    t = totp()
    uri = t.otpauth_uri(RFC_SECRET, "root+ops@example.test")
    assert uri == ("otpauth://totp/QuoteOps:root%2Bops%40example.test"
                   "?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=QuoteOps&algorithm=SHA1"
                   "&digits=6&period=30")
    parts = urlsplit(uri)
    q = parse_qs(parts.query)
    assert parts.scheme == "otpauth" and parts.netloc == "totp"
    assert q == {"secret": ["GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"], "issuer": ["QuoteOps"],
                 "algorithm": ["SHA1"], "digits": ["6"], "period": ["30"]}


def test_uri_escapes_characters_that_would_break_it():
    uri = totp().otpauth_uri(SECRET, "a&b?c#d/e:f@x.test")
    assert uri.count("?") == 1 and "#" not in uri
    assert urlsplit(uri).path == "/QuoteOps:a%26b%3Fc%23d%2Fe%3Af%40x.test"
    assert parse_qs(urlsplit(uri).query)["issuer"] == ["QuoteOps"]
