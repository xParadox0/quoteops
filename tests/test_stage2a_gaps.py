"""Stage 2a: tests for the gaps the first independent review found. Token expiry at the exact
second, the constant-time comparison, escaping of hostile values in every template, colour
contrast of the stylesheet, and control characters in sign-up and forgot input."""
import importlib
import re

import pytest
from markupsafe import escape

from tests.stage2a_support import (  # noqa: F401  (adb and env are fixtures)
    PASSWORD, SECRET, account, adb, csrf_from, env, finish_signup, forgot, form_csrf, login,
    reset_link, signed_up, signup, token_of, verify_link,
)

HOSTILE = "<script>x</script>\"'"
HOSTILE_ESCAPED = str(escape(HOSTILE))
HOSTILE_EMAIL = "o\"q'<b>@shop.test"


def _mod(name):
    return importlib.import_module(f"quoteops.{name}")


# --- tokens ---------------------------------------------------------------------------------------

def test_token_expires_at_the_exact_second():
    tokens = _mod("tokens")
    t = tokens.make("verify", "a@b.test", 60, SECRET.encode(), now=1_000_000)
    assert tokens.check(t, "verify", SECRET.encode(), now=1_000_060) is None
    assert tokens.check(t, "verify", SECRET.encode(), now=1_000_059) == "a@b.test"


def test_token_signature_is_compared_with_compare_digest(monkeypatch):
    tokens = _mod("tokens")
    t = tokens.make("verify", "a@b.test", 60, SECRET.encode())
    calls = []

    def recorder(a, b):
        calls.append((a, b))
        return False

    monkeypatch.setattr(tokens.hmac, "compare_digest", recorder)
    assert tokens.check(t, "verify", SECRET.encode()) is None  # the recorder's answer decides
    assert len(calls) == 1 and isinstance(calls[0][0], bytes) and len(calls[0][1]) == 32
    monkeypatch.undo()
    assert tokens.check(t, "verify", SECRET.encode()) == "a@b.test"


# --- hostile values in every template -------------------------------------------------------------

def _assert_escaped(html, raw, where):
    assert raw not in html, where
    assert str(escape(raw)) in html, where


def test_hostile_company_and_email_are_escaped_through_the_app(env):
    c = env.client()
    data = {"csrf": form_csrf(c, "/signup"), "email": HOSTILE_EMAIL, "company": HOSTILE}
    r = c.post("/signup", data=data)  # no terms: the form comes back with both values
    assert r.status_code == 400
    _assert_escaped(r.text, HOSTILE, "signup company value")
    _assert_escaped(r.text, HOSTILE_EMAIL, "signup email value")
    signed = account(env, HOSTILE_EMAIL, company=HOSTILE)
    page = signed.get("/app").text
    _assert_escaped(page, HOSTILE, "app company in title and heading")
    assert page.count(HOSTILE_ESCAPED) == 2
    _assert_escaped(page, HOSTILE_EMAIL, "app email in banner and facts")
    r = login(env.client(), HOSTILE_EMAIL, "wrong password here")
    assert r.status_code == 400
    _assert_escaped(r.text, HOSTILE_EMAIL, "login email value")
    c = env.client()
    r = c.post("/forgot", data={"csrf": form_csrf(c, "/forgot"), "email": HOSTILE})
    assert r.status_code == 400
    _assert_escaped(r.text, HOSTILE, "forgot email value")
    r = env.client().get("/reset", params={"token": HOSTILE})
    assert r.status_code == 400 and HOSTILE not in r.text


TEMPLATES = ["app.html", "forgot.html", "login.html", "message.html", "privacy.html",
             "reset.html", "signup.html", "terms.html", "verify.html"]


@pytest.mark.parametrize("template", TEMPLATES)
def test_every_template_escapes_every_dynamic_value(template):
    pages = _mod("pages")
    errors = {k: HOSTILE for k in ("email", "password", "company", "terms")}
    html = pages.html(template, title=HOSTILE, text=HOSTILE, link=("/x", HOSTILE),
                      company=HOSTILE, email=HOSTILE, role=HOSTILE, verified=False,
                      csrf=HOSTILE, token=HOSTILE, failure=HOSTILE, terms_version=HOSTILE,
                      errors=errors, values={"email": HOSTILE, "company": HOSTILE})
    assert HOSTILE not in html, template
    assert HOSTILE_ESCAPED in html, template
    assert "<script" not in html.lower(), template


# --- colour contrast ------------------------------------------------------------------------------

def _tokens(block):
    return {k: v.lower() for k, v in re.findall(r"--([a-z-]+):\s*(#[0-9A-Fa-f]{6})", block)}


def _themes():
    css = _mod("pages").CSS.decode("utf-8")
    dark_block, light_part = css.split("@media (prefers-color-scheme: light)", 1)
    dark = _tokens(dark_block)
    light = {**dark, **_tokens(light_part.split("}", 1)[0])}
    return {"dark": dark, "light": light}


def _luminance(colour):
    channels = [int(colour[i:i + 2], 16) / 255 for i in (1, 3, 5)]
    lin = [c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
    return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2]


def _ratio(a, b):
    hi, lo = sorted((_luminance(a), _luminance(b)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


TEXT_PAIRS = [("text", "ground"), ("muted", "ground"), ("cyan", "ground"), ("red", "ground"),
              ("text", "surface"), ("muted", "surface"), ("cyan", "surface"),
              ("red", "surface"), ("on-accent", "cyan")]
NON_TEXT_PAIRS = [("violet", "ground"), ("violet", "surface")]  # the focus outline


@pytest.mark.parametrize("theme", ["dark", "light"])
def test_css_colour_pairs_meet_wcag_aa(theme):
    t = _themes()[theme]
    assert {"ground", "surface", "text", "muted", "cyan", "red", "violet", "on-accent"} <= set(t)
    for fg, bg in TEXT_PAIRS:
        assert _ratio(t[fg], t[bg]) >= 4.5, (theme, fg, bg, round(_ratio(t[fg], t[bg]), 2))
    for fg, bg in NON_TEXT_PAIRS:
        assert _ratio(t[fg], t[bg]) >= 3, (theme, fg, bg, round(_ratio(t[fg], t[bg]), 2))


def test_contrast_formula_matches_known_values():
    assert round(_ratio("#000000", "#ffffff"), 2) == 21.0
    assert round(_ratio("#777777", "#ffffff"), 2) == 4.48


# --- control characters ---------------------------------------------------------------------------

BAD_EMAILS = ["own\x00er@shop.test", "owner@shop.test\x00", "own\x1fer@shop.test",
              "own\x7fer@shop.test", "own\x1ber@shop.test"]
BAD_COMPANIES = ["Bengkel\x00Maju", "Bengkel\x07Maju", "Bengkel\x1b[31mMaju", "Bengkel Maju\x00"]


def _counts(env):
    return env.scalar("SELECT count(*) FROM company"), env.scalar("SELECT count(*) FROM app_user")


@pytest.mark.parametrize("field,value", [("email", e) for e in BAD_EMAILS]
                         + [("company", v) for v in BAD_COMPANIES])
def test_signup_refuses_control_characters(env, field, value):
    c = env.client()
    data = {"csrf": form_csrf(c, "/signup"), "email": "owner@shop.test",
            "company": "Bengkel Maju", "terms": "yes", field: value}
    r = c.post("/signup", data=data)
    assert r.status_code == 400 and f'id="{field}-error"' in r.text
    assert _counts(env) == (0, 0) and env.mails() == []


@pytest.mark.parametrize("value", BAD_EMAILS)
def test_forgot_refuses_control_characters(env, value):
    account(env, "owner@shop.test")
    before = len(env.mails())
    c = env.client()
    r = c.post("/forgot", data={"csrf": form_csrf(c, "/forgot"), "email": value})
    assert r.status_code == 400 and 'id="email-error"' in r.text
    assert len(env.mails()) == before


# The rule: a password with any control character (Unicode category Cc: NUL, tab, newline,
# escape, DEL ...) is refused when it is chosen, at the verification link and at reset. A
# password field cannot type them, so only a crafted request carries one.
BAD_PASSWORDS = ["correct\x00horse battery", "correct horse battery\x00",
                 "correct\thorse battery", "correct\x1bhorse battery", "correct\x7fhorse battery"]


@pytest.mark.parametrize("pw", BAD_PASSWORDS)
def test_password_policy_refuses_control_characters(pw):
    assert "control" in _mod("passwords").policy_error(pw, "owner@shop.test")


@pytest.mark.parametrize("pw", BAD_PASSWORDS[:2])
def test_verify_and_reset_refuse_a_password_with_a_nul(env, pw):
    signed_up(env, "new@shop.test")
    verified = "SELECT email_verified_at FROM app_user WHERE email = 'new@shop.test'"
    r = finish_signup(env.client(), verify_link(env, "new@shop.test"), password=pw)
    assert r.status_code == 400 and 'id="password-error"' in r.text
    assert env.scalar(verified) is None
    account(env, "owner@shop.test")
    forgot(env.client(), "owner@shop.test")
    token = token_of(reset_link(env, "owner@shop.test"))
    c = env.client()
    form = c.get("/reset", params={"token": token})
    r = c.post("/reset", data={"csrf": csrf_from(form.text), "token": token, "password": pw})
    assert r.status_code == 400 and 'id="password-error"' in r.text
    assert login(env.client(), "owner@shop.test").status_code == 303
