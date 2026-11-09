"""Stage 2b part 1: invites (F5), roles (F6) and the user management they need (HLD "Stage 2b
part 1"). The Owner invites by email with a role; the invitee opens the link, chooses a password
and joins the inviting company. Only the Owner manages users. Every negative here is a security
rule: non-owners, other companies, replayed, expired, revoked and replaced links, races, tampered
roles and missing CSRF."""
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

from tests.conftest import Db
from tests.stage2a_support import (  # noqa: F401  (adb and env are fixtures)
    BASE, ENV_DEFAULTS_TO_CLEAR, PASSWORD, SECRET, account, adb, app_csrf, csrf_from, env,
    form_csrf, link_in, login, path_of, session_cookie, sha256, signed_up, throttle_key, token_of,
)
from tests.test_stage2a_fix3 import _assert_busy, _blocked, _no_connection, _throttle_rows

ROOT = Path(__file__).resolve().parent.parent
STAGE2A_SCHEMA = Path(__file__).resolve().parent / "data" / "schema_83ed11a.sql"

OWNER = "owner@shop.test"
SENT = "Invitation sent."
INVALID = "Enter a valid email address and choose a role."
CAP = "The company has reached its limit of"
NOT_VALID = "This link is not valid or has expired."
JOINED = "Your password is set. Sign in to continue."
FULL = "This company has reached its limit of users."
EXISTS_MAIL = "already has a QuoteOps account"
REFUSED = "This form has expired or was sent from another site."
ROLES = ("estimator", "accountant", "viewer")
BAD_ROLES = ["owner", "sysadmin", " owner", "OWNER", "Owner", "", " viewer", "viewer ",
             "admin", "estimator\n"]
WEEK = 7 * 24 * 3600


def _mod(name):
    return importlib.import_module(f"quoteops.{name}")


# --- helpers ------------------------------------------------------------------------------------

def owner(env, email=OWNER, company="Bengkel Maju", ip=None):
    return account(env, email, company=company, ip=ip)


def team_csrf(client) -> str:
    r = client.get("/team")
    assert r.status_code == 200, (r.status_code, r.text)
    return csrf_from(r.text)


def pre_csrf(client) -> str:
    return form_csrf(client, "/forgot")


def invite(client, email, role="estimator", csrf=None):
    return client.post("/team/invite", data={"csrf": csrf or team_csrf(client), "email": email,
                                             "role": role})


def invite_mails(env, email):
    return [m for m in env.mails_to(email) if any("/invite?token=" in x for x in m.links)]


def invite_link(env, email) -> str:
    found = invite_mails(env, email)
    assert found, f"no invitation mail for {email}"
    return link_in(found[-1], "/invite")


def accept(client, link, password=PASSWORD, terms=True, **extra):
    """Open an invitation link and send its form. Returns the answer to the POST, or to the GET
    when it shows no form."""
    r = client.get(path_of(link))
    if r.status_code != 200 or 'action="/invite"' not in r.text:
        return r
    data = {"csrf": csrf_from(r.text), "token": token_of(link), "password": password, **extra}
    if terms:
        data["terms"] = "yes"
    return client.post("/invite", data=data)


def post_accept(client, token, password=PASSWORD, csrf=None, **extra):
    """POST /invite without opening the link first."""
    data = {"csrf": pre_csrf(client) if csrf is None else csrf, "token": token,
            "password": password,
            "terms": "yes", **extra}
    return client.post("/invite", data=data)


def member(env, owner_client, email, role="estimator", password=PASSWORD):
    """Invite, accept and sign in. Returns a client holding the member's session."""
    r = invite(owner_client, email, role)
    assert r.status_code == 303, r.text
    r = accept(env.client(), invite_link(env, email), password=password)
    assert r.status_code == 200 and JOINED in r.text, r.text
    c = env.client()
    assert login(c, email, password).status_code == 303
    return c


def uid(env, email):
    return env.scalar("SELECT id FROM app_user WHERE email = %s", (email,))


def user_row(env, email):
    with env.owner() as c:
        return c.execute("SELECT company_id, role, disabled_at, email_verified_at,"
                         " consent_version FROM app_user WHERE email = %s", (email,)).fetchone()


def invites(env):
    with env.owner() as c:
        return c.execute("SELECT company_id, email::text, role, used_at, ref, created_by,"
                         " expires_at, created_at, id_hash FROM invite ORDER BY created_at"
                         ).fetchall()


def ref_of(env, email):
    return env.scalar("SELECT ref FROM invite WHERE email = %s AND used_at IS NULL", (email,))


def company_of(env, email):
    return env.scalar("SELECT company_id FROM app_user WHERE email = %s", (email,))


def state(env):
    """Everything the routes of this part may change."""
    with env.owner() as c:
        return (c.execute("SELECT id, company_id, email::text, role, disabled_at, pw_hash"
                          " FROM app_user ORDER BY email").fetchall(),
                c.execute("SELECT id_hash, company_id, email::text, role, used_at, expires_at"
                          " FROM invite ORDER BY id_hash").fetchall(),
                c.execute("SELECT count(*) FROM session").fetchone()[0],
                c.execute("SELECT count(*) FROM audit_event").fetchone()[0],
                c.execute("SELECT id, status, name FROM company ORDER BY id").fetchall())


def flash_after(client, r) -> str:
    """The redirect of a team POST and the page it leads to."""
    assert r.status_code == 303, (r.status_code, r.text)
    assert r.headers["location"] == "/team"
    page = client.get("/team")
    assert page.status_code == 200
    return page.text


def _answer(r):
    return r.status_code, tuple(sorted(r.headers.items())), r.content


# --- the owner's team page ----------------------------------------------------------------------

def test_team_page_lists_users_invites_and_the_cap(env):
    o = owner(env)
    member(env, o, "est@shop.test", "estimator")
    member(env, o, "acc@shop.test", "accountant")
    invite(o, "pending@shop.test", "viewer")
    r = o.get("/team")
    assert r.status_code == 200
    for text in (OWNER, "est@shop.test", "acc@shop.test", "pending@shop.test", "estimator",
                 "accountant", "viewer", "4 of 5 users"):
        assert text in r.text, text
    assert 'action="/team/invite"' in r.text and 'action="/team/invite/revoke"' in r.text
    assert 'action="/team/role"' in r.text and 'action="/team/disable"' in r.text
    assert "<script" not in r.text and " style=" not in r.text


def test_team_page_offers_no_form_for_the_owner_row(env):
    o = owner(env)
    member(env, o, "est@shop.test")
    page = o.get("/team").text
    owner_id, est_id = str(uid(env, OWNER)), str(uid(env, "est@shop.test"))
    assert f'value="{est_id}"' in page
    assert f'value="{owner_id}"' not in page


def test_role_select_offers_exactly_the_three_roles(env):
    o = owner(env)
    page = o.get("/team").text
    form = re.search(r'<form[^>]*action="/team/invite".*?</form>', page, re.S).group(0)
    assert re.findall(r'<option value="([^"]*)"', form) == list(ROLES)
    for name in re.findall(r'<(?:input|select)[^>]*\bid="([^"]+)"', form):
        assert f'for="{name}"' in form, name  # every visible input has a label


def test_every_input_on_the_team_page_has_a_label(env):
    o = owner(env)
    member(env, o, "est@shop.test")
    invite(o, "pending@shop.test")
    page = o.get("/team").text
    for tag in re.findall(r"<(?:input|select)[^>]*>", page):
        if 'type="hidden"' in tag:
            continue
        name = re.search(r'\bid="([^"]+)"', tag)
        assert name and f'for="{name.group(1)}"' in page, tag


def test_app_page_links_to_team_for_the_owner_only(env):
    o = owner(env)
    assert 'href="/team"' in o.get("/app").text
    for role in ROLES:
        c = member(env, o, f"{role}@shop.test", role)
        assert 'href="/team"' not in c.get("/app").text


def test_team_page_escapes_names(env):
    o = owner(env)
    with env.owner() as c:
        c.execute("UPDATE company SET name = '<b>Evil</b>'")
    r = o.get("/team")
    assert r.status_code == 200
    assert "<b>Evil</b>" not in r.text and "&lt;b&gt;Evil&lt;/b&gt;" in r.text


# --- invitation ---------------------------------------------------------------------------------

def test_invite_stores_only_the_hash_and_mails_the_link(env):
    o = owner(env)
    r = invite(o, "new@shop.test", "accountant")
    assert SENT in flash_after(o, r)
    rows = invites(env)
    assert len(rows) == 1
    company_id, email, role, used_at, ref, created_by, expires_at, created_at, id_hash = rows[0]
    assert (company_id, email, role, used_at) == (company_of(env, OWNER), "new@shop.test",
                                                  "accountant", None)
    assert created_by == uid(env, OWNER) and isinstance(ref, uuid.UUID)
    assert (expires_at - created_at).total_seconds() == pytest.approx(WEEK, abs=5)
    token = token_of(invite_link(env, "new@shop.test"))
    assert re.fullmatch(r"[A-Za-z0-9_-]{43}", token)  # 32 random bytes
    assert bytes(id_hash) == sha256(token)
    with env.owner() as c:  # the raw token is nowhere in the table
        dump = " ".join(str(v) for row in c.execute("SELECT * FROM invite").fetchall() for v in row)
        assert token not in dump and token.encode().hex() not in dump
        assert c.execute("SELECT count(*) FROM invite WHERE id_hash = %s",
                         (token.encode(),)).fetchone()[0] == 0


def test_invite_answer_is_identical_for_new_and_existing_addresses(env):
    o = owner(env)
    account(env, "taken@other.test", company="Other", ip="198.51.100.9")
    csrf = team_csrf(o)
    r_new = o.post("/team/invite", data={"csrf": csrf, "email": "new@shop.test", "role": "viewer"})
    r_old = o.post("/team/invite", data={"csrf": csrf, "email": "taken@other.test",
                                         "role": "viewer"})
    assert _answer(r_new) == _answer(r_old)
    assert r_new.status_code == 303 and r_new.headers["location"] == "/team"
    # The mail differs: a link for the new address, a notice without a link to join for the other.
    assert len(invite_mails(env, "new@shop.test")) == 1
    old = env.mails_to("taken@other.test")[-1]
    assert EXISTS_MAIL in old.body and "/invite" not in old.body
    assert not any("token=" in x for x in old.links)
    assert [row[1] for row in invites(env)] == ["new@shop.test"]
    assert company_of(env, "taken@other.test") != company_of(env, OWNER)


def test_inviting_a_member_of_the_same_company_creates_nothing(env):
    o = owner(env)
    member(env, o, "est@shop.test")
    before = invites(env)
    assert SENT in flash_after(o, invite(o, "est@shop.test", "viewer"))
    assert invites(env) == before
    assert user_row(env, "est@shop.test")[1] == "estimator"


def test_inviting_again_replaces_the_pending_invite(env):
    o = owner(env)
    invite(o, "new@shop.test", "estimator")
    first = invite_link(env, "new@shop.test")
    invite(o, "NEW@shop.test", "viewer")
    second = invite_link(env, "new@shop.test")
    assert first != second
    rows = invites(env)
    assert len(rows) == 1 and rows[0][2] == "viewer"
    c = env.client()
    r = c.get(path_of(first))
    assert r.status_code == 400 and NOT_VALID in r.text
    assert post_accept(c, token_of(first)).status_code == 400
    assert user_row(env, "new@shop.test") is None
    r = accept(env.client(), second)
    assert r.status_code == 200 and JOINED in r.text
    assert user_row(env, "new@shop.test")[1] == "viewer"


def test_one_pending_invite_per_company_and_email_in_the_database(env):
    o = owner(env)
    invite(o, "new@shop.test")
    cid = company_of(env, OWNER)
    with env.owner() as c:
        with pytest.raises(psycopg.errors.UniqueViolation):
            c.execute("INSERT INTO invite (id_hash, company_id, email, role, expires_at)"
                      " VALUES ('\\x01', %s, 'New@shop.test', 'viewer', now() + interval '1 day')",
                      (cid,))


@pytest.mark.parametrize("email", ["", "not-an-address", "a@b", "two@@x.test",
                                   "a\r\nBcc: x@evil.test@shop.test", "a b@shop.test",
                                   "x" * 250 + "@shop.test"])
def test_invite_refuses_a_bad_address(env, email):
    o = owner(env)
    before, mails = state(env), len(env.mails())
    assert INVALID in flash_after(o, invite(o, email))
    assert state(env) == before and len(env.mails()) == mails


@pytest.mark.parametrize("role", BAD_ROLES)
def test_invite_refuses_any_role_but_the_three(env, role):
    o = owner(env)
    before, mails, rows = state(env), len(env.mails()), _throttle_rows(env)
    assert INVALID in flash_after(o, invite(o, "new@shop.test", role))
    assert state(env) == before and len(env.mails()) == mails and _throttle_rows(env) == rows


def test_invite_role_check_in_the_database(env):
    o = owner(env)
    cid = company_of(env, OWNER)
    for role in ("owner", "sysadmin", "OWNER"):
        with env.db.connect("qo_web") as c:
            c.execute("SELECT set_config('app.company_id', %s, false)", (cid,))
            with pytest.raises(psycopg.errors.CheckViolation):
                c.execute("INSERT INTO invite (id_hash, company_id, email, role, expires_at)"
                          " VALUES ('\\x02', %s, 'x@shop.test', %s, now() + interval '1 day')",
                          (cid, role))
    assert o.get("/team").status_code == 200


def test_app_user_role_check_in_the_database(env):
    owner(env)
    cid = company_of(env, OWNER)
    with env.owner() as c:
        with pytest.raises(psycopg.errors.CheckViolation):
            c.execute("INSERT INTO app_user (id, company_id, email, pw_hash, pw_salt, role,"
                      " consent_version, consent_at) VALUES (%s, %s, 'z@shop.test', '\\x00',"
                      " '\\x00', 'admin', 'v1', now())", (uuid.uuid4(), cid))


def test_invitation_mail_is_built_from_the_base_url_not_the_host(env):
    o = owner(env)
    csrf = team_csrf(o)
    r = o.post("/team/invite", data={"csrf": csrf, "email": "new@shop.test", "role": "viewer"},
               headers={"Host": "evil.example", "X-Forwarded-Host": "evil.example"})
    assert r.status_code == 303
    mail = invite_mails(env, "new@shop.test")[-1]
    assert mail.links and all(x.startswith(BASE + "/") for x in mail.links)
    assert "evil.example" not in mail.body
    assert "\r" not in mail.to + mail.subject and "\n" not in mail.to + mail.subject


def test_company_name_with_newlines_and_markup_is_safe_in_mail_and_page(env):
    o = owner(env)
    evil = 'Evil <b>Co</b>\r\nSubject: hacked\n\nTo: victim@x.test "q"'
    with env.owner() as c:
        c.execute("UPDATE company SET name = %s", (evil,))
    invite(o, "new@shop.test")
    mail = invite_mails(env, "new@shop.test")[-1]
    texts = [p.read_text(encoding="utf-8") for p in env.mail_dir.iterdir()]
    text = [t for t in texts if "/invite?token=" in t][-1]
    assert "\r" not in text
    lines = text.split("\n")
    assert [x for x in lines if x.startswith("Subject:")] == [f"Subject: {mail.subject}"]
    assert [x for x in lines if x.startswith("To:")] == ["To: new@shop.test"]
    assert "Evil <b>Co</b>" in mail.body  # plain text: the markup is harmless and shown as is
    page = env.client().get(path_of(invite_link(env, "new@shop.test"))).text
    assert "<b>Co</b>" not in page and "&lt;b&gt;Co&lt;/b&gt;" in page


def test_invite_over_the_cap_says_so_and_changes_nothing(env):
    o = owner(env)
    for n in range(4):  # owner + 4 pending invitations = 5
        invite(o, f"p{n}@shop.test")
    before, mails, rows = state(env), len(env.mails()), _throttle_rows(env)
    page = flash_after(o, invite(o, "sixth@shop.test"))
    assert CAP in page and "5" in page
    assert state(env) == before and len(env.mails()) == mails and _throttle_rows(env) == rows
    assert "5 of 5 users" in page


def test_cap_counts_users_and_unexpired_invites_and_lets_a_replacement_through(env):
    o = owner(env)
    member(env, o, "est@shop.test")
    for n in range(3):
        invite(o, f"p{n}@shop.test")
    assert "5 of 5 users" in o.get("/team").text
    # Re-inviting a pending address replaces it and needs no new place.
    assert SENT in flash_after(o, invite(o, "p0@shop.test", "viewer"))
    assert len(invites(env)) == 4
    # An expired invitation holds no place.
    with env.owner() as c:
        c.execute("UPDATE invite SET expires_at = now() - interval '1 second'"
                  " WHERE email = 'p1@shop.test'")
    assert SENT in flash_after(o, invite(o, "new@shop.test"))
    assert len(invite_mails(env, "new@shop.test")) == 1


def test_cap_setting_is_used(env):
    env.monkeypatch.setenv("QO_MAX_USERS_PER_COMPANY", "2")
    o = owner(env)
    invite(o, "p0@shop.test")
    assert CAP in flash_after(o, invite(o, "p1@shop.test"))
    assert len(invites(env)) == 1


def test_disabled_users_count_toward_the_cap(env):
    env.monkeypatch.setenv("QO_MAX_USERS_PER_COMPANY", "2")
    o = owner(env)
    member(env, o, "est@shop.test")
    flash_after(o, o.post("/team/disable", data={"csrf": team_csrf(o),
                                                 "user": str(uid(env, "est@shop.test"))}))
    assert CAP in flash_after(o, invite(o, "new@shop.test"))


def test_two_parallel_invites_at_the_cap_admit_exactly_the_free_places(env):
    o = owner(env)
    for n in range(3):
        invite(o, f"p{n}@shop.test")  # 4 of 5: one free place
    auth, together = _mod("auth"), threading.Barrier(2)
    real, seen = auth._has_account, set()

    def both_at_once(email):  # both requests passed the visible cap check
        if email not in seen:  # only the first lookup of an address waits
            seen.add(email)
            together.wait(10)
        return real(email)

    env.monkeypatch.setattr(auth, "_has_account", both_at_once)
    csrf = team_csrf(o)
    clients = [env.client(), env.client()]
    for c in clients:
        c.cookies.set("qo_session", session_cookie(o), domain="qo.example")
    results = [None, None]

    def run(i):
        results[i] = clients[i].post("/team/invite", data={"csrf": csrf, "role": "viewer",
                                                           "email": f"race{i}@shop.test"})

    threads = [threading.Thread(target=run, args=(i,)) for i in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    assert all(r is not None and r.status_code == 303 for r in results)
    raced = [row for row in invites(env) if row[1].startswith("race")]
    assert len(raced) == 1, raced
    assert len(invites(env)) == 4
    assert len(invite_mails(env, "race0@shop.test") + invite_mails(env, "race1@shop.test")) == 1


# --- throttles ----------------------------------------------------------------------------------

def test_invites_per_company_per_day_are_throttled_silently(env):
    env.monkeypatch.setenv("QO_INVITES_PER_DAY", "2")
    o = owner(env)
    csrf = team_csrf(o)
    answers = [o.post("/team/invite", data={"csrf": csrf, "email": f"t{n}@shop.test",
                                            "role": "viewer"}) for n in range(3)]
    assert _answer(answers[0]) == _answer(answers[2])
    assert [len(invite_mails(env, f"t{n}@shop.test")) for n in range(3)] == [1, 1, 0]
    assert len(invites(env)) == 2
    cid = company_of(env, OWNER)
    with env.owner() as c:
        keys = {(bytes(k), kind) for k, kind in c.execute("SELECT key, kind FROM auth_throttle")}
    assert (throttle_key("invite_company", cid), "invite_company") in keys


def test_invites_per_address_per_day_count_across_companies(env):
    env.monkeypatch.setenv("QO_INVITES_PER_ADDRESS_PER_DAY", "2")
    a = owner(env, "a@a.test", company="A", ip="198.51.100.1")
    b = owner(env, "b@b.test", company="B", ip="198.51.100.2")
    invite(a, "target@x.test")
    invite(a, "target@x.test")
    r = invite(b, "target@x.test")
    assert r.status_code == 303 and SENT in flash_after(b, r)
    assert len(invite_mails(env, "target@x.test")) == 2
    assert [row[0] for row in invites(env)] == [company_of(env, "a@a.test")]
    with env.owner() as c:
        keys = {(bytes(k), kind) for k, kind in c.execute("SELECT key, kind FROM auth_throttle")}
        dump = " ".join(str(v) for row in c.execute("SELECT * FROM auth_throttle") for v in row)
    assert (throttle_key("invite_email", "target@x.test"), "invite_email") in keys
    assert "target" not in dump


# --- revoke -------------------------------------------------------------------------------------

def test_revoke_deletes_the_invite_and_the_link_fails(env):
    o = owner(env)
    invite(o, "new@shop.test")
    link, ref = invite_link(env, "new@shop.test"), ref_of(env, "new@shop.test")
    page = flash_after(o, o.post("/team/invite/revoke", data={"csrf": team_csrf(o),
                                                              "ref": str(ref)}))
    assert "Invitation revoked." in page and "new@shop.test" not in page
    assert invites(env) == []
    r = env.client().get(path_of(link))
    assert r.status_code == 400 and NOT_VALID in r.text
    with env.owner() as c:
        row = c.execute("SELECT actor, what, subject FROM audit_event").fetchone()
    assert row[0] == uid(env, OWNER) and row[1] == "invite.revoke" and str(ref) in row[2]


@pytest.mark.parametrize("ref", ["", "nope", "00000000-0000-0000-0000-000000000000"])
def test_revoke_of_an_unknown_reference_is_404(env, ref):
    o = owner(env)
    invite(o, "new@shop.test")
    before = state(env)
    r = o.post("/team/invite/revoke", data={"csrf": team_csrf(o), "ref": ref})
    assert r.status_code == 404 and state(env) == before


def test_revoke_does_not_accept_the_token_or_its_hash(env):
    o = owner(env)
    invite(o, "new@shop.test")
    token = token_of(invite_link(env, "new@shop.test"))
    before = state(env)
    for ref in (token, sha256(token).hex()):
        r = o.post("/team/invite/revoke", data={"csrf": team_csrf(o), "ref": ref})
        assert r.status_code == 404
    assert state(env) == before


# --- cross-company ------------------------------------------------------------------------------

def _two_companies(env):
    a = owner(env, "a@a.test", company="A", ip="198.51.100.1")
    b = owner(env, "b@b.test", company="B", ip="198.51.100.2")
    member(env, b, "bm@b.test", "estimator")
    invite(b, "bp@b.test", "viewer")
    return a, b


def test_owner_cannot_touch_another_companys_invite_or_users(env):
    a, _b = _two_companies(env)
    before = state(env)
    csrf = team_csrf(a)
    b_user, b_owner = str(uid(env, "bm@b.test")), str(uid(env, "b@b.test"))
    for path, data in [("/team/invite/revoke", {"ref": str(ref_of(env, "bp@b.test"))}),
                       ("/team/role", {"user": b_user, "role": "viewer"}),
                       ("/team/disable", {"user": b_user}),
                       ("/team/enable", {"user": b_user}),
                       ("/team/role", {"user": b_owner, "role": "viewer"}),
                       ("/team/disable", {"user": b_owner})]:
        r = a.post(path, data={"csrf": csrf, **data})
        assert r.status_code == 404, (path, r.status_code)
    assert state(env) == before
    page = a.get("/team").text
    assert "bm@b.test" not in page and "bp@b.test" not in page and "b@b.test" not in page


def test_an_invite_of_company_a_creates_a_user_in_company_a_whatever_the_form_says(env):
    a = owner(env, "a@a.test", company="A", ip="198.51.100.1")
    owner(env, "b@b.test", company="B", ip="198.51.100.2")
    invite(a, "new@x.test", "viewer")
    link = invite_link(env, "new@x.test")
    cid_b = company_of(env, "b@b.test")
    r = accept(env.client(), link, company_id=cid_b, company=cid_b, role="owner",
               email="other@x.test")
    assert r.status_code == 200 and JOINED in r.text
    assert user_row(env, "new@x.test")[:2] == (company_of(env, "a@a.test"), "viewer")
    assert user_row(env, "other@x.test") is None
    assert env.scalar("SELECT count(*) FROM app_user WHERE company_id = %s", (cid_b,)) == 1


# --- non-owners and anonymous -------------------------------------------------------------------

def _posts(env, target_email, ref):
    target = str(uid(env, target_email))
    return [("/team/invite", {"email": "new@shop.test", "role": "viewer"}),
            ("/team/invite/revoke", {"ref": str(ref)}),
            ("/team/role", {"user": target, "role": "viewer"}),
            ("/team/disable", {"user": target}),
            ("/team/enable", {"user": target})]


@pytest.mark.parametrize("role", ROLES)
def test_non_owner_gets_403_everywhere_and_changes_nothing(env, role):
    o = owner(env)
    c = member(env, o, f"{role}@shop.test", role)
    member(env, o, "other@shop.test", "accountant" if role != "accountant" else "viewer")
    invite(o, "pending@shop.test")
    assert c.get("/team").status_code == 403
    before, mails = state(env), len(env.mails())
    csrf = app_csrf(c)
    for path, data in _posts(env, "other@shop.test", ref_of(env, "pending@shop.test")):
        r = c.post(path, data={"csrf": csrf, **data})
        assert r.status_code == 403, (path, r.status_code)
    # Its own row, as well.
    for path in ("/team/disable", "/team/role"):
        r = c.post(path, data={"csrf": csrf, "user": str(uid(env, f"{role}@shop.test")),
                               "role": "estimator"})
        assert r.status_code == 403
    assert state(env) == before and len(env.mails()) == mails


def test_anonymous_is_sent_to_sign_in_and_changes_nothing(env):
    o = owner(env)
    member(env, o, "est@shop.test")
    invite(o, "pending@shop.test")
    anon = env.client()
    r = anon.get("/team")
    assert r.status_code == 303 and r.headers["location"] == "/login"
    before, mails = state(env), len(env.mails())
    csrf = team_csrf(o)
    for path, data in _posts(env, "est@shop.test", ref_of(env, "pending@shop.test")):
        r = anon.post(path, data={"csrf": csrf, **data})
        assert r.status_code in (303, 401, 403), path
        assert r.headers.get("location") in (None, "/login")
    assert state(env) == before and len(env.mails()) == mails


# --- CSRF and Origin ----------------------------------------------------------------------------

def _owner_posts(env):
    o = owner(env)
    member(env, o, "est@shop.test")
    invite(o, "pending@shop.test")
    return o, _posts(env, "est@shop.test", ref_of(env, "pending@shop.test"))


def test_every_team_post_refuses_a_missing_token(env):
    o, posts = _owner_posts(env)
    before, mails = state(env), len(env.mails())
    for path, data in posts:
        r = o.post(path, data=data)
        assert r.status_code == 403 and REFUSED in r.text, path
    assert state(env) == before and len(env.mails()) == mails


def test_every_team_post_refuses_a_token_of_another_session(env):
    o, posts = _owner_posts(env)
    other = env.client()
    assert login(other, OWNER).status_code == 303  # a second session of the same owner
    foreign = team_csrf(other)
    before, mails = state(env), len(env.mails())
    for path, data in posts:
        r = o.post(path, data={"csrf": foreign, **data})
        assert r.status_code == 403 and REFUSED in r.text, path
    assert state(env) == before and len(env.mails()) == mails


@pytest.mark.parametrize("origin", ["https://evil.example", "null", "http://qo.example"])
def test_every_team_post_refuses_a_bad_origin(env, origin):
    o, posts = _owner_posts(env)
    csrf = team_csrf(o)
    before, mails = state(env), len(env.mails())
    for path, data in posts:
        r = o.post(path, data={"csrf": csrf, **data}, headers={"Origin": origin})
        assert r.status_code == 403 and REFUSED in r.text, path
    assert state(env) == before and len(env.mails()) == mails


def test_invite_accept_refuses_missing_foreign_token_and_bad_origin(env):
    o = owner(env)
    invite(o, "new@shop.test")
    token = token_of(invite_link(env, "new@shop.test"))
    c, stranger = env.client(), env.client()
    foreign = pre_csrf(stranger)
    before = state(env)
    assert post_accept(c, token, csrf="").status_code == 403
    pre_csrf(c)
    assert post_accept(c, token, csrf=foreign).status_code == 403
    r = c.post("/invite", data={"csrf": pre_csrf(c), "token": token, "password": PASSWORD,
                                "terms": "yes"}, headers={"Origin": "https://evil.example"})
    assert r.status_code == 403
    assert state(env) == before


# --- role, disable, enable ----------------------------------------------------------------------

def test_owner_changes_a_role_and_an_audit_row_is_written(env):
    o = owner(env)
    c = member(env, o, "est@shop.test", "estimator")
    target = uid(env, "est@shop.test")
    page = flash_after(o, o.post("/team/role", data={"csrf": team_csrf(o), "user": str(target),
                                                     "role": "accountant"}))
    assert "Role changed." in page
    assert user_row(env, "est@shop.test")[1] == "accountant"
    with env.owner() as db:
        rows = db.execute("SELECT company_id, actor, what, subject FROM audit_event").fetchall()
    assert len(rows) == 1
    assert rows[0][:3] == (company_of(env, OWNER), uid(env, OWNER), "user.role")
    assert str(target) in rows[0][3] and "estimator" in rows[0][3] and "accountant" in rows[0][3]
    assert "est@shop.test" not in rows[0][3]
    assert "accountant" in c.get("/app").text  # the session carries the new role at once


@pytest.mark.parametrize("role", BAD_ROLES)
def test_role_change_refuses_any_role_but_the_three(env, role):
    o = owner(env)
    member(env, o, "est@shop.test", "estimator")
    before = state(env)
    r = o.post("/team/role", data={"csrf": team_csrf(o), "user": str(uid(env, "est@shop.test")),
                                   "role": role})
    assert r.status_code == 400
    assert state(env) == before


def test_there_is_never_a_second_owner_or_a_sysadmin(env):
    o = owner(env)
    member(env, o, "est@shop.test", "estimator")
    for role in ("owner", "sysadmin", " owner", "OWNER"):
        o.post("/team/role", data={"csrf": team_csrf(o), "user": str(uid(env, "est@shop.test")),
                                   "role": role})
        invite(o, f"x{len(role)}{role.strip().lower()}@shop.test", role)
    with env.owner() as c:
        assert c.execute("SELECT count(*) FROM app_user WHERE role IN ('owner', 'sysadmin')"
                         ).fetchone()[0] == 1
        # Only the estimator's own, used invitation exists.
        assert c.execute("SELECT count(*) FROM invite").fetchone()[0] == 1


@pytest.mark.parametrize("path,extra", [("/team/role", {"role": "viewer"}),
                                        ("/team/disable", {}), ("/team/enable", {})])
def test_owner_cannot_change_themselves(env, path, extra):
    o = owner(env)
    before = state(env)
    r = o.post(path, data={"csrf": team_csrf(o), "user": str(uid(env, OWNER)), **extra})
    assert r.status_code == 403
    assert state(env) == before
    assert o.get("/team").status_code == 200  # still the owner, still signed in


def test_disable_ends_the_sessions_at_once_and_enable_restores_sign_in(env):
    o = owner(env)
    c = member(env, o, "est@shop.test", "estimator")
    target = uid(env, "est@shop.test")
    assert c.get("/app").status_code == 200
    page = flash_after(o, o.post("/team/disable", data={"csrf": team_csrf(o),
                                                        "user": str(target)}))
    assert "User disabled." in page
    assert user_row(env, "est@shop.test")[2] is not None
    assert env.scalar("SELECT count(*) FROM session WHERE user_id = %s", (target,)) == 0
    r = c.get("/app")
    assert r.status_code == 303 and r.headers["location"] == "/login"
    assert login(env.client(), "est@shop.test").status_code == 400
    page = flash_after(o, o.post("/team/enable", data={"csrf": team_csrf(o),
                                                       "user": str(target)}))
    assert "User enabled." in page
    assert user_row(env, "est@shop.test")[2] is None
    assert c.get("/app").status_code == 303  # the old session stays gone after enabling
    fresh = env.client()
    assert login(fresh, "est@shop.test").status_code == 303
    with env.owner() as db:
        rows = db.execute("SELECT actor, what, subject FROM audit_event ORDER BY id").fetchall()
    assert [(a, w) for a, w, _ in rows] == [(uid(env, OWNER), "user.disable"),
                                           (uid(env, OWNER), "user.enable")]
    assert all(str(target) in s for _, _, s in rows)


@pytest.mark.parametrize("path", ["/team/role", "/team/disable", "/team/enable"])
@pytest.mark.parametrize("user", ["", "nope", "00000000-0000-0000-0000-000000000000"])
def test_unknown_user_is_404(env, path, user):
    o = owner(env)
    before = state(env)
    r = o.post(path, data={"csrf": team_csrf(o), "user": user, "role": "viewer"})
    assert r.status_code == 404 and state(env) == before


def test_every_team_post_redirects_to_team_without_secrets(env):
    o = owner(env)
    member(env, o, "est@shop.test")
    target = str(uid(env, "est@shop.test"))
    invite(o, "pending@shop.test")
    csrf = team_csrf(o)
    for path, data in [("/team/invite", {"email": "new@shop.test", "role": "viewer"}),
                       ("/team/invite/revoke", {"ref": str(ref_of(env, "pending@shop.test"))}),
                       ("/team/role", {"user": target, "role": "viewer"}),
                       ("/team/disable", {"user": target}),
                       ("/team/enable", {"user": target}),
                       ("/team/invite", {"email": "bad", "role": "viewer"})]:
        r = o.post(path, data={"csrf": csrf, **data})
        assert r.status_code == 303 and r.headers["location"] == "/team", path
        cookie = r.headers.get("set-cookie", "")
        assert "qo_flash=" in cookie and "httponly" in cookie.lower()
        assert "secure" in cookie.lower() and "samesite=lax" in cookie.lower()


def test_flash_is_shown_once_and_a_forged_flash_is_ignored(env):
    o = owner(env)
    page = flash_after(o, invite(o, "new@shop.test"))
    assert SENT in page
    assert SENT not in o.get("/team").text
    o.cookies.set("qo_flash", "sent.0000", domain="qo.example", path="/team")
    assert SENT not in o.get("/team").text


# --- the invitee --------------------------------------------------------------------------------

def test_invite_link_shows_the_form_and_changes_nothing(env):
    o = owner(env)
    invite(o, "new@shop.test", "accountant")
    link = invite_link(env, "new@shop.test")
    before, rows = state(env), _throttle_rows(env)
    r = env.client().get(path_of(link))
    assert r.status_code == 200 and 'action="/invite"' in r.text
    assert "Bengkel Maju" in r.text and "accountant" in r.text and "new@shop.test" in r.text
    assert re.search(r'<input[^>]*value="new@shop.test"[^>]*readonly', r.text)
    assert re.search(r'<input[^>]*type="password"[^>]*autocomplete="new-password"', r.text)
    assert 'name="terms"' in r.text and _mod("auth").TERMS_VERSION in r.text
    assert state(env) == before and _throttle_rows(env) == rows


def test_accepting_creates_the_member_from_the_invite_row(env):
    o = owner(env)
    invite(o, "New@Shop.test", "viewer")
    link = invite_link(env, "new@shop.test")
    c = env.client()
    r = accept(c, link)
    assert r.status_code == 200 and JOINED in r.text and 'href="/login"' in r.text
    assert "qo_session=" not in r.headers.get("set-cookie", "")
    assert env.scalar("SELECT count(*) FROM session") == 1  # only the owner's
    company_id, role, disabled_at, verified_at, consent = user_row(env, "new@shop.test")
    assert (company_id, role, disabled_at) == (company_of(env, OWNER), "viewer", None)
    assert verified_at is not None and consent == _mod("auth").TERMS_VERSION
    assert env.scalar("SELECT used_at FROM invite") is not None
    m = env.client()
    assert login(m, "new@shop.test").status_code == 303
    assert "viewer" in m.get("/app").text


def test_accept_applies_the_password_rules_and_terms_and_changes_nothing(env):
    o = owner(env)
    invite(o, "new@shop.test")
    link = invite_link(env, "new@shop.test")
    before = state(env)
    for password, terms in [("new@shop.test", True), ("short", True), ("password123", True),
                            (PASSWORD, False)]:
        r = accept(env.client(), link, password=password, terms=terms)
        assert r.status_code == 400 and 'action="/invite"' in r.text, password
    assert state(env) == before
    assert accept(env.client(), link).status_code == 200


def test_used_expired_revoked_and_replaced_links_fail_identically(env):
    o = owner(env)
    for e in ("used", "expired", "revoked", "replaced"):
        invite(o, f"{e}@shop.test")
    links = {e: invite_link(env, f"{e}@shop.test") for e in ("used", "expired", "revoked",
                                                             "replaced")}
    assert accept(env.client(), links["used"]).status_code == 200
    with env.owner() as c:
        c.execute("UPDATE invite SET expires_at = now() - interval '1 second'"
                  " WHERE email = 'expired@shop.test'")
    o.post("/team/invite/revoke", data={"csrf": team_csrf(o),
                                        "ref": str(ref_of(env, "revoked@shop.test"))})
    invite(o, "replaced@shop.test")
    before = state(env)
    gets, posts = [], []
    for e, link in links.items():
        c = env.client()
        gets.append(_answer(c.get(path_of(link))))
        posts.append(_answer(post_accept(c, token_of(link), password="fresh password 77")))
    assert len(set(gets)) == 1 and gets[0][0] == 400 and NOT_VALID.encode() in gets[0][2]
    assert len(set(posts)) == 1 and posts[0][0] == 400 and NOT_VALID.encode() in posts[0][2]
    assert state(env) == before


@pytest.mark.parametrize("token", ["", "x", "A" * 43, "A" * 44, "%00", "../../etc"])
def test_unknown_or_malformed_tokens_show_the_not_valid_page(env, token):
    owner(env)
    c = env.client()
    r = c.get("/invite", params={"token": token})
    assert r.status_code == 400 and NOT_VALID in r.text
    before = state(env)
    r = post_accept(c, token)
    assert r.status_code == 400 and NOT_VALID in r.text
    assert state(env) == before


def test_the_seven_day_boundary(env):
    o = owner(env)
    invite(o, "late@shop.test")
    invite(o, "ontime@shop.test")
    late, ontime = invite_link(env, "late@shop.test"), invite_link(env, "ontime@shop.test")
    with env.owner() as c:  # created 7 days and 1 second ago, and 7 days less 1 second ago
        c.execute("UPDATE invite SET created_at = now() - interval '7 days 1 second',"
                  " expires_at = now() - interval '1 second' WHERE email = 'late@shop.test'")
        c.execute("UPDATE invite SET created_at = now() - interval '7 days' + interval '1 second',"
                  " expires_at = now() + interval '1 second' WHERE email = 'ontime@shop.test'")
    c = env.client()
    assert c.get(path_of(ontime)).status_code == 200
    r = c.get(path_of(late))
    assert r.status_code == 400 and NOT_VALID in r.text
    assert post_accept(c, token_of(late)).status_code == 400
    assert user_row(env, "late@shop.test") is None
    with env.owner() as db:
        db.execute("UPDATE invite SET expires_at = now() + interval '1 second'"
                   " WHERE email = 'ontime@shop.test'")
    r = post_accept(c, token_of(ontime))
    assert r.status_code == 200 and JOINED in r.text
    assert user_row(env, "ontime@shop.test") is not None


@pytest.mark.parametrize("status", ["unverified", "suspended", "deleting"])
def test_accept_is_refused_unless_the_company_is_active(env, status):
    o = owner(env)
    invite(o, "new@shop.test")
    link = invite_link(env, "new@shop.test")
    c = env.client()
    data = {"csrf": csrf_from(c.get(path_of(link)).text), "token": token_of(link),
            "password": PASSWORD, "terms": "yes"}
    with env.owner() as db:
        db.execute("UPDATE company SET status = %s", (status,))
    before = state(env)
    r = c.get(path_of(link))
    assert r.status_code == 400 and NOT_VALID in r.text
    r = c.post("/invite", data=data)
    assert r.status_code == 400 and NOT_VALID in r.text
    assert state(env) == before and user_row(env, "new@shop.test") is None


def test_accept_rechecks_the_user_cap(env):
    o = owner(env)
    invite(o, "new@shop.test")
    link = invite_link(env, "new@shop.test")
    cid = company_of(env, OWNER)
    with env.owner() as c:  # four users join by another path meanwhile: 5 of 5
        for n in range(4):
            c.execute("INSERT INTO app_user (id, company_id, email, pw_hash, pw_salt, role,"
                      " consent_version, consent_at) VALUES (%s, %s, %s, '\\x00', '\\x00',"
                      " 'viewer', 'v1', now())", (uuid.uuid4(), cid, f"x{n}@shop.test"))
    before = state(env)
    r = accept(env.client(), link)
    assert r.status_code == 403 and FULL in r.text
    assert state(env) == before


def test_accept_when_the_address_registered_elsewhere_meanwhile(env):
    o = owner(env)
    invite(o, "new@shop.test")
    link = invite_link(env, "new@shop.test")
    signed_up(env, "new@shop.test", company="Elsewhere", ip="198.51.100.7")
    other = company_of(env, "new@shop.test")
    before = state(env)
    r = accept(env.client(), link)
    assert r.status_code == 400 and NOT_VALID in r.text
    assert state(env) == before  # the invite use was rolled back with the insert
    assert company_of(env, "new@shop.test") == other
    assert env.scalar("SELECT used_at FROM invite") is None


def test_an_invite_row_with_a_forbidden_role_never_creates_that_role(env):
    """Defence in depth: even a row the CHECK no longer guards (it was created before the
    constraint, or the constraint is gone) cannot make an owner."""
    o = owner(env)
    invite(o, "new@shop.test", "viewer")
    link = invite_link(env, "new@shop.test")
    with env.owner() as c:
        name = c.execute("SELECT conname FROM pg_constraint WHERE conrelid = 'invite'::regclass"
                         " AND contype = 'c'").fetchone()[0]
        c.execute(f'ALTER TABLE invite DROP CONSTRAINT "{name}"')
        c.execute("UPDATE invite SET role = 'owner'")
    r = accept(env.client(), link)
    assert r.status_code == 400 and NOT_VALID in r.text
    assert user_row(env, "new@shop.test") is None
    assert env.scalar("SELECT used_at FROM invite") is None


def test_busy_accept_changes_nothing_and_opens_no_connection(env):
    o = owner(env)
    invite(o, "new@shop.test")
    link = invite_link(env, "new@shop.test")
    c = env.client()
    data = {"csrf": csrf_from(c.get(path_of(link)).text), "token": token_of(link),
            "password": PASSWORD, "terms": "yes"}
    before, rows, mails = state(env), _throttle_rows(env), len(env.mails())
    with _blocked(env):
        with _no_connection(env):
            r = c.post("/invite", data=data)
    _assert_busy(r)
    assert state(env) == before and _throttle_rows(env) == rows and len(env.mails()) == mails
    r = c.post("/invite", data=data)  # the link still works
    assert r.status_code == 200 and JOINED in r.text


def test_accept_hashes_only_inside_the_slot(env):
    o = owner(env)
    invite(o, "new@shop.test")
    link = invite_link(env, "new@shop.test")
    passwords, seen = _mod("passwords"), []
    real = passwords.hash_password

    def spy(password):
        seen.append(getattr(passwords._held, "depth", 0))
        return real(password)

    env.monkeypatch.setattr(passwords, "hash_password", spy)
    assert accept(env.client(), link).status_code == 200
    assert seen == [1]


def test_the_raw_token_is_never_logged(env, caplog):
    caplog.set_level(logging.DEBUG)
    o = owner(env)
    invite(o, "new@shop.test")
    link = invite_link(env, "new@shop.test")
    token = token_of(link)
    accept(env.client(), link)
    accept(env.client(), link)
    texts = [f"{x.getMessage()} {x.args!r} {x.exc_text or ''}" for x in caplog.records
             if not x.name.startswith(("httpx", "httpcore"))]
    assert not any(token in t or sha256(token).hex() in t for t in texts)


def test_a_mail_failure_on_invite_is_logged_by_class_only(env, caplog):
    o = owner(env)
    caplog.set_level(logging.DEBUG)

    class MailBoom(OSError):
        pass

    def boom(self, to, subject, text):
        raise MailBoom("detail-that-must-not-leak new@shop.test")

    env.monkeypatch.setattr(_mod("mail").FileMailer, "send", boom)
    r = invite(o, "new@shop.test")
    assert SENT in flash_after(o, r)
    texts = [f"{x.getMessage()} {x.args!r} {x.exc_text or ''}" for x in caplog.records
             if not x.name.startswith(("httpx", "httpcore"))]
    assert any("MailBoom" in t for t in texts)
    assert not any("detail-that-must-not-leak" in t or "new@shop.test" in t for t in texts)
    assert not any(x.exc_info for x in caplog.records)


# --- races --------------------------------------------------------------------------------------

def test_two_parallel_accepts_of_one_link_make_one_account(env):
    o = owner(env)
    invite(o, "new@shop.test")
    link = invite_link(env, "new@shop.test")
    pws = ["first parallel phrase 1", "second parallel phrase 2"]
    clients = [env.client(), env.client()]
    datas = [{"csrf": csrf_from(c.get(path_of(link)).text), "token": token_of(link),
              "password": pw, "terms": "yes"} for c, pw in zip(clients, pws)]
    passwords, together = _mod("passwords"), threading.Barrier(2)
    real = passwords.hash_password

    def hash_after_both_looked_up(password):
        together.wait(10)
        return real(password)

    env.monkeypatch.setattr(passwords, "hash_password", hash_after_both_looked_up)
    results = [None, None]

    def run(i):
        results[i] = clients[i].post("/invite", data=datas[i])

    threads = [threading.Thread(target=run, args=(i,)) for i in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    codes = sorted(r.status_code for r in results)
    assert codes == [200, 400], [r.text for r in results]
    assert env.scalar("SELECT count(*) FROM app_user WHERE email = 'new@shop.test'") == 1
    winner = pws[[r.status_code for r in results].index(200)]
    env.monkeypatch.setattr(passwords, "hash_password", real)
    assert login(env.client(), "new@shop.test", winner).status_code == 303


def test_the_compare_and_set_alone_stops_a_stale_invite(env):
    """The lookup saw the link unused, the link was used meanwhile, and the address is free again
    (the unique email no longer helps): only the compare-and-set on used_at stops a second
    account. Added after GREEN for the breakage proof of the compare-and-set."""
    team = _mod("team")
    o = owner(env)
    invite(o, "new@shop.test")
    link = invite_link(env, "new@shop.test")
    stale = team._open_invite(token_of(link))
    assert accept(env.client(), link).status_code == 200
    with env.owner() as c:
        c.execute("DELETE FROM app_user WHERE email = 'new@shop.test'")
    env.monkeypatch.setattr(team, "_open_invite", lambda token: stale)
    before = state(env)
    r = post_accept(env.client(), token_of(link), password="another fresh phrase 9")
    assert r.status_code == 400 and NOT_VALID in r.text
    assert state(env) == before and user_row(env, "new@shop.test") is None


@pytest.mark.parametrize("revoke_delay", [0.0, 0.6])
def test_accept_racing_revoke_is_all_or_nothing(env, revoke_delay):
    o = owner(env)
    invite(o, "new@shop.test")
    link, ref = invite_link(env, "new@shop.test"), ref_of(env, "new@shop.test")
    c = env.client()
    data = {"csrf": csrf_from(c.get(path_of(link)).text), "token": token_of(link),
            "password": PASSWORD, "terms": "yes"}
    csrf = team_csrf(o)
    passwords, together = _mod("passwords"), threading.Barrier(2)
    real = passwords.hash_password

    def hash_at_the_barrier(password):
        together.wait(10)
        return real(password)

    env.monkeypatch.setattr(passwords, "hash_password", hash_at_the_barrier)
    results = {}

    def do_accept():
        results["accept"] = c.post("/invite", data=data)

    def do_revoke():
        together.wait(10)
        time.sleep(revoke_delay)
        results["revoke"] = o.post("/team/invite/revoke", data={"csrf": csrf, "ref": str(ref)})

    threads = [threading.Thread(target=do_accept), threading.Thread(target=do_revoke)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    user = user_row(env, "new@shop.test")
    rows = invites(env)
    if results["accept"].status_code == 200:
        assert results["revoke"].status_code == 404
        assert user is not None and len(rows) == 1 and rows[0][3] is not None
    else:
        assert results["accept"].status_code == 400
        assert results["revoke"].status_code == 303
        assert user is None and rows == []


# --- schema -------------------------------------------------------------------------------------

def test_invite_columns(adb):
    with adb.connect() as c:
        cols = dict(c.execute("SELECT column_name, data_type || ' ' || is_nullable || ' '"
                              " || coalesce(column_default, '-')"
                              " FROM information_schema.columns WHERE table_name = 'invite'"
                              ).fetchall())
        unique = c.execute("SELECT count(*) FROM pg_index i JOIN pg_attribute a"
                           " ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey)"
                           " WHERE i.indrelid = 'invite'::regclass AND i.indisunique"
                           " AND a.attname = 'ref' AND i.indnatts = 1").fetchone()[0]
    assert cols["ref"] == "uuid NO gen_random_uuid()"
    assert cols["created_by"].startswith("uuid YES")
    assert cols["created_at"] == "timestamp with time zone NO now()"
    assert unique == 1


def test_admin_has_no_access_to_invite(adb):
    with adb.connect() as c:
        assert not c.execute("SELECT bool_or(has_table_privilege('qo_admin', 'invite', p))"
                             " FROM unnest(ARRAY['SELECT','INSERT','UPDATE','DELETE','TRUNCATE',"
                             "'REFERENCES','TRIGGER']) p").fetchone()[0]
        assert not c.execute("SELECT has_any_column_privilege('qo_admin', 'invite',"
                             " 'SELECT,INSERT,UPDATE,REFERENCES')").fetchone()[0]
    with adb.connect("qo_admin") as c:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute("SELECT ref FROM invite")


def test_no_new_definer_function(adb):
    with adb.connect() as c:
        names = sorted(r[0] for r in c.execute(
            "SELECT p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace"
            " WHERE n.nspname = 'public' AND p.prosecdef"))
    # Stage 2b part 2 adds the six qo_admin_* functions (callable by qo_admin only); stage 2b
    # part 1 itself added none.
    assert names == sorted(["qo_login_lookup", "qo_session_create", "qo_session_lookup",
                            "qo_session_delete", "qo_invite_lookup", "qo_throttle_check",
                            "qo_throttle_reset", "qo_company_count", "qo_session_delete_user",
                            "qo_purge_unverified", "qo_admin_login_lookup", "qo_admin_totp_use",
                            "qo_admin_session_create", "qo_admin_session_lookup",
                            "qo_admin_session_delete", "qo_admin_session_delete_user"])


def test_web_role_reaches_only_its_own_companys_invites(adb):
    with adb.connect() as c:
        for cid in ("c_a", "c_b"):
            c.execute("INSERT INTO company (id, name, status) VALUES (%s, %s, 'active')", (cid, cid))
            c.execute("INSERT INTO invite (id_hash, company_id, email, role, expires_at)"
                      " VALUES (%s, %s, 'x@x.test', 'viewer', now() + interval '1 day')",
                      (cid.encode(), cid))
    with adb.connect("qo_web") as c:
        c.execute("SELECT set_config('app.company_id', 'c_a', false)")
        assert c.execute("SELECT company_id FROM invite").fetchall() == [("c_a",)]
        assert c.execute("DELETE FROM invite WHERE company_id = 'c_b'").rowcount == 0
        assert c.execute("UPDATE invite SET used_at = now() WHERE company_id = 'c_b'"
                         ).rowcount == 0
    with adb.connect() as c:
        assert c.execute("SELECT count(*) FROM invite WHERE used_at IS NULL").fetchone()[0] == 2


def test_migration_applies_twice_over_a_stage2a_database(empty_db):
    with empty_db.connect(autocommit=True) as c:
        c.execute(STAGE2A_SCHEMA.read_text(encoding="ascii"))
        c.execute("INSERT INTO company (id, name, status) VALUES ('c_old', 'Old', 'active')")
        u = uuid.uuid4()
        c.execute("INSERT INTO app_user (id, company_id, email, pw_hash, pw_salt, role,"
                  " email_verified_at, consent_version, consent_at) VALUES (%s, 'c_old',"
                  " 'old@x.test', '\\x01', '\\x02', 'owner', now(), 'v1', now())", (u,))
        c.execute("INSERT INTO session (id_hash, user_id, expires_at)"
                  " VALUES ('\\x0a', %s, now() + interval '1 day')", (u,))
        c.execute("INSERT INTO invite (id_hash, company_id, email, role, expires_at)"
                  " VALUES ('\\x0b', 'c_old', 'inv@x.test', 'viewer', now() + interval '1 day')")
        c.execute("INSERT INTO invite (id_hash, company_id, email, role, expires_at)"
                  " VALUES ('\\x0c', 'c_old', 'odd@x.test', 'owner', now() + interval '1 day')")
        assert c.execute("SELECT count(*) FROM information_schema.columns"
                         " WHERE table_name = 'invite' AND column_name = 'ref'").fetchone()[0] == 0
    try:
        for _ in range(2):
            empty_db.migrate()
            with empty_db.connect() as c:
                rows = c.execute("SELECT id_hash, ref, created_at FROM invite ORDER BY id_hash"
                                 ).fetchall()
                assert [bytes(r[0]) for r in rows] == [b"\x0b", b"\x0c"]
                assert all(r[1] is not None and r[2] is not None for r in rows)
                assert len({r[1] for r in rows}) == 2
                assert c.execute("SELECT count(*) FROM app_user").fetchone()[0] == 1
                with pytest.raises(psycopg.errors.CheckViolation):
                    c.execute("INSERT INTO invite (id_hash, company_id, email, role, expires_at)"
                              " VALUES ('\\x0d', 'c_old', 'n@x.test', 'owner', now())")
            with empty_db.connect("qo_web") as c:
                assert c.execute("SELECT email::text FROM qo_invite_lookup('\\x0b')"
                                 ).fetchone() == ("inv@x.test",)
                assert c.execute("SELECT user_id FROM qo_session_lookup('\\x0a')"
                                 ).fetchone() == (u,)
    finally:
        with Db(empty_db.port, "postgres").connect(autocommit=True) as c:
            c.execute(f'DROP DATABASE IF EXISTS "{empty_db.dbname}" WITH (FORCE)')


# --- settings -----------------------------------------------------------------------------------

@pytest.fixture
def cfg(monkeypatch):
    for k in list(os.environ):
        if k.startswith("QO_"):
            monkeypatch.delenv(k)
    monkeypatch.setenv("QO_SECRET", SECRET)
    monkeypatch.setenv("QO_BASE_URL", "https://qo.example")
    return monkeypatch


SETTINGS = {"QO_MAX_USERS_PER_COMPANY": ("max_users_per_company", 5, 100),
            "QO_INVITES_PER_DAY": ("invites_per_day", 20, 1000),
            "QO_INVITES_PER_ADDRESS_PER_DAY": ("invites_per_address_per_day", 3, 100)}


def test_team_settings_defaults(cfg):
    s = _mod("config").load_settings()
    for attr, default, _ in SETTINGS.values():
        assert getattr(s, attr) == default


@pytest.mark.parametrize("var", sorted(SETTINGS))
@pytest.mark.parametrize("which", ["0", "-1", "many", "1.5", "max", "1", "default", "over"])
def test_team_settings_are_checked(cfg, var, which):
    config = _mod("config")
    attr, default, maximum = SETTINGS[var]
    value = {"max": str(maximum), "default": str(default), "over": str(maximum + 1)}.get(which,
                                                                                       which)
    cfg.setenv(var, value)
    if which in ("max", "1", "default"):
        assert getattr(config.load_settings(), attr) == int(value)
        return
    with pytest.raises(config.ConfigError) as exc:
        config.load_settings()
    assert var in str(exc.value) and value not in str(exc.value)


def test_team_settings_reach_the_web_container_the_example_and_the_tests():
    web = yaml.safe_load((ROOT / "deploy" / "compose.yaml").read_text())["services"]["web"]
    example = (ROOT / "deploy" / ".env.example").read_text()
    for var, (_, default, _) in SETTINGS.items():
        assert web["environment"][var] == f"${{{var}:-{default}}}"
        assert var in example
        assert var in ENV_DEFAULTS_TO_CLEAR


def test_signup_and_login_throttle_defaults_are_unchanged(cfg):
    s = _mod("config").load_settings()
    assert (s.login_fails_per_email, s.login_fails_per_ip, s.login_window_seconds,
            s.login_block_seconds, s.forgot_per_email, s.forgot_per_ip, s.signup_per_ip,
            s.signup_per_email) == (5, 30, 900, 900, 3, 10, 5, 3)


# --- review fixes: the Owner routes need an active company ------------------------------------------

NOT_ACTIVE = "This company is not active."


def _active_owner_posts(env, o):
    """Every /team POST with valid CSRF and real targets, taken while the company is active."""
    member(env, o, "est@shop.test")
    invite(o, "pending@shop.test")
    csrf, target, ref = team_csrf(o), str(uid(env, "est@shop.test")), str(ref_of(env, "pending@shop.test"))
    return [("/team/invite", {"csrf": csrf, "email": "new@shop.test", "role": "viewer"}),
            ("/team/invite/revoke", {"csrf": csrf, "ref": ref}),
            ("/team/role", {"csrf": csrf, "user": target, "role": "viewer"}),
            ("/team/disable", {"csrf": csrf, "user": target}),
            ("/team/enable", {"csrf": csrf, "user": target})]


@pytest.mark.parametrize("status", ["unverified", "suspended", "deleting"])
def test_owner_routes_need_an_active_company(env, status):
    o = owner(env)
    posts = _active_owner_posts(env, o)
    with env.owner() as db:
        db.execute("UPDATE company SET status = %s", (status,))
    before = state(env)
    answers = [o.get("/team", follow_redirects=False)]
    answers += [o.post(path, data=data, follow_redirects=False) for path, data in posts]
    for r in answers:
        if status == "unverified":  # the session lookup still returns the session
            assert r.status_code == 403 and NOT_ACTIVE in r.text, (r.status_code, r.text)
        else:  # the session lookup already refuses the session
            assert r.status_code in (303, 403), r.status_code
            assert r.status_code == 403 or r.headers["location"].startswith("/login")
        assert "Invitation sent." not in r.text and 'action="/team/invite"' not in r.text
    assert state(env) == before
    assert not invite_mails(env, "new@shop.test")
    with env.owner() as db:
        db.execute("UPDATE company SET status = 'active'")
    if status == "unverified":  # the same session works again
        assert o.get("/team").status_code == 200
        path, data = posts[0]
        r = o.post(path, data=data)
        assert r.status_code == 303 and r.headers["location"] == "/team"


# --- review fixes: the address that gets an account between the lookup and the insert --------------

def _has_account_answers(env, *answers):
    calls = []
    seq = iter(answers)

    def fake(email):
        calls.append(email)
        return next(seq)

    env.monkeypatch.setattr(_mod("auth"), "_has_account", fake)
    return calls


def _run_finish(env, email="new@shop.test"):
    team = _mod("team")
    team._finish_invite(team.load_settings(), str(company_of(env, OWNER)), uid(env, OWNER),
                        email, "viewer")


def _pending(env, email):
    return [r for r in invites(env) if r[1] == email and r[3] is None]


def test_an_account_made_between_lookup_and_insert_gets_the_notice_not_the_link(env):
    owner(env)
    calls = _has_account_answers(env, False, True)
    _run_finish(env)
    assert len(calls) == 2
    assert not invite_mails(env, "new@shop.test")
    assert len(env.mails_to("new@shop.test")) == 1
    assert EXISTS_MAIL in env.mails_to("new@shop.test")[0].body
    assert _pending(env, "new@shop.test") == []


def test_no_account_at_either_check_mails_the_link_and_keeps_the_row(env):
    owner(env)
    calls = _has_account_answers(env, False, False)
    _run_finish(env)
    assert len(calls) == 2
    assert len(invite_mails(env, "new@shop.test")) == 1
    assert len(_pending(env, "new@shop.test")) == 1


def test_an_account_at_the_first_check_gets_the_notice_and_no_row(env):
    owner(env)
    calls = _has_account_answers(env, True)
    _run_finish(env)
    assert len(calls) == 1
    assert not invite_mails(env, "new@shop.test")
    assert EXISTS_MAIL in env.mails_to("new@shop.test")[0].body
    assert _pending(env, "new@shop.test") == []


def test_a_failing_second_check_is_logged_by_class_and_mails_no_link(env, caplog):
    owner(env)
    caplog.set_level(logging.DEBUG)

    class LookupBoom(RuntimeError):
        pass

    answers = iter([False])

    def fake(email):
        try:
            return next(answers)
        except StopIteration:
            raise LookupBoom("detail-that-must-not-leak new@shop.test")

    env.monkeypatch.setattr(_mod("auth"), "_has_account", fake)
    _run_finish(env)
    assert not invite_mails(env, "new@shop.test")
    assert len(_pending(env, "new@shop.test")) <= 1
    texts = [f"{x.getMessage()} {x.args!r} {x.exc_text or ''}" for x in caplog.records
             if not x.name.startswith(("httpx", "httpcore"))]
    assert any("LookupBoom" in t for t in texts)
    assert not any("detail-that-must-not-leak" in t or "new@shop.test" in t for t in texts)
    assert not any(x.exc_info for x in caplog.records)
