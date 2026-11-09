**Verdict:** fail

Verified `stage2b` HEAD `9797baa` against supplied passed-stage base `83ed11a`. `git log --oneline main..HEAD` could not run because this clone has no local `main` ref (only `origin/main`); I used `83ed11a..HEAD`.

DEFECT (low): an Owner session remains authorized for all `/team` routes when the company is `unverified`.

1. Sign in as Owner while the company is active and retain the session.
2. Change the company status to `unverified` (for example through an operational transition or restored inconsistent data).
3. `qo_session_lookup` excludes only `suspended` and `deleting`, so it returns this session and the current DB role.
4. `require_owner` checks role and `require_verified`, but the latter checks only `app_user.email_verified_at`, not company status.
5. The Owner can GET `/team` and, with their valid Origin/CSRF, invite, revoke, change roles, disable, and enable users, contrary to the brief's explicit unverified-company restriction.

Role changes are read on every request; disabled users and suspended/deleting companies are rejected. No test covers `/team` with an unverified company; `test_accept_is_refused_unless_the_company_is_active` covers only public invite acceptance.

DEFECT (low): the background account lookup and invite creation are not atomic, so an address that acquires an account between them receives a join link instead of the promised notice without one.

1. Invite an address with no account.
2. `_finish_invite` calls `_has_account` and gets false.
3. Before its tenant insert, the address completes account creation in another company.
4. The task does not recheck; it inserts a pending invite and mails the token and inviting company name.
5. Later acceptance is safely stopped by global email uniqueness and `UniqueViolation` rolls back `used_at`, but the wrong mail was sent and an unusable pending invite remains.

No test covers this lookup-to-insert race. The identical-answer test covers a pre-existing account; `test_accept_when_the_address_registered_elsewhere_meanwhile` covers registration after invite creation.

OBSERVATION: `/team` reveals whether an address already has an account because only a new address leaves a pending invite. This is the stated known/accepted limit and is bounded by the documented throttles, so it is not a defect here.

OBSERVATION: one company can consume the cross-company recipient throttle and delay other companies for a day. This too is explicitly documented as accepted.

OBSERVATION: early `return` inside `tenant_conn` commits, but the inactive-company, full-company, and missing-CAS returns occur before any data-changing statement. A forbidden returned role raises `_Undo`; `UniqueViolation` and `_Undo` roll back the `used_at` update.

OBSERVATION: cap arithmetic is consistent. Invite creation counts users plus unexpired unused invites (excluding the replaced recipient) under the company lock. Acceptance uses the same lock and permits insertion only while users are below the current cap. Disabled users count; expired invites do not; a lowered cap cannot be exceeded by old invites.

OBSERVATION: accept holds the scrypt slot through lookup, hashing, connection acquisition, advisory-lock wait, and insertion. This preserves slot-first/no-change-on-503, but company lock contention can occupy a scarce slot. The design accepts this and specifies no lock timeout.

Process

- RED `5bd3b3b` adds only `tests/test_stage2b_team.py` and stage-2a snapshot `tests/data/schema_83ed11a.sql`.
- `63872ed`: old `csrf or pre_csrf` silently replaced `""`; new `csrf is None` sends the empty token and strengthens the missing-CSRF test.
- `58b6bf1`: old sorted headers list raised `TypeError` in a set; tuple preserves values and makes the answer hashable.
- `3aca9f1`: the only pre-existing behavioral fixture change gives the expired unused invite its own address. Old data had two unused invites for one company/address and could not migrate under the new index; assertions are unchanged. Justified.
- `tests/stage2a_support.py` only adds the three settings to environment cleanup; no assertion changes.
- Added lines contain no non-ASCII characters. `git diff --check` passed.
- No dependency file changed. No file outside `quoteops/`, `tests/`, `deploy/`, or `docs/` changed.
- The schema diff adds no `GRANT`, function, or `SECURITY DEFINER`. Columns/indexes use `IF NOT EXISTS`; constraints check `pg_constraint`. `NOT VALID` binds new/changed rows. `app_user_role_known` includes `sysadmin`; PostgreSQL 16 provides `gen_random_uuid()` in core.

Implementation review

- Every team route uses `require_owner`; every team POST checks session CSRF plus Origin. Targets use the Owner's tenant transaction and forced RLS. Owner/self rows are blocked. Only exact invitable roles pass.
- Accept ignores forged company/email/role fields. It takes the scrypt slot before any connection, uses `qo_invite_lookup`, validates, hashes in-slot, locks, checks active status and cap, then CAS-updates the invite and inserts from `RETURNING` values.
- Different companies may invite one address; global email uniqueness makes the first accepted account win and later acceptance rolls back cleanly.
- Replacement deletes all unused same-address tenant rows, including expired ones. Cap counting excludes expired rows. The partial unique index includes expired unused rows, which replacement removes.
- Throttles use secret-hashed company ID and normalized recipient email, one-day window/block. Recipient is hit only if company allowance remains.
- Flash keys are fixed, MAC-bound to session hash, scoped `/team`, HttpOnly/SameSite/Secure, autoescaped, and redirects are fixed. Templates autoescape quoted attributes, label visible inputs, contain no inline script, and use `autocomplete="new-password"`.
- Audit subjects contain UUIDs/fixed role words, no email; inserts use principal company under RLS and occur only for represented changes.
- Mail links use configured base URL, not Host. Recipient validation excludes whitespace, subjects are fixed, company controls are flattened/capped, role is fixed-set. Reviewed logs contain no token/email; background errors log class only.
- HLD section 10 matches code except the two defects. No admin/second-factor, Graph, profile, jobs, transfer, or deletion routes were added.
- Compose/example/defaults agree: cap 5, company 20/day, recipient 3/day.

Hand mutations

- Forged role: `test_invite_refuses_any_role_but_the_three`; forged company: `test_an_invite_of_company_a_creates_a_user_in_company_a_whatever_the_form_says`.
- Raw token stored: `test_invite_stores_only_the_hash_and_mails_the_link`.
- CAS removed: `test_the_compare_and_set_alone_stops_a_stale_invite` (also parallel accept).
- Cap skipped at request/background/accept: respectively `test_invite_over_the_cap_says_so_and_changes_nothing`, `test_two_parallel_invites_at_the_cap_admit_exactly_the_free_places`, `test_accept_rechecks_the_user_cap`.
- Company lock removed: parallel-invite cap test catches the intended race; no deterministic unit mutation covers every invite/accept interleaving.
- Session deletion skipped: `test_disable_ends_the_sessions_at_once_and_enable_restores_sign_in`.
- Owner self-target allowed: `test_owner_cannot_change_themselves`.
- Role CSRF removed: missing-token, foreign-session-token, and bad-Origin team POST tests.
- Host-derived link: `test_invitation_mail_is_built_from_the_base_url_not_the_host`.
- One-second-expired accepted: `test_the_seven_day_boundary`.
- Accept status check skipped: `test_accept_is_refused_unless_the_company_is_active`.
- Revoke on RLS-bypassing connection: `test_owner_cannot_touch_another_companys_invite_or_users` catches route deletion by another company's ref; DB-role coverage is in `test_web_role_reaches_only_its_own_companys_invites` and `test_admin_has_no_access_to_invite`.

Checks run

- `python3 -m compileall -q quoteops tests`: passed.
- Controlled config parsing (with a non-DB import stub) checked `0`, `1`, max, max+1, `x`, empty. Bounds/defaults passed: 1..100/default 5; 1..1000/default 20; 1..100/default 3.
- Static stdlib checks confirmed 43-character token pattern, SHA-256 size, `token_urlsafe(32)`, base-URL link, exact roles, and flash MAC inputs.
- The supplied orchestrator reports 582 passing tests and 15 passing attacks. I did not run or reproduce them.

Not checked

- PostgreSQL execution, migration, privileges/RLS, advisory-lock races, and the full tests: no PostgreSQL and Docker denied.
- `pytest`: `/usr/bin/python3 -m pytest` failed with `No module named pytest`; no packages were installed.
- Live ASGI/background scheduling, real mail files, browser behavior, timing, memory, and load.
- The orchestrator's runtime evidence was not independently reproduced.
