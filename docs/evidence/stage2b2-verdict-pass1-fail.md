**Verdict:** fail

## Process review (step 1)

OBSERVATION: `903b975..c793188` contains the expected 16 commits. RED commit `f62c98f` adds only seven test/support files, including `tests/data/schema_903b975.sql`; it changes no production file and no pre-existing test.

OBSERVATION: Every later change to a pre-existing test is approved-behaviour coverage, with no weakened assertion lacking an equivalent:

- `test_stage1_fix.py`: exact `qo_definer` table grants add `admin_session` INSERT/DELETE; exact column grants add SELECT of `admin_factor.(user_id,totp_secret,last_counter)`, UPDATE of `last_counter`, and SELECT of `admin_session.(id_hash,user_id,expires_at)`. The exact-set assertions remain exact.
- `test_stage1_fix2.py`: the sysadmin expectation changes from `[(None, None)]` to `[]` for `qo_login_lookup`, exactly matching the hardening decision.
- `test_stage2a_schema.py`: the old `(owner, web, admin, public) == (true,true,false,false)` expectation becomes `(true,true,true,false)` only for the two throttle functions and remains `(true,true,false,false)` for every other function; the direct rejection test drops those two calls, replaces them with successful admin calls, and continues rejecting `qo_company_count` and `qo_session_delete_user`. The migration assertion is changed identically.
- `test_stage2b_team.py`: the exact SECURITY DEFINER inventory grows from ten functions to those ten plus the six specified admin functions. It remains an exact inventory.

OBSERVATION: `3b1e707` intentionally repairs the exact SECURITY DEFINER inventory after the schema commit. The tree between those commits has a failing inventory test, but the final history restores the exact security assertion and the ordering does not weaken HEAD.

OBSERVATION: `5990138` fixes only new tests: it creates test TOTP values before installing work counters and preserves the pre-login CSRF token for the re-login test. The asserted security behavior is unchanged.

OBSERVATION: No dependency/lock file changed. No changed file lies outside `quoteops/`, `tests/`, `deploy/`, `docs/`, or `README.md`. No added line contains non-ASCII text. `git diff --check` is clean.

## Implementation review (step 2)

DEFECT (medium): Admin login has no bounded preprocessing/request-size path for the password. `POST /login` accepts an unrestricted form string, and `passwords._matches` calls `unicodedata.normalize("NFKC", password)` before deciding that the normalized value exceeds 128 characters. An unauthenticated client can send several very large passwords concurrently; form parsing retains each body and each admitted request normalizes the attacker-sized string while holding one of the three default slots. In the 512 MiB admin container this can cause disproportionate allocation and process/container termination. The slot bounds concurrent scrypt memory but does not bound request-body or Unicode-normalization memory. No new test covers a large password or a request-body limit. The code field is bounded computationally after parsing (`len != 6` short-circuits its character scan), but its request body is likewise not capped. This violates the requested bounded-work review and the service's promise to be strong when exposed to the public internet.

OBSERVATION: TOTP follows HOTP/RFC 4226 dynamic truncation over an 8-byte big-endian counter, SHA-1, six digits and 30-second steps. `well_formed` accepts exactly six ASCII digits. `match` always makes three HOTPs and three `hmac.compare_digest` calls, uses `max(counter, 0)` for work at the epoch edge, and accepts a match only where `counter >= 0`. The otpauth label and query values percent-encode the email/issuer; the fresh secret is 20 random bytes. The database initializes `last_counter` to zero, so the counter-zero code cannot pass the strict replay CAS at Unix epoch itself; this has no present-day operational effect.

OBSERVATION: The six new functions are SECURITY DEFINER, owned by `qo_definer`, pin `search_path` to `pg_catalog, public, pg_temp`, qualify tables, and end with exact admin-only EXECUTE grants (plus the two throttle functions for both application roles). The two new tables have forced RLS, no policies, no application/PUBLIC table grants, and exact definer column/table grants. The one-statement replay UPDATE is concurrency-safe under READ COMMITTED: a conflicting updater waits and PostgreSQL re-evaluates `last_counter < p_counter` against the updated row, so the second call returns false.

OBSERVATION: `qo_admin_session_create` can receive any UUID, but lookup resolves only an active, verified, company-less sysadmin. `qo_login_lookup` now excludes sysadmins without changing its result type, so migration via CREATE OR REPLACE works and public sign-in takes the dummy-scrypt path. Public forgot/reset also use that lookup and require a non-NULL company, so they cannot mail or reset a sysadmin. Sign-up and invite acceptance can send a link for the address but the global unique email prevents insertion or mutation of the sysadmin. No public UPDATE-by-email path changes it, and the only Python literal that creates role `sysadmin` is the CLI.

OBSERVATION: The older `qo_session_lookup` SECURITY DEFINER function still returns a matching sysadmin session row, and `qo_web` can call `qo_session_create` for a UUID it already knows. The Python `current_principal` explicitly rejects every row whose `company_id` is NULL, so such a row is not a public-app principal and does not bypass the separate admin sign-in. Filtering sysadmins in `qo_session_lookup` as defense in depth would reduce this residual oracle, but the reviewed behavior is not an authentication bypass.

OBSERVATION: Admin login order is pre-session CSRF/Origin, scrypt slot, connection, IP throttle, email throttle, conditional lookup, one real/dummy scrypt, three real/dummy HOTP comparisons, replay CAS, email-throttle reset and session creation. Busy returns 503 before a connection or mutation; throttle blocks intentionally return 429 without cryptographic checks. All ordinary credential/factor failure branches use `_failed` with the same empty form. The per-email lockout and the shared-proxy IP limitation are accurately listed as accepted limits. A configured client-IP header must be stripped/set by a trusted proxy; otherwise it is spoofable, leaving the per-email throttle as the remaining bound.

OBSERVATION: The admin cookie is 32 random bytes encoded with `token_urlsafe`, only SHA-256 is stored, and it is HttpOnly, SameSite=Strict, Path=/, Secure by default with an absolute 1\u201324 hour lifetime. The public cookie name is ignored. Logout checks same-origin plus an HMAC bound to the cookie hash. Every authenticated page performs a database lookup. The generic middleware covers 404/405/422/unhandled errors and applies the documented headers; `/healthz` emits FastAPI's constant JSON 503 detail and logs only the exception class. No open redirect or response-splitting input was found.

OBSERVATION: CLI passwords come from two `getpass` prompts on a TTY or one stdin line, never argv. Creation refuses every existing account and handles the insert race by catching the unique violation. Reset updates password/factor and deletes sessions in one transaction, preserves `disabled_at`, and refuses non-sysadmins/company users. Output contains the secret/URI only after commit and never the password. Handled database errors print only their exception class, not connection data. `hash_password` uses the same re-entrant slot limiter; malformed limiter configuration can produce an uncaught configuration exception, but no secret value is included.

OBSERVATION: The guard refactor preserves the prior helper algorithms and middleware behavior. Its 405 computation now includes HEAD in `Allow`, correcting the advertised methods where a route supports HEAD; this is the one deliberate externally visible detail beyond relocation. Admin configuration enforces required password/key/base URL, key length, HTTPS unless insecure local cookies, session 1\u201324 hours and login-limit bounds. Web and admin loaders do not read one another's service variables. Distinct admin/web secret values are documented but cannot be compared/enforced because each loader intentionally does not read the other value; deployment must follow the documented requirement.

OBSERVATION: Compose gives admin only its DB password/key/base URL and common bounded settings, no web/owner password, mail configuration or host port; it is read-only with `/tmp` tmpfs, 512 MiB limit and a port-8092 healthcheck. Web receives no admin variables. Migrate necessarily receives owner, web and admin DB passwords to create/set roles; the CLI commands use only the owner connection. The documented `compose run --rm migrate ...` normally allocates a TTY, and `-T` supports the one-line stdin path. README/HLD accurately describe the implemented routes and deferred F18 pages, recovery, Graph and tunnel work.

OBSERVATION: The scrypt slot remains held across throttle SQL, lookup, TOTP/CAS, reset and session creation. This is the documented stage-2a availability tradeoff. Admin database connections are per-request autocommit connections. Generic 400/429/503 pages reveal only failure class (ordinary credential failure, throttle block, or local capacity), as documented.

## Hand mutation review (step 3)

The following mutations were reviewed statically against named tests (mutants were not written into the worktree):

- Skip replay CAS: caught by `test_replay_of_a_used_code_is_refused_like_a_wrong_code`, `test_the_same_code_in_parallel_gives_exactly_one_session`, `test_totp_use_is_compare_and_set`, and `test_totp_use_counts_once_under_concurrency`.
- Accept seven-digit or non-ASCII codes: caught by `test_malformed_codes_are_refused_even_when_their_digits_are_right` and `test_every_failure_is_the_same_answer_with_one_scrypt`.
- Accept step -2/+2: caught by `test_two_steps_away_is_refused` and `test_two_steps_away_refused`.
- Decide code equality with `==`: caught by `test_codes_are_compared_with_compare_digest` and `test_equal_operator_is_not_what_decides`.
- Skip code work when password is wrong: caught by `test_every_failure_is_the_same_answer_with_one_scrypt` (its HMAC counters require three comparisons on every listed failure).
- Skip dummy password/code path for unknown users: caught by `test_every_failure_is_the_same_answer_with_one_scrypt`.
- Give wrong-code failures a distinct response: caught by `test_every_failure_is_the_same_answer_with_one_scrypt` and `test_replay_of_a_used_code_is_refused_like_a_wrong_code`.
- Take the slot after throttle/connection: caught by `test_busy_answers_503_changes_nothing_and_opens_no_connection`.
- Remove the sysadmin predicate from `qo_login_lookup`: caught by `test_web_login_lookup_never_returns_a_sysadmin`, `test_public_sign_in_treats_the_sysadmin_like_an_unknown_address`, and the changed stage-2a lookup assertion.
- Grant `qo_web` EXECUTE on an admin function: caught by `test_admin_function_execute_for_qo_admin_only`, `test_callable_function_sets_per_role`, and `test_web_cannot_call_any_admin_function`.
- Give `qo_admin` SELECT on `admin_factor`: caught by `test_no_grant_on_admin_tables_for_app_roles`, `test_app_roles_are_refused_on_admin_tables`, and the exact privilege tests.
- Store a raw session token: caught by `test_sign_in_with_password_and_code`/admin-session row assertions and `test_forged_cookies_are_refused`; schema shape and the create-call also pin hash storage.
- Skip Origin on login: caught by `test_login_refuses_without_csrf_and_origin` and `test_referer_is_used_when_origin_is_absent`.
- Skip logout CSRF or Origin: caught by `test_logout_needs_the_session_token_and_origin`.
- Set SameSite=None or omit HttpOnly: caught for the admin session by `test_sign_in_with_password_and_code`, and for pre-session CSRF by `test_pre_session_cookie_is_strict_and_http_only`.
- Give web `QO_ADMIN_PASSWORD`: caught by `test_compose_web_gets_nothing_of_the_admin_service` and the older compose separation test.
- Let create-admin reuse an existing email: caught by `test_create_admin_refuses_an_address_with_any_account` (including case-insensitive and company/admin cases).
- Leave sessions alive during reset: caught by `test_reset_admin_new_password_new_secret_and_no_sessions`.
- Add a second Python path inserting role `sysadmin`: caught by `test_only_the_cli_module_names_the_sysadmin_role_in_code`, `test_only_known_places_insert_into_app_user`, and `test_public_routes_ignore_a_role_field`.

OBSERVATION: The reviewed suite has strong mutation coverage for the stated authentication and privilege invariants. It has no test for an oversized admin login body/password or a configured maximum request size; that absence corresponds to the defect above.

## Executed checks (step 4)

OBSERVATION: `python3 -m compileall -q quoteops tests` completed successfully. (`python` is not installed under that name.)

OBSERVATION: A standalone stdlib run passed all ten RFC 4226 Appendix D HOTP vectors and all six RFC 6238 Appendix B SHA-1/eight-digit vectors. Additional assertions passed for counter zero, six ASCII digits, rejection of full-width digits and rejection of seven digits.

OBSERVATION: AST parsing of every `quoteops/*.py` file passed. Static schema assertions found all six admin function definitions and the pinned SECURITY DEFINER search path pattern. `git diff --check` passed.

OBSERVATION: An isolated config-parser run with an in-memory stub for the unavailable database import passed: defaults, session lower/upper rejection, short-key rejection, HTTPS enforcement, insecure local HTTP opt-in, and independence of web/admin settings. It ran under `env -i` and did not inspect or print workspace environment files or secrets.

OBSERVATION: I could not run pytest because the local Python lacks pytest, psycopg and FastAPI. I did not claim the orchestrator's 851-test or live PostgreSQL results as my own; I used them only as supplied evidence. Docker is present as a command but execution is denied by the stated sandbox, and no PostgreSQL server is available, so I did not attempt a container/live database run.

## Not checked

- A real authenticator application.
- Any live PostgreSQL behavior, including privilege queries, migration execution and actual concurrent row-lock re-evaluation; these were reviewed statically and against the supplied orchestrator evidence only.
- The compose stack, container healthchecks, resource limits and CLI TTY behavior at runtime.
- Cloudflare Access, tunnel routing, proxy stripping/injection of `QO_CLIENT_IP_HEADER`, TLS and HSTS at the edge.
- Full pytest execution in this clone, because its runtime dependencies are unavailable.
