**Verdict:** fail

## Findings

DEFECT (medium): The password-changed notice is not sent in a background task after the response.

`quoteops/auth.py::_reset` calls `_send(...)` synchronously after committing the password change and before constructing the success response. Reproduction: configure Graph mode; complete a valid password reset; let the token endpoint or send endpoint consume its 10-second socket timeout. The password is already changed, but the HTTP success answer waits for the mail operation (potentially a token call plus a send, and potentially another token and send after a 401). `_send` catches `MailError`, so this does not expose account existence or turn success into a 500, but it violates the explicit requirement that mails run in background tasks after the response. HLD section 12 accurately describes the implementation (\u201cin the reset route after the password is changed\u201d), but that implementation is weaker than the governing requirement.

DEFECT (low): A non-finite `expires_in` can make a token remain cached forever.

`GraphMailer._fetch_token` accepts every non-boolean `int` or `float`, without requiring `math.isfinite(lifetime)`. Python's `json.loads` accepts the non-standard numeric token `NaN`. Reproduction with the stubbed opener: return HTTP 200 with `{"access_token":"nan-token","expires_in":NaN}`; `_token_until` becomes NaN; every later `now >= self._token_until` comparison is false; subsequent sends continue using that token and do not refresh it. An `Infinity` value likewise defeats refresh until monotonic time could reach infinity. This violates \u201creused until five minutes before it expires.\u201d The Entra endpoint is trusted and is not expected to emit this malformed value, which limits severity, but malformed token replies are explicitly meant to fail and cache nothing. No test covers non-finite lifetimes.

OBSERVATION: The existing invitation failure behavior is documented and privacy-safe, but lossy. `_finish_invite` commits the pending invitation before sending its link. If Graph then fails, the row remains and the recipient has no link; resubmission replaces it and sends a new token. This is consistent with the documented no-queue/no-retry limit and the existing Stage 2b behavior.

OBSERVATION: The token-refresh lock is intentionally held across the token network request. Concurrent background sends can accumulate waiting worker threads for up to the token request's per-socket timeout (or longer under the documented slow-drip limitation), but only one refresh request is made. There is no bounded mail worker queue.

OBSERVATION: `Settings.graph_client_secret` is excluded from dataclass repr/str, but it still participates in generated equality and hashing. The frozen `Settings` hash therefore incorporates Python's process-local hash of the secret. This does not echo the secret and no reviewed code hashes `Settings`; the mailer cache uses SHA-256 of the four Graph values instead. `GraphMailer.__repr__` exposes only the configured sender UPN, not the client secret or token.

OBSERVATION: The `.env.example` value `change-me-graph-secret` satisfies syntactic validation. If an operator enables Graph without replacing it, startup succeeds and sends fail at token acquisition. The README tells the operator to replace every placeholder.

OBSERVATION: HLD section 12 and PRD Q1 say DKIM and DMARC are not configured/open. The supplied current state is newer: DMARC `p=none` was published on 2026-11-09 and DKIM CNAMEs were published while Microsoft signing provisioning remained pending. The documents need a factual update, but this DNS/provisioning state is not a defect of this stage.

OBSERVATION: Microsoft\u2019s v1.0 `sendMail` documentation confirms successful `POST /users/{id | userPrincipalName}/sendMail` returns only 202 Accepted, that 202 is queued rather than proof of delivery, and that `saveToSentItems=false` is supported. Thus the implementation\u2019s `status != 202` rule is correct.

## Process and diff review

- `git log --oneline 6cc90d6..HEAD` contains exactly five commits: `41913d6`, `0c199e0`, `50b4402`, `08e6749`, and `42c8ae6`.
- RED commit `41913d6` changes only five newly added test/support files.
- The only change to a test file present at `6cc90d6` is removal of the `("QO_MAIL", "graph", "not available in this stage")` row from `tests/test_stage2a_units.py::test_config_refuses`. This is justified because Graph is now supported, and the new config suite covers its valid and invalid configurations.
- No non-ASCII bytes were found in added diff lines. `git diff --check` passed.
- No dependency, schema, or migration file changed. No changed file is outside `quoteops/`, `tests/`, `deploy/`, `docs/`, and `README.md`.
- I read the complete `6cc90d6..HEAD` diff for `quoteops`, `deploy`, `docs`, and `README.md`, plus HLD sections 4, 9, 10, 11, 12, PRD Q1, and the README.

## Security and correctness review

- Failure strings are fixed phrases plus status. HTTP bodies are discarded on `HTTPError`; no response body, secret, token, recipient, or subject enters `MailError`. Network exceptions use `raise ... from None`; the stubbed HTTP-error exercise confirmed `MailError.__context__ is None`. The mailer has no logging. Reviewed auth/team/guard call sites log `type(exc).__name__` without `exc_info`; the outer guard consumes unhandled exceptions and also logs only the class.
- The token request body necessarily contains the client secret, but urllib/http.client debug logging is not enabled by this code. The secret remains in the web container environment, an accepted limit. It is absent from `Settings` repr and `GraphMailer` repr. The global cache key is a SHA-256 digest of the four Graph values.
- `ProxyHandler({})` prevents environment proxies. `build_opener` contains `_NoRedirect` rather than the default `HTTPRedirectHandler`, so redirects become `HTTPError` and are not followed. HTTPS verification uses urllib's default verified context. Default handlers for other schemes exist, but production URLs derive from module constants with fixed HTTPS schemes; tenant and sender cannot change the scheme/authority.
- Tenant and client IDs require full, unbraced GUIDs (upper/lower hex accepted). Sender is validated with the common email rule and percent-encoded with `safe=''`. Recipient is validated; recipient and subject reject CR/LF. Subject, recipient, and body are JSON encoded. Default `ensure_ascii=True` makes `.encode('ascii')` safe, including lone surrogates.
- The refresh uses `time.monotonic`; refresh is serialized; failed refreshes are not assigned to the cache. Tiny or negative finite lifetimes cause immediate refresh on the next send. `_drop` removes only the token that received 401, preserving a concurrently refreshed token. One 401 causes one resend with a fresh token; a second 401 fails. Other 4xx, 429, and 5xx do not retry. Token response reads are capped at 65,536 bytes. Missing/wrong token fields and ordinary malformed JSON fail closed. The non-finite lifetime exception is the defect above.
- Sign-up, forgot-password, invitations, and member-exists notices run as background tasks and catch every exception by class name. The password-changed notice catches both `OSError` and `MailError`, so Graph failure does not change the success page, but it is synchronous as described above. No other `.send` call was found.
- File mode does not invoke `_graph_settings`, so it does not read Graph variables. Admin settings do not read or contain mail fields. Compose passes `QO_MAIL` and all four Graph settings only to `web`; `admin`, `migrate`, and `db` receive none. Empty Graph defaults are accepted only in file mode; graph mode fails startup naming the missing variable without its value.
- The mailer instance map is protected by a lock and keyed by the settings digest. Settings changes create another instance; old instances remain until process exit. Hot reload/process restart intentionally loses the in-memory token.

## Hand-mutation coverage

These are static mutation judgments; I did not edit the source.

| Mutation | Catching test, or gap |
|---|---|
| Follow redirects | `test_a_redirect_is_a_failure_and_is_not_followed`; `test_every_redirect_status_fails` |
| Put response body in `MailError` | `test_errors_and_logs_hold_no_body_secret_token_recipient_or_subject` |
| Log the response body | `test_errors_and_logs_hold_no_body_secret_token_recipient_or_subject`; app class-only tests |
| Put recipient in the error | `test_errors_and_logs_hold_no_body_secret_token_recipient_or_subject` |
| Cache a failed token request | `test_a_failed_token_request_is_not_cached`; unusable-token parameter cases |
| Remove the refresh lock | `test_parallel_sends_fetch_one_token`; `test_parallel_sends_after_expiry_refresh_once` |
| Retry 5xx | `test_other_statuses_fail_without_a_retry`; token-endpoint failure test |
| Retry 401 twice | `test_a_second_401_is_a_failure_without_a_third_try` |
| Set `saveToSentItems` true | `test_send_request_is_exact` |
| Drop CR/LF refusal | `test_line_breaks_are_refused_before_any_network_call` |
| Make the production token constant HTTP | `test_default_urls_are_https_and_exact` |
| Put the secret in repr | `test_the_mailer_repr_holds_no_secret`; config `test_the_secret_is_in_no_repr_or_str_of_the_settings` |
| Make `load_admin_settings` read Graph variables | config `test_admin_settings_read_no_mail_setting`; app admin-start test |
| Give admin Graph variables in Compose | `test_compose_other_services_have_no_graph_or_mail_variable` |
| Use display address instead of mailbox UPN | No executable test can distinguish two syntactically valid addresses. HLD states the required real UPN, while mailer path tests use a test UPN. This remains deployment/configuration evidence. |
| Revert `_send` to catch only `OSError` | `test_a_failing_changed_notice_does_not_break_the_password_reset` |
| Own: accept 200/204 as send success | `test_only_202_is_success` |
| Own: stop percent-encoding the sender | `test_sender_is_percent_encoded_completely`; exact-send test |
| Own: omit client secret from the instance cache key | `test_mailer_returns_one_graph_mailer_per_process_and_settings` explicitly varies the secret |
| Own: read/validate Graph variables in file mode | `test_file_is_the_default_and_reads_no_graph_value`; `test_file_mode_ignores_even_invalid_graph_values` |
| Own: accept `NaN`/`Infinity` token lifetime | No test; dynamically reproduced and reported as a defect |

## Executed checks

- `python3 -m compileall -q quoteops tests`: passed. (`python` is absent; Python 3.12 is available.)
- `python3 -m pytest ...`: could not run because pytest is not installed. FastAPI and psycopg are also not installed, so the application suites could not be imported.
- Local `http.server` exercise on `127.0.0.1`: attempted, but this sandbox denied socket creation with `PermissionError: Operation not permitted`.
- Stubbed-opener stdlib exercise of the real `quoteops/mail.py`: passed for exact HTTPS URL construction, full sender quoting, ASCII JSON, `saveToSentItems=false`, one 401 refresh/retry, fixed 500 error text, suppressed exception context, and opener handler composition. It also reproduced the NaN lifetime defect.
- Standalone config helper exercise with dependency stubs: passed for canonical and uppercase GUIDs; rejected braces, whitespace, missing hyphens, overlong secrets, spaces, and control characters; accepted exactly 256 secret characters; error text did not repeat the tested invalid secret.
- Static grep/AST-equivalent review covered all `.send`/`_send` call sites, logging calls, admin settings, and Compose variable placement.
- I did not contact Microsoft. The only external lookup was Microsoft Learn documentation for the `sendMail` response contract. I relied on the supplied orchestrator evidence for its 1,159-test run, 139 new-test comparison, PostgreSQL/uvicorn fake-server run, and separate real-mail proof; I do not claim to have rerun them.

## Not checked

- PostgreSQL-backed tests and all 1,159 repository tests: PostgreSQL is unavailable, Docker is denied, and pytest/application dependencies are absent.
- The 139-test totals supplied by the orchestrator were not independently reproduced.
- Any real Microsoft token or mail endpoint, tenant/app/access-policy state, mailbox display behavior, secret expiry, or delivery/bounce/spam behavior.
- Live DNS, DKIM signing activation, DMARC behavior, and the production server/container environment.
- Total wall-clock timeout under a slow-drip server beyond the documented per-socket timeout.
- Runtime behavior under actual uvicorn/Starlette thread-pool saturation or process reload.
