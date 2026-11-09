**Verdict:** fail

## Findings

### DEFECT (HIGH): authenticated slow uploads can hold every process slot indefinitely

Confirmed. `quoteops/uploads.py:29` defines only `READ_TIMEOUT_SECONDS = 30.0`. `receive_upload` at lines 425-453 puts `anyio.fail_after(READ_TIMEOUT_SECONDS)` around each individual `await receive()` (431-432), with no whole-request deadline or minimum transfer rate. Both process slots (`MAX_PARALLEL = 2`, line 27) are acquired before that loop at lines 257-269.

Exploit: two verified, active-company uploaders open valid multipart requests, send valid CSRF and begin the file, then send one byte less than 30 seconds apart. Each timeout resets; both slots remain occupied and every other company waits five seconds then gets 503. The supplied real-uvicorn observation (two eight-second drips alive after 56 seconds; company C refused until they ended) matches the code exactly.

Severity is HIGH: two ordinary tenant accounts can reliably deny uploads across companies indefinitely with negligible bandwidth, though this affects uploads rather than the whole app. The smallest correct fix is a monotonic total deadline around receive/parse, scaled to permit a maximum file at a conservative documented rate (or a minimum sustained-rate rule with a grace period), while retaining the per-read timeout. Add a test that continuously sends within 30 seconds yet reaches the total deadline, returns 408, removes temp state and releases slots. HLD section 13 lines 451-454 must state that bound; its accepted-limit statement at line 476 explicitly describing an indefinite hold must be removed/replaced.

No per-company or per-IP upload-attempt throttle exists; sign-up/login/reset/invite throttles do not cover this route. It is useful defense in depth but cannot replace a total deadline because two open requests require no new attempts.

### OBSERVATION: cancellation cleanup is not pinned

`quoteops/jobs.py:424-425` awaits `run_in_threadpool(stream.discard)` in an async `finally`. Timeout, disconnect, refusal and write failure are tested, but no test cancels the route task inside `receive_upload` and proves cleanup runs under AnyIO cancellation. I did not demonstrate a leaked temp file, so this is not a defect.

### OBSERVATION: no upload-attempt throttle test

No counter is consulted before `upload_slot`, and no stage 3a test pins an attempt throttle. Admission consists of authorization and the two in-memory slots.

## Process

`848cb17..0a7c935` contains exactly six commits: `a4facf7`, `c9d7151`, `18aa4f9`, `30f9432`, `d055d7d`, `0a7c935`. RED `a4facf7` adds only four test/support Python files and `tests/data/schema_848cb17.sql`, no production code. GREEN is `18aa4f9`; the last two commits add tests and correct refusal text as described.

The only pre-existing test changed is `tests/test_stage2a_flows.py` in `c9d7151`: one assertion replaces obsolete placeholder text with `href="/jobs"`. It follows the delivered navigation without weakening the surrounding assertions.

No changed path falls outside the allowed folders. No dependency file changed. `git diff --check` passed. Added diff lines contain no non-ASCII. The RED schema snapshot is test data, not production code.

## Implementation review

- Permission roles match the decision table and every job route uses `require`. Unknown actions fail closed. Session, role, verification, active company, Origin, target job, multipart type and slots precede body reads. CSRF must validate before a file descriptor opens; a second CSRF is rejected. `setdefault` preserves the first repeated ordinary field, so later fields cannot override it.
- Upload uses `request.receive`, not buffering form/body APIs. Headers plus fields share 16,384 bytes; parts cap at ten. File bytes stream to mode-0600 `O_EXCL|O_NOFOLLOW` temp files. Generated company ids (`c_` plus 32 hex) match the folder regex. App-created directories are checked with `lstat`.
- Content rules match the owner decisions: PNG signature+IHDR, JPEG signature, PDF marker anywhere in the first 1024 bytes, documented DXF rules, and `<script`/`<html` scan in the first 1024. Extensions are case-insensitive and the final suffix must agree. Truncated/signature polyglots are accurately documented accepted limits and downloads are never inline.
- Safe names are normalized, bounded and never storage paths. The ASCII fallback and percent-encoded `filename*` prevent header injection.
- The distinct per-company advisory lock is taken only after receipt and covers active recheck, quotas, counter/insert, drawing/audit rows and rename. PostgreSQL 16 is pinned, so three-argument `date_trunc` is supported. Exactly-at-cap is accepted. Failed transactions roll back `job_next`; uniqueness prevents collisions.
- Coded exits discard temp files; rename-before-commit cleanup exists. Delete intentionally may leave a logged orphan. Startup sweep does not follow symlinks.
- Downloads are tenant/RLS filtered, realpath-confined, `O_NOFOLLOW`, 64-KiB streamed and fd-closing. Cross-company/outside symlinks fail. Attachment, octet-stream, actual Content-Length, nosniff, no-store and sandbox CSP are present. The two CSP headers are cumulative and compatible, not a defect. Range/ETag/Last-Modified are not promised.
- Field, quantity, date, control and draft checks are present. Jinja autoescape is used; no job template uses `|safe`. Audit subjects contain ids/field names only.
- Schema has forced RLS, composite tenant FK, idempotent migration, no new SECURITY DEFINER function and no new admin right. `qo_web` company UPDATE is needed for `job_next`; job/drawing/audit grants are narrowed. `NOT VALID` checks still bind new/changed rows. Later company-file deletion is noted as deferred.
- Only web mounts `qofiles`; migrate/admin do not. Read-only roots and uid 10001 directory creation are correct; README warns about existing-volume ownership.
- Only exact `POST /jobs/upload` gets the larger streamed limit. Every other route retains 16 KiB. Declared and streamed sizes are bounded; early responses close the connection.

## Hand-mutation coverage

- Remove role check on upload/create/delete: `test_permission_table_for_every_role_on_every_route`, `test_every_job_route_uses_the_permission_dependency` (create also `test_a_create_refused_by_the_create_job_row_names_the_role_and_reads_no_body`).
- Remove company isolation on download: `test_company_b_gets_404_on_every_route_of_company_a_and_nothing_changes`.
- Remove extension/content agreement: `test_the_name_must_agree_with_the_content`.
- Size off-by-one either way: `test_a_file_of_exactly_the_limit_passes_and_one_byte_more_is_413`.
- Remove advisory lock: the parallel last-job and last-megabyte tests.
- Leave temp on failure: refused-file, disk-write, timeout and abort tests.
- Check CSRF after storage: `test_csrf_matrix_refuses_without_creating_a_temp_file`.
- Inline disposition / drop nosniff: `test_download_is_an_attachment_of_octet_stream_with_the_safety_headers`.
- Drop realpath: `test_a_stored_path_outside_the_company_folder_is_a_404_and_a_log_line`.
- Drop semaphore / company slot: third-upload-503 / one-upload-per-company tests.
- Apply route limit globally / lift 16 KiB: exact-route-table / every-other-route tests.
- Remove declared-length check: `test_a_declared_length_of_1_gb_is_refused_before_a_byte_is_read`.
- Drop `Connection: close`: asserted by declared/chunked/CSRF/origin/role refusal tests.
- Permit file before CSRF: CSRF matrix and form-order tests.
- Remove field budget / `MAX_PARTS`: `test_the_fields_beside_the_file_have_the_16_kb_budget`.
- Drop `O_NOFOLLOW`: no direct flag assertion; practical escape remains covered by symlink/path tests.
- Drop active recheck: `test_a_company_suspended_between_the_check_and_the_store_stores_nothing`.
- Drop final-file failed-commit cleanup: `test_a_commit_that_fails_after_the_rename_removes_the_final_file`.
- Drop startup sweep: `test_the_startup_sweep_removes_old_temp_files_only`.
- Drop draft-only delete: `test_a_job_that_is_not_a_draft_cannot_be_changed`.
- Audit customer text: create/upload and edit audit tests.

Additional mutations: no total deadline\u2014none (the defect); remove per-read timeout\u2014stalled-upload test; accept two files\u2014two-file test; trust client Content-Type\u2014type/content tests; store user filename on disk\u2014random-name/weird-name tests; remove composite FK\u2014cross-company-FK test; permit non-draft edit\u2014non-draft test; log customer/file/content\u2014log-redaction test.

## Checks run

- `python3 -m compileall -q quoteops tests`: passed.
- `python3 -m pytest -q`: could not run; `pytest` is absent. Imports also confirmed `fastapi`, `psycopg`, and `python_multipart` are absent. I do not claim the orchestrator's 1,456 tests as my run.
- With minimal in-memory import stubs only, stdlib exercises of `Sniffer`/`detect`, `safe_name`, `content_disposition`, `boundary_of`, `tmp_dir`, `resolve`, outside symlinks and `sweep_tmp` passed. They covered PDF marker at byte 500, script-bearing JPEG refusal, PNG/DXF, control/path cleanup, boundary variants, confinement and old-temp removal.
- Stdlib AST parsed all `quoteops/*.py`. `jobs.py` request attributes are only `headers`, `query_params`, and `receive`, confirming no buffering request API there.
- I read the full production/deployment/docs diff and statically inspected relevant tests.

## Not checked

- Pytest, PostgreSQL migration/RLS/privileges, Docker/compose, uvicorn, browser, Cloudflare, disk-full and real cancellation behavior were not run here.
- Supplied orchestrator live/test evidence was not rerun; only the slow-upload source cause was independently confirmed.
- No environment file, `~/.config`, or secret was read.
