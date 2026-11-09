**Verdict:** fail

## Findings

### OBSERVATION: process checks passed

`git log --oneline 0a7c935..HEAD` contains the expected pass-1 evidence commit, the rate-rule test/code/docs sequence, and the cooldown/four-slot test/code/docs sequence through `709f88f`. The two explicitly RED commits are test-only: `b15292e` changes only two test files and `9207f99` adds only `tests/test_stage3a_cooldown.py`.

Every change to a pre-existing test/support file since `0a7c935` was reviewed:

- `tests/stage3a_support.py`: clears process-global cooldown state in the per-test fixture. Legitimate isolation; it does not weaken an assertion.
- `tests/test_stage3a_schema.py`: adds an HLD wording test; its needle was later changed from `per-company or per-IP throttle` to `per-IP throttle` to match the new per-company cooldown. Legitimate correction, not a weakened product assertion. The negative assertions remove stale indefinite/two-slot claims.
- `tests/test_stage3a_upload.py`: adds rate tests, and changes the old slot test from two acquired slots/"third upload" to `MAX_PARALLEL` (four)/"upload beyond the slots". Legitimate adaptation that retains the same saturation, 503, wait, and Retry-After assertions; no assertion was weakened.

No non-ASCII was added (`git diff` byte scan), `git diff --check` is clean, no dependency or schema file changed, and no changed path falls outside `quoteops/`, `tests/`, `deploy/`, `docs/`, `README.md`, or `Dockerfile` (in fact the changes are limited to `quoteops/`, `tests/`, and `docs/`).

The evidence files committed by `1107918` are byte-for-byte unchanged afterward; the analogous evidence files at base/evidence commit `848cb17` are also unchanged afterward. The commit-message hashes are documented as hashes of the original verifier text, while the committed copies replace non-ASCII with `\\uXXXX`; therefore their committed-file SHA-256 values differ (`cce62e...` for stage 3a pass 1 and `6ad11e...` for stage 2b3), consistently with `docs/evidence/stage3a-notes.md`. I did not possess the original unescaped files and therefore could not independently reproduce the commit-message hashes.

### DEFECT (MEDIUM): HLD understates the per-connection bound and the sustained-rate attack

The pass-1 indefinite-connection defect is fixed: total request bytes are capped and, after 10 seconds, cumulative request bytes must cover 65,536 bytes/s. However, HLD section 13 says a minimum-rate client holds a slot "at most" file-size/rate plus grace (about 400 seconds). The check runs only after a message. A client may send `X` bytes quickly and then send one byte just under every 30-second per-read deadline; it is cut at the first such message after `10 + X/65536`, up to almost another 30 seconds later. For a 25 MiB burst the credit boundary is 410 seconds and 29-second messages cut at 435 seconds; including the guard's up-to-64-KiB multipart allowance, the code's worst-case bound approaches 441 seconds. A 25 MiB burst followed by complete silence is instead cut by the per-read timeout about 30 seconds after the burst.

The HLD's named "residual limit" then discusses only below-rate attackers being active about 12 seconds per 72 seconds and says four accounts can cause 503 only "part of the time." Four verified companies can instead each send at or just above the allowed minimum, occupy all four slots for roughly 410 seconds (or use burst-and-29-second-drip timing for roughly 435 seconds), finish with invalid content so no storage quota is consumed and no cooldown starts, and repeat. Other companies then repeatedly receive 503 apart from handoff gaps. With `N` attacker companies, up to `min(N, 4)` slots can be held this way; four suffice to saturate the process. This behavior is allowed by design, but the HLD's claimed bound and residual-risk characterization are not truthful to the code and exploitable behavior.

### DEFECT (LOW): README still documents two upload slots

README's stage-3a section says at most two uploads run and a third is busy. Code and HLD now use four, with the fifth being the first process-slot refusal. This is stale operator/user documentation.

### OBSERVATION: cooldown implementation otherwise matches the decision

- Authorization/active-and-verified-company dependency, Origin, target job/status and multipart type precede `cooldown_left`; cooldown precedes `upload_slot`. Thus viewer/accountant, bad-Origin, unverified/suspended, and missing/closed-job refusals retain precedence. Only owner/estimator can reach receipt; one legitimate editor can pause their entire company, as HLD documents. The key is the authenticated company id, so company A cannot pause company B.
- The `except TimeoutError` syntactically covers only `await receive_upload`. Within that call, possible sources are `MultipartParser(...)`, `anyio.fail_after`/`await receive`, mapping/body operations, `parser.write` and its callbacks (including file open/write/hash/sniffer work), and `_now`/arithmetic. The intended sources are the per-read fail-after and explicit rate exception, but an ASGI `receive` or file/parser callback raising built-in `TimeoutError` (also an `OSError`) would be caught first and pause an honest company. I did not demonstrate such a production path.
- Timeout handling calls `stream.discard` before `start_cooldown`, then the outer `finally` discards again. If `discard` itself raises (notably `os.close`; unlink errors are caught), cooldown is skipped and the exception becomes a 500. This is not remotely demonstrated/exploitable here, but the order is not pinned by a test.
- `_companies_lock` is acquired only for short synchronous set/dict/clock operations. `_claim`, `_release`, `start_cooldown`, and `cooldown_left` do not nest acquisition or hold it across an await/file operation. `stream.discard` runs in a worker and takes no such lock. A very brief event-loop block is possible if another caller holds the lock, but there is no lock cycle.
- Ended cooldown entries are purged on every nonempty `cooldown_left` call. An ended entry for a company that never uploads again remains until any company checks; only an active verified editor can create one, so cardinality is bounded by the verified-company cap (20, with multiple users sharing ids), not by unverified signups. `start_cooldown` replaces the company's end time using `_now` under the lock. `math.ceil(left)`, the numeric `Retry-After`, and the explanatory 429 text match the decision.
- Four uploads stream independently. Per-upload in-memory state is bounded (multipart message, 16-KiB fields/headers, 1-KiB sniffer head and tiny decoder/tail state); no 25-MiB body copy was found. Disk exposure is four temporary files up to 25 MiB each by default (about 100 MiB), followed by existing company quota enforcement. The supplied 70-71-MiB single-upload RSS evidence was not rerun and does not itself measure four concurrent uploads.

### OBSERVATION: new tests have limited real-time timing exposure

Most rate/cooldown tests patch `uploads._now`. Real-time tests/margins are: maximum upload must finish under 20 seconds; rate drip must cut under 3 seconds with 0.3-second grace; four-slot setup polls up to 10 seconds, worker gates wait 15 seconds and joins 20 seconds; real cooldown sleeps until 1.05 seconds after cut; older slot/timeout assertions use 0.3-second configured waits with multi-second upper bounds. These are generous except the usual scheduling sensitivity of wall-clock tests; no likely loaded-machine flake was demonstrated.

HLD constants, cooldown ordering/scope, per-process/restart/multi-worker limits, 20-company cap, absence of per-IP throttle because the Cloudflare client-IP header is not configured, and the 60-second honest-user pause match code. The two stale/misleading items above do not. PRD contains no stale slot count. Grep also found historical "indefinitely"/two-slot wording only in immutable pass-1 evidence, which is appropriate.

### OBSERVATION: hand-mutation coverage has one ordering gap

Static mapping (mutants were not written to the worktree):

- Remove rate check: `test_one_byte_per_five_seconds_is_cut_after_the_grace_period`, `test_a_client_one_byte_below_the_minimum_rate_is_cut`, and the real-time drip test.
- Ignore grace: `test_before_the_grace_period_ends_even_one_byte_in_total_is_not_cut`.
- Change `<` to `<=`: `test_a_client_at_exactly_the_minimum_rate_is_not_cut`.
- Reset the clock start on every message: the one-byte-per-five-seconds and real-time drip tests (the elapsed window never grows enough, so they fail).
- Count file bytes only: `test_a_client_at_exactly_the_minimum_rate_is_not_cut` constructs total request bytes exactly on the boundary, so omitting multipart bytes cuts it.
- Swallow `TimeoutError`: stall/rate tests expecting 408, cleanup, and cooldown fail.
- Skip discard on timeout: `test_one_byte_per_five_seconds_is_cut_after_the_grace_period`, the stall cooldown test, and `cut_slow` callers assert no temp file.
- Never start cooldown: `test_after_a_too_slow_cut_the_next_upload_of_the_company_is_429_without_a_slot` and the per-read-stall test.
- Start cooldown on every refusal: parametrized `test_no_other_refusal_starts_a_cooldown`.
- Use one cooldown for all companies: `test_the_cooldown_belongs_to_the_whole_company_and_to_no_other`.
- Never check cooldown: the first cooldown test expects 429, zero reads and zero slot use.
- Check after `upload_slot`: the same helper deliberately holds every process slot yet requires immediate 429.
- Check before role: `test_session_role_origin_and_job_checks_still_come_first` (viewer must get 403, not 429).
- Ignore expiry: `test_after_the_cooldown_the_company_can_upload_again` and the exact-end test.
- Do not purge: `test_the_dict_is_purged_of_expired_entries_by_any_call` and the 200-company bound test.
- Omit `Retry-After`: every `refused(...)` cooldown assertion.
- Restore `MAX_PARALLEL = 2`: both constant tests and both four-slot saturation tests.
- Start cooldown before discard: **none** observes call order; existing tests observe only both eventual effects.

Six additional mutations:

- Round `Retry-After` down: `test_a_cooldown_of_a_fraction_of_a_second_is_announced_as_one_second`.
- Key cooldown by user rather than company: `test_the_cooldown_belongs_to_the_whole_company_and_to_no_other` (owner cut, estimator retry).
- Omit cooldown for per-read stalls but retain it for rate cuts: `test_after_a_per_read_stall_the_cooldown_starts_too`.
- Purge only the queried company rather than all ended companies: `test_the_dict_is_purged_of_expired_entries_by_any_call` queries `c_z` and requires expired `c_a`/`c_b` removal.
- Read a body byte before checking cooldown: `refused(...)` asserts `out.receives == 0` and `out.sent == 0`.
- Release only the company slot, not the process semaphore, after a rate timeout: the rate tests call `_slots_free`, and cooldown tests assert semaphore value equals `MAX_PARALLEL`.

### OBSERVATION: runnable static and stdlib checks passed

- `python3 -m compileall -q quoteops tests`: passed.
- A stdlib-only import exercise used minimal stubs for `anyio`, `python_multipart`, and `quoteops.guard`, patched `uploads._now`, and exercised `start_cooldown`/`cooldown_left`: passed (60, 0.75 and zero seconds remaining; cross-company expiry purge also passed).
- A standalone simulation of the exact rate predicate passed cases for one byte per second (cut at the 11-second message), exactly 65,536 B/s (passed through 60 seconds), one byte below, a 25-MiB burst then silence, and burst plus one-byte messages every 29 seconds. It calculated 410 seconds for the 25-MiB credit boundary, a cut at the next 29-second message (435 seconds), and up to about 411 seconds of credit / almost 441 seconds elapsed when the 64-KiB request-overhead allowance is included.
- Python AST and `symtable` checks parsed `quoteops/jobs.py`, found no referenced-but-undefined global names, and confirmed `math` is imported.
- `pytest`, `fastapi`, `psycopg`, and `python_multipart` are absent. I therefore did not run pytest or import the real application. I do not claim the orchestrator's 1,488 tests or live results as my runs.

Not checked

- PostgreSQL/schema/RLS behavior, Docker/compose, uvicorn/live HTTP, filesystem pressure, four-upload RSS, browser behavior, Cloudflare, real network timing, and cancellation behavior were not run in this sandbox.
- The supplied orchestrator test and live evidence was considered as supplied but not independently rerun.
- I did not read any environment file, anything under `~/.config`, or any secret.
