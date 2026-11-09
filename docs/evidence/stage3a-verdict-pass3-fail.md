**Verdict:** fail

DEFECT (low): HLD section 13 gives the wrong burst-and-drip bound without the multipart allowance. From the source constants, the general bound is `X/65536 + 10 + 30` seconds. For a 25 MiB file, it is 440 seconds without `guard.UPLOAD_OVERHEAD`, and 441 seconds with the 64 KiB allowance. The HLD instead says "about 435 seconds without the allowance." The allowance accounts for exactly one second at the minimum rate, not six seconds. This also makes that sentence internally inconsistent with its correct 441-second value. The new pinning test asserts 441 and the formula but does not assert the without-allowance value, so this false number passes it.

OBSERVATION: Process/delta checks matched the disclosed scope.

- `git log --oneline a80c06f..HEAD` shows `70e366a`, `de5682e`, `339b83a`, and `81dc164`. The RED commit `70e366a` adds only `tests/test_stage3a_docs.py`.
- `git diff a80c06f..HEAD --stat` names only README.md, docs/HLD.md, tests/test_stage3a_docs.py, tests/test_stage3a_cooldown.py, and tests/test_stage3a_schema.py.
- Command and complete output for the product/deployment check:

  ```text
  $ git diff a80c06f..HEAD -- quoteops deploy Dockerfile
  ```

  It produced no output.
- The only pre-existing-test edits are documentation needles. In `test_stage3a_schema.py`, `about 400 seconds` becomes `burst-and-drip bound`. In `test_stage3a_cooldown.py`, `with four or more accounts used in turn` and `part of the time` become `a below-rate account is cut after about 12 seconds`. They follow the rewritten HLD and do not weaken an assertion about product behavior.
- As disclosed, `de5682e` and `339b83a` remain red until `81dc164`: their HLD and README blobs still contain the old residual-limit and two-slot text. Those intermediate revisions are not valid release points, but this test-first/documentation sequence does not itself invalidate a fast-forward to the endpoint.
- No added diff line contains a non-ASCII character. `git diff --check a80c06f..HEAD` produced no output.

OBSERVATION: The rest of the rewritten documentation agrees with the inspected code. `uploads.py` defines four process slots, a five-second slot wait, 30-second read timeout, ten-second grace, 65,536-byte/s minimum, and 60-second cooldown; `guard.py` defines a 64 KiB upload allowance. The default 25 MiB limit gives 400 seconds of file bytes, 401 seconds for a full allowed body at a steady 64 KiB/s, 440 seconds for the burst-and-drip formula without allowance, and 441 seconds with it. Thus "about 400" for a steady 25 MiB file and 441 for the maximum allowed body are correct; only 435 is not. The roughly 410-to-441 attack range is consistent with using the ten-second grace before minimum-rate transmission and the maximum burst-and-drip behavior.

OBSERVATION: Section 13 now truthfully states that four verified companies can occupy all four slots almost continuously; the cooldown does not stop at-or-above-rate clients; an invalid final file can consume no quota; nothing is stored and no data is exposed; the attack is bounded by 20 verified companies, real accounts, and bandwidth; and the listed per-IP throttle, per-company attempt limit, cut/503 log line, shorter total deadline, and higher minimum rate are not built and are owner decisions. Searches of the HLD, PRD, README, and relevant uploads/jobs comments found no remaining old "part of the time," "many accounts," two-slot, "indefinitely," "at most about 400," or operator-visibility claim. The README's Stage 3a numbers, including four slots, the fifth request, and five-second wait, match the code.

OBSERVATION: The documentation tests pin the principal corrected claims with specific, non-vacuous text in HLD section 13 and the README. The bound test imports and reads `RATE_GRACE_SECONDS`, `MIN_BYTES_PER_SECOND`, `READ_TIMEOUT_SECONDS`, and `UPLOAD_OVERHEAD`, although it hard-codes the default 25 MiB size. Each requested hand mutation has a failing pin: restoring either obsolete bound phrase hits a negative assertion; changing any of the three rate constants hits explicit constant/formula/bound assertions; restoring the README two-slot sentence fails its positive and negative checks; deleting the cooldown sentence fails its exact assertion; deleting the not-built list fails its required needles; changing 441 to 400 fails the bound needle/computed interpolation; and restoring "part of the time" fails a negative assertion. No test pins the erroneous 435 figure.

OBSERVATION: `python3 -m compileall -q quoteops tests` completed successfully. A stdlib AST exercise read the constants directly from `quoteops/uploads.py` and `quoteops/guard.py`, computed 441.0 with the allowance and 440.0 without it, computed 401.0/400.0 for steady transfer with/without allowance, and found the expected HLD/README strings. Its first version failed before producing bounds because its deliberately small expression evaluator did not initially handle `64 * 1024`; the corrected stdlib exercise completed as reported. Pytest is unavailable (`No module named pytest`), so no pytest suite or test was run.

Not checked

- PostgreSQL-backed behavior, because PostgreSQL is unavailable.
- Docker/compose behavior, because Docker is denied.
- Runtime pytest results, because pytest and project Python dependencies are unavailable.
- Real socket timing, uvicorn, browser, Cloudflare, and multi-process behavior; this pass inspected the requested documentation delta and source constants rather than rerunning the accepted pass-2 code review.
