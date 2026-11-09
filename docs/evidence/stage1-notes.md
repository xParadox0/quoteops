# Stage 1 review record

Date: 2026-11-08. Branch stage1, reviewed head 216b02b.

- Independent verifier (Sol, static only: no PostgreSQL, no Docker in its sandbox) pass 1 on 2fe2edf: fail, one low defect (/healthz returned the exception class name). Its file was overwritten by the pass 2 clone and is not kept here; the defect and the test gaps are described in the commit messages of 536508c and 65ba1c8.
- Pass 2 on 216b02b: pass. File: stage1-verdict-pass2.md, copied unchanged. sha256 fb87bc307efec5317f1ceb80f5710be3277effe51cf1995aa7f9ec90d7c2dca0
- Runtime evidence for the database tests comes from the orchestrator replays on fresh clones (106 passed), not from the verifier.
- Known and accepted: login lookup returns one account's hash to the web role; the web role can create a session for any user (web tier proves the password; admin second factor in stage 2); the migration login is a superuser.
- Not covered: non-superuser migration login, PostgreSQL versions other than 16, compose stack run end to end, privilege matrices for qo_web and qo_definer beyond the existing tests.
