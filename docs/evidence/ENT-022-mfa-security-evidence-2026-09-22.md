# ENT-022 MFA and privileged-action security evidence

This evidence covers PR #58's proposed final code and test tree. The binding is
the SHA-256 of sorted Git index mode/blob/path records, excluding only
`docs/evidence/ENT-022-*` to avoid a self-referential digest:
`252b321d1fcb15964bf024dff7757fc1c33cdf94acb39913118390e1fd8ccd50`.
The evidence files are scanned independently and the binding is recomputed after
the final commit.

## Supported test environment

- Linux containers on Docker Desktop
- PostgreSQL 16.10 in disposable database `authclaw_pr58_test`
- PostgreSQL owner, migrator, application, agent migrator, and restricted agent
  runtime roles created only for this disposable test database
- Redis 7.4.7 on the isolated test network
- Repository-locked Python dependencies
- No production or non-`*_test` database was addressed

## Results

| Security contract | Result |
| --- | --- |
| Backend MFA abuse, replay, credential-purpose, and authorization selection | 168 passed |
| Agent exact CI security selection | 265 passed; 174 subtests passed |
| Backend-to-agent real TOTP assertion, signed approval, execution, and audit | 1 passed |
| Concurrent PostgreSQL auditor OTP consumption and invalid-attempt accounting | 2 passed |
| PostgreSQL tenant isolation, migration, T10, MFA recovery, and privileged-audit selection | 55 passed; 1 opt-in synthetic measurement skipped |
| PostgreSQL gateway decision authorization, concurrency, and audit selection | 10 passed |
| Workflow response and focused MFA regression selection | 84 passed |
| Console current-role signing contract | 4 passed |
| Focused agent authorization/token/telemetry seams | 5 passed |

The agent suite validates approval assertion expiry, replay rejection, body and
operation binding, tenant and actor binding, role revocation, idempotency,
terminal outcomes, provider failure behavior, and restricted-role RLS. The
backend selection validates TOTP replay prevention, abuse limits, recovery-code
purpose separation, interactive-session requirements, role checks, and durable
audit behavior. It also proves that agent assertions bind the locked current
owner/admin role and that gateway approve/reject decisions reject low-role and
machine credentials. The cross-runtime test proves that a backend-verified TOTP
assertion completes signed agent approval and execution in UTC,
America/Los_Angeles, and Asia/Kolkata.

The raw generated audit artifact is
`ENT-022-privileged-audit-raw-2026-09-22.json`; its mechanically redacted view is
`ENT-022-privileged-audit-redacted-2026-09-22.json`. Command and artifact digest
metadata is in `ENT-022-privileged-audit-command-metadata-2026-09-22.json`.
