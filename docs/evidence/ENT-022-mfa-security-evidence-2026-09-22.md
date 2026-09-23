# ENT-022 MFA and privileged-action security evidence

This record covers PR #58 at `372b746b61b6a9482e02db9960080ab06288df66`
plus the single test-fixture change in
`backend/tests/test_mfa_credential_purpose.py` and these ENT-022 evidence files.
The proposed source tree is bound by SHA-256 of sorted UTF-8 records
`<Git mode> <Git blob> <path>\n`, excluding `docs/evidence/ENT-022-*` to avoid
self-reference: `2714f57394709edf19b4cfd8a61ad0ef810edfe3ee3b341c7aa074f3ebd41096`.
The fixture blob is `ba518001792b9e6c56ad5fe56fc06e8fdb516a1a`.
Recompute the binding after the final commit. The evidence directory is scanned
separately.

## Test environment and provenance

- Windows host with the existing `backend/.venv` Python test dependencies and
  Docker Desktop services. Tests used disposable PostgreSQL 17 database
  `authclaw_test` and test-created `*_test` databases; test-role setup used the
  same container's disposable `authclaw_test_anchor`. Redis 7.4.11 used the
  isolated test port.
- The fixture-only edit was present for the full backend MFA selection and the
  broad PostgreSQL selection. Other runtime selections ran on a clean archive
  of `372b746`; the fixture edit does not alter application or agent behavior.
- The first clean-HEAD MFA run exposed two missing-mock-field failures:
  `166 passed, 2 failed`, exit 1. With `tenant_status="active"` in the mock,
  the complete selection passed. No application logic was changed.
- T01 activation verifier passed on 2026-09-23 with `status: active`, merge
  commit `1e40bdb5c8fd6b4e28c827035ab7d06645530ccb`, effective
  `2026-09-16T12:57:25Z`.

## Fresh results

| Security contract and selection | Result | Exit |
| --- | --- | ---: |
| Backend MFA abuse, replay, credential purpose and authorization: `test_auth_baseline.py test_mfa_replay.py test_ent022_mfa_security.py test_mfa_credential_purpose.py test_authorization_matrix.py` | 168 passed | 0 |
| PostgreSQL tenant isolation, T10 including suspension, MFA recovery, audit metrics and concurrent auditor OTP: `test_tenant_isolation.py test_t10_postgres.py test_mfa_recovery_postgres.py test_audit_metrics.py test_review_otp_postgres.py` | 58 passed, 1 opt-in synthetic measurement skipped | 0 |
| Clean-HEAD focused PostgreSQL suspension, replay, recovery, concurrent OTP and audit selection | 21 passed, 25 deselected | 0 |
| Clean-HEAD gateway approval authorization, concurrency and immutable audit: `test_phase10.py` | 10 passed | 0 |
| Clean-HEAD agent control-plane authorization, execution authorization and privileged policy tests | 60 passed, 57 subtests passed | 0 |
| Clean-HEAD agent signed approval, replay, RLS and audit with PostgreSQL/Redis | 9 passed | 0 |
| Clean-HEAD backend TOTP assertion through signed agent approval/execution in UTC, Los Angeles and Kolkata | 1 passed | 0 |
| Agent terminal-outcome audit artifact test | 1 passed, 4 subtests passed | 0 |

The backend selection checks TOTP replay prevention, recovery-code purpose,
interactive-session requirements and role checks. The PostgreSQL tests exercise
tenant suspension during an approval lock wait and restricted-role isolation.
The agent tests check assertion expiry and replay, operation/body binding,
role and tenant binding, provider outcomes, RLS and audit records. The
cross-runtime test verifies a real backend TOTP assertion followed by signed
agent approval and execution across three time zones.

The previous 2026-09-22 evidence recorded a broader exact agent CI selection
(265 passed, 174 subtests) and console signing tests (4 passed). Those selections
were not rerun during this regeneration; the fresh selections above are the
current local proof. CI and independent reviewer approval remain pending.

`ENT-022-privileged-audit-raw-2026-09-22.json` combines six generated audit
outputs. `ENT-022-privileged-audit-redacted-2026-09-22.json` masks identifiers,
request IDs, timestamps and integrity values while preserving actions and
outcomes. The command and artifact hashes are in
`ENT-022-privileged-audit-command-metadata-2026-09-22.json`.
Gitleaks scan commands, exit codes and zero-finding reports are in
`ENT-022-gitleaks-command-metadata-2026-09-22.json`.
