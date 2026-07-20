# ACL-18 remediation and human-approval evidence

| Metadata | Value |
|---|---|
| Owner | Vidhi Sharma |
| Collaborators | Kunal, Ravi |
| Jira issue | ACL-18 |
| Branch | `feat/agent/ACL-18-remediation-approval-controls` |
| Evidence date | 2026-07-20 |
| Status | Local implementation evidence; CI and authorized review pending |

## Acceptance mapping

| Acceptance criterion | Implementation evidence | Verification |
|---|---|---|
| Plan shows proposed changes, risk, and rollback | `generate_remediation_plan` and `normalize_remediation_plan` emit explicit review fields | `test_plan_exposes_change_risk_and_rollback` |
| Approval is bound to tenant, user, action hash, and expiry | `PendingApproval` stores tenant, approver, canonical SHA-256 action hash, and expiry | `test_action_hash_is_stable_and_detects_changes`, `test_approval_is_bound_to_tenant_user_and_workflow` |
| Expired, replayed, altered, and unapproved actions are rejected and audited | The runner evaluates and atomically consumes tenant-scoped approvals, records rejection reasons, and increments outcome metrics | `test_expired_replayed_altered_and_unapproved_actions_are_rejected` |

## Changed surfaces

- `backend/app/services/remediation_approval.py`: plan normalization, hash binding,
  and pure approval decision logic.
- `backend/app/orchestrator/runner.py`: tenant-scoped row locking, validation,
  one-time consumption, audit, and metrics.
- `backend/app/api/v1/endpoints/workflows.py`: tenant/action-bound approval queries,
  tamper check, approver binding, and response evidence.
- `backend/app/orchestrator/graph.py`: explicit proposed-change, risk, and rollback
  fields.
- `backend/app/db/models.py` and migration `027`: persisted action hash,
  consumption state, reason, and audit context.

## Audit events and telemetry

The approval audit records `APPROVED`, `REJECTED`, `EXPIRED`, `CONSUMED`, and rejected
execution outcomes such as `REPLAYED_REJECTED` and `ALTERED_REJECTED`.

Outcome counters use the prefix `remediation_approval_`, including:

- `remediation_approval_consumed_total`
- `remediation_approval_expired_total`
- `remediation_approval_replayed_rejected_total`
- `remediation_approval_altered_rejected_total`
- `remediation_approval_unapproved_rejected_total`

No raw remediation target contents or sensitive values are placed in these audit fields.

## Local verification

The following commands are the required local evidence commands:

```powershell
backend\.venv\Scripts\python.exe -m pytest backend/tests/test_acl18_remediation_approval.py -q
backend\.venv\Scripts\python.exe -m pytest backend/tests/test_orchestrator.py backend/tests/test_remediation_connector.py -q
backend\.venv\Scripts\python.exe -m pytest backend/tests/test_migration_027.py -q
backend\.venv\Scripts\python.exe -m py_compile backend/app/services/remediation_approval.py backend/app/orchestrator/runner.py backend/app/api/v1/endpoints/workflows.py
git diff --check
```

Observed local result:

- ACL-18 acceptance tests: `5 passed`
- Existing orchestrator and remediation regression tests: `7 passed`
- ACL-18 migration tests: `2 passed`
- Changed Python modules: compilation passed
- Whitespace validation: passed
- Database-backed workflow API tests: not run locally because the required isolated
  `TEST_OWNER_DATABASE_URL` and `DATABASE_URL` ending in `_test` were not configured.
  The repository safety gate correctly refused to run them against a non-test database.
- Ruff: not available in the repository virtual environment; CI remains authoritative
  for lint evidence.

CI results, database-backed test results, and authorized reviewer approval must be
attached manually before ACL-18 is moved to Done.
