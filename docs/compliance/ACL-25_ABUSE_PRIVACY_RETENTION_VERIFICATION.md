# ACL-25 abuse, privacy request, and retention verification

## Scope

ACL-25 verifies that adversarial agent behavior and GDPR lifecycle operations are
tenant-scoped, authorized, observable, and evidence-producing. All abuse probes use
synthetic prompts and simulation mode is the safe default.

## Acceptance mapping

| Jira acceptance criterion | Implementation | Verification |
|---|---|---|
| Prompt injection, data disclosure, and tool-abuse cases are severity-ranked | The red-team catalogue contains explicit `PROMPT_INJECTION`, `DATA_DISCLOSURE`, and `TOOL_ABUSE` cases. Each case has a severity, numeric rank, and risk score. Results are ordered by severity rank. | `backend/tests/test_acl25_abuse_privacy_retention.py`; `backend/tests/test_red_team_service.py`; Risk UI contract test |
| Access, export, and deletion requests enforce authorization and scope | Data-subject endpoints require owner/admin roles and read/write scopes. Service lookups bind both request ID and authenticated tenant ID. Export and deletion require verified, approved requests. | `backend/tests/test_endpoints.py::test_data_subject_request_lifecycle_authorization_and_isolation`; ACL-25 focused tenant-binding test |
| Retention and deletion jobs produce verifiable results without cross-tenant impact | Expired redaction mappings are selected by tenant, deletion returns counts and an audit record ID, and canonical audit evidence records the tenant and deletion count without personal values. GDPR deletion reports deleted and retained categories and preserves tenant-scoped audit evidence. | `backend/tests/test_privacy_lifecycle.py`; ACL-25 focused retention test; data-subject lifecycle integration test |

## Security and evidence rules

1. Red-team simulation is the default; live mode requires explicit server-side enablement.
2. Raw observed model responses are graded in memory but are not copied into red-team
   result evidence. Only matched signal names, decision metadata, severity, and reason
   are retained.
3. Failed probes create tenant-scoped evidence and findings. Passing probes retain
   informational evidence without creating findings.
4. Cross-tenant privacy request identifiers return not found rather than exposing the
   existence of another tenant's request.
5. Export and deletion require an authenticated owner/admin with write scope, verified
   identity, and an approved request state.
6. Retention deletion records contain counts and control metadata, not deleted personal
   values.

## Telemetry

The red-team runner records:

- `red_team_runs_total`
- `red_team_probes_total`
- `red_team_probe_failures_total`
- category failure counters such as `red_team_tool_abuse_failures_total`
- severity failure counters such as `red_team_critical_failures_total`
- `red_team_run_failures_total` when persistence fails

Existing GDPR and retention telemetry records created, verified, approved, exported,
deleted, purged, and failed operations.

## Local verification results

- ACL-25 focused backend, red-team, privacy-lifecycle, access-request, and
  authorization-matrix tests: 70 passed.
- Destructive data-subject lifecycle integration test: 1 passed against the isolated
  `authclaw_acl25_integration_test` PostgreSQL database.
- Console unit and ACL-25 UI contract tests: 30 passed.
- Console lint: passed.
- Console production build: passed; 56 pages generated, including `/risk`.
- Docker console image production build: passed.
- Authenticated Risk-page smoke test: passed. Prompt injection, data disclosure, and
  tool-abuse categories rendered with severity labels; simulation-only mode and the
  safe-simulation action were enabled by default, and response inputs were empty.
- Git whitespace validation: passed.
- Wider backend regression run: 268 passed and 1 skipped. One existing ACL-18
  remediation/Kafka audit test failed; the failing application and test files are
  unchanged from `master` and are outside ACL-25 scope.

The destructive integration run used explicit owner and restricted application URLs
ending in `authclaw_acl25_integration_test`. It did not target the normal development
database.

## Verification commands

```powershell
cd backend
& .\.venv\Scripts\python.exe -m pytest -p no:cacheprovider `
  tests\test_acl25_abuse_privacy_retention.py `
  tests\test_red_team_service.py `
  tests\test_privacy_lifecycle.py `
  tests\test_access_requests.py `
  -q
```

The database-backed data-subject lifecycle integration test must run against an isolated
database whose name ends in `_test`:

```powershell
& .\.venv\Scripts\python.exe -m pytest -p no:cacheprovider `
  tests\test_endpoints.py::test_data_subject_request_lifecycle_authorization_and_isolation `
  -q
```

```powershell
cd console
npm.cmd run test:unit
npm.cmd run lint
npm.cmd run build
```

## Rollback

1. Revert the ACL-25 application commit.
2. Rebuild the backend and console images.
3. No database migration is introduced by ACL-25, so no schema downgrade is required.
4. Verify the prior red-team probe catalogue and existing privacy endpoints remain
   healthy.

## Evidence to attach to Jira

- Focused backend test output.
- Isolated-database data-subject lifecycle output.
- Console unit, lint, and production-build output.
- Screenshot of the Risk page showing prompt injection, data disclosure, and tool-abuse
  severity/risk ranking.
- Pull request, CI, reviewer approval, and controlled-beta smoke-test evidence.
