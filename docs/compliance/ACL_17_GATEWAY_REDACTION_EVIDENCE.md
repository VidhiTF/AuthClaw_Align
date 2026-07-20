# ACL-17 gateway policy and redaction evidence

| Metadata | Value |
|---|---|
| Owner | Vidhi Sharma |
| Collaborator | Kunal |
| Jira issue | ACL-17 |
| Branch | `feat/gateway/ACL-17-policy-redaction` |
| Evidence date | 2026-07-17 |
| Status | Local implementation evidence; CI and reviewer approval pending |

## Scope

ACL-17 prevents or transforms sensitive data at the gateway before a request is sent
to a model provider. This evidence covers tenant-configurable block, warn, redact and
approval behavior, fail-closed processing, safe telemetry, and approved PII/PHI test
fixtures.

## Acceptance evidence

| Requirement | Implementation and evidence |
|---|---|
| Detect approved PII/PHI fixtures | `gateway/acl17_policy_redaction_test.go` covers email, US SSN, health data and person-name fixtures. |
| Tenant-configurable block, warn and redact | `gateway/policy.go` validates all three actions; `gateway/proxy.go` applies them before provider egress. |
| Block prevents provider egress | Matching block rules return HTTP 403 before request proxying. |
| Warn is observable and safe | Warning headers, notification, audit event and counter are emitted; matching content is redacted before continuing. |
| Redact transforms provider payload | Tests rebuild an OpenAI request and verify the raw fixture is absent and a token is present. |
| Fail closed | Normalization, warning evaluation, redaction and payload-rebuild failures stop the request. |
| No raw sensitive data in normal logs or audit | Audit traces store entity/action plus a SHA-256 fingerprint; debug logging records only identifiers and counts. |
| Telemetry | Block, warn, redact and fail-closed counters are exposed through gateway metrics. |

## Changed files

- `gateway/policy.go`
- `gateway/proxy.go`
- `gateway/kafka.go`
- `gateway/acl17_policy_redaction_test.go`
- `gateway/README.md`
- `docs/adr/0008-acl-17-gateway-policy-redaction.md`

## Verification record

The following local checks were completed:

```text
go test -run "^$" ./...
Result: PASS (gateway packages compile)

go test -run "^TestACL17" ./...
Result: PASS

go test -count=1 -run
  "^(TestACL17|TestExtractAndNormalize|TestValidatePolicyYAML|
  TestProviderRouteValidation|TestApplyProviderCredentialHeaders|
  TestNormalizeDetectedEntity|TestFallbackAnalyzeUsesCustomNERRecognizers|
  TestPresidioAnalyzeRequestIncludesCustomNERRecognizers|
  TestHashStrategyIsTenantSalted)" ./...
Result: PASS (uncached focused regression run)

go vet ./...
Result: PASS

backend\.venv\Scripts\python.exe -m pytest
  tests/test_auth_baseline.py tests/test_migration_026.py -q
Result: 28 passed

npm.cmd run test:unit
Result: 12 passed
```

The full gateway integration suite additionally requires PostgreSQL with the gateway
test role, Redis, OPA and the configured analyzer services. A local run reached those
external boundaries but could not provide a green full-suite result because Redis and
OPA were not running and the application database role was not configured. This is an
environment limitation, not recorded as passing evidence.

GitHub-hosted CI confirmation is pending because the organization Actions allowance is
currently exhausted. Reviewer approval and a successful CI run remain release gates.

## Rollback evidence

Rollback is performed by reverting the ACL-17 implementation commit on its integration
branch, then rerunning the focused policy/redaction tests. Audit and metric output must
be reviewed after rollback; raw-prompt debug logging must remain disabled.
