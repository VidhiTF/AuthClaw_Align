# ADR-0007: ACL-15 GDPR data lifecycle controls

| Metadata | Value |
|---|---|
| Status | Proposed |
| Owner | Vidhi Sharma |
| Collaborator | Kunal |
| Jira issue | ACL-15 |
| Branch | `feat/privacy/ACL-15-gdpr-data-lifecycle` |
| Date | 2026-07-17 |

## Context

AuthClaw processes tenant-scoped personal data through identity, gateway,
agent, approval, audit and document-processing flows.

The repository already provides tenant-scoped redaction mappings, configurable
token retention, expiration metadata and expired-token purge operations.
However, deletion is implemented in separate backend and gateway paths, and
durable non-sensitive deletion evidence is incomplete.

ACL-15 must make P0 personal-data processing visible, minimized, governed by
explicit retention rules and supported by auditable deletion.

This ADR defines an engineering control. Organizational lawful basis, legal
holds, processor agreements and final retention periods require authorized
organizational review.

## Decision

### 1. Data inventory

`docs/compliance/GDPR_DATA_INVENTORY.md` is the engineering inventory for P0
personal-data flows.

Each flow records:

- Personal-data classes.
- Technical purpose.
- Source.
- Storage and processing components.
- Recipient or processor.
- Tenant-isolation boundary.
- Current retention and deletion behaviour.
- Open organizational decisions.

### 2. Data minimization

Operational logs and audit evidence must contain metadata instead of raw
personal values.

Permitted metadata includes:

- Tenant and request identifiers.
- Data class or entity type.
- Operation and outcome.
- Number of affected records.
- Policy or retention version.
- Timestamp and duration.
- Non-sensitive error category.

Raw prompts, responses, credentials, token mappings and detected personal
values must not be logged by default.

### 3. Tenant-aware retention

Retention evaluation must use the authenticated tenant context.

Redaction mappings continue to use the configured
`redaction_token_retention_days` value:

- Minimum: 1 day.
- Default: 90 days.
- Maximum: 3650 days.

A tenant operation must never read, expire or delete another tenant's records.

### 4. Deletion service

Backend retention and deletion behaviour will be centralized in a testable
privacy-lifecycle service.

The service will:

1. Accept the authenticated tenant identifier and request identifier.
2. Select only expired records belonging to that tenant.
3. Delete the expired personal-data records.
4. Record non-sensitive deletion evidence.
5. Return the affected-record count and operation status.

The existing admin endpoint will call this service instead of implementing
deletion directly.

### 5. Audit evidence

Deletion evidence will use AuthClaw's existing audit infrastructure rather than
creating a separate audit system.

Deletion evidence must record:

- Tenant identifier.
- Request or correlation identifier.
- Action such as `privacy:purge_expired`.
- Data class.
- Number of deleted records.
- Success or failure.
- Timestamp and duration.

It must not contain the deleted values.

### 6. Authorization and isolation

Manual deletion requires administrative scope.

The tenant identifier in the authenticated request context must match the
tenant identifier in the requested operation. A mismatch returns HTTP 403.

Database operations continue to use tenant-scoped sessions and row-level
isolation controls.

### 7. Idempotency and failure handling

Deletion is idempotent. Running an expired-data purge more than once is safe;
subsequent successful runs may return zero deleted records.

A failed deletion must:

- Roll back the database transaction.
- Produce a non-sensitive failure signal.
- Avoid reporting success.
- Remain safe to retry.

### 8. Telemetry

Retention operations will expose non-sensitive operational signals for:

- Records deleted.
- Successful operations.
- Failed operations.
- Operation duration.

Personal values, prompts, credentials and decrypted mappings must never be used
as metric labels or log fields.

## Alternatives considered

### Keep deletion inside API endpoints

Rejected because it duplicates lifecycle logic and is harder to test, reuse and
audit consistently.

### Soft-delete the encrypted personal value

Rejected for expired redaction mappings because retaining the encrypted
personal value after expiry does not satisfy the intended purge behaviour.

### Create a separate privacy audit database

Rejected for ACL-15 because AuthClaw already has tenant-aware audit
infrastructure. A second audit system would add unnecessary operational and
integrity complexity.

## Security and privacy consequences

Positive consequences:

- Retention and deletion become testable and tenant-aware.
- Deletion produces evidence without preserving deleted personal data.
- Manual and automatic lifecycle operations follow documented rules.
- Logging requirements explicitly prohibit raw personal values.

Risks:

- Incorrect tenant context could cause unauthorized deletion.
- Audit failure could make deletion difficult to prove.
- Excessive audit detail could recreate personal data.
- A retention misconfiguration could delete data earlier or later than intended.

These risks require authorization, tenant-isolation tests, synthetic test data,
safe defaults and observable failures.

## Verification

ACL-15 must verify:

1. Expired Tenant A data is deleted.
2. Active Tenant A data remains.
3. Tenant B data is unchanged.
4. Cross-tenant deletion returns HTTP 403.
5. Non-admin deletion is rejected.
6. A successful deletion produces non-sensitive evidence.
7. A failed deletion rolls back and remains retryable.
8. Running deletion twice is safe.
9. Logs and audit evidence contain no synthetic personal-data values.
10. Backend and gateway test suites pass.

## Rollback

If the ACL-15 implementation causes unsafe deletion or audit failures:

1. Disable the new lifecycle invocation path.
2. Restore the previous endpoint behaviour through a reviewed revert.
3. Preserve existing tenant retention configuration.
4. Preserve previously generated non-sensitive audit evidence.
5. Investigate affected tenants using request identifiers and counts.
6. Re-enable deletion only after tenant-isolation and retry tests pass.

Deleted personal data must not be restored merely to roll back application
code. Any restoration from backups requires an authorized organizational
decision.

## Consequences

The repository gains an explicit P0 data inventory and a reusable,
tenant-aware deletion design.

Some retention periods and legal exceptions remain shared-responsibility
decisions. The implementation must not represent AuthClaw as independently
establishing GDPR compliance.
