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

## F11 data-subject request workflow

F11 uses the existing tenant authentication, authorization, database session,
append-only audit, and signed-export infrastructure. Authorized tenant owners
and administrators process requests through this state model:

`PENDING -> VERIFIED -> APPROVED | REJECTED`

Approved export and deletion requests move to `COMPLETED` only after the
operation and its audit evidence commit successfully. Row locking makes each
transition atomic. Requests, lookups, exports, and deletions remain scoped to
the authenticated tenant.

The supported export contains the subject's AuthClaw user profile,
tenant-managed API-key metadata, and actor-linked audit metadata. It excludes
key hashes, credentials, platform-managed keys, and data without an
authoritative subject link. The signed artifact uses the existing audit-export
key and manifest format.

Deletion removes tenant-managed API keys, notifications, and onboarding status
linked to the subject. User identity is retained for account and tenant
lifecycle integrity. Immutable audit metadata and legal-acceptance records are
retained as compliance evidence, and platform-managed keys remain subject to
controlled platform operations. These exceptions are returned as categories
and reasons without reproducing deleted personal data.

Operators must verify identity before making a decision, record a decision
reason, confirm the request type and scope, and review reported deletion
exceptions. They must not treat completion as authorization to restore deleted
data.

The existing metrics framework records:

- `gdpr_requests_created_total`
- `gdpr_requests_verified_total`
- `gdpr_requests_approved_total`
- `gdpr_exports_completed_total`
- `gdpr_deletions_completed_total`
- `gdpr_request_failures_total`

Metric labels and logs do not contain subject data.

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

For an F11 deployment, operators must also:

1. Verify the current Alembic revision and take a database backup before
   applying revision `035`.
2. Apply the migration before deploying application code that exposes the F11
   routes, then verify the table, tenant policies, and restricted-role grants.
3. Stop new F11 processing before rollback and identify requests currently in
   `PENDING`, `VERIFIED`, or `APPROVED` state.
4. Revert application code first. Keep revision `035` applied while any F11
   rows must be preserved; the older application does not depend on that table.
5. Downgrade from `035` only when an authorized operator has confirmed that no
   required request record will be lost, because the downgrade drops the F11
   table.
6. After rollback, verify existing authentication, tenant isolation, audit
   append, and non-F11 API behavior. Preserve immutable audit events already
   emitted for F11 operations.

In-flight transactions either commit their operation and audit evidence
together or roll back. A rollback must never recreate personal data already
deleted by a completed request, reactivate deleted credentials, or alter
retained immutable evidence.

## F11 acceptance evidence

- Lifecycle, authorization, and tenant isolation:
  `backend/tests/test_endpoints.py::test_data_subject_request_lifecycle_authorization_and_isolation`.
- Export scope, signing, completion, and secret exclusion: assertions in the
  same integration test against the signed export artifact.
- Deletion, exceptions, idempotency, and transaction rollback: deletion and
  forced-failure assertions in the same integration test.
- Immutable audit evidence: asserted lifecycle, export, and deletion actions
  emitted through `append_audit_event` without subject email or credentials.
- Migration upgrade and rollback: revision
  `backend/alembic/versions/035_add_data_subject_requests.py` and migration
  validation in the backend CI job.

## Consequences

The repository gains an explicit P0 data inventory and a reusable,
tenant-aware deletion design.

Some retention periods and legal exceptions remain shared-responsibility
decisions. The implementation must not represent AuthClaw as independently
establishing GDPR compliance.

## Pentest W-3 decision gate

Pentest finding W-3 remains open. The current F11 implementation intentionally
retains the user identity and raw email for account and tenant lifecycle integrity,
but that engineering rationale is not by itself a lawful-retention decision.

Before changing deletion behavior or declaring W-3 closed, privacy/legal must approve:

- account deletion versus removal from one tenant;
- handling of the last tenant owner and platform administrators;
- legal acceptance evidence, immutable audit records and legal holds;
- re-enrollment and email uniqueness after deletion;
- retention and erasure behavior for PostgreSQL, Redis, Kafka, ClickHouse, logs,
  exports, object storage, processors and backups.

Engineering must then update the data inventory, use non-reversible keyed
pseudonymous identifiers where approved continuity is required, provide a dry-run
inventory, and attach tenant-isolation and failure-recovery evidence. Until those
decisions and tests exist, W-3 is approved for investigation only, not implementation
or closure.
