# ENT-017 / T02 review and verification

## Scope and corrected disposition

Security defect, not complete before this review: the active agent download route
still served filenames without a tenant-authorized record lookup. Backend-only
changes did not remediate that path. This working-tree change covers backend S3
evidence, agent local evidence, their access audits, migration compatibility and
the supporting IAM/endpoint policies. No deployment or production readiness claim.

T01 verification passed with `scripts/repository_policy.py --verify-github`:
PR 52, reviewed b8b23993a7a467396598eefdd23b97da83d47042, merged
1e40bdb5c8fd6b4e28c827035ab7d06645530ccb, effective 2026-09-16T12:57:25Z;
ruleset 21141288 active with zero bypass actors. Review baseline is that merged
commit plus the pre-existing working-tree changes. Unrelated compose/gateway
changes were preserved. This document is evidence preparation, not PR approval.

## Findings fixed and reuse

- Agent downloads resolve numeric registry IDs with the authenticated integer
  tenant key, not filenames. Full SHA-256, tenant-local object path, retention and
  download policy are checked; a bounded private snapshot is streamed after
  verification. Generated files now use tenant directories and unique names.
- Backend uses existing EvidenceRecord lookup/integrity verification and existing
  authenticated UUID tenant/RLS context. S3 downloads validate the checksum from
  the same GetObject response; deletion uses conditional ETag matching, explicit
  permission and an expired timezone-aware retention timestamp.
- Reused the audit publisher/outbox and transaction-binding hook rather than
  duplicating credential rebinding. Access events retain actor and purpose;
  repeated correlation IDs no longer collapse distinct access events.
- Agent access auditing reuses its existing diagnostic audit writer, failing
  closed before dispatch. It is not the authoritative backend immutable chain.
  Auditor report exports are included. Unsafe client-path unlinking was removed;
  retained local files cannot be deleted via the registry endpoint.
- CSV export uses a fixed safe filename; file downloads encode disposition names.
  Report formats are allowlisted. Responses do not expose storage exception text.
- Migration 049 switches audit append authorization to authenticated DB context.
  Backend/gateway/compose/Terraform revision defaults and compatibility were updated.
- Backend evidence deletion IAM and endpoint permissions use only configured
  backend bucket resources, not agent-only buckets; policy documents are exposed
  as Terraform outputs for deployment evidence collection.

New production logic is necessary because neither the original agent filename
route nor existing audit utilities performed file-record authorization. Existing
DB schemas, metadata fields, auth middleware, report producer, AWS client and
streaming response were reused; no dependency or general framework was added.
Redundant UUID parsing, duplicate rebinding, unsafe unlink logic and verbose
migration/error handling were removed. No semantic-duplicate merge was performed.
Net LOC increases: authorization and regression coverage were missing, so this
is not a net-LOC-reduction claim. `git diff --numstat` counts tracked additions
and deletions; untracked migration/service/tests must be included in the PR's
material-growth digest. Owner approval of the >=100-line growth exception is
still required; the author cannot grant it.

## Fresh checks (2026-09-17)

- Python: 58 tests passed across `test_tenant_isolation`,
  `test_evidence_downloads`, `test_agent_evidence_access`, `test_migration_chain`,
  `test_event_backbone`, `test_audit_export_access`, `test_audit_export`, and
  `test_acl19_continuous_evidence`. Run from backend using `.venv-t02`, pytest
  plugin autoload disabled, and the disposable database described below.
- PostgreSQL 17, isolated `authclaw_ent017_test` database at localhost:55432:
  bootstrap prepare, backend migration to 049, agent migrations, bootstrap finalize
  and database-security verification passed. Live RLS denies foreign records even
  through raw ORM lookup; audit access persists across transaction commits.
  Regression checks examine actor, tenant, action and purpose in persisted rows.
- Gateway: `go test ./... -run
  'Test(DatabaseConfigTLS|CompatibleDatabaseRevisions|AuditAuthenticatedContextPostgres)$'
  -count=1` passed against the disposable database.
- Terraform: `terraform fmt -check -recursive` and `terraform test -no-color`:
  20 passed, zero failed. Providers are mocked; no resources were deployed.
- Changed agent modules compile; changed targeted Python files formatted with
  Black; `git diff --check` passed. Tests were rerun after the simplification and
  adversarial review passes, including export-header and repeated-audit scenarios.

Earlier unrestricted gateway-suite invocation stopped at its test-database safety
gate because DATABASE_URL was absent; the targeted rerun used an explicit _test
database and passed. The agent legacy conftest can drop a database, so it was not
run. Agent tests exercise the actual file service and extracted actual middleware
with a mocked audit-writer boundary; they do not constitute full ASGI/deployed
agent verification. Python reports existing Pydantic/Alembic/datetime deprecations.

## Contracts, release, risk and rollback

Agent download URL values are now record IDs; filename URLs and legacy truncated
hash/shared-path records fail closed. Regenerate or explicitly migrate legacy
records only after proving tenant ownership; no ownership was guessed or data
silently backfilled. Generated local files have indefinite `retain` policy;
automated expiry/purge is not implemented. API-key-only requests without a user
subject cannot satisfy the agent actor requirement. These are release-note and
consumer-review items, not transparent compatibility changes.

Apply migration 049 using the migration identity before relying on new audit
behavior. Use the explicit 048,049 revision compatibility window during coordinated
rollout, then require 049. Test the actual old/new deployed image mix before release.
Do not roll back the authenticated audit authorization to the legacy tenant GUC.
On failure disable evidence access and roll forward; any application rollback must
retain the tenant authorization fix and support revision 049. No evidence files
were deleted or legacy records rewritten by this change.

## Remaining release requirements (not satisfied)

- Two current-head independent human component/security/consumer approvals and
  the repository-required material line-growth exception, PR CI and merge evidence.
- Actual environment S3/IAM/KMS/retention verification and a deployed policy export.
  `gateway_endpoint_policy_documents` and `evidence_object_access_policy` expose
  configured policies; mocked tests are not proof of effective AWS bucket access.
- Deployed end-to-end evidence smoke tests, including agent database auditing,
  legacy-record migration/regeneration acceptance and consumer compatibility.

These external release requirements prevent labeling the task production-ready.

## Delivery evidence follow-up

The 58-test Python suite passed again after adding export to the live audit
persistence scenarios. Five synthetic persisted rows are retained in
`docs/evidence/ENT-017-audit-records.json`, with actor, tenant, purpose, sequence
and integrity hash. This proves the audit persistence seam, not deployed HTTP/S3
operations. The second download shares a correlation ID but remains a separate row.

Read-only AWS discovery found only `authclaw-terraform-state-ap-south-1` in the
configured account and no ECS clusters in ap-south-1, us-east-1 or us-west-2.
No evidence-bucket policy was available to export. The user explicitly deferred
AWS deployment verification and policy evidence collection until deployment.
No AWS resources were created or changed. Code/PR delivery remains in scope;
release approval and task closure must not treat the deferred evidence as passed.
