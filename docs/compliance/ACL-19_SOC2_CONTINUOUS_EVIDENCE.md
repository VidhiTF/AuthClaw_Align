# ACL-19 SOC 2 control mapping and continuous evidence

## Scope

ACL-19 implements the repository's P0 SOC 2 readiness baseline. It does not assert
certification or completion of a SOC examination. The authoritative control set is
defined in `docs/compliance/GDPR_SOC2_CONTROL_MATRIX.md`.

## Acceptance mapping

| Jira acceptance criterion | Implementation | Verification |
|---|---|---|
| P0 controls have owners, implementation status, and evidence sources | The SOC2 control catalogue exposes product owners, operational owners, implementation status, mapped evidence sources, and collection frequency for CC6.1, CC6.6, CC7.1, CC7.2, CC7.3, CC8.1, A1.2, and C1.1. | `backend/tests/test_compliance_scoring.py`; compliance dashboard contract test |
| Automated evidence records timestamps, tenant context, and integrity metadata | Evidence records include tenant ID, creation time, SHA-256 canonical integrity hash, algorithm, and version. API reads verify the stored hash. Migration 038 backfills existing records and makes records immutable at the database layer. | `backend/tests/test_acl19_continuous_evidence.py`; `backend/tests/test_migration_038.py`; live migration/API verification |
| Exceptions and missing evidence remain visible and cannot appear compliant | Control gaps produce open exceptions. A control with a gap, partial implementation, or no control-specific evidence is capped below compliant. Framework and overall readiness cannot be `audit_ready` while a control or framework remains below audit-ready. | `backend/tests/test_compliance_scoring.py`; `console/tests/acl19-ui-contract.test.mts`; manual dashboard verification |

## Operating evidence rules

1. Evidence must use a control-specific source reference such as `SOC2:CC6.1` so the
   dashboard can distinguish control evidence from generic framework records.
2. Framework-level evidence is not silently substituted for missing control evidence.
3. Open exceptions remain visible until implementation and operating evidence exist.
4. Example, local, or synthetic records prove behavior only; they do not prove
   controlled-beta operation.
5. Evidence integrity verification protects record content, tenant binding, source,
   classification, and collection timestamp.

## Telemetry

Daily compliance snapshots retain control scores, evidence totals, open findings, and
critical findings. Existing score-drop notifications alert when a framework falls by at
least five points. The compliance and evidence pages expose the live status, open
exceptions, traceability links, and integrity-verification result.

## Local verification results

- Backend ACL-19 scoring, integrity, and migration tests: 13 passed.
- Console unit and ACL-19 UI contract tests: 30 passed.
- Console lint: passed.
- Console production build: passed; 76 pages generated.
- Isolated database upgrade from revision 037 to 038: passed on a fresh ACL-19 test database.
- Existing synthetic evidence backfill: SHA-256, version 1, 64 lowercase hex characters.
- Database immutability: an attempted evidence update was rejected and the original row remained unchanged.
- Evidence row-level security remained enabled and forced after migration.
- Integrity algorithm, hash-format, and version constraints were present after migration.
- Authenticated API verification passed for evidence integrity, missing and invalid credentials,
  tenant-scoped reads, cross-tenant concealment, truthful SOC 2 scoring, visible exceptions,
  and idempotent daily score snapshots.
- Manual isolated-console verification passed for SOC 2 owners, implementation status,
  evidence sources, collection frequency, blocked open exceptions, control traceability,
  score history, and evidence integrity metadata.

These are local verification results and do not represent controlled-beta operating evidence
or SOC 2 certification.

## Rollback

1. Revert the ACL-19 application commit.
2. Run `alembic downgrade 037` only if integrity metadata must be removed and retained
   evidence has first been exported according to the evidence runbook.
3. Downgrade removes the evidence immutability trigger and integrity columns; it does not
   delete evidence records.
4. Restore the prior application images and verify compliance and evidence endpoints.

## Evidence to attach to Jira

- Backend unit and migration test output.
- Console contract and build output.
- Fresh-database migration proof from revision 037 to 038.
- Tenant-isolation and tamper-rejection API/database proof.
- Screenshots of control ownership, evidence sources, open exceptions, and verified
  integrity metadata.
- Pull request, CI, reviewer approval, and rollback evidence.
