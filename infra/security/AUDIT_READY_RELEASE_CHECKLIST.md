# Audit-Ready Release Checklist

Local release proof must pass before a release candidate is marked audit-ready.

## Supported launch configuration

- **Deployment:** the supported launch target is the controlled-beta AWS deployment
  described in [ADR-0006](../../docs/adr/0006-acl-14-controlled-beta-delivery.md) and the
  [beta deployment guide](../terraform/BETA_DEPLOYMENT.md). Local and CI validation use
  the canonical full-stack Docker Compose command in the [repository README](../../README.md);
  a local run is not production deployment evidence.
- **Browsers:** release-candidate browser coverage runs the Playwright `chromium` project
  with the Desktop Chrome device profile from
  [`console/playwright.config.ts`](../../console/playwright.config.ts).
- **Roles:** the launch browser role matrix covers Owner, Admin, Operator, and Viewer.
  Route access and permission-denied behavior are exercised by the
  [release-candidate smoke suite](../../console/tests/e2e/release-candidate-smoke.spec.ts);
  backend authorization remains authoritative.
- **Environments:** checked-in defaults support local development and CI. Controlled-beta
  deployment is opt-in and remains disabled until its GitHub environment and AWS bootstrap
  inputs are configured.
- **Required infrastructure:** use the existing encrypted AWS Terraform baseline and the
  external bootstrap inputs listed in the [beta deployment guide](../terraform/BETA_DEPLOYMENT.md).
  The canonical service and data boundaries are defined by
  [ADR-0001](../../docs/adr/0001-canonical-monorepo-component-boundaries.md).
- **Assumptions:** production encryption, signing, SSO, secrets, email delivery, provider
  credentials, edge controls, and audit services must be configured for the deployed
  environment. Missing required production configuration is designed to fail closed.

## Known launch limitations

- Repository validation does not prove a live AWS deployment, DNS route, active branch
  protection, or completed rollback drill. Those items require environment-owned evidence
  described in [ADR-0006](../../docs/adr/0006-acl-14-controlled-beta-delivery.md).
- The release browser gate currently covers Chromium/Desktop Chrome only; other browser
  engines are not represented by the checked-in Playwright project configuration.
- Live email delivery, provider credentials, cloud connector, storage, KMS, CDN/WAF, and
  origin-denial evidence remain environment-owned deployment gates listed in the
  [console compatibility record](../../docs/CONSOLE_API_COMPATIBILITY.md#remaining-production-evidence).
- Product controls support compliance readiness but do not establish organizational
  compliance. Shared responsibilities and report boundaries are defined in the
  [compliance boundary](../../docs/COMPLIANCE_BOUNDARY.md#shared-responsibility).
- No verified final SOC 2 Type II report, SOC 3 report, or external penetration-test report
  is present. Conditional public claims require their recorded evidence and approval; see
  the [public claim register](../../docs/compliance/PUBLIC_CLAIM_REGISTER.md) and
  [approval record](../../docs/compliance/ACL-35_PUBLIC_CLAIMS_APPROVAL.md).
- External distribution remains subject to the owner/legal license decisions recorded in
  the [license inventory](../../docs/provenance/LICENSE_INVENTORY.md#required-owner-decisions-and-follow-up).

## Acceptance evidence index

This index references the existing evidence sources; it does not replace or duplicate
their assertions.

| Release assertion | Existing evidence |
|---|---|
| Browser and role smoke coverage | [`console/tests/e2e/release-candidate-smoke.spec.ts`](../../console/tests/e2e/release-candidate-smoke.spec.ts) |
| Backend authorization and tenant isolation | [`backend/tests/test_authorization_matrix.py`](../../backend/tests/test_authorization_matrix.py) |
| Trust Center rendering and access | [`console/tests/e2e/trust-summary.spec.ts`](../../console/tests/e2e/trust-summary.spec.ts) |
| Signed evidence export and verification | [`backend/tests/test_audit_export.py`](../../backend/tests/test_audit_export.py) and the [audit-evidence operator runbook](../../docs/runbooks/ACL_21_AUDIT_EVIDENCE.md) |
| Public claim validation and approved wording | [`console/scripts/check-public-claims.mjs`](../../console/scripts/check-public-claims.mjs), the [claim register](../../docs/compliance/PUBLIC_CLAIM_REGISTER.md), and the [approval record](../../docs/compliance/ACL-35_PUBLIC_CLAIMS_APPROVAL.md) |
| F21 consolidated acceptance evidence | [F21 release-candidate evidence index](../../docs/compliance/F21_RELEASE_CANDIDATE_EVIDENCE.md) |
| Release gates and operational evidence | This checklist, the [compliance hardening runbook](COMPLIANCE_HARDENING_RUNBOOK.md), and the [controlled-beta deployment guide](../terraform/BETA_DEPLOYMENT.md) |

- Tests: backend, gateway, console, HA validator, hardening validator, no-credential validator.
- Scans: SAST, dependency, secret, IaC, and container gates are represented in hardening evidence.
- Migrations: Alembic migrations are present and rollback notes are linked from release evidence.
- Rollback notes: release rollback is documented in the compliance hardening runbook.
- DR notes: multi-region recovery and database promotion are documented in `infra/terraform/DR_RUNBOOK.md`.
- Signed audit export verification: local signed export tests must prove valid signatures and tamper detection.
- Red-team thresholds: no critical/high failures are allowed in release evidence.
- Tenant isolation: synthetic tenant isolation tests must pass.
