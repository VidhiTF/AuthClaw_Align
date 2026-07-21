# F21 release-candidate acceptance evidence

| Metadata | Value |
|---|---|
| Jira | F21 |
| Scope | Release-candidate UX, trust content, and claim audit |
| Release target | Controlled beta |
| Evidence status | Repository evidence complete; required remote CI pending |

This index references existing implementation, tests, governance records, and release
documentation. It does not duplicate their evidence or represent live deployment proof.

## Acceptance evidence

| Acceptance criterion | Repository evidence | Release gate |
|---|---|---|
| Critical console flows pass browser and role-based smoke tests | [Release-candidate browser and role matrix](../../console/tests/e2e/release-candidate-smoke.spec.ts), [full-stack browser coverage](../../console/tests/e2e/full-stack-wiring.spec.ts), and [backend authorization matrix](../../backend/tests/test_authorization_matrix.py) | Full-stack Playwright execution in `.github/workflows/ci.yml` |
| Website, demo, and Trust Center claims link to evidence or approved wording | [Public claim scanner](../../console/scripts/check-public-claims.mjs), [marketing browser checks](../../console/tests/e2e/marketing.spec.ts), [Trust Center checks](../../console/tests/e2e/trust-summary.spec.ts), [claim register](PUBLIC_CLAIM_REGISTER.md), and [approval record](ACL-35_PUBLIC_CLAIMS_APPROVAL.md) | `npm run test:claims` and full-stack Playwright execution |
| Known limitations and supported launch configuration are published | [Audit-ready release checklist](../../infra/security/AUDIT_READY_RELEASE_CHECKLIST.md#supported-launch-configuration), including its [known limitations](../../infra/security/AUDIT_READY_RELEASE_CHECKLIST.md#known-launch-limitations) | F21 release-document validation in `.github/workflows/ci.yml` |

## Definition-of-Done evidence

- **Code and tests:** the browser smoke, role matrix, claim scanner, marketing, and Trust
  Center validation sources above are executed by existing required CI jobs.
- **Documentation:** supported configuration, known limitations, and their authoritative
  sources are consolidated in the audit-ready release checklist.
- **Telemetry:** GitHub job and required-check outcomes are the execution telemetry for
  this test-and-documentation feature. F21 adds no runtime path, so no runtime metric is
  emitted and no telemetry subsystem is introduced.
- **Rollback:** F21 claim, documentation, and release rollback uses the existing
  [compliance hardening runbook](../../infra/security/COMPLIANCE_HARDENING_RUNBOOK.md#f21-release-content-rollback).
- **CI:** claim scanning, Playwright, and release-document validation feed the existing
  `ACL-14 Required Checks` aggregate gate.
- **Acceptance evidence:** this file is the index; GitHub run logs and summaries provide
  the release-specific execution result.

## Evidence handling

A release owner records the commit and required-check URL after remote CI completes.
Repository-local validation is not evidence of live AWS deployment, public DNS, or an
external attestation. Those boundaries remain governed by the
[release checklist](../../infra/security/AUDIT_READY_RELEASE_CHECKLIST.md).

## Local validation

Validated on 2026-07-21 against the repository full-stack Compose environment:

| Check | Result |
|---|---|
| Playwright Chromium suite | 46 passed |
| Public claim scanner | Passed |
| ESLint | Passed |
| TypeScript (`tsc --noEmit`) | Passed |
| Console production build | Passed |
| Documentation link targets and required sections | Passed |
| GitHub Actions YAML parse | Passed |
| `git diff --check` | Passed |

Remote `ACL-14 Required Checks` execution remains required for release approval.
