# Audit-Ready Release Checklist

Local release proof must pass before a release candidate is marked audit-ready.

- Tests: backend, gateway, console, HA validator, hardening validator, no-credential validator.
- Scans: SAST, dependency, secret, IaC, and container gates are represented in hardening evidence.
- Migrations: Alembic migrations are present and rollback notes are linked from release evidence.
- Rollback notes: release rollback is documented in the compliance hardening runbook.
- DR notes: multi-region recovery and database promotion are documented in `infra/terraform/DR_RUNBOOK.md`.
- Signed audit export verification: local signed export tests must prove valid signatures and tamper detection.
- Red-team thresholds: no critical/high failures are allowed in release evidence.
- Tenant isolation: synthetic tenant isolation tests must pass.
