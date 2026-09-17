# T03 / ENT-020 diagnostic exposure evidence

**Date:** 2026-09-17
**Status:** implementation locally verified; live controlled-beta external probes pending

## Contract and changed boundary

- Public backend and gateway health retain only stable `status` and `service` fields.
- Shared-test, staging, and production backend/agent applications do not register
  framework-generated `/docs`, `/redoc`, or `/openapi.json` routes.
- The backend schema remains available at `/api/v1/platform/openapi.json` only to
  an active tenantless platform-admin session.
- Agent readiness probes retain `200`/`503` semantics but return only `status`.
  Detailed checks moved to the platform-admin-only `/operations/health/details`.
- CloudFront WAF blocks legacy documentation, detailed-health, and metrics paths.
  Terraform continues to expose no public agent endpoint.

No tenant data path, tenant key, database schema, or RLS policy changed. Tenant-sensitive
evidence is therefore not applicable to this route-exposure change.

## Fresh local evidence

| Evidence | Result |
|---|---|
| T01 live activation verifier | Passed; PR 52 merged, ruleset enforcement active, zero bypass actors |
| Agent RBAC/control-plane smoke tests | 6 passed |
| Authenticated agent diagnostic endpoint regression | Anonymous and tenant-admin requests denied; platform-admin request reached the handler; configuration validation names absent from the response and correlated to protected logs |
| Backend authorization matrix | 28 passed |
| Backend in-process shared-environment surface | `/health` 200 with exact two-field body; docs/OpenAPI 404; operator schema 401; metrics 401 |
| Agent in-process shared-environment surface | `/health` 200; `/health/ready` 503 with only `status` while the local database was unavailable; detailed endpoint 403 |
| Authenticated agent detail response contract | 503 with `status` and `checks`; expected database-unavailable result |
| Terraform 1.15.7 format and validation | Passed |
| Terraform public-edge test | 5 passed, 0 failed |
| Deployment workflow YAML and modified Bash step syntax | Passed |
| Repository policy and ACL-14 delivery tests | 52 passed |
| Tokei 12.1.2 repository line-budget check | Passed |
| PR growth | 268 positive net non-prose lines by per-file `git diff --numstat`; material-growth owner approval is required |
| `git diff --check` | Passed |

The focused backend endpoint test did not run because this checkout has no configured
`TEST_OWNER_DATABASE_URL`/`TEST_DATABASE_URL` ending in `_test`. The gateway package
suite did not execute because Windows Application Control blocked the freshly compiled
test executable. Docker was not running, so container-based substitutes were unavailable.
These are recorded as environment limitations, not passing results.

The material increase is the minimum coherent evidence path for the review findings:
the deployment workflow records each external probe with request correlation, creates
an allow-listed runtime configuration snapshot, and uploads both artifacts; the agent
test exercises the complete JWT, middleware, dependency, handler, and serialization
path. Reusing only the existing RBAC helper test or deployment assertions would leave
the reported evidence gaps unresolved.

## Required live evidence before closure

The controlled-beta deployment workflow now fails unless external API and gateway
health responses contain only the approved fields, legacy diagnostic/documentation
paths return `403` or `404`, and an unauthenticated operator-schema request returns
`401`. It retains `diagnostic-surface-probes.json` with UTC timestamps plus CloudFront
and application request IDs, and `diagnostic-surface-config.json` with an allow-listed
snapshot of public endpoint names, the deployed WAF rule, task-definition identity,
and `AUTHCLAW_ENV` values. It deliberately excludes response bodies, arbitrary
environment variables, secret values, and secret references.

A live workflow URL and its retained versions of those two artifacts are still
required before ENT-020 is marked closed. No live deployment was performed while
preparing this evidence, and no live output is claimed here.

Rollback must preserve the WAF diagnostic deny rule. If operator access must be
restored, roll back only the authenticated/private diagnostic route; never restore
anonymous public documentation or detailed readiness.
