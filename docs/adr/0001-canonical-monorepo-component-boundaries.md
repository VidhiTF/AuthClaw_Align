# ADR-0001: Canonical monorepo and component boundaries

- Jira: ACL-6 / F01
- Status: Proposed -- pending Binod approval
- Decision date: 2026-07-13
- Decision owner: Binod / AgentsArchitects
- Component owners: Kunal, Vidhi and Ravi

## Context

AuthClaw is maintained as one consolidated product repository. The repository already
contains the selected gateway, control plane, agent, console, redaction, identity and
audit implementations. ACL-6 records that existing decision so later work does not
create competing implementations or reopen repository selection.

This ADR documents the current monorepo as the canonical baseline. Historical comparison
of predecessor repositories is not part of this decision record. Build, integration and
deployment verification for the consolidated product belongs to ACL-14.

## Decision

`AuthClaw` is the only canonical AuthClaw product codebase. Feature work must
extend the selected path and authority below instead of introducing a parallel service,
identity model, console, audit path or public gateway.

| Capability | Canonical path | Authority and boundary | Primary owner |
| --- | --- | --- | --- |
| Provider gateway | `gateway/` | Only supported public model-egress path; authenticates requests and applies policy, rate-limit, redaction and audit controls before provider traffic | Kunal |
| Control plane | `backend/` | Canonical tenant, user, RBAC, SSO configuration, API-key, policy, workflow, evidence and findings API | Kunal |
| Agent and RAG | `services/agent/` | LangGraph orchestration, regulatory retrieval, document intelligence, risk and HITL processing behind an authenticated service boundary | Vidhi |
| Operator console | `console/` | Canonical Next.js customer/operator interface; consumes backend contracts and does not own a separate identity or data model | Ravi |
| Identity | `backend/app/core/` and backend auth endpoints | Backend is the authority for principals, tenant context, authorization and authentication policy; console only stores/presents authenticated state | Kunal |
| Redaction | `gateway/`, backend redaction records, and agent internal processing | Gateway owns model-egress enforcement; backend owns control-plane records; agent may redact internal workflow data but may not create a bypass around gateway policy | Kunal + Vidhi |
| Audit | Gateway/backend producers, `audit_consumer/`, PostgreSQL and ClickHouse | One tenant-scoped event contract; PostgreSQL is the system of record and the audit consumer projects ordered events to ClickHouse | Kunal |
| Infrastructure and delivery | `infra/`, `docker-compose*.yml`, `.github/workflows/` | Canonical infrastructure, local stack and delivery definitions; completion and deployment proof are owned by ACL-14 | Kunal |

## Integration rules

1. `backend/` is the only end-user identity and tenant-authorization authority.
2. `gateway/` is the only supported public route for model-provider egress.
3. `services/agent/` must receive authenticated service identity and tenant context before
   its routes are exposed outside the private service boundary.
4. `console/` must use canonical backend routes. Its temporary API adapter is a migration
   seam, not a second API contract.
5. Gateway, backend and agent redaction responsibilities must preserve one enforcement
   outcome and one auditable event contract.
6. New audit producers publish the canonical tenant-scoped event shape; they do not write
   an independent audit history.
7. Shared secrets, production credentials and customer data never belong in source,
   browser-visible configuration, logs or prompts.

## Ownership and review

Repository review routing is defined by [`.github/CODEOWNERS`](../../.github/CODEOWNERS):

- Kunal owns gateway, backend, audit and infrastructure work.
- Vidhi owns agent-service work.
- Ravi owns console work.
- Binod / AgentsArchitects is the final reviewer for every repository change.

Cross-boundary changes require every affected component owner plus Binod. CODEOWNERS
routes review but does not replace protected-branch rules or explicit approval.

## Unresolved integration risks

| Risk | Owner | Closure ticket or gate |
| --- | --- | --- |
| Console routes and response shapes are not yet fully aligned with backend APIs | Ravi + Kunal | Console contract work and ACL-14 integration gate |
| Agent service-to-service authentication and tenant context are not complete | Vidhi + Kunal | Agent integration work before public exposure |
| Redaction behavior spans gateway, backend records and agent workflows | Vidhi + Kunal | Canonical contract and end-to-end policy tests |
| Local Compose, clean build and required CI do not yet prove the complete stack | Kunal | ACL-14 |
| AWS edge, private origins and environment separation are not implemented | Kunal | ACL-29 decision followed by ACL-14/ACL-30 implementation |
| Compliance language must remain audit-readiness language until independent reports exist | Vidhi + Binod | Claims review and release go/no-go |

These risks do not reopen component selection. Each must be closed or explicitly accepted
by its named owner in the relevant delivery ticket.

## Evidence

- [`README.md`](../../README.md) records the canonical repository map and component
  ownership.
- [`.github/CODEOWNERS`](../../.github/CODEOWNERS) records review routing and final owner
  review.
- [`docs/ARCHITECTURE.md`](../ARCHITECTURE.md) records runtime authority and integration
  boundaries.
- [`docs/CONSOLE_API_COMPATIBILITY.md`](../CONSOLE_API_COMPATIBILITY.md) records the
  current console/backend integration boundary and remaining work.
- Binod's approval of this ADR must be retained in the approved pull request or linked
  Jira evidence before ACL-6 is considered accepted.

## Consequences

- Later tickets integrate and verify the monorepo; they do not choose another base.
- A capability may span components only when authority is explicit and no public bypass
  or duplicate system of record is created.
- ACL-29 consumes these boundaries to define AWS origins and URLs.
- ACL-14 owns clean consolidated builds, local startup, CI gates and the encrypted beta
  deployment baseline.
- Any proposal to replace a canonical component requires a new superseding ADR approved
  by Binod and the affected component owners.
