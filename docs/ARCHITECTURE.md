# Consolidated architecture

The proposed canonical monorepo and component boundaries are recorded in
[ADR-0001](adr/0001-canonical-monorepo-component-boundaries.md), pending Binod approval.
The proposed public URL, AWS edge, environment-isolation and ownership contract is
recorded in [ADR-0002](adr/0002-aws-url-environment-boundary.md). ADR-0002 remains
pending Binod approval; existing Terraform must not be interpreted as satisfying it
until ACL-14 supplies implementation and acceptance evidence.
The managed cryptography, key-rotation, TLS-boundary and no-credential evidence model
is recorded in [ADR-0004](adr/0004-acl-10-managed-cryptography.md).

## Runtime boundaries

1. The **console** calls the FastAPI **control plane** using a short-lived bearer API key.
2. The control plane owns tenants, users, RBAC, SSO configuration, API keys, policies,
   compliance scores, evidence, findings, and approval state.
3. The Go **gateway** is the only supported model-egress path. It performs authentication,
   policy checks, rate limits, redaction and audit publication before proxying providers.
4. The **agent service** performs LangGraph orchestration, regulatory retrieval, document
   processing, redaction, risk classification and HITL flows. It remains a separate process
   so its Python/dependency lifecycle cannot destabilize the control plane.
5. The **audit consumer** writes gateway and control-plane events to ClickHouse while
   PostgreSQL remains the tenant-scoped system of record.

## Integration rules

- `backend/` is the authority for identity and tenant authorization.
- `services/agent/` must not issue independent end-user identities in the consolidated
  deployment. Service-to-service authentication and tenant context are required before
  exposing agent routes publicly.
- `console/src/lib/api-client.ts` contains the temporary path adapter between Ravi's UI
  contract and Kunal's canonical control-plane routes. New code should use canonical
  routes directly.
- Encryption keys and signing keys are injected at runtime. No production secret belongs
  in source, Compose defaults, browser variables, logs, prompts, or audit payloads.

## Launch blockers

- Finish end-to-end contract tests for every console route enabled in production.
- Require authenticated service-to-service calls between backend and agent.
- Complete external penetration testing and remediate launch-blocking findings.
- Validate backup restore, key rotation, incident response and data-subject workflows.
- Obtain independent legal/audit review before making compliance claims.
- Resolve source licensing and contributor-rights review before distribution.
