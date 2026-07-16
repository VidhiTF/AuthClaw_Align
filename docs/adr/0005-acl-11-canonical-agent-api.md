# ADR 0005: Canonical versioned agent API

- Status: Accepted
- Date: 2026-07-16
- Jira: ACL-11
- Owner: Vidhi Sharma

## Context

The Agent service had legacy chat and health routes but no single versioned contract
for Agent execution, RAG retrieval, and remediation-plan creation. Tenant identity
was present in graph state, while caller correlation context was not explicit.

## Decision

The Agent service exposes:

- `GET /api/v1/agent/health`
- `GET /api/v1/agent/health/ready`
- `POST /api/v1/agent/executions`

The execution endpoint supports `chat`, `rag`, and `remediation_plan`. Authentication
resolves the tenant server-side; callers cannot override `tenant_id`. Middleware
uses `X-Request-ID` as the correlation identifier or generates one when absent, and
chat execution propagates that identifier into LangGraph state.

RAG delegates to the existing checked-in retriever. Remediation-plan creation uses
the existing allowlisted, tenant-scoped runtime and does not execute the plan. The
existing approval and MFA controls remain mandatory for execution.

Legacy `/chat`, `/gateway/chat`, `/health`, and `/health/ready` routes remain during
the migration window.

## Verification

Run from `services/agent`:

```text
python -m compileall -q .
python -m unittest discover -s smoke_tests -v
```

The ACL-11 smoke tests verify the canonical response envelope, RAG context, and
tenant-scoped remediation-plan creation. Full-stack CI calls the versioned readiness
endpoint.

## Telemetry

Canonical requests emit structured start and completion log records containing the
operation, tenant ID, and correlation ID. Existing gateway and graph audit telemetry
continues to capture chat execution.

## Rollback

Revert the ACL-11 commit and restore the full-stack smoke URL to `/health/ready`.
Legacy endpoints remain unchanged, so rollback needs no data migration.
