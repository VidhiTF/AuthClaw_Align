# ADR 0009: One immutable audit evidence authority

- Status: Accepted
- Jira: ACL-21
- Date: 2026-07-20

## Decision

PostgreSQL `audit_log_metadata` is the only authoritative compliance evidence
chain. Migration 028 supplies the only append operation,
`append_audit_event_v2`. It serializes each tenant with an advisory transaction
lock, assigns `tenant_sequence`, stores the exact canonical payload and SHA-256
chain proof, and inserts `audit_outbox` in the same transaction.

Gateway and backend code call the function; they do not select a chain tail or
calculate an authoritative hash. Kafka receives committed outbox payloads keyed
by `tenant_id`. ClickHouse is a deterministic, rebuildable mirror ordered by
`(tenant_id, tenant_sequence)`. Its consumer validates PostgreSQL proof data and
never creates another chain.

`UPDATE` and `DELETE` on authoritative rows are rejected by a database trigger.
Recovery is one-way: PostgreSQL can reconstruct ClickHouse, never the reverse.

## Agent compatibility boundary

The agent service has historical integer tenant IDs and a separate
`audit_logs` table. Those rows remain operational diagnostics so old references
continue to resolve, but new writes do not maintain or publish its former hash
chain. They are excluded from ACL-21 exports and compliance claims.

A later data migration may map an agent integer tenant to a control-plane UUID
and append a migration event plus normalized historical references. Historical
rows must not be inserted between existing canonical sequences or presented as
if they were native ACL-21 records.

## Consequences

- PostgreSQL availability is required for authoritative audit acceptance.
- Kafka and ClickHouse outages create retryable outbox/mirror backlog, not a
  second source of truth.
- Application rollback may restore older writers only after disabling their
  evidence claim; it must not drop ACL-21 columns, triggers, outbox rows, or
  immutable audit records.
