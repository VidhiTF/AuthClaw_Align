-- Phase 7: ClickHouse audit_events schema
-- Append-only MergeTree table with hash-chaining for tamper evidence

CREATE DATABASE IF NOT EXISTS authclaw;

CREATE TABLE IF NOT EXISTS authclaw.audit_events
(
    record_id          UUID,
    tenant_id          UUID,
    timestamp          DateTime64(3, 'UTC'),
    actor_id           String,
    actor_type         String,
    action             String,           -- 'allow' | 'block'
    policy_id          String,
    provider           String,
    model              String,
    reason             String,
    prompt_count       UInt32,
    request_size       UInt32,
    response_status    UInt16,
    duration_ms        Int64,
    frameworks_affected Array(String),
    execution_trace    String,           -- JSON array of trace steps
    request_id         String,           -- propagated from X-Request-ID gateway header
    prior_hash         String,           -- SHA-256 of previous record in chain
    integrity_hash     String,           -- SHA-256(record_json + prior_hash)
    created_at         DateTime DEFAULT now()
)
ENGINE = MergeTree()
ORDER BY (tenant_id, timestamp, record_id)
SETTINGS index_granularity = 8192;

-- Materialized view for per-tenant event counts (analytics convenience)
CREATE TABLE IF NOT EXISTS authclaw.audit_events_daily
(
    tenant_id  UUID,
    event_date Date,
    action     String,
    provider   String,
    count      UInt64
)
ENGINE = SummingMergeTree()
ORDER BY (tenant_id, event_date, action, provider);

CREATE MATERIALIZED VIEW IF NOT EXISTS authclaw.audit_events_daily_mv
TO authclaw.audit_events_daily
AS
SELECT
    tenant_id,
    toDate(timestamp) AS event_date,
    action,
    provider,
    count() AS count
FROM authclaw.audit_events
GROUP BY tenant_id, event_date, action, provider;

-- Production RBAC guardrails:
-- - authclaw_audit_writer can append/read audit rows for prior-hash lookup.
-- - authclaw_audit_reader can query analytics only.
-- Neither role receives ALTER, DELETE, TRUNCATE, DROP, or OPTIMIZE privileges.
CREATE ROLE IF NOT EXISTS authclaw_audit_writer;
CREATE ROLE IF NOT EXISTS authclaw_audit_reader;

GRANT INSERT, SELECT ON authclaw.audit_events TO authclaw_audit_writer;
GRANT SELECT ON authclaw.audit_events TO authclaw_audit_reader;
GRANT SELECT ON authclaw.audit_events_daily TO authclaw_audit_reader;

-- Operators should create environment-specific users and attach only one role:
--   GRANT authclaw_audit_writer TO authclaw_audit_ingest;
--   GRANT authclaw_audit_reader TO authclaw_audit_analytics;
