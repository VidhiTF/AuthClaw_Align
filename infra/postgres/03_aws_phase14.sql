-- =============================================================================
-- Phase 14: AWS Connector Framework — Database Migration
-- Additive-only: no existing tables are modified.
-- Safe to run on an existing Phase 1-13 database.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- 1. aws_usage_limits — Bedrock daily usage tracking and cost protection
--    Checked by Go Gateway BEFORE any Bedrock request is forwarded to AWS.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS aws_usage_limits (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Daily counters (reset each day by reset_at column logic)
    daily_requests      INTEGER NOT NULL DEFAULT 0,
    daily_tokens        INTEGER NOT NULL DEFAULT 0,

    -- Hard limits (enforced at gateway level)
    max_daily_requests  INTEGER NOT NULL DEFAULT 100,
    max_daily_tokens    INTEGER NOT NULL DEFAULT 50000,
    max_daily_cost_usd  NUMERIC(10,4) NOT NULL DEFAULT 1.0000,

    -- Cost estimate tracking (approximate, based on token pricing)
    daily_cost_estimate NUMERIC(10,4) NOT NULL DEFAULT 0.0000,

    -- Reset timestamp (gateway resets counters when date changes)
    last_reset          TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_aws_usage_tenant UNIQUE (tenant_id)
);

-- Index for fast gateway lookups by tenant
CREATE INDEX IF NOT EXISTS idx_aws_usage_tenant ON aws_usage_limits(tenant_id);

-- RLS: tenants can only see their own usage limits
ALTER TABLE aws_usage_limits ENABLE ROW LEVEL SECURITY;

CREATE POLICY aws_usage_limits_isolation ON aws_usage_limits
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id')::uuid);

-- Grant access to app user
GRANT SELECT, INSERT, UPDATE ON aws_usage_limits TO authclaw;

-- ---------------------------------------------------------------------------
-- 2. aws_s3_documents — Synced S3 document metadata per tenant
--    Populated by POST /v1/aws/s3/sync. No actual file content stored here.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS aws_s3_documents (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- S3 object metadata
    bucket_name     VARCHAR(255) NOT NULL,
    object_key      TEXT NOT NULL,          -- Full S3 key e.g. tenant-abc123/report.pdf
    file_name       VARCHAR(512) NOT NULL,  -- Basename extracted from key
    file_size_bytes BIGINT,
    content_type    VARCHAR(255),
    last_modified   TIMESTAMP WITH TIME ZONE,

    -- Sync metadata
    synced_at       TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    etag            VARCHAR(255),           -- S3 ETag for change detection

    CONSTRAINT uq_s3_doc_tenant_key UNIQUE (tenant_id, bucket_name, object_key)
);

CREATE INDEX IF NOT EXISTS idx_s3_docs_tenant ON aws_s3_documents(tenant_id);
CREATE INDEX IF NOT EXISTS idx_s3_docs_synced ON aws_s3_documents(synced_at DESC);

-- RLS: tenants can only see their own synced documents
ALTER TABLE aws_s3_documents ENABLE ROW LEVEL SECURITY;

CREATE POLICY aws_s3_docs_isolation ON aws_s3_documents
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id')::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON aws_s3_documents TO authclaw;

-- =============================================================================
-- Completion log
-- =============================================================================
DO $$
BEGIN
    RAISE NOTICE 'Phase 14 AWS migration complete: aws_usage_limits, aws_s3_documents created.';
END
$$;
