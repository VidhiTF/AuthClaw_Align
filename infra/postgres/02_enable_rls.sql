"""
PostgreSQL Row-Level Security (RLS) Policies for Multi-Tenant Isolation
Run this script after initial schema creation to enable RLS.

This script enforces tenant isolation at the database layer,
preventing any query from accessing data outside the current tenant context.
"""

-- Enable RLS on all tenant-scoped tables
ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE gateway_configs ENABLE ROW LEVEL SECURITY;
ALTER TABLE redaction_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE pending_approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log_metadata ENABLE ROW LEVEL SECURITY;

-- Tenants table: Users can only see their own tenant
CREATE POLICY tenants_isolation ON tenants
    FOR SELECT
    USING (id = current_setting('app.current_tenant_id')::uuid);

-- Users table: Users can only see users in their tenant
CREATE POLICY users_isolation ON users
    FOR SELECT
    USING (tenant_id = current_setting('app.current_tenant_id')::uuid);

CREATE POLICY users_insert ON users
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id')::uuid);

CREATE POLICY users_update ON users
    FOR UPDATE
    USING (tenant_id = current_setting('app.current_tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id')::uuid);

CREATE POLICY users_delete ON users
    FOR DELETE
    USING (tenant_id = current_setting('app.current_tenant_id')::uuid);

-- API Keys table: Users can only see API keys in their tenant
CREATE POLICY api_keys_isolation ON api_keys
    FOR SELECT
    USING (tenant_id = current_setting('app.current_tenant_id')::uuid);

CREATE POLICY api_keys_insert ON api_keys
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id')::uuid);

CREATE POLICY api_keys_update ON api_keys
    FOR UPDATE
    USING (tenant_id = current_setting('app.current_tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id')::uuid);

CREATE POLICY api_keys_delete ON api_keys
    FOR DELETE
    USING (tenant_id = current_setting('app.current_tenant_id')::uuid);

-- Policies table: Users can only see policies in their tenant
CREATE POLICY policies_isolation ON policies
    FOR SELECT
    USING (tenant_id = current_setting('app.current_tenant_id')::uuid);

CREATE POLICY policies_insert ON policies
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id')::uuid);

CREATE POLICY policies_update ON policies
    FOR UPDATE
    USING (tenant_id = current_setting('app.current_tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id')::uuid);

CREATE POLICY policies_delete ON policies
    FOR DELETE
    USING (tenant_id = current_setting('app.current_tenant_id')::uuid);

-- Gateway Configs table: Users can only see configs in their tenant
CREATE POLICY gateway_configs_isolation ON gateway_configs
    FOR SELECT
    USING (tenant_id = current_setting('app.current_tenant_id')::uuid);

CREATE POLICY gateway_configs_insert ON gateway_configs
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id')::uuid);

CREATE POLICY gateway_configs_update ON gateway_configs
    FOR UPDATE
    USING (tenant_id = current_setting('app.current_tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id')::uuid);

CREATE POLICY gateway_configs_delete ON gateway_configs
    FOR DELETE
    USING (tenant_id = current_setting('app.current_tenant_id')::uuid);

-- Redaction Tokens table: Users can only see tokens for their tenant
CREATE POLICY redaction_tokens_isolation ON redaction_tokens
    FOR SELECT
    USING (tenant_id = current_setting('app.current_tenant_id')::uuid);

CREATE POLICY redaction_tokens_insert ON redaction_tokens
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id')::uuid);

-- Pending Approvals table: Users can only see approvals in their tenant
CREATE POLICY pending_approvals_isolation ON pending_approvals
    FOR SELECT
    USING (tenant_id = current_setting('app.current_tenant_id')::uuid);

CREATE POLICY pending_approvals_insert ON pending_approvals
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id')::uuid);

CREATE POLICY pending_approvals_update ON pending_approvals
    FOR UPDATE
    USING (tenant_id = current_setting('app.current_tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id')::uuid);

-- Audit Log Metadata table: Users can only see audit logs for their tenant
CREATE POLICY audit_log_metadata_isolation ON audit_log_metadata
    FOR SELECT
    USING (tenant_id = current_setting('app.current_tenant_id')::uuid);

CREATE POLICY audit_log_metadata_insert ON audit_log_metadata
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id')::uuid);

-- Grant permissions to app user
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO authclaw;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO authclaw;

-- Log RLS activation for verification
SELECT * FROM pg_policies WHERE schemaname = 'public' LIMIT 1;
