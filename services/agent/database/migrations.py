import json
import logging
from datetime import datetime, timedelta
from sqlalchemy import text
from database import engine

logger = logging.getLogger("authclaw.database.migrations")

def run_startup_migrations():
    """
    Runs database migrations to create and seed all required tables.
    Fails application startup if migrations fail.
    """
    migration_sql = """
    -- Core Audit Logs
    CREATE TABLE IF NOT EXISTS audit_logs (
        id SERIAL PRIMARY KEY,
        user_query TEXT,
        response TEXT,
        allowed BOOLEAN,
        created_at TIMESTAMP,
        risk_level VARCHAR(20),
        approval_status VARCHAR(50),
        integrity_hash VARCHAR(64),
        previous_hash VARCHAR(64)
    );

    ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS user_query TEXT;
    ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS response TEXT;
    ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS allowed BOOLEAN;
    ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS created_at TIMESTAMP;
    ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS risk_level VARCHAR(20);
    ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS approval_status VARCHAR(50);
    ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS integrity_hash VARCHAR(64);
    ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS previous_hash VARCHAR(64);
    ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS approval_id VARCHAR(100);
    ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS approver VARCHAR(100);
    ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS original_request TEXT;
    ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS approval_timestamp TIMESTAMP;
    ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS execution_timestamp TIMESTAMP;
    ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS execution_status VARCHAR(50);
    ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS policy_name VARCHAR(100);
    ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS policy_type VARCHAR(50);
    ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS matched_pattern VARCHAR(100);
    ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS redacted_value TEXT;
    ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS username VARCHAR(100);

    -- Gateway Request Logs
    CREATE TABLE IF NOT EXISTS gateway_requests (
        id SERIAL PRIMARY KEY,
        timestamp TIMESTAMP NOT NULL,
        risk_level VARCHAR(20) DEFAULT 'LOW',
        allowed BOOLEAN DEFAULT TRUE,
        status VARCHAR(50) DEFAULT 'allowed',
        request_id VARCHAR(50),
        tenant_id VARCHAR(50) DEFAULT 'tenant-default',
        route_id VARCHAR(50),
        provider VARCHAR(50),
        model VARCHAR(50),
        latency INTEGER DEFAULT 0,
        tokens_in INTEGER DEFAULT 0,
        tokens_out INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        decision VARCHAR(50),
        duration_ms INTEGER
    );

    ALTER TABLE gateway_requests ADD COLUMN IF NOT EXISTS timestamp TIMESTAMP;
    ALTER TABLE gateway_requests ADD COLUMN IF NOT EXISTS risk_level VARCHAR(20);
    ALTER TABLE gateway_requests ADD COLUMN IF NOT EXISTS allowed BOOLEAN;
    ALTER TABLE gateway_requests ADD COLUMN IF NOT EXISTS status VARCHAR(50);
    ALTER TABLE gateway_requests ADD COLUMN IF NOT EXISTS request_id VARCHAR(50);
    ALTER TABLE gateway_requests ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(50);
    ALTER TABLE gateway_requests ADD COLUMN IF NOT EXISTS route_id VARCHAR(50);
    ALTER TABLE gateway_requests ADD COLUMN IF NOT EXISTS provider VARCHAR(50);
    ALTER TABLE gateway_requests ADD COLUMN IF NOT EXISTS model VARCHAR(50);
    ALTER TABLE gateway_requests ADD COLUMN IF NOT EXISTS latency INTEGER;
    ALTER TABLE gateway_requests ADD COLUMN IF NOT EXISTS tokens_in INTEGER;
    ALTER TABLE gateway_requests ADD COLUMN IF NOT EXISTS tokens_out INTEGER;
    ALTER TABLE gateway_requests ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;
    ALTER TABLE gateway_requests ADD COLUMN IF NOT EXISTS decision VARCHAR(50);
    ALTER TABLE gateway_requests ADD COLUMN IF NOT EXISTS duration_ms INTEGER;

    -- Gateway Routes
    CREATE TABLE IF NOT EXISTS gateway_routes (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        provider VARCHAR(50) NOT NULL,
        endpoint VARCHAR(255) NOT NULL,
        model VARCHAR(50) NOT NULL,
        rate_limit INTEGER DEFAULT 100,
        redaction_enabled BOOLEAN DEFAULT TRUE,
        enabled BOOLEAN DEFAULT TRUE,
        tenant_assignment VARCHAR(100) DEFAULT 'tenant-default'
    );

    -- Tenants
    CREATE TABLE IF NOT EXISTS tenants (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        status VARCHAR(20) DEFAULT 'active',
        usage_count INTEGER DEFAULT 0,
        tokens_used INTEGER DEFAULT 0,
        domain VARCHAR(255),
        email VARCHAR(255),
        password_hash VARCHAR(255),
        email_verified BOOLEAN DEFAULT FALSE,
        email_verification_token VARCHAR(255),
        domain_verified BOOLEAN DEFAULT FALSE,
        domain_verification_token VARCHAR(255),
        totp_secret VARCHAR(32),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    ALTER TABLE tenants ADD COLUMN IF NOT EXISTS domain VARCHAR(255);
    ALTER TABLE tenants ADD COLUMN IF NOT EXISTS email VARCHAR(255);
    ALTER TABLE tenants ADD COLUMN IF NOT EXISTS password_hash VARCHAR(255);
    ALTER TABLE tenants ADD COLUMN IF NOT EXISTS email_verified BOOLEAN DEFAULT FALSE;
    ALTER TABLE tenants ADD COLUMN IF NOT EXISTS email_verification_token VARCHAR(255);
    ALTER TABLE tenants ADD COLUMN IF NOT EXISTS domain_verified BOOLEAN DEFAULT FALSE;
    ALTER TABLE tenants ADD COLUMN IF NOT EXISTS domain_verification_token VARCHAR(255);
    ALTER TABLE tenants ADD COLUMN IF NOT EXISTS totp_secret VARCHAR(32);
    ALTER TABLE tenants ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;
    ALTER TABLE tenants ADD COLUMN IF NOT EXISTS subscription_tier VARCHAR(50) DEFAULT 'enterprise';
    ALTER TABLE tenants ADD COLUMN IF NOT EXISTS plan VARCHAR(50) DEFAULT 'enterprise';
    ALTER TABLE tenants ADD COLUMN IF NOT EXISTS tier VARCHAR(50) DEFAULT 'enterprise';
    ALTER TABLE tenants ADD COLUMN IF NOT EXISTS plan_override TEXT;
    ALTER TABLE tenants ADD COLUMN IF NOT EXISTS plan_updated_at TIMESTAMP;
    ALTER TABLE tenants DROP CONSTRAINT IF EXISTS tenants_name_key;
    ALTER TABLE gateway_routes ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES tenants(id) ON DELETE CASCADE;

    -- Pending Customer Onboarding
    CREATE TABLE IF NOT EXISTS onboarding_registrations (
        id SERIAL PRIMARY KEY,
        organization_name VARCHAR(255) NOT NULL,
        full_name VARCHAR(255) NOT NULL,
        work_email VARCHAR(255) NOT NULL UNIQUE,
        domain VARCHAR(255) NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        email_verification_token VARCHAR(255) NOT NULL UNIQUE,
        domain_verification_token VARCHAR(255) NOT NULL,
        email_verified BOOLEAN DEFAULT FALSE,
        domain_verified BOOLEAN DEFAULT FALSE,
        tenant_id INTEGER REFERENCES tenants(id) ON DELETE SET NULL,
        totp_secret VARCHAR(32) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        email_verified_at TIMESTAMP,
        domain_verified_at TIMESTAMP,
        activated_at TIMESTAMP
    );

    ALTER TABLE onboarding_registrations ADD COLUMN IF NOT EXISTS full_name VARCHAR(255);
    ALTER TABLE onboarding_registrations ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES tenants(id) ON DELETE SET NULL;
    ALTER TABLE onboarding_registrations ADD COLUMN IF NOT EXISTS email_verified_at TIMESTAMP;
    ALTER TABLE onboarding_registrations ADD COLUMN IF NOT EXISTS domain_verified_at TIMESTAMP;
    ALTER TABLE onboarding_registrations ADD COLUMN IF NOT EXISTS activated_at TIMESTAMP;
    ALTER TABLE onboarding_registrations DROP CONSTRAINT IF EXISTS onboarding_registrations_domain_key;

    -- Tenant-Scoped Users
    CREATE TABLE IF NOT EXISTS tenant_users (
        id SERIAL PRIMARY KEY,
        tenant_id INTEGER REFERENCES tenants(id) ON DELETE CASCADE,
        first_name VARCHAR(100),
        last_name VARCHAR(100),
        email VARCHAR(255) NOT NULL UNIQUE,
        password_hash VARCHAR(255) NOT NULL,
        role VARCHAR(50) NOT NULL DEFAULT 'Super Admin',
        permissions TEXT NOT NULL DEFAULT 'all_access',
        email_verified BOOLEAN DEFAULT FALSE,
        mfa_enabled BOOLEAN DEFAULT TRUE,
        totp_secret VARCHAR(32),
        status VARCHAR(20) DEFAULT 'active',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login_at TIMESTAMP
    );

    ALTER TABLE tenant_users ADD COLUMN IF NOT EXISTS first_name VARCHAR(100);
    ALTER TABLE tenant_users ADD COLUMN IF NOT EXISTS last_name VARCHAR(100);
    ALTER TABLE tenant_users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN DEFAULT FALSE;
    ALTER TABLE tenant_users ADD COLUMN IF NOT EXISTS mfa_enabled BOOLEAN DEFAULT TRUE;
    ALTER TABLE tenant_users ADD COLUMN IF NOT EXISTS totp_secret VARCHAR(32);
    ALTER TABLE tenant_users ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'active';
    ALTER TABLE tenant_users ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;
    ALTER TABLE tenant_users ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMP;

    -- Persistent Refresh Token Lifecycle
    CREATE TABLE IF NOT EXISTS auth_refresh_tokens (
        jti VARCHAR(100) PRIMARY KEY,
        tenant_id INTEGER REFERENCES tenants(id) ON DELETE CASCADE,
        user_id INTEGER REFERENCES tenant_users(id) ON DELETE CASCADE,
        subject VARCHAR(255) NOT NULL,
        issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP NOT NULL,
        revoked_at TIMESTAMP
    );

    -- Tenant API Keys (SHA-256 Hashed)
    CREATE TABLE IF NOT EXISTS tenant_api_keys (
        id SERIAL PRIMARY KEY,
        tenant_id INTEGER REFERENCES tenants(id) ON DELETE CASCADE,
        name VARCHAR(100) NOT NULL,
        key_hash VARCHAR(64) NOT NULL UNIQUE,
        key_prefix VARCHAR(16),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_used_at TIMESTAMP,
        expires_at TIMESTAMP,
        revoked_at TIMESTAMP
    );

    ALTER TABLE tenant_api_keys ADD COLUMN IF NOT EXISTS key_prefix VARCHAR(16);
    ALTER TABLE tenant_api_keys ADD COLUMN IF NOT EXISTS expires_at TIMESTAMP;
    ALTER TABLE tenant_api_keys ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMP;

    -- Persistent MFA Sessions
    CREATE TABLE IF NOT EXISTS auth_mfa_sessions (
        session_id VARCHAR(100) PRIMARY KEY,
        username VARCHAR(255) NOT NULL,
        role VARCHAR(50) NOT NULL,
        permissions TEXT NOT NULL,
        tenant_id INTEGER REFERENCES tenants(id) ON DELETE CASCADE,
        user_id INTEGER REFERENCES tenant_users(id) ON DELETE CASCADE,
        email_verified BOOLEAN DEFAULT FALSE,
        domain_verified BOOLEAN DEFAULT FALSE,
        step VARCHAR(20) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP NOT NULL
    );

    ALTER TABLE auth_mfa_sessions ADD COLUMN IF NOT EXISTS user_id INTEGER REFERENCES tenant_users(id) ON DELETE CASCADE;

    -- Password Reset Tokens (hashed, single-use)
    CREATE TABLE IF NOT EXISTS auth_password_reset_tokens (
        token_hash VARCHAR(64) PRIMARY KEY,
        tenant_id INTEGER REFERENCES tenants(id) ON DELETE CASCADE,
        user_id INTEGER REFERENCES tenant_users(id) ON DELETE CASCADE,
        email VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP NOT NULL,
        used_at TIMESTAMP
    );

    -- Tenant Enterprise Identity Provider Configuration (OIDC / SSO)
    CREATE TABLE IF NOT EXISTS tenant_identity_providers (
        id SERIAL PRIMARY KEY,
        tenant_id INTEGER REFERENCES tenants(id) ON DELETE CASCADE,
        provider_type VARCHAR(50) NOT NULL,
        display_name VARCHAR(255) NOT NULL,
        client_id VARCHAR(255) NOT NULL,
        encrypted_client_secret TEXT NOT NULL,
        discovery_url TEXT,
        issuer TEXT NOT NULL,
        authorization_endpoint TEXT NOT NULL,
        token_endpoint TEXT NOT NULL,
        userinfo_endpoint TEXT,
        jwks_uri TEXT NOT NULL,
        redirect_uri TEXT NOT NULL,
        scopes TEXT DEFAULT 'openid email profile offline_access',
        groups_claim VARCHAR(100) DEFAULT 'groups',
        role_mapping TEXT DEFAULT '{}',
        enabled BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT uniq_tenant_identity_provider_client UNIQUE(tenant_id, provider_type, client_id)
    );

    ALTER TABLE tenant_identity_providers ADD COLUMN IF NOT EXISTS provider_type VARCHAR(50);
    ALTER TABLE tenant_identity_providers ADD COLUMN IF NOT EXISTS display_name VARCHAR(255);
    ALTER TABLE tenant_identity_providers ADD COLUMN IF NOT EXISTS client_id VARCHAR(255);
    ALTER TABLE tenant_identity_providers ADD COLUMN IF NOT EXISTS encrypted_client_secret TEXT;
    ALTER TABLE tenant_identity_providers ADD COLUMN IF NOT EXISTS discovery_url TEXT;
    ALTER TABLE tenant_identity_providers ADD COLUMN IF NOT EXISTS issuer TEXT;
    ALTER TABLE tenant_identity_providers ADD COLUMN IF NOT EXISTS authorization_endpoint TEXT;
    ALTER TABLE tenant_identity_providers ADD COLUMN IF NOT EXISTS token_endpoint TEXT;
    ALTER TABLE tenant_identity_providers ADD COLUMN IF NOT EXISTS userinfo_endpoint TEXT;
    ALTER TABLE tenant_identity_providers ADD COLUMN IF NOT EXISTS jwks_uri TEXT;
    ALTER TABLE tenant_identity_providers ADD COLUMN IF NOT EXISTS redirect_uri TEXT;
    ALTER TABLE tenant_identity_providers ADD COLUMN IF NOT EXISTS scopes TEXT DEFAULT 'openid email profile offline_access';
    ALTER TABLE tenant_identity_providers ADD COLUMN IF NOT EXISTS groups_claim VARCHAR(100) DEFAULT 'groups';
    ALTER TABLE tenant_identity_providers ADD COLUMN IF NOT EXISTS role_mapping TEXT DEFAULT '{}';
    ALTER TABLE tenant_identity_providers ADD COLUMN IF NOT EXISTS enabled BOOLEAN DEFAULT TRUE;
    ALTER TABLE tenant_identity_providers ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;
    ALTER TABLE tenant_identity_providers ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;

    CREATE TABLE IF NOT EXISTS oidc_login_states (
        state_hash VARCHAR(64) PRIMARY KEY,
        tenant_id INTEGER REFERENCES tenants(id) ON DELETE CASCADE,
        provider_id INTEGER REFERENCES tenant_identity_providers(id) ON DELETE CASCADE,
        code_verifier TEXT NOT NULL,
        nonce VARCHAR(255) NOT NULL,
        redirect_uri TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP NOT NULL,
        used_at TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS oidc_jwks_cache (
        provider_id INTEGER PRIMARY KEY REFERENCES tenant_identity_providers(id) ON DELETE CASCADE,
        tenant_id INTEGER REFERENCES tenants(id) ON DELETE CASCADE,
        jwks_json TEXT NOT NULL,
        refreshed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP NOT NULL,
        last_error TEXT
    );

    CREATE TABLE IF NOT EXISTS oidc_user_sessions (
        id SERIAL PRIMARY KEY,
        tenant_id INTEGER REFERENCES tenants(id) ON DELETE CASCADE,
        provider_id INTEGER REFERENCES tenant_identity_providers(id) ON DELETE CASCADE,
        user_id INTEGER REFERENCES tenant_users(id) ON DELETE CASCADE,
        provider_subject VARCHAR(255),
        encrypted_provider_refresh_token TEXT,
        token_version INTEGER DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        revoked_at TIMESTAMP,
        CONSTRAINT uniq_oidc_provider_user_session UNIQUE(provider_id, user_id)
    );

    ALTER TABLE oidc_user_sessions ADD COLUMN IF NOT EXISTS provider_subject VARCHAR(255);
    ALTER TABLE oidc_user_sessions ADD COLUMN IF NOT EXISTS encrypted_provider_refresh_token TEXT;
    ALTER TABLE oidc_user_sessions ADD COLUMN IF NOT EXISTS token_version INTEGER DEFAULT 1;
    ALTER TABLE oidc_user_sessions ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMP;

    -- Provider Credentials (Encrypted)
    CREATE TABLE IF NOT EXISTS tenant_credentials (
        id SERIAL PRIMARY KEY,
        tenant_id INTEGER REFERENCES tenants(id) ON DELETE CASCADE,
        provider VARCHAR(50) NOT NULL,
        encrypted_payload TEXT NOT NULL,
        secret_ref TEXT,
        secret_backend VARCHAR(50) DEFAULT 'database_fernet',
        secret_version VARCHAR(255),
        key_fingerprint VARCHAR(64),
        key_prefix VARCHAR(32),
        health_status VARCHAR(50) DEFAULT 'unknown',
        health_checked_at TIMESTAMP,
        health_message TEXT,
        rotated_at TIMESTAMP,
        revoked_at TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT uniq_tenant_prov UNIQUE(tenant_id, provider)
    );

    ALTER TABLE tenant_credentials ADD COLUMN IF NOT EXISTS secret_ref TEXT;
    ALTER TABLE tenant_credentials ADD COLUMN IF NOT EXISTS secret_backend VARCHAR(50) DEFAULT 'database_fernet';
    ALTER TABLE tenant_credentials ADD COLUMN IF NOT EXISTS secret_version VARCHAR(255);
    ALTER TABLE tenant_credentials ADD COLUMN IF NOT EXISTS key_fingerprint VARCHAR(64);
    ALTER TABLE tenant_credentials ADD COLUMN IF NOT EXISTS key_prefix VARCHAR(32);
    ALTER TABLE tenant_credentials ADD COLUMN IF NOT EXISTS health_status VARCHAR(50) DEFAULT 'unknown';
    ALTER TABLE tenant_credentials ADD COLUMN IF NOT EXISTS health_checked_at TIMESTAMP;
    ALTER TABLE tenant_credentials ADD COLUMN IF NOT EXISTS health_message TEXT;
    ALTER TABLE tenant_credentials ADD COLUMN IF NOT EXISTS rotated_at TIMESTAMP;
    ALTER TABLE tenant_credentials ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMP;

    -- Agent Trace Events
    CREATE TABLE IF NOT EXISTS agent_events (
        id SERIAL PRIMARY KEY,
        tenant_id INTEGER REFERENCES tenants(id) ON DELETE CASCADE,
        session_id VARCHAR(100) NOT NULL,
        message_id VARCHAR(100),
        request_id VARCHAR(50),
        sequence INTEGER,
        agent_name VARCHAR(50) NOT NULL,
        event_type VARCHAR(100) NOT NULL,
        details TEXT NOT NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    ALTER TABLE agent_events ADD COLUMN IF NOT EXISTS request_id VARCHAR(50);
    ALTER TABLE agent_events ADD COLUMN IF NOT EXISTS sequence INTEGER;

    -- Persistent Gateway Approvals
    CREATE TABLE IF NOT EXISTS gateway_approvals (
        id SERIAL PRIMARY KEY,
        approval_id VARCHAR(100) NOT NULL UNIQUE,
        request_id VARCHAR(100),
        correlation_id VARCHAR(100),
        tenant_id INTEGER REFERENCES tenants(id) ON DELETE SET NULL,
        status VARCHAR(50) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP,
        approved_at TIMESTAMP,
        rejected_at TIMESTAMP,
        executed_at TIMESTAMP,
        requested_action TEXT,
        query TEXT,
        risk_level VARCHAR(20),
        audit_id INTEGER REFERENCES audit_logs(id) ON DELETE SET NULL,
        reason VARCHAR(100),
        comments TEXT,
        approved_by VARCHAR(255),
        rejected_by VARCHAR(255),
        executed_by VARCHAR(255),
        mfa_verified BOOLEAN DEFAULT FALSE,
        last_action_at TIMESTAMP,
        metadata TEXT,
        approval_mfa_verified BOOLEAN DEFAULT FALSE,
        execution_mfa_verified BOOLEAN DEFAULT FALSE,
        approval_mfa_binding_hash VARCHAR(64),
        execution_mfa_binding_hash VARCHAR(64),
        approval_mfa_counter BIGINT,
        execution_mfa_counter BIGINT,
        execution_token_hash VARCHAR(64),
        execution_token_used_at TIMESTAMP,
        execution_expires_at TIMESTAMP
    );

    ALTER TABLE gateway_approvals ADD COLUMN IF NOT EXISTS approval_id VARCHAR(100);
    ALTER TABLE gateway_approvals ADD COLUMN IF NOT EXISTS request_id VARCHAR(100);
    ALTER TABLE gateway_approvals ADD COLUMN IF NOT EXISTS correlation_id VARCHAR(100);
    ALTER TABLE gateway_approvals ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES tenants(id) ON DELETE SET NULL;
    ALTER TABLE gateway_approvals ADD COLUMN IF NOT EXISTS status VARCHAR(50);
    ALTER TABLE gateway_approvals ADD COLUMN IF NOT EXISTS created_at TIMESTAMP;
    ALTER TABLE gateway_approvals ADD COLUMN IF NOT EXISTS expires_at TIMESTAMP;
    ALTER TABLE gateway_approvals ADD COLUMN IF NOT EXISTS approved_at TIMESTAMP;
    ALTER TABLE gateway_approvals ADD COLUMN IF NOT EXISTS rejected_at TIMESTAMP;
    ALTER TABLE gateway_approvals ADD COLUMN IF NOT EXISTS executed_at TIMESTAMP;
    ALTER TABLE gateway_approvals ADD COLUMN IF NOT EXISTS requested_action TEXT;
    ALTER TABLE gateway_approvals ADD COLUMN IF NOT EXISTS query TEXT;
    ALTER TABLE gateway_approvals ADD COLUMN IF NOT EXISTS risk_level VARCHAR(20);
    ALTER TABLE gateway_approvals ADD COLUMN IF NOT EXISTS audit_id INTEGER REFERENCES audit_logs(id) ON DELETE SET NULL;
    ALTER TABLE gateway_approvals ADD COLUMN IF NOT EXISTS reason VARCHAR(100);
    ALTER TABLE gateway_approvals ADD COLUMN IF NOT EXISTS comments TEXT;
    ALTER TABLE gateway_approvals ADD COLUMN IF NOT EXISTS approved_by VARCHAR(255);
    ALTER TABLE gateway_approvals ADD COLUMN IF NOT EXISTS rejected_by VARCHAR(255);
    ALTER TABLE gateway_approvals ADD COLUMN IF NOT EXISTS executed_by VARCHAR(255);
    ALTER TABLE gateway_approvals ADD COLUMN IF NOT EXISTS mfa_verified BOOLEAN DEFAULT FALSE;
    ALTER TABLE gateway_approvals ADD COLUMN IF NOT EXISTS last_action_at TIMESTAMP;
    ALTER TABLE gateway_approvals ADD COLUMN IF NOT EXISTS metadata TEXT;
    ALTER TABLE gateway_approvals ADD COLUMN IF NOT EXISTS approval_mfa_verified BOOLEAN DEFAULT FALSE;
    ALTER TABLE gateway_approvals ADD COLUMN IF NOT EXISTS execution_mfa_verified BOOLEAN DEFAULT FALSE;
    ALTER TABLE gateway_approvals ADD COLUMN IF NOT EXISTS approval_mfa_binding_hash VARCHAR(64);
    ALTER TABLE gateway_approvals ADD COLUMN IF NOT EXISTS execution_mfa_binding_hash VARCHAR(64);
    ALTER TABLE gateway_approvals ADD COLUMN IF NOT EXISTS approval_mfa_counter BIGINT;
    ALTER TABLE gateway_approvals ADD COLUMN IF NOT EXISTS execution_mfa_counter BIGINT;
    ALTER TABLE gateway_approvals ADD COLUMN IF NOT EXISTS execution_token_hash VARCHAR(64);
    ALTER TABLE gateway_approvals ADD COLUMN IF NOT EXISTS execution_token_used_at TIMESTAMP;
    ALTER TABLE gateway_approvals ADD COLUMN IF NOT EXISTS execution_expires_at TIMESTAMP;

    CREATE TABLE IF NOT EXISTS approval_audit_events (
        id SERIAL PRIMARY KEY,
        tenant_id INTEGER REFERENCES tenants(id) ON DELETE CASCADE,
        approval_id VARCHAR(100),
        request_id VARCHAR(100),
        action VARCHAR(50) NOT NULL,
        actor VARCHAR(255),
        comment TEXT,
        mfa_verified BOOLEAN DEFAULT FALSE,
        reason VARCHAR(100),
        metadata TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    -- Usage Events
    CREATE TABLE IF NOT EXISTS usage_events (
        id SERIAL PRIMARY KEY,
        tenant_id INTEGER REFERENCES tenants(id) ON DELETE CASCADE,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        tokens_in INTEGER DEFAULT 0,
        tokens_out INTEGER DEFAULT 0,
        provider VARCHAR(50) NOT NULL,
        cost_estimation NUMERIC(8, 4) DEFAULT 0.0
    );

    -- Secrets/API Keys (Existing Legacy)
    CREATE TABLE IF NOT EXISTS secrets (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        provider VARCHAR(50) NOT NULL,
        key_hash VARCHAR(100) NOT NULL,
        expiry VARCHAR(20) NOT NULL,
        last_rotated VARCHAR(20) NOT NULL,
        rotation_count INTEGER DEFAULT 0
    );

    -- Policies (Database-Driven)
    CREATE TABLE IF NOT EXISTS policies (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        type VARCHAR(50) NOT NULL,
        rules TEXT NOT NULL,
        enabled BOOLEAN DEFAULT TRUE,
        tenant_id INTEGER REFERENCES tenants(id) ON DELETE CASCADE,
        severity_level VARCHAR(20) DEFAULT 'MEDIUM'
    );

    ALTER TABLE policies ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES tenants(id) ON DELETE CASCADE;
    ALTER TABLE policies ADD COLUMN IF NOT EXISTS severity_level VARCHAR(20) DEFAULT 'MEDIUM';
    ALTER TABLE policies ADD COLUMN IF NOT EXISTS version INTEGER DEFAULT 1;
    ALTER TABLE policies ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'published';
    ALTER TABLE policies ADD COLUMN IF NOT EXISTS published_at TIMESTAMP;
    ALTER TABLE policies ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT NOW();
    ALTER TABLE policies ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT NOW();
    ALTER TABLE policies ADD COLUMN IF NOT EXISTS created_by VARCHAR(255);
    ALTER TABLE policies ADD COLUMN IF NOT EXISTS updated_by VARCHAR(255);
    ALTER TABLE policies ADD COLUMN IF NOT EXISTS checksum VARCHAR(128);
    ALTER TABLE policies ADD COLUMN IF NOT EXISTS changelog TEXT;
    ALTER TABLE policies ADD COLUMN IF NOT EXISTS approved_by VARCHAR(255);
    ALTER TABLE policies ADD COLUMN IF NOT EXISTS approved_at TIMESTAMP;
    ALTER TABLE policies ADD COLUMN IF NOT EXISTS archived_at TIMESTAMP;
    ALTER TABLE policies ADD COLUMN IF NOT EXISTS deprecated_at TIMESTAMP;

    CREATE TABLE IF NOT EXISTS policy_audit_history (
        id SERIAL PRIMARY KEY,
        tenant_id INTEGER REFERENCES tenants(id) ON DELETE CASCADE,
        policy_id INTEGER REFERENCES policies(id) ON DELETE SET NULL,
        action VARCHAR(50) NOT NULL,
        actor VARCHAR(255),
        before_rules TEXT,
        after_rules TEXT,
        version INTEGER DEFAULT 1,
        status VARCHAR(20) DEFAULT 'published',
        created_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS policy_versions (
        id SERIAL PRIMARY KEY,
        tenant_id INTEGER REFERENCES tenants(id) ON DELETE CASCADE,
        policy_id INTEGER REFERENCES policies(id) ON DELETE CASCADE,
        version INTEGER NOT NULL,
        status VARCHAR(30) DEFAULT 'draft',
        rules TEXT NOT NULL,
        checksum VARCHAR(128) NOT NULL,
        author VARCHAR(255),
        approver VARCHAR(255),
        changelog TEXT,
        created_at TIMESTAMP DEFAULT NOW(),
        approved_at TIMESTAMP,
        published_at TIMESTAMP,
        archived_at TIMESTAMP,
        UNIQUE(policy_id, version)
    );

    CREATE TABLE IF NOT EXISTS policy_change_approvals (
        id SERIAL PRIMARY KEY,
        tenant_id INTEGER REFERENCES tenants(id) ON DELETE CASCADE,
        policy_id INTEGER REFERENCES policies(id) ON DELETE CASCADE,
        version_id INTEGER REFERENCES policy_versions(id) ON DELETE SET NULL,
        status VARCHAR(30) DEFAULT 'pending',
        requested_by VARCHAR(255),
        reviewed_by VARCHAR(255),
        comments TEXT,
        created_at TIMESTAMP DEFAULT NOW(),
        decided_at TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS policy_simulation_results (
        id SERIAL PRIMARY KEY,
        tenant_id INTEGER REFERENCES tenants(id) ON DELETE CASCADE,
        policy_id INTEGER REFERENCES policies(id) ON DELETE SET NULL,
        actor VARCHAR(255),
        sample_hash VARCHAR(128),
        result TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS policy_evaluation_audit (
        id SERIAL PRIMARY KEY,
        tenant_id INTEGER REFERENCES tenants(id) ON DELETE CASCADE,
        request_id VARCHAR(100),
        route_path VARCHAR(255),
        decision VARCHAR(40) NOT NULL,
        reason TEXT,
        evaluation_time_ms INTEGER DEFAULT 0,
        matched_policies TEXT,
        policy_versions TEXT,
        created_at TIMESTAMP DEFAULT NOW()
    );

    -- RAG Documents
    CREATE TABLE IF NOT EXISTS knowledge_documents (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        type VARCHAR(20) NOT NULL, -- PDF, DOCX, TXT
        size_bytes INTEGER NOT NULL,
        status VARCHAR(20) DEFAULT 'indexed',
        last_indexed VARCHAR(20) NOT NULL,
        chunks_count INTEGER DEFAULT 0
    );

    -- RAG Chunks
    CREATE TABLE IF NOT EXISTS knowledge_chunks (
        id SERIAL PRIMARY KEY,
        document_id INTEGER NOT NULL,
        content TEXT NOT NULL,
        embedding_preview VARCHAR(100) NOT NULL,
        embedding_vector TEXT
    );

    ALTER TABLE knowledge_chunks ADD COLUMN IF NOT EXISTS embedding_vector TEXT;
    ALTER TABLE knowledge_documents ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES tenants(id) ON DELETE CASCADE;
    ALTER TABLE knowledge_chunks ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES tenants(id) ON DELETE CASCADE;

    -- Ephemeral Workers
    CREATE TABLE IF NOT EXISTS ephemeral_workers (
        id SERIAL PRIMARY KEY,
        provider VARCHAR(50) NOT NULL, -- AWS, GCP, GitHub
        status VARCHAR(20) DEFAULT 'completed',
        lifespan_seconds INTEGER DEFAULT 30,
        started_at VARCHAR(30) NOT NULL,
        logs TEXT NOT NULL,
        cost NUMERIC(6, 2) DEFAULT 0.00,
        tokens_used INTEGER DEFAULT 0
    );

    -- Remediation findings
    CREATE TABLE IF NOT EXISTS remediation_findings (
        id SERIAL PRIMARY KEY,
        finding VARCHAR(255) NOT NULL,
        recommendation TEXT NOT NULL,
        severity VARCHAR(20) NOT NULL, -- HIGH, MEDIUM, LOW
        fix_plan TEXT NOT NULL,
        approval_status VARCHAR(20) DEFAULT 'pending'
    );

    ALTER TABLE remediation_findings ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES tenants(id) ON DELETE CASCADE;
    ALTER TABLE remediation_findings ADD COLUMN IF NOT EXISTS connector_id INTEGER;
    ALTER TABLE remediation_findings ADD COLUMN IF NOT EXISTS provider VARCHAR(50);
    ALTER TABLE remediation_findings ADD COLUMN IF NOT EXISTS resource_id VARCHAR(255);
    ALTER TABLE remediation_findings ADD COLUMN IF NOT EXISTS finding_type VARCHAR(100);
    ALTER TABLE remediation_findings ADD COLUMN IF NOT EXISTS status VARCHAR(50) DEFAULT 'open';
    ALTER TABLE remediation_findings ADD COLUMN IF NOT EXISTS worker_id VARCHAR(100);
    ALTER TABLE remediation_findings ADD COLUMN IF NOT EXISTS evidence TEXT;
    ALTER TABLE remediation_findings ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;
    ALTER TABLE remediation_findings ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;

    CREATE TABLE IF NOT EXISTS remediation_connectors (
        id SERIAL PRIMARY KEY,
        tenant_id INTEGER REFERENCES tenants(id) ON DELETE CASCADE,
        provider VARCHAR(50) NOT NULL,
        name VARCHAR(255) NOT NULL,
        credential_ref TEXT NOT NULL,
        role_identifier TEXT,
        region VARCHAR(100),
        scope TEXT,
        status VARCHAR(50) DEFAULT 'configured',
        health_message TEXT,
        last_tested_at TIMESTAMP,
        metadata TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT uniq_remediation_connector UNIQUE(tenant_id, provider, name)
    );

    CREATE TABLE IF NOT EXISTS worker_credential_leases (
        lease_id VARCHAR(100) PRIMARY KEY,
        tenant_id INTEGER REFERENCES tenants(id) ON DELETE CASCADE,
        connector_id INTEGER REFERENCES remediation_connectors(id) ON DELETE CASCADE,
        provider VARCHAR(50) NOT NULL,
        scope TEXT NOT NULL,
        token_hash VARCHAR(64) NOT NULL,
        issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP NOT NULL,
        revoked_at TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS remediation_worker_runs (
        worker_id VARCHAR(100) PRIMARY KEY,
        tenant_id INTEGER REFERENCES tenants(id) ON DELETE CASCADE,
        connector_id INTEGER REFERENCES remediation_connectors(id) ON DELETE SET NULL,
        provider VARCHAR(50) NOT NULL,
        mode VARCHAR(50) NOT NULL,
        status VARCHAR(50) NOT NULL,
        credential_lease_id VARCHAR(100) REFERENCES worker_credential_leases(lease_id) ON DELETE SET NULL,
        finding_id INTEGER,
        plan_id INTEGER,
        approval_id VARCHAR(100),
        started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        completed_at TIMESTAMP,
        expires_at TIMESTAMP NOT NULL,
        logs TEXT,
        evidence TEXT,
        error TEXT
    );

    CREATE TABLE IF NOT EXISTS remediation_plans (
        id SERIAL PRIMARY KEY,
        tenant_id INTEGER REFERENCES tenants(id) ON DELETE CASCADE,
        finding_id INTEGER REFERENCES remediation_findings(id) ON DELETE CASCADE,
        connector_id INTEGER REFERENCES remediation_connectors(id) ON DELETE SET NULL,
        provider VARCHAR(50) NOT NULL,
        resource_id VARCHAR(255) NOT NULL,
        proposed_action VARCHAR(100) NOT NULL,
        risk_level VARCHAR(20) NOT NULL,
        rollback_plan TEXT NOT NULL,
        evidence_requirements TEXT NOT NULL,
        status VARCHAR(50) DEFAULT 'planned',
        approval_id VARCHAR(100),
        plan_payload TEXT NOT NULL,
        execution_evidence TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS remediation_worker_audit_events (
        id SERIAL PRIMARY KEY,
        tenant_id INTEGER REFERENCES tenants(id) ON DELETE CASCADE,
        worker_id VARCHAR(100),
        connector_id INTEGER,
        finding_id INTEGER,
        plan_id INTEGER,
        approval_id VARCHAR(100),
        event_type VARCHAR(100) NOT NULL,
        details TEXT NOT NULL,
        metadata TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    -- Access Control Users & Roles
    CREATE TABLE IF NOT EXISTS user_roles (
        id SERIAL PRIMARY KEY,
        username VARCHAR(100) NOT NULL UNIQUE,
        role VARCHAR(50) NOT NULL,
        permissions TEXT NOT NULL
    );

    -- Security Penetration Simulator
    CREATE TABLE IF NOT EXISTS pentest_simulations (
        id SERIAL PRIMARY KEY,
        type VARCHAR(100) NOT NULL,
        payload TEXT NOT NULL,
        status VARCHAR(20) NOT NULL, -- PASS, FAIL
        timestamp VARCHAR(30) NOT NULL
    );

    -- Red Team Attack Simulator
    CREATE TABLE IF NOT EXISTS redteam_attacks (
        id SERIAL PRIMARY KEY,
        type VARCHAR(100) NOT NULL,
        success BOOLEAN DEFAULT FALSE,
        findings TEXT NOT NULL,
        vulnerability VARCHAR(100) NOT NULL,
        timestamp VARCHAR(30) NOT NULL
    );

    -- Compliance Evidence Vault
    CREATE TABLE IF NOT EXISTS compliance_evidence (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        category VARCHAR(20) NOT NULL, -- SOC2, GDPR, HIPAA
        file_path VARCHAR(255) NOT NULL,
        collected_at VARCHAR(20) NOT NULL,
        hash VARCHAR(64) NOT NULL
    );

    ALTER TABLE compliance_evidence ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES tenants(id) ON DELETE CASCADE;
    ALTER TABLE compliance_evidence ADD COLUMN IF NOT EXISTS control_id VARCHAR(100);
    ALTER TABLE compliance_evidence ADD COLUMN IF NOT EXISTS source_type VARCHAR(50) DEFAULT 'manual';
    ALTER TABLE compliance_evidence ADD COLUMN IF NOT EXISTS source_id VARCHAR(100);
    ALTER TABLE compliance_evidence ADD COLUMN IF NOT EXISTS framework VARCHAR(50);
    ALTER TABLE compliance_evidence ADD COLUMN IF NOT EXISTS metadata TEXT;

    CREATE TABLE IF NOT EXISTS compliance_control_catalog (
        control_id VARCHAR(100) PRIMARY KEY,
        framework VARCHAR(50) NOT NULL,
        title VARCHAR(255) NOT NULL,
        description TEXT NOT NULL,
        weight INTEGER NOT NULL DEFAULT 10,
        evidence_types TEXT NOT NULL,
        corpus_version VARCHAR(50) NOT NULL DEFAULT '2026.07'
    );

    CREATE TABLE IF NOT EXISTS compliance_control_evidence (
        id SERIAL PRIMARY KEY,
        tenant_id INTEGER REFERENCES tenants(id) ON DELETE CASCADE,
        framework VARCHAR(50) NOT NULL,
        control_id VARCHAR(100) NOT NULL,
        source_type VARCHAR(50) NOT NULL,
        source_id VARCHAR(100),
        evidence_id INTEGER,
        evidence_hash VARCHAR(128),
        reason TEXT NOT NULL,
        impact INTEGER NOT NULL DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        metadata TEXT
    );

    CREATE TABLE IF NOT EXISTS compliance_control_scores (
        id SERIAL PRIMARY KEY,
        tenant_id INTEGER REFERENCES tenants(id) ON DELETE CASCADE,
        framework VARCHAR(50) NOT NULL,
        control_id VARCHAR(100) NOT NULL,
        score INTEGER NOT NULL,
        status VARCHAR(50) NOT NULL,
        evidence_count INTEGER NOT NULL DEFAULT 0,
        negative_findings INTEGER NOT NULL DEFAULT 0,
        reason TEXT NOT NULL,
        source_event VARCHAR(100),
        calculated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        metadata TEXT,
        CONSTRAINT uniq_control_score UNIQUE(tenant_id, framework, control_id)
    );

    CREATE TABLE IF NOT EXISTS compliance_score_changes (
        id SERIAL PRIMARY KEY,
        tenant_id INTEGER REFERENCES tenants(id) ON DELETE CASCADE,
        framework VARCHAR(50) NOT NULL,
        control_id VARCHAR(100),
        previous_score INTEGER,
        current_score INTEGER NOT NULL,
        reason TEXT NOT NULL,
        source_event VARCHAR(100),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        metadata TEXT
    );

    CREATE TABLE IF NOT EXISTS regulatory_corpus_versions (
        version_id VARCHAR(50) PRIMARY KEY,
        description TEXT NOT NULL,
        frameworks TEXT NOT NULL,
        document_count INTEGER NOT NULL DEFAULT 0,
        embedding_backend VARCHAR(100) NOT NULL,
        vector_backend VARCHAR(100) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        activated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS event_delivery_records (
        id SERIAL PRIMARY KEY,
        event_id VARCHAR(160) NOT NULL UNIQUE,
        tenant_id INTEGER REFERENCES tenants(id) ON DELETE CASCADE,
        stream VARCHAR(50) NOT NULL,
        topic VARCHAR(160) NOT NULL,
        source VARCHAR(100),
        status VARCHAR(40) NOT NULL DEFAULT 'queued',
        attempts INTEGER NOT NULL DEFAULT 0,
        next_retry_at TIMESTAMP,
        delivered_at TIMESTAMP,
        error_message TEXT,
        payload TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS event_dead_letters (
        id SERIAL PRIMARY KEY,
        event_id VARCHAR(160) NOT NULL UNIQUE,
        tenant_id INTEGER REFERENCES tenants(id) ON DELETE CASCADE,
        stream VARCHAR(50) NOT NULL,
        topic VARCHAR(160) NOT NULL,
        payload TEXT NOT NULL,
        error_message TEXT,
        attempts INTEGER NOT NULL DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        resolved_at TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS event_consumer_checkpoints (
        id SERIAL PRIMARY KEY,
        stream VARCHAR(50) NOT NULL,
        consumer_group VARCHAR(120) NOT NULL,
        pending_events INTEGER NOT NULL DEFAULT 0,
        dead_letter_count INTEGER NOT NULL DEFAULT 0,
        lag_seconds INTEGER NOT NULL DEFAULT 0,
        last_delivered_at TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(stream, consumer_group)
    );

    CREATE TABLE IF NOT EXISTS rate_limit_events (
        id SERIAL PRIMARY KEY,
        tenant_id INTEGER REFERENCES tenants(id) ON DELETE CASCADE,
        limiter_key VARCHAR(200) NOT NULL,
        limit_count INTEGER NOT NULL,
        remaining INTEGER NOT NULL,
        backend VARCHAR(40) NOT NULL,
        allowed BOOLEAN NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS worker_throttle_events (
        id SERIAL PRIMARY KEY,
        tenant_id INTEGER REFERENCES tenants(id) ON DELETE CASCADE,
        worker_type VARCHAR(80) NOT NULL,
        throttle_key VARCHAR(200) NOT NULL,
        limit_count INTEGER NOT NULL,
        active_count INTEGER NOT NULL,
        allowed BOOLEAN NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    ALTER TABLE knowledge_documents ADD COLUMN IF NOT EXISTS corpus_version VARCHAR(50);
    ALTER TABLE knowledge_chunks ADD COLUMN IF NOT EXISTS corpus_version VARCHAR(50);
    ALTER TABLE knowledge_chunks ADD COLUMN IF NOT EXISTS vector_backend VARCHAR(100) DEFAULT 'postgres_json';

    -- High Availability failsafe status
    CREATE TABLE IF NOT EXISTS ha_status (
        id SERIAL PRIMARY KEY,
        active_region VARCHAR(50) NOT NULL,
        backup_region VARCHAR(50) NOT NULL,
        failover_status VARCHAR(30) DEFAULT 'nominal', -- nominal, failing_over, failed_over
        last_failover VARCHAR(30) NOT NULL
    );

    -- Chat Sessions
    CREATE TABLE IF NOT EXISTS chat_sessions (
        id SERIAL PRIMARY KEY,
        session_id VARCHAR(100) NOT NULL UNIQUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        title TEXT,
        user_id VARCHAR(100) DEFAULT 'admin_user',
        tenant_id INTEGER REFERENCES tenants(id) ON DELETE CASCADE
    );

    ALTER TABLE chat_sessions ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES tenants(id) ON DELETE CASCADE;

    -- Chat Messages
    CREATE TABLE IF NOT EXISTS chat_messages (
        id SERIAL PRIMARY KEY,
        session_id VARCHAR(100) NOT NULL,
        role VARCHAR(20) NOT NULL,
        content TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        trace TEXT,
        CONSTRAINT fk_session FOREIGN KEY (session_id) REFERENCES chat_sessions(session_id) ON DELETE CASCADE
    );

    ALTER TABLE chat_messages ADD COLUMN IF NOT EXISTS trace TEXT;
    ALTER TABLE chat_messages ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES tenants(id) ON DELETE CASCADE;
    UPDATE chat_messages AS m
    SET tenant_id = s.tenant_id
    FROM chat_sessions AS s
    WHERE m.session_id = s.session_id
      AND m.tenant_id IS NULL
      AND s.tenant_id IS NOT NULL;

    -- New Document Security & Compliance Engine Tables
    CREATE TABLE IF NOT EXISTS documents (
        id SERIAL PRIMARY KEY,
        filename VARCHAR(255) NOT NULL,
        source VARCHAR(50) NOT NULL,
        status VARCHAR(50) DEFAULT 'pending',
        size_bytes INTEGER NOT NULL,
        risk_score INTEGER DEFAULT 0,
        severity VARCHAR(20) DEFAULT 'LOW',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS document_findings (
        id SERIAL PRIMARY KEY,
        document_id INTEGER REFERENCES documents(id) ON DELETE CASCADE,
        finding_type VARCHAR(50) NOT NULL,
        matched_pattern VARCHAR(100) NOT NULL,
        matched_text TEXT NOT NULL,
        risk_level VARCHAR(20) NOT NULL,
        recommendation TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS document_scans (
        id SERIAL PRIMARY KEY,
        document_id INTEGER REFERENCES documents(id) ON DELETE CASCADE,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        scan_duration_ms INTEGER DEFAULT 0,
        raw_findings TEXT,
        status VARCHAR(50) DEFAULT 'completed'
    );

    CREATE TABLE IF NOT EXISTS document_audits (
        id SERIAL PRIMARY KEY,
        document_id INTEGER NOT NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        action VARCHAR(100) NOT NULL,
        actor VARCHAR(100) NOT NULL,
        details TEXT NOT NULL,
        integrity_hash VARCHAR(64),
        previous_hash VARCHAR(64)
    );

    CREATE TABLE IF NOT EXISTS compliance_score_history (
        id SERIAL PRIMARY KEY,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        framework VARCHAR(50) NOT NULL,
        score INTEGER NOT NULL,
        details TEXT
    );

    CREATE TABLE IF NOT EXISTS compliance_drift_alerts (
        id SERIAL PRIMARY KEY,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        framework VARCHAR(50) NOT NULL,
        score_drop INTEGER NOT NULL,
        previous_score INTEGER NOT NULL,
        current_score INTEGER NOT NULL,
        details TEXT NOT NULL
    );

    ALTER TABLE document_findings ADD COLUMN IF NOT EXISTS impact VARCHAR(255);
    ALTER TABLE document_findings ADD COLUMN IF NOT EXISTS priority VARCHAR(10);
    ALTER TABLE document_findings ADD COLUMN IF NOT EXISTS location_evidence TEXT;
    ALTER TABLE documents ADD COLUMN IF NOT EXISTS document_uid VARCHAR(100);
    ALTER TABLE documents ADD COLUMN IF NOT EXISTS version INTEGER DEFAULT 1;
    ALTER TABLE documents ADD COLUMN IF NOT EXISTS parent_document_id INTEGER REFERENCES documents(id) ON DELETE SET NULL;
    ALTER TABLE documents ADD COLUMN IF NOT EXISTS content_sha256 VARCHAR(64);
    ALTER TABLE documents ADD COLUMN IF NOT EXISTS mime_type VARCHAR(255);
    ALTER TABLE documents ADD COLUMN IF NOT EXISTS page_count INTEGER DEFAULT 0;
    ALTER TABLE documents ADD COLUMN IF NOT EXISTS extraction_method VARCHAR(50);
    ALTER TABLE documents ADD COLUMN IF NOT EXISTS ocr_status VARCHAR(50);
    ALTER TABLE documents ADD COLUMN IF NOT EXISTS ocr_required BOOLEAN DEFAULT FALSE;
    ALTER TABLE documents ADD COLUMN IF NOT EXISTS metadata_json TEXT;
    ALTER TABLE documents ADD COLUMN IF NOT EXISTS original_extracted_text TEXT;
    ALTER TABLE documents ADD COLUMN IF NOT EXISTS redacted_text TEXT;
    ALTER TABLE documents ADD COLUMN IF NOT EXISTS redacted_pdf_base64 TEXT;
    ALTER TABLE documents ADD COLUMN IF NOT EXISTS findings_report TEXT;
    ALTER TABLE documents ADD COLUMN IF NOT EXISTS compliance_summary TEXT;
    ALTER TABLE documents ADD COLUMN IF NOT EXISTS processing_history TEXT;
    ALTER TABLE documents ADD COLUMN IF NOT EXISTS progress INTEGER DEFAULT 0;
    ALTER TABLE documents ADD COLUMN IF NOT EXISTS latest_scan_id INTEGER;

    ALTER TABLE document_findings ADD COLUMN IF NOT EXISTS field_type VARCHAR(100);
    ALTER TABLE document_findings ADD COLUMN IF NOT EXISTS page_number INTEGER;
    ALTER TABLE document_findings ADD COLUMN IF NOT EXISTS line_number INTEGER;
    ALTER TABLE document_findings ADD COLUMN IF NOT EXISTS paragraph_number INTEGER;
    ALTER TABLE document_findings ADD COLUMN IF NOT EXISTS char_start INTEGER;
    ALTER TABLE document_findings ADD COLUMN IF NOT EXISTS char_end INTEGER;
    ALTER TABLE document_findings ADD COLUMN IF NOT EXISTS bbox TEXT;
    ALTER TABLE document_findings ADD COLUMN IF NOT EXISTS confidence NUMERIC;
    ALTER TABLE document_findings ADD COLUMN IF NOT EXISTS policy_violated VARCHAR(255);
    ALTER TABLE document_findings ADD COLUMN IF NOT EXISTS explanation TEXT;
    ALTER TABLE document_findings ADD COLUMN IF NOT EXISTS action_taken VARCHAR(50);
    ALTER TABLE document_findings ADD COLUMN IF NOT EXISTS fingerprint VARCHAR(128);

    ALTER TABLE document_scans ADD COLUMN IF NOT EXISTS scan_id VARCHAR(100);
    ALTER TABLE document_scans ADD COLUMN IF NOT EXISTS progress INTEGER DEFAULT 0;
    ALTER TABLE document_scans ADD COLUMN IF NOT EXISTS extraction_method VARCHAR(50);
    ALTER TABLE document_scans ADD COLUMN IF NOT EXISTS ocr_status VARCHAR(50);
    ALTER TABLE document_scans ADD COLUMN IF NOT EXISTS ocr_required BOOLEAN DEFAULT FALSE;
    ALTER TABLE document_scans ADD COLUMN IF NOT EXISTS compliance_summary TEXT;
    ALTER TABLE document_scans ADD COLUMN IF NOT EXISTS outputs_json TEXT;

    ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES tenants(id) ON DELETE CASCADE;
    ALTER TABLE documents ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES tenants(id) ON DELETE CASCADE;
    ALTER TABLE document_findings ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES tenants(id) ON DELETE CASCADE;
    ALTER TABLE document_scans ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES tenants(id) ON DELETE CASCADE;
    ALTER TABLE document_audits ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES tenants(id) ON DELETE CASCADE;
    ALTER TABLE secrets ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES tenants(id) ON DELETE CASCADE;
    ALTER TABLE compliance_evidence ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES tenants(id) ON DELETE CASCADE;

    CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_id ON audit_logs(tenant_id);
    CREATE INDEX IF NOT EXISTS idx_gateway_requests_tenant_id ON gateway_requests(tenant_id);
    CREATE INDEX IF NOT EXISTS idx_gateway_routes_tenant_id ON gateway_routes(tenant_id);
    CREATE INDEX IF NOT EXISTS idx_tenant_api_keys_tenant_id ON tenant_api_keys(tenant_id);
    CREATE INDEX IF NOT EXISTS idx_auth_refresh_tokens_tenant_id ON auth_refresh_tokens(tenant_id);
    CREATE INDEX IF NOT EXISTS idx_auth_mfa_sessions_tenant_id ON auth_mfa_sessions(tenant_id);
    CREATE INDEX IF NOT EXISTS idx_auth_password_reset_tokens_user ON auth_password_reset_tokens(tenant_id, user_id, expires_at);
    CREATE INDEX IF NOT EXISTS idx_tenant_identity_providers_tenant_id ON tenant_identity_providers(tenant_id);
    CREATE INDEX IF NOT EXISTS idx_tenant_identity_providers_enabled ON tenant_identity_providers(tenant_id, enabled);
    CREATE INDEX IF NOT EXISTS idx_oidc_login_states_tenant_provider ON oidc_login_states(tenant_id, provider_id, expires_at);
    CREATE INDEX IF NOT EXISTS idx_oidc_jwks_cache_tenant_id ON oidc_jwks_cache(tenant_id);
    CREATE INDEX IF NOT EXISTS idx_oidc_user_sessions_tenant_user ON oidc_user_sessions(tenant_id, user_id);
    CREATE INDEX IF NOT EXISTS idx_tenant_credentials_tenant_id ON tenant_credentials(tenant_id);
    CREATE INDEX IF NOT EXISTS idx_tenant_credentials_provider ON tenant_credentials(tenant_id, provider);
    CREATE INDEX IF NOT EXISTS idx_agent_events_tenant_id ON agent_events(tenant_id);
    CREATE INDEX IF NOT EXISTS idx_gateway_approvals_tenant_id ON gateway_approvals(tenant_id);
    CREATE INDEX IF NOT EXISTS idx_approval_audit_events_tenant_id ON approval_audit_events(tenant_id);
    CREATE INDEX IF NOT EXISTS idx_approval_audit_events_approval_id ON approval_audit_events(approval_id);
    CREATE INDEX IF NOT EXISTS idx_policies_tenant_id ON policies(tenant_id);
    CREATE INDEX IF NOT EXISTS idx_policies_tenant_status ON policies(tenant_id, status);
    CREATE INDEX IF NOT EXISTS idx_policy_audit_history_tenant_id ON policy_audit_history(tenant_id);
    CREATE INDEX IF NOT EXISTS idx_policy_audit_history_policy_id ON policy_audit_history(policy_id);
    CREATE INDEX IF NOT EXISTS idx_policy_versions_tenant_policy ON policy_versions(tenant_id, policy_id, version);
    CREATE INDEX IF NOT EXISTS idx_policy_change_approvals_tenant_policy ON policy_change_approvals(tenant_id, policy_id, status);
    CREATE INDEX IF NOT EXISTS idx_policy_simulation_results_tenant_policy ON policy_simulation_results(tenant_id, policy_id);
    CREATE INDEX IF NOT EXISTS idx_policy_evaluation_audit_tenant_request ON policy_evaluation_audit(tenant_id, request_id);
    CREATE INDEX IF NOT EXISTS idx_remediation_connectors_tenant ON remediation_connectors(tenant_id, provider);
    CREATE INDEX IF NOT EXISTS idx_remediation_findings_tenant ON remediation_findings(tenant_id, status);
    CREATE INDEX IF NOT EXISTS idx_remediation_plans_tenant ON remediation_plans(tenant_id, finding_id);
    CREATE INDEX IF NOT EXISTS idx_remediation_worker_runs_tenant ON remediation_worker_runs(tenant_id, status);
    CREATE INDEX IF NOT EXISTS idx_worker_credential_leases_tenant ON worker_credential_leases(tenant_id, connector_id);
    CREATE INDEX IF NOT EXISTS idx_compliance_control_evidence_tenant ON compliance_control_evidence(tenant_id, framework, control_id);
    CREATE INDEX IF NOT EXISTS idx_compliance_control_scores_tenant ON compliance_control_scores(tenant_id, framework);
    CREATE INDEX IF NOT EXISTS idx_compliance_score_changes_tenant ON compliance_score_changes(tenant_id, framework, created_at);
    CREATE INDEX IF NOT EXISTS idx_event_delivery_records_status ON event_delivery_records(status, stream, created_at);
    CREATE INDEX IF NOT EXISTS idx_event_delivery_records_tenant ON event_delivery_records(tenant_id, stream, status);
    CREATE INDEX IF NOT EXISTS idx_event_dead_letters_tenant ON event_dead_letters(tenant_id, stream, created_at);
    CREATE INDEX IF NOT EXISTS idx_rate_limit_events_tenant ON rate_limit_events(tenant_id, created_at);
    CREATE INDEX IF NOT EXISTS idx_worker_throttle_events_tenant ON worker_throttle_events(tenant_id, created_at);
    CREATE INDEX IF NOT EXISTS idx_knowledge_documents_tenant_id ON knowledge_documents(tenant_id);
    CREATE INDEX IF NOT EXISTS idx_knowledge_chunks_tenant_document ON knowledge_chunks(tenant_id, document_id);
    CREATE INDEX IF NOT EXISTS idx_documents_tenant_id ON documents(tenant_id);
    CREATE INDEX IF NOT EXISTS idx_document_findings_tenant_document ON document_findings(tenant_id, document_id);
    CREATE INDEX IF NOT EXISTS idx_document_scans_tenant_document ON document_scans(tenant_id, document_id);
    CREATE INDEX IF NOT EXISTS idx_document_audits_tenant_document ON document_audits(tenant_id, document_id);
    CREATE INDEX IF NOT EXISTS idx_documents_tenant_uid ON documents(tenant_id, document_uid);
    CREATE INDEX IF NOT EXISTS idx_document_scans_scan_id ON document_scans(scan_id);
    CREATE INDEX IF NOT EXISTS idx_compliance_evidence_tenant_id ON compliance_evidence(tenant_id);
    CREATE INDEX IF NOT EXISTS idx_chat_messages_tenant_session ON chat_messages(tenant_id, session_id);
    """
    rls_sql = """
    ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS tenant_isolation_audit_logs ON audit_logs;
    CREATE POLICY tenant_isolation_audit_logs ON audit_logs
        USING (tenant_id::text = current_setting('app.tenant_id', true))
        WITH CHECK (tenant_id::text = current_setting('app.tenant_id', true));

    ALTER TABLE gateway_requests ENABLE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS tenant_isolation_gateway_requests ON gateway_requests;
    CREATE POLICY tenant_isolation_gateway_requests ON gateway_requests
        USING (tenant_id = current_setting('app.tenant_id', true))
        WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

    ALTER TABLE gateway_routes ENABLE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS tenant_isolation_gateway_routes ON gateway_routes;
    CREATE POLICY tenant_isolation_gateway_routes ON gateway_routes
        USING (tenant_id::text = current_setting('app.tenant_id', true))
        WITH CHECK (tenant_id::text = current_setting('app.tenant_id', true));

    ALTER TABLE tenant_users ENABLE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS tenant_isolation_tenant_users ON tenant_users;
    CREATE POLICY tenant_isolation_tenant_users ON tenant_users
        USING (
            tenant_id::text = COALESCE(NULLIF(current_setting('app.current_tenant_id', true), ''), NULLIF(current_setting('app.tenant_id', true), ''))
            OR current_setting('app.auth_lookup', true) = 'on'
        )
        WITH CHECK (tenant_id::text = COALESCE(NULLIF(current_setting('app.current_tenant_id', true), ''), NULLIF(current_setting('app.tenant_id', true), '')));

    ALTER TABLE tenant_api_keys ENABLE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS tenant_isolation_tenant_api_keys ON tenant_api_keys;
    CREATE POLICY tenant_isolation_tenant_api_keys ON tenant_api_keys
        USING (
            tenant_id::text = current_setting('app.tenant_id', true)
            OR current_setting('app.auth_lookup', true) = 'on'
        )
        WITH CHECK (tenant_id::text = current_setting('app.tenant_id', true));

    ALTER TABLE auth_refresh_tokens ENABLE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS tenant_isolation_auth_refresh_tokens ON auth_refresh_tokens;
    CREATE POLICY tenant_isolation_auth_refresh_tokens ON auth_refresh_tokens
        USING (tenant_id::text = current_setting('app.tenant_id', true))
        WITH CHECK (tenant_id::text = current_setting('app.tenant_id', true));

    ALTER TABLE auth_mfa_sessions ENABLE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS tenant_isolation_auth_mfa_sessions ON auth_mfa_sessions;
    CREATE POLICY tenant_isolation_auth_mfa_sessions ON auth_mfa_sessions
        USING (
            tenant_id::text = current_setting('app.tenant_id', true)
            OR current_setting('app.auth_lookup', true) = 'on'
        )
        WITH CHECK (
            tenant_id::text = current_setting('app.tenant_id', true)
            OR current_setting('app.auth_lookup', true) = 'on'
        );

    ALTER TABLE auth_password_reset_tokens ENABLE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS tenant_isolation_auth_password_reset_tokens ON auth_password_reset_tokens;
    CREATE POLICY tenant_isolation_auth_password_reset_tokens ON auth_password_reset_tokens
        USING (
            tenant_id::text = current_setting('app.tenant_id', true)
            OR current_setting('app.auth_lookup', true) = 'on'
        )
        WITH CHECK (
            tenant_id::text = current_setting('app.tenant_id', true)
            OR current_setting('app.auth_lookup', true) = 'on'
        );

    ALTER TABLE tenant_identity_providers ENABLE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS tenant_isolation_tenant_identity_providers ON tenant_identity_providers;
    CREATE POLICY tenant_isolation_tenant_identity_providers ON tenant_identity_providers
        USING (
            tenant_id::text = current_setting('app.tenant_id', true)
            OR current_setting('app.auth_lookup', true) = 'on'
        )
        WITH CHECK (tenant_id::text = current_setting('app.tenant_id', true));

    ALTER TABLE oidc_login_states ENABLE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS tenant_isolation_oidc_login_states ON oidc_login_states;
    CREATE POLICY tenant_isolation_oidc_login_states ON oidc_login_states
        USING (
            tenant_id::text = current_setting('app.tenant_id', true)
            OR current_setting('app.auth_lookup', true) = 'on'
        )
        WITH CHECK (tenant_id::text = current_setting('app.tenant_id', true));

    ALTER TABLE oidc_jwks_cache ENABLE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS tenant_isolation_oidc_jwks_cache ON oidc_jwks_cache;
    CREATE POLICY tenant_isolation_oidc_jwks_cache ON oidc_jwks_cache
        USING (
            tenant_id::text = current_setting('app.tenant_id', true)
            OR current_setting('app.auth_lookup', true) = 'on'
        )
        WITH CHECK (tenant_id::text = current_setting('app.tenant_id', true));

    ALTER TABLE oidc_user_sessions ENABLE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS tenant_isolation_oidc_user_sessions ON oidc_user_sessions;
    CREATE POLICY tenant_isolation_oidc_user_sessions ON oidc_user_sessions
        USING (tenant_id::text = current_setting('app.tenant_id', true))
        WITH CHECK (tenant_id::text = current_setting('app.tenant_id', true));

    ALTER TABLE tenant_credentials ENABLE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS tenant_isolation_tenant_credentials ON tenant_credentials;
    CREATE POLICY tenant_isolation_tenant_credentials ON tenant_credentials
        USING (tenant_id::text = current_setting('app.tenant_id', true))
        WITH CHECK (tenant_id::text = current_setting('app.tenant_id', true));

    ALTER TABLE agent_events ENABLE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS tenant_isolation_agent_events ON agent_events;
    CREATE POLICY tenant_isolation_agent_events ON agent_events
        USING (tenant_id::text = current_setting('app.tenant_id', true))
        WITH CHECK (tenant_id::text = current_setting('app.tenant_id', true));

    ALTER TABLE gateway_approvals ENABLE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS tenant_isolation_gateway_approvals ON gateway_approvals;
    CREATE POLICY tenant_isolation_gateway_approvals ON gateway_approvals
        USING (tenant_id::text = current_setting('app.tenant_id', true))
        WITH CHECK (tenant_id::text = current_setting('app.tenant_id', true));

    ALTER TABLE approval_audit_events ENABLE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS tenant_isolation_approval_audit_events ON approval_audit_events;
    CREATE POLICY tenant_isolation_approval_audit_events ON approval_audit_events
        USING (tenant_id::text = current_setting('app.tenant_id', true))
        WITH CHECK (tenant_id::text = current_setting('app.tenant_id', true));

    ALTER TABLE usage_events ENABLE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS tenant_isolation_usage_events ON usage_events;
    CREATE POLICY tenant_isolation_usage_events ON usage_events
        USING (tenant_id::text = current_setting('app.tenant_id', true))
        WITH CHECK (tenant_id::text = current_setting('app.tenant_id', true));

    ALTER TABLE policies ENABLE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS tenant_isolation_policies ON policies;
    CREATE POLICY tenant_isolation_policies ON policies
        USING (tenant_id::text = COALESCE(NULLIF(current_setting('app.current_tenant_id', true), ''), NULLIF(current_setting('app.tenant_id', true), '')))
        WITH CHECK (tenant_id::text = COALESCE(NULLIF(current_setting('app.current_tenant_id', true), ''), NULLIF(current_setting('app.tenant_id', true), '')));

    ALTER TABLE policy_audit_history ENABLE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS tenant_isolation_policy_audit_history ON policy_audit_history;
    CREATE POLICY tenant_isolation_policy_audit_history ON policy_audit_history
        USING (tenant_id::text = current_setting('app.tenant_id', true))
        WITH CHECK (tenant_id::text = current_setting('app.tenant_id', true));

    ALTER TABLE policy_versions ENABLE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS tenant_isolation_policy_versions ON policy_versions;
    CREATE POLICY tenant_isolation_policy_versions ON policy_versions
        USING (tenant_id::text = current_setting('app.tenant_id', true))
        WITH CHECK (tenant_id::text = current_setting('app.tenant_id', true));

    ALTER TABLE policy_change_approvals ENABLE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS tenant_isolation_policy_change_approvals ON policy_change_approvals;
    CREATE POLICY tenant_isolation_policy_change_approvals ON policy_change_approvals
        USING (tenant_id::text = current_setting('app.tenant_id', true))
        WITH CHECK (tenant_id::text = current_setting('app.tenant_id', true));

    ALTER TABLE policy_simulation_results ENABLE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS tenant_isolation_policy_simulation_results ON policy_simulation_results;
    CREATE POLICY tenant_isolation_policy_simulation_results ON policy_simulation_results
        USING (tenant_id::text = current_setting('app.tenant_id', true))
        WITH CHECK (tenant_id::text = current_setting('app.tenant_id', true));

    ALTER TABLE policy_evaluation_audit ENABLE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS tenant_isolation_policy_evaluation_audit ON policy_evaluation_audit;
    CREATE POLICY tenant_isolation_policy_evaluation_audit ON policy_evaluation_audit
        USING (tenant_id::text = current_setting('app.tenant_id', true))
        WITH CHECK (tenant_id::text = current_setting('app.tenant_id', true));

    ALTER TABLE knowledge_documents ENABLE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS tenant_isolation_knowledge_documents ON knowledge_documents;
    CREATE POLICY tenant_isolation_knowledge_documents ON knowledge_documents
        USING (tenant_id::text = current_setting('app.tenant_id', true))
        WITH CHECK (tenant_id::text = current_setting('app.tenant_id', true));

    ALTER TABLE knowledge_chunks ENABLE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS tenant_isolation_knowledge_chunks ON knowledge_chunks;
    CREATE POLICY tenant_isolation_knowledge_chunks ON knowledge_chunks
        USING (tenant_id::text = current_setting('app.tenant_id', true))
        WITH CHECK (tenant_id::text = current_setting('app.tenant_id', true));

    ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS tenant_isolation_documents ON documents;
    CREATE POLICY tenant_isolation_documents ON documents
        USING (tenant_id::text = current_setting('app.tenant_id', true))
        WITH CHECK (tenant_id::text = current_setting('app.tenant_id', true));

    ALTER TABLE document_findings ENABLE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS tenant_isolation_document_findings ON document_findings;
    CREATE POLICY tenant_isolation_document_findings ON document_findings
        USING (tenant_id::text = current_setting('app.tenant_id', true))
        WITH CHECK (tenant_id::text = current_setting('app.tenant_id', true));

    ALTER TABLE document_scans ENABLE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS tenant_isolation_document_scans ON document_scans;
    CREATE POLICY tenant_isolation_document_scans ON document_scans
        USING (tenant_id::text = current_setting('app.tenant_id', true))
        WITH CHECK (tenant_id::text = current_setting('app.tenant_id', true));

    ALTER TABLE document_audits ENABLE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS tenant_isolation_document_audits ON document_audits;
    CREATE POLICY tenant_isolation_document_audits ON document_audits
        USING (tenant_id::text = current_setting('app.tenant_id', true))
        WITH CHECK (tenant_id::text = current_setting('app.tenant_id', true));

    ALTER TABLE chat_sessions ENABLE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS tenant_isolation_chat_sessions ON chat_sessions;
    CREATE POLICY tenant_isolation_chat_sessions ON chat_sessions
        USING (tenant_id::text = COALESCE(NULLIF(current_setting('app.current_tenant_id', true), ''), NULLIF(current_setting('app.tenant_id', true), '')))
        WITH CHECK (tenant_id::text = COALESCE(NULLIF(current_setting('app.current_tenant_id', true), ''), NULLIF(current_setting('app.tenant_id', true), '')));

    ALTER TABLE chat_messages ENABLE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS tenant_isolation_chat_messages ON chat_messages;
    CREATE POLICY tenant_isolation_chat_messages ON chat_messages
        USING (tenant_id::text = COALESCE(NULLIF(current_setting('app.current_tenant_id', true), ''), NULLIF(current_setting('app.tenant_id', true), '')))
        WITH CHECK (tenant_id::text = COALESCE(NULLIF(current_setting('app.current_tenant_id', true), ''), NULLIF(current_setting('app.tenant_id', true), '')));

    ALTER TABLE secrets ENABLE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS tenant_isolation_secrets ON secrets;
    CREATE POLICY tenant_isolation_secrets ON secrets
        USING (tenant_id::text = current_setting('app.tenant_id', true))
        WITH CHECK (tenant_id::text = current_setting('app.tenant_id', true));

    ALTER TABLE compliance_evidence ENABLE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS tenant_isolation_compliance_evidence ON compliance_evidence;
    CREATE POLICY tenant_isolation_compliance_evidence ON compliance_evidence
        USING (tenant_id::text = current_setting('app.tenant_id', true))
        WITH CHECK (tenant_id::text = current_setting('app.tenant_id', true));

    ALTER TABLE compliance_control_evidence ENABLE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS tenant_isolation_compliance_control_evidence ON compliance_control_evidence;
    CREATE POLICY tenant_isolation_compliance_control_evidence ON compliance_control_evidence
        USING (tenant_id::text = current_setting('app.tenant_id', true))
        WITH CHECK (tenant_id::text = current_setting('app.tenant_id', true));

    ALTER TABLE compliance_control_scores ENABLE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS tenant_isolation_compliance_control_scores ON compliance_control_scores;
    CREATE POLICY tenant_isolation_compliance_control_scores ON compliance_control_scores
        USING (tenant_id::text = current_setting('app.tenant_id', true))
        WITH CHECK (tenant_id::text = current_setting('app.tenant_id', true));

    ALTER TABLE compliance_score_changes ENABLE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS tenant_isolation_compliance_score_changes ON compliance_score_changes;
    CREATE POLICY tenant_isolation_compliance_score_changes ON compliance_score_changes
        USING (tenant_id::text = current_setting('app.tenant_id', true))
        WITH CHECK (tenant_id::text = current_setting('app.tenant_id', true));

    ALTER TABLE event_delivery_records ENABLE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS tenant_isolation_event_delivery_records ON event_delivery_records;
    CREATE POLICY tenant_isolation_event_delivery_records ON event_delivery_records
        USING (tenant_id IS NULL OR tenant_id::text = current_setting('app.tenant_id', true))
        WITH CHECK (tenant_id IS NULL OR tenant_id::text = current_setting('app.tenant_id', true));

    ALTER TABLE event_dead_letters ENABLE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS tenant_isolation_event_dead_letters ON event_dead_letters;
    CREATE POLICY tenant_isolation_event_dead_letters ON event_dead_letters
        USING (tenant_id IS NULL OR tenant_id::text = current_setting('app.tenant_id', true))
        WITH CHECK (tenant_id IS NULL OR tenant_id::text = current_setting('app.tenant_id', true));

    ALTER TABLE rate_limit_events ENABLE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS tenant_isolation_rate_limit_events ON rate_limit_events;
    CREATE POLICY tenant_isolation_rate_limit_events ON rate_limit_events
        USING (tenant_id::text = current_setting('app.tenant_id', true))
        WITH CHECK (tenant_id::text = current_setting('app.tenant_id', true));

    ALTER TABLE worker_throttle_events ENABLE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS tenant_isolation_worker_throttle_events ON worker_throttle_events;
    CREATE POLICY tenant_isolation_worker_throttle_events ON worker_throttle_events
        USING (tenant_id::text = current_setting('app.tenant_id', true))
        WITH CHECK (tenant_id::text = current_setting('app.tenant_id', true));

    ALTER TABLE remediation_connectors ENABLE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS tenant_isolation_remediation_connectors ON remediation_connectors;
    CREATE POLICY tenant_isolation_remediation_connectors ON remediation_connectors
        USING (tenant_id::text = current_setting('app.tenant_id', true))
        WITH CHECK (tenant_id::text = current_setting('app.tenant_id', true));

    ALTER TABLE remediation_findings ENABLE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS tenant_isolation_remediation_findings ON remediation_findings;
    CREATE POLICY tenant_isolation_remediation_findings ON remediation_findings
        USING (tenant_id::text = current_setting('app.tenant_id', true))
        WITH CHECK (tenant_id::text = current_setting('app.tenant_id', true));

    ALTER TABLE remediation_plans ENABLE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS tenant_isolation_remediation_plans ON remediation_plans;
    CREATE POLICY tenant_isolation_remediation_plans ON remediation_plans
        USING (tenant_id::text = current_setting('app.tenant_id', true))
        WITH CHECK (tenant_id::text = current_setting('app.tenant_id', true));

    ALTER TABLE remediation_worker_runs ENABLE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS tenant_isolation_remediation_worker_runs ON remediation_worker_runs;
    CREATE POLICY tenant_isolation_remediation_worker_runs ON remediation_worker_runs
        USING (tenant_id::text = current_setting('app.tenant_id', true))
        WITH CHECK (tenant_id::text = current_setting('app.tenant_id', true));

    ALTER TABLE worker_credential_leases ENABLE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS tenant_isolation_worker_credential_leases ON worker_credential_leases;
    CREATE POLICY tenant_isolation_worker_credential_leases ON worker_credential_leases
        USING (tenant_id::text = current_setting('app.tenant_id', true))
        WITH CHECK (tenant_id::text = current_setting('app.tenant_id', true));

    ALTER TABLE remediation_worker_audit_events ENABLE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS tenant_isolation_remediation_worker_audit_events ON remediation_worker_audit_events;
    CREATE POLICY tenant_isolation_remediation_worker_audit_events ON remediation_worker_audit_events
        USING (tenant_id::text = current_setting('app.tenant_id', true))
        WITH CHECK (tenant_id::text = current_setting('app.tenant_id', true));
    """
    force_rls_sql = """
    ALTER TABLE audit_logs FORCE ROW LEVEL SECURITY;
    ALTER TABLE gateway_requests FORCE ROW LEVEL SECURITY;
    ALTER TABLE gateway_routes FORCE ROW LEVEL SECURITY;
    ALTER TABLE tenant_users FORCE ROW LEVEL SECURITY;
    ALTER TABLE tenant_api_keys FORCE ROW LEVEL SECURITY;
    ALTER TABLE auth_refresh_tokens FORCE ROW LEVEL SECURITY;
    ALTER TABLE auth_mfa_sessions FORCE ROW LEVEL SECURITY;
    ALTER TABLE auth_password_reset_tokens FORCE ROW LEVEL SECURITY;
    ALTER TABLE tenant_identity_providers FORCE ROW LEVEL SECURITY;
    ALTER TABLE oidc_login_states FORCE ROW LEVEL SECURITY;
    ALTER TABLE oidc_jwks_cache FORCE ROW LEVEL SECURITY;
    ALTER TABLE oidc_user_sessions FORCE ROW LEVEL SECURITY;
    ALTER TABLE tenant_credentials FORCE ROW LEVEL SECURITY;
    ALTER TABLE agent_events FORCE ROW LEVEL SECURITY;
    ALTER TABLE gateway_approvals FORCE ROW LEVEL SECURITY;
    ALTER TABLE approval_audit_events FORCE ROW LEVEL SECURITY;
    ALTER TABLE usage_events FORCE ROW LEVEL SECURITY;
    ALTER TABLE policies FORCE ROW LEVEL SECURITY;
    ALTER TABLE policy_audit_history FORCE ROW LEVEL SECURITY;
    ALTER TABLE policy_versions FORCE ROW LEVEL SECURITY;
    ALTER TABLE policy_change_approvals FORCE ROW LEVEL SECURITY;
    ALTER TABLE policy_simulation_results FORCE ROW LEVEL SECURITY;
    ALTER TABLE policy_evaluation_audit FORCE ROW LEVEL SECURITY;
    ALTER TABLE knowledge_documents FORCE ROW LEVEL SECURITY;
    ALTER TABLE knowledge_chunks FORCE ROW LEVEL SECURITY;
    ALTER TABLE documents FORCE ROW LEVEL SECURITY;
    ALTER TABLE document_findings FORCE ROW LEVEL SECURITY;
    ALTER TABLE document_scans FORCE ROW LEVEL SECURITY;
    ALTER TABLE document_audits FORCE ROW LEVEL SECURITY;
    ALTER TABLE chat_sessions FORCE ROW LEVEL SECURITY;
    ALTER TABLE chat_messages FORCE ROW LEVEL SECURITY;
    ALTER TABLE secrets FORCE ROW LEVEL SECURITY;
    ALTER TABLE compliance_evidence FORCE ROW LEVEL SECURITY;
    ALTER TABLE compliance_control_evidence FORCE ROW LEVEL SECURITY;
    ALTER TABLE compliance_control_scores FORCE ROW LEVEL SECURITY;
    ALTER TABLE compliance_score_changes FORCE ROW LEVEL SECURITY;
    ALTER TABLE event_delivery_records FORCE ROW LEVEL SECURITY;
    ALTER TABLE event_dead_letters FORCE ROW LEVEL SECURITY;
    ALTER TABLE rate_limit_events FORCE ROW LEVEL SECURITY;
    ALTER TABLE worker_throttle_events FORCE ROW LEVEL SECURITY;
    ALTER TABLE remediation_connectors FORCE ROW LEVEL SECURITY;
    ALTER TABLE remediation_findings FORCE ROW LEVEL SECURITY;
    ALTER TABLE remediation_plans FORCE ROW LEVEL SECURITY;
    ALTER TABLE remediation_worker_runs FORCE ROW LEVEL SECURITY;
    ALTER TABLE worker_credential_leases FORCE ROW LEVEL SECURITY;
    ALTER TABLE remediation_worker_audit_events FORCE ROW LEVEL SECURITY;
    """
    try:
        with engine.connect() as conn:
            conn.execute(text(migration_sql))
            conn.execute(text(rls_sql))
            conn.execute(text(force_rls_sql))
            conn.execute(text("""
                INSERT INTO tenant_users (
                    tenant_id, first_name, last_name, email, password_hash,
                    role, permissions, email_verified, mfa_enabled,
                    totp_secret, status
                )
                SELECT
                    id,
                    NULL,
                    NULL,
                    email,
                    password_hash,
                    'Super Admin',
                    'all_access',
                    COALESCE(email_verified, FALSE),
                    CASE WHEN totp_secret IS NOT NULL THEN TRUE ELSE FALSE END,
                    totp_secret,
                    status
                FROM tenants
                WHERE email IS NOT NULL
                  AND password_hash IS NOT NULL
                ON CONFLICT (email) DO NOTHING
            """))
            conn.commit()
            
        seed_data()
        
        success_log = {
            "event": "database_migration",
            "status": "success",
            "message": "AuthClaw database migrations completed.",
            "details": {
                "tables": [
                    "audit_logs", "gateway_requests", "gateway_routes", "gateway_approvals", "tenants", 
                    "secrets", "policies", "knowledge_documents", "knowledge_chunks", 
                    "ephemeral_workers", "remediation_findings", "user_roles", 
                    "pentest_simulations", "redteam_attacks", "compliance_evidence", "ha_status",
                    "chat_sessions", "chat_messages", "documents", "document_findings", 
                    "document_scans", "document_audits"
                ]
            }
        }
        logger.info(json.dumps(success_log))
        print(json.dumps(success_log), flush=True)

    except Exception as e:
        failure_log = {
            "event": "database_migration",
            "status": "failed",
            "message": f"Database migrations failed: {str(e)}"
        }
        logger.error(json.dumps(failure_log))
        print(json.dumps(failure_log), flush=True)
        raise RuntimeError("Database migration failed. Aborting startup.") from e

def seed_data():
    """
    Intentionally empty. Production databases start without demo records.
    """
    pass
