from alembic import op
"""Add RLS policies"""



# Alembic identifiers
revision = "002"
down_revision = "001"
branch_labels = None
depends_on = None
def upgrade():
    # TENANTS
    op.execute("ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE tenants FORCE ROW LEVEL SECURITY;")
    op.execute("""
    CREATE POLICY tenants_tenant_isolation
    ON tenants
    USING (
        id = nullif(current_setting('app.current_tenant_id', true), '')::uuid
    );
    """)

    # USERS
    op.execute("ALTER TABLE users ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE users FORCE ROW LEVEL SECURITY;")
    op.execute("""
    CREATE POLICY users_tenant_isolation
    ON users
    USING (
        tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid
    );
    """)

    # API KEYS
    op.execute("ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE api_keys FORCE ROW LEVEL SECURITY;")
    op.execute("""
    CREATE POLICY api_keys_tenant_isolation
    ON api_keys
    USING (
        tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid
    );
    """)

    # POLICIES
    op.execute("ALTER TABLE policies ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE policies FORCE ROW LEVEL SECURITY;")
    op.execute("""
    CREATE POLICY policies_tenant_isolation
    ON policies
    USING (
        tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid
    );
    """)

    # GATEWAY CONFIGS
    op.execute("ALTER TABLE gateway_configs ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE gateway_configs FORCE ROW LEVEL SECURITY;")
    op.execute("""
    CREATE POLICY gateway_configs_tenant_isolation
    ON gateway_configs
    USING (
        tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid
    );
    """)

    # REDACTION TOKENS
    op.execute("ALTER TABLE redaction_tokens ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE redaction_tokens FORCE ROW LEVEL SECURITY;")
    op.execute("""
    CREATE POLICY redaction_tokens_tenant_isolation
    ON redaction_tokens
    USING (
        tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid
    );
    """)

    # PENDING APPROVALS
    op.execute("ALTER TABLE pending_approvals ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE pending_approvals FORCE ROW LEVEL SECURITY;")
    op.execute("""
    CREATE POLICY pending_approvals_tenant_isolation
    ON pending_approvals
    USING (
        tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid
    );
    """)

    # AUDIT LOG METADATA
    op.execute("ALTER TABLE audit_log_metadata ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE audit_log_metadata FORCE ROW LEVEL SECURITY;")
    op.execute("""
    CREATE POLICY audit_log_metadata_tenant_isolation
    ON audit_log_metadata
    USING (
        tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid
    );
    """)

def downgrade():
    op.execute("DROP POLICY IF EXISTS tenants_tenant_isolation ON tenants")
    op.execute("ALTER TABLE tenants NO FORCE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE tenants DISABLE ROW LEVEL SECURITY;")

    op.execute("DROP POLICY IF EXISTS users_tenant_isolation ON users")
    op.execute("ALTER TABLE users NO FORCE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE users DISABLE ROW LEVEL SECURITY;")

    op.execute("DROP POLICY IF EXISTS api_keys_tenant_isolation ON api_keys")
    op.execute("ALTER TABLE api_keys NO FORCE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE api_keys DISABLE ROW LEVEL SECURITY;")

    op.execute("DROP POLICY IF EXISTS policies_tenant_isolation ON policies")
    op.execute("ALTER TABLE policies NO FORCE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE policies DISABLE ROW LEVEL SECURITY;")

    op.execute("DROP POLICY IF EXISTS gateway_configs_tenant_isolation ON gateway_configs")
    op.execute("ALTER TABLE gateway_configs NO FORCE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE gateway_configs DISABLE ROW LEVEL SECURITY;")

    op.execute("DROP POLICY IF EXISTS redaction_tokens_tenant_isolation ON redaction_tokens")
    op.execute("ALTER TABLE redaction_tokens NO FORCE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE redaction_tokens DISABLE ROW LEVEL SECURITY;")

    op.execute("DROP POLICY IF EXISTS pending_approvals_tenant_isolation ON pending_approvals")
    op.execute("ALTER TABLE pending_approvals NO FORCE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE pending_approvals DISABLE ROW LEVEL SECURITY;")

    op.execute("DROP POLICY IF EXISTS audit_log_metadata_tenant_isolation ON audit_log_metadata")
    op.execute("ALTER TABLE audit_log_metadata NO FORCE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE audit_log_metadata DISABLE ROW LEVEL SECURITY;")