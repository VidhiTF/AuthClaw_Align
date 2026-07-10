"""
Alembic migration - Create findings table for Phase 17
This is version 006 - Findings Dashboard
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "006"
down_revision = "005"
branch_labels = None
depends_on = None

def upgrade():
    # Verify no existing findings schema before migration
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = inspector.get_table_names()
    if 'evidence_records' not in existing_tables:
        op.create_table(
            'evidence_records',
            sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
            sa.Column('tenant_id', postgresql.UUID(as_uuid=True), nullable=False),
            sa.Column('workflow_id', sa.String(255), nullable=True),
            sa.Column('framework', sa.String(50), nullable=False),
            sa.Column('source_type', sa.String(100), nullable=False),
            sa.Column('source_reference', sa.Text(), nullable=True),
            sa.Column('evidence_type', sa.String(100), nullable=False),
            sa.Column('evidence_data', postgresql.JSON(), nullable=False),
            sa.Column('severity', sa.String(50), nullable=False, server_default='info'),
            sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ondelete='CASCADE'),
            sa.PrimaryKeyConstraint('id'),
        )
        op.create_index('idx_evidence_tenant', 'evidence_records', ['tenant_id'])
        op.create_index('idx_evidence_workflow', 'evidence_records', ['workflow_id'])
        op.create_index('idx_evidence_framework', 'evidence_records', ['framework'])
        op.create_index('idx_evidence_type', 'evidence_records', ['evidence_type'])
        op.create_index('idx_evidence_severity', 'evidence_records', ['severity'])
        op.create_index('idx_evidence_created', 'evidence_records', ['created_at'])

    if 'evidence_links' not in existing_tables:
        op.create_table(
            'evidence_links',
            sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
            sa.Column('tenant_id', postgresql.UUID(as_uuid=True), nullable=False),
            sa.Column('evidence_id', postgresql.UUID(as_uuid=True), nullable=False),
            sa.Column('linked_type', sa.String(50), nullable=False),
            sa.Column('linked_id', sa.String(255), nullable=False),
            sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ondelete='CASCADE'),
            sa.ForeignKeyConstraint(['evidence_id'], ['evidence_records.id'], ondelete='CASCADE'),
            sa.PrimaryKeyConstraint('id'),
        )
        op.create_index('idx_evidence_link_tenant', 'evidence_links', ['tenant_id'])
        op.create_index('idx_evidence_link_evidence', 'evidence_links', ['evidence_id'])
        op.create_index('idx_evidence_link_linked', 'evidence_links', ['linked_type', 'linked_id'])

    if 'findings' in existing_tables:
        print("WARNING: Existing findings table detected. Skipping creation.")
    else:
        op.create_table(
            'findings',
            sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
            sa.Column('tenant_id', postgresql.UUID(as_uuid=True), nullable=False),
            sa.Column('workflow_id', sa.String(255), nullable=True),
            sa.Column('evidence_id', postgresql.UUID(as_uuid=True), nullable=True),
            sa.Column('framework', sa.String(50), nullable=False),
            sa.Column('finding_key', sa.String(512), nullable=False),
            sa.Column('title', sa.String(512), nullable=False),
            sa.Column('description', sa.Text(), nullable=True),
            sa.Column('severity', sa.String(50), nullable=False, server_default="medium"),
            sa.Column('status', sa.String(50), nullable=False, server_default="OPEN"),
            sa.Column('finding_type', sa.String(100), nullable=False),
            sa.Column('risk_score', sa.Float(), nullable=False, server_default="0.0"),
            sa.Column('remediation_summary', sa.Text(), nullable=True),
            sa.Column('owner_user_id', postgresql.UUID(as_uuid=True), nullable=True),
            sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True),
            sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ondelete='CASCADE'),
            sa.ForeignKeyConstraint(['evidence_id'], ['evidence_records.id'], ),
            sa.ForeignKeyConstraint(['owner_user_id'], ['users.id'], ),
            sa.PrimaryKeyConstraint('id'),
        )
        op.create_index('idx_finding_tenant', 'findings', ['tenant_id'])
        op.create_index('idx_finding_workflow', 'findings', ['workflow_id'])
        op.create_index('idx_finding_framework', 'findings', ['framework'])
        op.create_index('idx_finding_status', 'findings', ['status'])
        op.create_index('idx_finding_severity', 'findings', ['severity'])
        op.create_index('idx_finding_type', 'findings', ['finding_type'])
        op.create_index('idx_finding_created', 'findings', ['created_at'])
        op.create_index('idx_finding_key', 'findings', ['finding_key'])

    # Enable RLS on findings
    op.execute("ALTER TABLE findings ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE findings FORCE ROW LEVEL SECURITY;")
    op.execute("""
    CREATE POLICY findings_tenant_isolation
    ON findings
    USING (
        tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid
    );
    """)
    op.execute("ALTER TABLE evidence_records ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE evidence_records FORCE ROW LEVEL SECURITY;")
    op.execute("""
    CREATE POLICY evidence_records_tenant_isolation
    ON evidence_records
    USING (
        tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid
    );
    """)
    op.execute("ALTER TABLE evidence_links ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE evidence_links FORCE ROW LEVEL SECURITY;")
    op.execute("""
    CREATE POLICY evidence_links_tenant_isolation
    ON evidence_links
    USING (
        tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid
    );
    """)

def downgrade():
    op.execute("DROP POLICY IF EXISTS findings_tenant_isolation ON findings;")
    op.execute("ALTER TABLE findings NO FORCE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE findings DISABLE ROW LEVEL SECURITY;")
    op.drop_table('findings')
    op.execute("DROP POLICY IF EXISTS evidence_links_tenant_isolation ON evidence_links;")
    op.execute("ALTER TABLE evidence_links NO FORCE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE evidence_links DISABLE ROW LEVEL SECURITY;")
    op.drop_table('evidence_links')
    op.execute("DROP POLICY IF EXISTS evidence_records_tenant_isolation ON evidence_records;")
    op.execute("ALTER TABLE evidence_records NO FORCE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE evidence_records DISABLE ROW LEVEL SECURITY;")
    op.drop_table('evidence_records')
