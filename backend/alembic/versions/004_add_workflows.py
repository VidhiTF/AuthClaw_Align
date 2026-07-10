"""
Alembic migration - Create compliance_workflows table for Phase 8
This is version 004 - LangGraph Compliance Orchestrator schema
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "004"
down_revision = "003"
branch_labels = None
depends_on = None

def upgrade():
    # Compliance Workflows table
    op.create_table(
        'compliance_workflows',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('workflow_id', sa.String(255), nullable=False, unique=True),
        sa.Column('request_id', sa.String(255), nullable=True),
        sa.Column('framework', sa.String(50), nullable=False),
        sa.Column('current_state', sa.String(50), nullable=False, server_default='GATHER_EVIDENCE'),
        sa.Column('findings', postgresql.JSON(), nullable=True),
        sa.Column('risk_score', sa.Float(), nullable=True),
        sa.Column('remediation_plan', postgresql.JSON(), nullable=True),
        sa.Column('approval_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('approval_status', sa.String(50), nullable=True),
        sa.Column('execution_status', sa.String(50), nullable=False, server_default='RUNNING'),
        sa.Column('execution_result', postgresql.JSON(), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('retry_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('state_data', postgresql.JSON(), nullable=True),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ),
        sa.ForeignKeyConstraint(['approval_id'], ['pending_approvals.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('workflow_id'),
    )
    op.create_index('idx_workflow_tenant', 'compliance_workflows', ['tenant_id'])
    op.create_index('idx_workflow_status', 'compliance_workflows', ['execution_status'])
    op.create_index('idx_workflow_state', 'compliance_workflows', ['current_state'])
    op.create_index('idx_workflow_wfid', 'compliance_workflows', ['workflow_id'])

    # RLS policy for tenant isolation (matches pattern from migration 002)
    op.execute("ALTER TABLE compliance_workflows ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE compliance_workflows FORCE ROW LEVEL SECURITY;")
    op.execute("""
    CREATE POLICY compliance_workflows_tenant_isolation
    ON compliance_workflows
    USING (
        tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid
    );
    """)


def downgrade():
    op.execute("DROP POLICY IF EXISTS compliance_workflows_tenant_isolation ON compliance_workflows;")
    op.drop_table('compliance_workflows')
