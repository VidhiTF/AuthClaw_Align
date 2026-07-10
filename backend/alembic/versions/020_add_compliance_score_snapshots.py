"""Add compliance score snapshots

Revision ID: 020
Revises: 019
Create Date: 2026-07-01 10:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "020"
down_revision = "019"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "compliance_score_snapshots",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("framework", sa.String(length=50), nullable=False),
        sa.Column("snapshot_date", sa.String(length=10), nullable=False),
        sa.Column("overall_score", sa.Float(), nullable=False, server_default="0"),
        sa.Column("readiness_level", sa.String(length=50), nullable=False, server_default="insufficient_evidence"),
        sa.Column("control_scores", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("evidence_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("audit_event_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("open_findings", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("critical_findings", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.UniqueConstraint("tenant_id", "framework", "snapshot_date", name="uq_compliance_score_tenant_framework_date"),
    )
    op.create_index("idx_compliance_score_tenant", "compliance_score_snapshots", ["tenant_id"])
    op.create_index("idx_compliance_score_framework", "compliance_score_snapshots", ["tenant_id", "framework"])
    op.create_index("idx_compliance_score_date", "compliance_score_snapshots", ["tenant_id", "snapshot_date"])

    op.execute("ALTER TABLE compliance_score_snapshots ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE compliance_score_snapshots FORCE ROW LEVEL SECURITY;")
    op.execute(
        """
        CREATE POLICY compliance_score_snapshots_tenant_isolation
        ON compliance_score_snapshots
        USING (
            tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid
        );
        """
    )


def downgrade():
    op.execute("DROP POLICY IF EXISTS compliance_score_snapshots_tenant_isolation ON compliance_score_snapshots")
    op.execute("ALTER TABLE compliance_score_snapshots NO FORCE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE compliance_score_snapshots DISABLE ROW LEVEL SECURITY;")
    op.drop_index("idx_compliance_score_date", table_name="compliance_score_snapshots")
    op.drop_index("idx_compliance_score_framework", table_name="compliance_score_snapshots")
    op.drop_index("idx_compliance_score_tenant", table_name="compliance_score_snapshots")
    op.drop_table("compliance_score_snapshots")
