"""Add tenant-scoped GDPR data-subject request lifecycle.

Revision ID: 035
Revises: 034
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "035"
down_revision = "034"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "data_subject_requests",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id"),
            nullable=False,
        ),
        sa.Column("subject_id", sa.String(length=255), nullable=False),
        sa.Column("request_type", sa.String(length=20), nullable=False),
        sa.Column(
            "status", sa.String(length=20), nullable=False, server_default="PENDING"
        ),
        sa.Column(
            "identity_verified", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
        sa.Column(
            "identity_verified_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id"),
            nullable=True,
        ),
        sa.Column("identity_verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("scope", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("decision", sa.String(length=20), nullable=True),
        sa.Column("decision_reason", sa.Text(), nullable=True),
        sa.Column(
            "decision_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id"),
            nullable=True,
        ),
        sa.Column("decision_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.CheckConstraint(
            "request_type IN ('ACCESS', 'EXPORT', 'DELETION')",
            name="ck_data_subject_request_type",
        ),
        sa.CheckConstraint(
            "status IN ('PENDING', 'VERIFIED', 'APPROVED', 'REJECTED', 'COMPLETED')",
            name="data_subject_request_status",
        ),
        sa.CheckConstraint(
            "decision IS NULL OR decision IN ('APPROVED', 'REJECTED')",
            name="ck_data_subject_request_decision",
        ),
    )
    op.create_index(
        "idx_data_subject_request_tenant_status",
        "data_subject_requests",
        ["tenant_id", "status"],
    )
    op.create_index(
        "idx_data_subject_request_tenant_created",
        "data_subject_requests",
        ["tenant_id", "created_at"],
    )
    op.create_index(
        "idx_data_subject_request_tenant_subject",
        "data_subject_requests",
        ["tenant_id", "subject_id"],
    )
    op.execute("ALTER TABLE data_subject_requests ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE data_subject_requests FORCE ROW LEVEL SECURITY;")
    op.execute("""
        CREATE POLICY data_subject_requests_tenant_isolation
        ON data_subject_requests
        USING (
            tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid
        );
        """)


def downgrade():
    op.execute(
        "DROP POLICY IF EXISTS data_subject_requests_tenant_isolation ON data_subject_requests"
    )
    op.execute("ALTER TABLE data_subject_requests NO FORCE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE data_subject_requests DISABLE ROW LEVEL SECURITY;")
    op.drop_index(
        "idx_data_subject_request_tenant_subject", table_name="data_subject_requests"
    )
    op.drop_index(
        "idx_data_subject_request_tenant_created", table_name="data_subject_requests"
    )
    op.drop_index(
        "idx_data_subject_request_tenant_status", table_name="data_subject_requests"
    )
    op.drop_table("data_subject_requests")
