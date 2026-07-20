"""Add ACL-18 remediation approval controls.

Revision ID: 027
Revises: 026
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "027"
down_revision = "026"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("pending_approvals", sa.Column("action_hash", sa.String(length=64), nullable=True))
    op.add_column("pending_approvals", sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column(
        "pending_approvals",
        sa.Column("consumed_by_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.add_column("pending_approvals", sa.Column("resolution_reason", sa.Text(), nullable=True))
    op.create_foreign_key(
        "fk_pending_approvals_consumed_by",
        "pending_approvals",
        "users",
        ["consumed_by_id"],
        ["id"],
    )
    op.create_index(
        "idx_approval_tenant_action_hash",
        "pending_approvals",
        ["tenant_id", "action_hash"],
    )

    op.add_column("approval_audit", sa.Column("action_hash", sa.String(length=64), nullable=True))
    op.add_column("approval_audit", sa.Column("reason", sa.Text(), nullable=True))
    op.add_column("approval_audit", sa.Column("details", sa.JSON(), nullable=True))


def downgrade():
    op.drop_column("approval_audit", "details")
    op.drop_column("approval_audit", "reason")
    op.drop_column("approval_audit", "action_hash")
    op.drop_index("idx_approval_tenant_action_hash", table_name="pending_approvals")
    op.drop_constraint("fk_pending_approvals_consumed_by", "pending_approvals", type_="foreignkey")
    op.drop_column("pending_approvals", "resolution_reason")
    op.drop_column("pending_approvals", "consumed_by_id")
    op.drop_column("pending_approvals", "consumed_at")
    op.drop_column("pending_approvals", "action_hash")
