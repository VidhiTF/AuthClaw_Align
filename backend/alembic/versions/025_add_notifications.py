"""Add in-app notifications

Revision ID: 025
Revises: 024
Create Date: 2026-07-10 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "025"
down_revision = "024"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "notifications",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("type", sa.String(length=100), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False, server_default="info"),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("body", sa.Text(), nullable=False, server_default=""),
        sa.Column("link", sa.String(length=512), nullable=True),
        sa.Column("read_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
    )
    op.create_index("idx_notification_tenant_created", "notifications", ["tenant_id", "created_at"])
    op.create_index("idx_notification_tenant_read", "notifications", ["tenant_id", "read_at"])
    op.create_index("idx_notification_user", "notifications", ["tenant_id", "user_id"])
    op.execute("ALTER TABLE notifications ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE notifications FORCE ROW LEVEL SECURITY;")
    op.execute(
        """
        CREATE POLICY notifications_tenant_isolation
        ON notifications
        USING (
            tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid
        );
        """
    )


def downgrade():
    op.execute("DROP POLICY IF EXISTS notifications_tenant_isolation ON notifications")
    op.execute("ALTER TABLE notifications NO FORCE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE notifications DISABLE ROW LEVEL SECURITY;")
    op.drop_index("idx_notification_user", table_name="notifications")
    op.drop_index("idx_notification_tenant_read", table_name="notifications")
    op.drop_index("idx_notification_tenant_created", table_name="notifications")
    op.drop_table("notifications")
