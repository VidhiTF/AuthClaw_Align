"""Add public access requests

Revision ID: 029
Revises: 028
"""

import os

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "029"
down_revision = "028"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "access_requests",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("reference", sa.String(length=35), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("business_email", sa.String(length=255), nullable=False),
        sa.Column("company", sa.String(length=255), nullable=False),
        sa.Column("role", sa.String(length=100), nullable=False),
        sa.Column("use_case", sa.Text(), nullable=False),
        sa.Column("requested_access", sa.String(length=100), nullable=False),
        sa.Column("consent_timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("notice_version", sa.String(length=50), nullable=False),
        sa.Column("source_page", sa.String(length=512), nullable=False),
        sa.Column("status", sa.String(length=50), nullable=False, server_default="PENDING"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_access_requests_reference", "access_requests", ["reference"], unique=True)
    op.create_index("idx_access_requests_status_created", "access_requests", ["status", "created_at"])
    app_role = op.get_bind().dialect.identifier_preparer.quote(
        os.getenv("POSTGRES_APP_USER", "authclaw_app")
    )
    op.execute(f"GRANT SELECT, INSERT ON access_requests TO {app_role}")


def downgrade():
    op.drop_index("idx_access_requests_status_created", table_name="access_requests")
    op.drop_index("idx_access_requests_reference", table_name="access_requests")
    op.drop_table("access_requests")
