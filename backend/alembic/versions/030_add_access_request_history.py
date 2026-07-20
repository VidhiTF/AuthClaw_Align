"""Add public access request history

Revision ID: 030
Revises: 029
"""

import os

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "030"
down_revision = "029"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "access_request_history",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("access_request_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("actor_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("event_type", sa.String(length=50), nullable=False),
        sa.Column("old_status", sa.String(length=50), nullable=True),
        sa.Column("new_status", sa.String(length=50), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "metadata",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default="{}",
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "idx_access_request_history_request",
        "access_request_history",
        ["access_request_id", "created_at"],
    )
    app_role = op.get_bind().dialect.identifier_preparer.quote(
        os.getenv("POSTGRES_APP_USER", "authclaw_app")
    )
    op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON access_requests TO {app_role}")
    op.execute(f"GRANT SELECT, INSERT ON access_request_history TO {app_role}")
    op.execute(f"GRANT SELECT ON onboarding_email_otps TO {app_role}")


def downgrade():
    app_role = op.get_bind().dialect.identifier_preparer.quote(
        os.getenv("POSTGRES_APP_USER", "authclaw_app")
    )
    op.execute(f"REVOKE SELECT ON onboarding_email_otps FROM {app_role}")
    op.execute(f"REVOKE SELECT, INSERT ON access_request_history FROM {app_role}")
    op.execute(f"REVOKE UPDATE, DELETE ON access_requests FROM {app_role}")
    op.drop_index(
        "idx_access_request_history_request",
        table_name="access_request_history",
    )
    op.drop_table("access_request_history")
