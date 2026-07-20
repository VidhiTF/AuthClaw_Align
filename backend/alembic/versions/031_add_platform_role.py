"""Add global platform roles

Revision ID: 031
Revises: 030
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "031"
down_revision = "030"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    role_type = postgresql.ENUM("NONE", "ADMIN", name="platform_role")
    role_type.create(bind, checkfirst=True)
    op.add_column(
        "users",
        sa.Column(
            "platform_role",
            role_type,
            nullable=False,
            server_default="NONE",
        ),
    )
    op.alter_column("users", "platform_role", server_default=None)


def downgrade():
    bind = op.get_bind()
    op.drop_column("users", "platform_role")
    postgresql.ENUM(name="platform_role").drop(bind, checkfirst=True)
