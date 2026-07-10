"""Update legacy HITL timeout values

Revision ID: 013
Revises: 012
"""
from alembic import op


revision = "013"
down_revision = "012"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(
        """
        UPDATE policies
        SET policy_yaml = replace(policy_yaml, 'hitl_timeout_seconds: 300', 'hitl_timeout_seconds: 1800')
        WHERE policy_yaml LIKE '%hitl_timeout_seconds: 300%'
        """
    )


def downgrade():
    pass
