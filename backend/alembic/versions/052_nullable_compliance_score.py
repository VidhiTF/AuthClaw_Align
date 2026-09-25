"""Preserve unknown framework scores instead of fabricated zeroes.

Revision ID: 052
Revises: 051
Expand-only: old numeric writers remain compatible. Deploy null-aware readers
before enabling the new scorer; rollback keeps this nullable storage contract.
"""
from alembic import op
import sqlalchemy as sa

revision = "052"
down_revision = "051"
branch_labels = depends_on = None


def upgrade():
    op.alter_column("compliance_score_snapshots", "overall_score", existing_type=sa.Float(), nullable=True, server_default=None)


def downgrade():
    # Retain this backward-compatible expansion: replacing unknown values or
    # restoring NOT NULL would destroy evidence or make an application rollback fail.
    return
