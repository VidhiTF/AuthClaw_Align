"""Add keyed lookup index for randomized redaction ciphertext.

Revision ID: 037
Revises: 036
"""

from alembic import op
import sqlalchemy as sa


revision = "037"
down_revision = "036"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "redaction_tokens",
        sa.Column("original_value_blind_index", sa.String(length=64), nullable=True),
    )
    op.drop_constraint(
        "uq_redaction_tokens_tenant_original_strategy",
        "redaction_tokens",
        type_="unique",
    )
    op.create_unique_constraint(
        "uq_redaction_tokens_tenant_blind_index_strategy",
        "redaction_tokens",
        ["tenant_id", "original_value_blind_index", "strategy"],
    )


def downgrade():
    op.drop_constraint(
        "uq_redaction_tokens_tenant_blind_index_strategy",
        "redaction_tokens",
        type_="unique",
    )
    op.create_unique_constraint(
        "uq_redaction_tokens_tenant_original_strategy",
        "redaction_tokens",
        ["tenant_id", "original_value", "strategy"],
    )
    op.drop_column("redaction_tokens", "original_value_blind_index")
