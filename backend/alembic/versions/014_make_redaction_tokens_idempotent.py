"""Make redaction token persistence idempotent

Revision ID: 014
Revises: 013
"""
from alembic import op


revision = "014"
down_revision = "013"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(
        """
        WITH ranked AS (
            SELECT
                id,
                ROW_NUMBER() OVER (
                    PARTITION BY tenant_id, original_value, strategy
                    ORDER BY created_at ASC, id ASC
                ) AS row_number
            FROM redaction_tokens
        )
        DELETE FROM redaction_tokens AS tokens
        USING ranked
        WHERE tokens.id = ranked.id
          AND ranked.row_number > 1
        """
    )
    op.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1
                FROM pg_constraint
                WHERE conname = 'uq_redaction_tokens_tenant_original_strategy'
            ) THEN
                ALTER TABLE redaction_tokens
                ADD CONSTRAINT uq_redaction_tokens_tenant_original_strategy
                UNIQUE (tenant_id, original_value, strategy);
            END IF;
        END
        $$;
        """
    )


def downgrade():
    op.execute(
        """
        ALTER TABLE redaction_tokens
        DROP CONSTRAINT IF EXISTS uq_redaction_tokens_tenant_original_strategy
        """
    )
