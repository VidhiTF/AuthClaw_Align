"""Enforce the canonical finding-status domain.

Revision ID: 047
Revises: 046
"""

from alembic import op

revision = "047"
down_revision = "046"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("""
        DO $$
        DECLARE invalid_statuses text;
        BEGIN
          SELECT string_agg(status || '=' || status_count::text, ', ' ORDER BY status)
            INTO invalid_statuses
            FROM (
              SELECT status, count(*) AS status_count
                FROM public.findings
               WHERE status NOT IN (
                 'OPEN', 'ACKNOWLEDGED', 'IN_PROGRESS', 'AWAITING_APPROVAL',
                 'RESOLVED', 'FALSE_POSITIVE', 'ACCEPTED_RISK'
               )
               GROUP BY status
            ) invalid;
          IF invalid_statuses IS NOT NULL THEN
            RAISE EXCEPTION
              'Cannot enforce finding status constraint; approve remediation for: %',
              invalid_statuses
              USING ERRCODE = '23514';
          END IF;
        END $$;

        ALTER TABLE public.findings
          ADD CONSTRAINT ck_findings_status
          CHECK (status IN (
            'OPEN', 'ACKNOWLEDGED', 'IN_PROGRESS', 'AWAITING_APPROVAL',
            'RESOLVED', 'FALSE_POSITIVE', 'ACCEPTED_RISK'
          )) NOT VALID;
        ALTER TABLE public.findings VALIDATE CONSTRAINT ck_findings_status;
    """)


def downgrade():
    op.execute("ALTER TABLE public.findings DROP CONSTRAINT IF EXISTS ck_findings_status")
