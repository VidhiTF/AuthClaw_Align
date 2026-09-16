"""Allow a read-only audit verifier to select one tenant's origin rows.

Revision ID: 048
Revises: 047
"""

from alembic import op


revision = "048"
down_revision = "047"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("""
        CREATE POLICY audit_log_metadata_origin_reader
        ON public.audit_log_metadata
        FOR SELECT
        USING (
          tenant_id = nullif(
            current_setting('app.current_tenant_id', true), ''
          )::uuid
          AND has_table_privilege(
            session_user, 'public.audit_log_metadata', 'SELECT'
          )
          AND NOT has_table_privilege(
            session_user, 'public.audit_log_metadata', 'INSERT'
          )
          AND NOT has_table_privilege(
            session_user, 'public.audit_log_metadata', 'UPDATE'
          )
          AND NOT has_table_privilege(
            session_user, 'public.audit_log_metadata', 'DELETE'
          )
        );
    """)


def downgrade():
    op.execute(
        "DROP POLICY IF EXISTS audit_log_metadata_origin_reader "
        "ON public.audit_log_metadata"
    )
