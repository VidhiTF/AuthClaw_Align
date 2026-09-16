"""Add a restricted audit-origin verification function.

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
        CREATE FUNCTION public.verify_audit_origin(
          p_tenant_id uuid, p_record_id uuid, p_canonical_payload text,
          p_prior_hash text, p_integrity_hash text
        ) RETURNS boolean
        LANGUAGE sql STABLE SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
          SELECT EXISTS (
            SELECT 1 FROM public.audit_log_metadata
             WHERE tenant_id = p_tenant_id
               AND record_id = p_record_id
               AND canonical_payload = p_canonical_payload
               AND prior_hash IS NOT DISTINCT FROM p_prior_hash
               AND integrity_hash IS NOT DISTINCT FROM p_integrity_hash
          )
        $$;
        REVOKE ALL ON FUNCTION public.verify_audit_origin(
          uuid, uuid, text, text, text
        ) FROM PUBLIC;
    """)


def downgrade():
    op.execute(
        "DROP FUNCTION IF EXISTS public.verify_audit_origin(uuid,uuid,text,text,text)"
    )
