"""Version compliance history and preserve assessment approval provenance.

Revision ID: 050
Revises: 049
Drain old backend snapshot writers before upgrade. Historic records are not
reclassified. Downgrade refuses to discard a non-legacy calculation.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "050"
down_revision = "049"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("compliance_score_snapshots", sa.Column(
        "calculation_version", sa.String(100), nullable=False, server_default="legacy_unversioned",
    ))
    op.add_column("compliance_score_snapshots", sa.Column(
        "assessment_metadata", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb"),
    ))
    op.drop_constraint("uq_compliance_score_tenant_framework_date", "compliance_score_snapshots", type_="unique")
    op.create_unique_constraint("uq_compliance_score_tenant_framework_date_version", "compliance_score_snapshots", [
        "tenant_id", "framework", "snapshot_date", "calculation_version",
    ])
    # Keep the existing forced tenant RLS and runtime role privileges unchanged.
    op.execute("""
        CREATE FUNCTION reject_control_assessment_audit_change() RETURNS trigger
        LANGUAGE plpgsql SET search_path = pg_catalog AS $$
        BEGIN
            IF OLD.action LIKE 'ASSESSMENT_%' THEN
                RAISE EXCEPTION 'control assessment audit records are immutable' USING ERRCODE = '55000';
            END IF;
            IF TG_OP = 'UPDATE' THEN
                IF NEW.action LIKE 'ASSESSMENT_%' THEN
                    RAISE EXCEPTION 'control assessment audit records are immutable' USING ERRCODE = '55000';
                END IF;
                RETURN NEW;
            END IF;
            RETURN OLD;
        END;
        $$;
        CREATE TRIGGER control_assessment_audit_immutable
        BEFORE UPDATE OR DELETE ON approval_audit
        FOR EACH ROW EXECUTE FUNCTION reject_control_assessment_audit_change();
    """)


def downgrade():
    # Migration owners also obey forced RLS. A table lock plus a temporary
    # migration-only RLS disable makes the retention guard cover every tenant;
    # PostgreSQL rolls the whole transaction back if the guard fails.
    op.execute("LOCK TABLE compliance_score_snapshots, approval_audit IN ACCESS EXCLUSIVE MODE")
    op.execute("ALTER TABLE compliance_score_snapshots DISABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE approval_audit DISABLE ROW LEVEL SECURITY")
    op.execute("""
        DO $$ BEGIN
            IF EXISTS (SELECT 1 FROM compliance_score_snapshots WHERE calculation_version <> 'legacy_unversioned')
               OR EXISTS (SELECT 1 FROM approval_audit WHERE action LIKE 'ASSESSMENT_%') THEN
                RAISE EXCEPTION 'Retained T10 history requires a forward fix; downgrade refused';
            END IF;
        END $$;
    """)
    op.execute("ALTER TABLE compliance_score_snapshots ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE approval_audit ENABLE ROW LEVEL SECURITY")
    op.execute("DROP TRIGGER control_assessment_audit_immutable ON approval_audit")
    op.execute("DROP FUNCTION reject_control_assessment_audit_change()")
    op.drop_constraint("uq_compliance_score_tenant_framework_date_version", "compliance_score_snapshots", type_="unique")
    op.create_unique_constraint("uq_compliance_score_tenant_framework_date", "compliance_score_snapshots", ["tenant_id", "framework", "snapshot_date"])
    op.drop_column("compliance_score_snapshots", "assessment_metadata")
    op.drop_column("compliance_score_snapshots", "calculation_version")
