"""Add ACL-19 integrity metadata and immutability to evidence records.

Revision ID: 038
Revises: 037
"""

from __future__ import annotations

import hashlib
import json
from datetime import timezone

from alembic import op
import sqlalchemy as sa


revision = "038"
down_revision = "037"
branch_labels = None
depends_on = None


def _canonical_hash(row) -> str:
    created_at = row["created_at"]
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
    payload = {
        "created_at": created_at.astimezone(timezone.utc).isoformat(timespec="microseconds"),
        "evidence_data": row["evidence_data"] or {},
        "evidence_type": row["evidence_type"],
        "framework": row["framework"].upper(),
        "id": str(row["id"]),
        "severity": row["severity"].lower(),
        "source_reference": row["source_reference"] or "",
        "source_type": row["source_type"],
        "tenant_id": str(row["tenant_id"]),
        "workflow_id": row["workflow_id"] or "",
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def upgrade():
    # Revision 036 forces tenant RLS. The owner migration must temporarily bypass
    # it so every existing tenant's evidence receives integrity metadata.
    op.execute("ALTER TABLE evidence_records NO FORCE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE evidence_records DISABLE ROW LEVEL SECURITY")
    op.add_column("evidence_records", sa.Column("integrity_hash", sa.String(length=64), nullable=True))
    op.add_column(
        "evidence_records",
        sa.Column("integrity_algorithm", sa.String(length=20), nullable=False, server_default="sha256"),
    )
    op.add_column(
        "evidence_records",
        sa.Column("integrity_version", sa.Integer(), nullable=False, server_default="1"),
    )

    bind = op.get_bind()
    rows = bind.execute(
        sa.text(
            """
            SELECT id, tenant_id, workflow_id, framework, source_type,
                   source_reference, evidence_type, evidence_data, severity, created_at
            FROM evidence_records
            """
        )
    ).mappings()
    for row in rows:
        bind.execute(
            sa.text("UPDATE evidence_records SET integrity_hash=:integrity_hash WHERE id=:id"),
            {"id": row["id"], "integrity_hash": _canonical_hash(row)},
        )

    op.alter_column("evidence_records", "integrity_hash", nullable=False)
    op.create_check_constraint(
        "ck_evidence_integrity_hash_sha256",
        "evidence_records",
        "integrity_hash ~ '^[0-9a-f]{64}$'",
    )
    op.create_check_constraint(
        "ck_evidence_integrity_algorithm",
        "evidence_records",
        "integrity_algorithm = 'sha256'",
    )
    op.create_check_constraint(
        "ck_evidence_integrity_version",
        "evidence_records",
        "integrity_version >= 1",
    )

    op.execute(
        """
        CREATE OR REPLACE FUNCTION reject_evidence_record_update()
        RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'evidence_records are immutable'
                USING ERRCODE = '55000';
        END;
        $$ LANGUAGE plpgsql;

        CREATE TRIGGER evidence_records_immutable
        BEFORE UPDATE ON evidence_records
        FOR EACH ROW EXECUTE FUNCTION reject_evidence_record_update();
        """
    )
    op.execute("ALTER TABLE evidence_records ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE evidence_records FORCE ROW LEVEL SECURITY")


def downgrade():
    op.execute("DROP TRIGGER IF EXISTS evidence_records_immutable ON evidence_records")
    op.execute("DROP FUNCTION IF EXISTS reject_evidence_record_update()")
    op.drop_constraint("ck_evidence_integrity_version", "evidence_records", type_="check")
    op.drop_constraint("ck_evidence_integrity_algorithm", "evidence_records", type_="check")
    op.drop_constraint("ck_evidence_integrity_hash_sha256", "evidence_records", type_="check")
    op.drop_column("evidence_records", "integrity_version")
    op.drop_column("evidence_records", "integrity_algorithm")
    op.drop_column("evidence_records", "integrity_hash")
