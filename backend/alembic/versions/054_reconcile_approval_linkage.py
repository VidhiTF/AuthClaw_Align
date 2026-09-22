"""Reconcile legacy approval linkage before enforcing action uniqueness.

Revision ID: 054
Revises: 053
"""

from alembic import op


revision = "054"
down_revision = "053"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Keep one canonical approval per action. Prefer the most progressed approval,
    # then an existing workflow link, followed by stable timestamps/ID.
    # Duplicate approvals and their audit rows are retained: non-canonical
    # approvals are moved to a deterministic historical action key and point to
    # their canonical approval in resolution metadata.  Audit ownership is
    # immutable forensic evidence and must never be re-parented.
    for table in ("pending_approvals", "compliance_workflows", "approval_audit"):
        op.execute(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")
    op.execute("DROP TABLE IF EXISTS approval_linkage_054")
    op.execute(
        """
        CREATE TEMP TABLE approval_linkage_054 ON COMMIT DROP AS
        SELECT id, tenant_id, action_type, action_id,
               first_value(id) OVER (
                   PARTITION BY tenant_id, action_type, action_id
                   ORDER BY
                       CASE upper(status)
                           WHEN 'CONSUMED' THEN 0
                           WHEN 'APPROVED' THEN 1
                           WHEN 'PENDING' THEN 2
                           WHEN 'REJECTED' THEN 3
                           WHEN 'EXPIRED' THEN 4
                           ELSE 5
                       END,
                       CASE WHEN EXISTS (
                           SELECT 1 FROM compliance_workflows cw
                           WHERE cw.tenant_id = pending_approvals.tenant_id
                             AND cw.workflow_id = pending_approvals.action_id
                             AND cw.approval_id = pending_approvals.id
                       ) THEN 0 ELSE 1 END,
                       created_at NULLS LAST,
                       id::text
               ) AS keeper_id,
               row_number() OVER (
                   PARTITION BY tenant_id, action_type, action_id
                   ORDER BY
                       CASE upper(status)
                           WHEN 'CONSUMED' THEN 0
                           WHEN 'APPROVED' THEN 1
                           WHEN 'PENDING' THEN 2
                           WHEN 'REJECTED' THEN 3
                           WHEN 'EXPIRED' THEN 4
                           ELSE 5
                       END,
                       CASE WHEN EXISTS (
                           SELECT 1 FROM compliance_workflows cw
                           WHERE cw.tenant_id = pending_approvals.tenant_id
                             AND cw.workflow_id = pending_approvals.action_id
                             AND cw.approval_id = pending_approvals.id
                       ) THEN 0 ELSE 1 END,
                       created_at NULLS LAST,
                       id::text
               ) AS duplicate_rank
        FROM pending_approvals
        """
    )
    op.execute(
        """
        UPDATE compliance_workflows cw
        SET approval_id = canonical.keeper_id,
            state_data = jsonb_set(
                COALESCE(cw.state_data::jsonb, '{}'::jsonb),
                '{approval_id}', to_jsonb(canonical.keeper_id::text), true
            )::json,
            updated_at = GREATEST(cw.updated_at, CURRENT_TIMESTAMP)
        FROM approval_linkage_054 canonical
        WHERE canonical.duplicate_rank = 1
          AND canonical.action_type = 'remediation'
          AND canonical.tenant_id = cw.tenant_id
          AND canonical.action_id = cw.workflow_id
          AND cw.approval_id IS DISTINCT FROM canonical.keeper_id
        """
    )
    op.execute(
        """
        UPDATE pending_approvals approval
        SET action_id = left(approval.action_id, 200) || '#superseded:' || approval.id::text,
            resolution_reason = CASE
                WHEN COALESCE(approval.resolution_reason, '') LIKE '%[migration-054:%'
                    THEN approval.resolution_reason
                ELSE concat_ws(
                    ' ', NULLIF(approval.resolution_reason, ''),
                    '[migration-054: duplicate of ' || duplicate.keeper_id::text || ']'
                )
            END,
            updated_at = GREATEST(approval.updated_at, CURRENT_TIMESTAMP)
        FROM approval_linkage_054 duplicate
        WHERE duplicate.duplicate_rank > 1
          AND approval.id = duplicate.id
        """
    )
    op.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_constraint
                WHERE conname = 'uq_pending_approval_tenant_action'
                  AND conrelid = 'pending_approvals'::regclass
            ) THEN
                ALTER TABLE pending_approvals
                ADD CONSTRAINT uq_pending_approval_tenant_action
                UNIQUE (tenant_id, action_type, action_id);
            END IF;
        END
        $$
        """
    )
    for table in ("pending_approvals", "compliance_workflows", "approval_audit"):
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")


def downgrade() -> None:
    op.execute(
        "ALTER TABLE pending_approvals "
        "DROP CONSTRAINT IF EXISTS uq_pending_approval_tenant_action"
    )
