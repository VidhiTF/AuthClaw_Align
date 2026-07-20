"""Create the canonical immutable audit append path.

Revision ID: 028
Revises: 027
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "028"
down_revision = "027"
branch_labels = None
depends_on = None


APPEND_FUNCTION = r"""
CREATE OR REPLACE FUNCTION append_audit_event_v2(
    p_tenant_id uuid,
    p_record_id uuid,
    p_idempotency_key text,
    p_occurred_at timestamptz,
    p_actor_id uuid DEFAULT NULL,
    p_actor_type text DEFAULT 'backend',
    p_action text DEFAULT '',
    p_request_id text DEFAULT '',
    p_policy_id uuid DEFAULT NULL,
    p_provider text DEFAULT '',
    p_model text DEFAULT '',
    p_reason text DEFAULT '',
    p_prompt_count integer DEFAULT 0,
    p_request_size integer DEFAULT 0,
    p_response_status integer DEFAULT 0,
    p_duration_ms integer DEFAULT 0,
    p_frameworks text[] DEFAULT ARRAY[]::text[],
    p_execution_trace jsonb DEFAULT '[]'::jsonb
)
RETURNS TABLE (
    record_id uuid,
    tenant_sequence bigint,
    prior_hash text,
    integrity_hash text,
    canonical_payload text,
    duplicate boolean
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_existing audit_log_metadata%ROWTYPE;
    v_sequence bigint;
    v_prior_hash text;
    v_canonical text;
    v_integrity_hash text;
    v_frameworks text[];
    v_trace jsonb;
    v_occurred_at timestamptz;
BEGIN
    IF p_idempotency_key IS NULL OR btrim(p_idempotency_key) = '' THEN
        RAISE EXCEPTION 'audit idempotency key is required'
            USING ERRCODE = '22023';
    END IF;

    IF nullif(current_setting('app.current_tenant_id', true), '')::uuid
        IS DISTINCT FROM p_tenant_id THEN
        RAISE EXCEPTION 'audit tenant context does not match append tenant'
            USING ERRCODE = '42501';
    END IF;

    PERFORM pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 0));

    v_frameworks := ARRAY(
        SELECT DISTINCT framework
        FROM unnest(COALESCE(p_frameworks, ARRAY[]::text[])) AS framework
        WHERE framework <> ''
        ORDER BY framework
    );
    v_trace := COALESCE(p_execution_trace, '[]'::jsonb);
    v_occurred_at := date_trunc('milliseconds', COALESCE(p_occurred_at, clock_timestamp()));

    SELECT *
      INTO v_existing
      FROM audit_log_metadata AS audit
     WHERE audit.tenant_id = p_tenant_id
       AND audit.idempotency_key = p_idempotency_key;

    IF FOUND THEN
        v_canonical := jsonb_build_object(
            'record_id', v_existing.record_id::text,
            'tenant_id', p_tenant_id::text,
            'tenant_sequence', v_existing.tenant_sequence,
            'chain_version', 2,
            'timestamp', to_char(
                date_trunc('milliseconds', v_existing.created_at) AT TIME ZONE 'UTC',
                'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
            ),
            'actor_id', COALESCE(p_actor_id::text, ''),
            'actor_type', COALESCE(p_actor_type, 'backend'),
            'action', COALESCE(p_action, ''),
            'policy_id', COALESCE(p_policy_id::text, ''),
            'provider', COALESCE(p_provider, ''),
            'model', COALESCE(p_model, ''),
            'reason', COALESCE(p_reason, ''),
            'prompt_count', COALESCE(p_prompt_count, 0),
            'request_size', COALESCE(p_request_size, 0),
            'response_status', COALESCE(p_response_status, 0),
            'duration_ms', COALESCE(p_duration_ms, 0),
            'frameworks_affected', to_jsonb(v_frameworks),
            'execution_trace', v_trace::text,
            'request_id', COALESCE(p_request_id, '')
        )::text;

        IF v_existing.canonical_payload IS DISTINCT FROM v_canonical THEN
            RAISE EXCEPTION 'audit idempotency-key collision for tenant % and key %',
                p_tenant_id, p_idempotency_key
                USING ERRCODE = '23505';
        END IF;

        RETURN QUERY SELECT
            v_existing.record_id,
            v_existing.tenant_sequence,
            COALESCE(v_existing.prior_hash, 'GENESIS')::text,
            COALESCE(v_existing.integrity_hash, '')::text,
            v_existing.canonical_payload,
            true;
        RETURN;
    END IF;

    IF EXISTS (
        SELECT 1 FROM audit_log_metadata AS audit
        WHERE audit.record_id = p_record_id
    ) THEN
        RAISE EXCEPTION 'audit record_id collision for %', p_record_id
            USING ERRCODE = '23505';
    END IF;

    SELECT COALESCE(MAX(audit.tenant_sequence), 0) + 1,
           COALESCE(
               (ARRAY_AGG(audit.integrity_hash ORDER BY audit.tenant_sequence DESC))[1],
               'GENESIS'
           )
      INTO v_sequence, v_prior_hash
      FROM audit_log_metadata AS audit
     WHERE audit.tenant_id = p_tenant_id;

    v_canonical := jsonb_build_object(
        'record_id', p_record_id::text,
        'tenant_id', p_tenant_id::text,
        'tenant_sequence', v_sequence,
        'chain_version', 2,
        'timestamp', to_char(v_occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
        'actor_id', COALESCE(p_actor_id::text, ''),
        'actor_type', COALESCE(p_actor_type, 'backend'),
        'action', COALESCE(p_action, ''),
        'policy_id', COALESCE(p_policy_id::text, ''),
        'provider', COALESCE(p_provider, ''),
        'model', COALESCE(p_model, ''),
        'reason', COALESCE(p_reason, ''),
        'prompt_count', COALESCE(p_prompt_count, 0),
        'request_size', COALESCE(p_request_size, 0),
        'response_status', COALESCE(p_response_status, 0),
        'duration_ms', COALESCE(p_duration_ms, 0),
        'frameworks_affected', to_jsonb(v_frameworks),
        'execution_trace', v_trace::text,
        'request_id', COALESCE(p_request_id, '')
    )::text;
    v_integrity_hash := encode(
        digest(convert_to(v_canonical || v_prior_hash, 'UTF8'), 'sha256'),
        'hex'
    );

    INSERT INTO audit_log_metadata (
        id, tenant_id, record_id, tenant_sequence, idempotency_key, chain_version,
        canonical_payload, actor_id, actor_type, action, request_id, policy_id,
        provider, model, reason, prompt_count, request_size, response_status,
        duration_ms, frameworks_affected, execution_trace, prior_hash,
        integrity_hash, created_at
    ) VALUES (
        gen_random_uuid(), p_tenant_id, p_record_id, v_sequence, p_idempotency_key, 2,
        v_canonical, p_actor_id, COALESCE(p_actor_type, 'backend'),
        COALESCE(p_action, ''), COALESCE(p_request_id, ''), p_policy_id,
        COALESCE(p_provider, ''), COALESCE(p_model, ''), COALESCE(p_reason, ''),
        COALESCE(p_prompt_count, 0), COALESCE(p_request_size, 0),
        COALESCE(p_response_status, 0), COALESCE(p_duration_ms, 0),
        v_frameworks, v_trace::text, v_prior_hash, v_integrity_hash,
        v_occurred_at
    );

    INSERT INTO audit_outbox (
        tenant_id, record_id, tenant_sequence, event_payload
    ) VALUES (
        p_tenant_id,
        p_record_id,
        v_sequence,
        v_canonical::jsonb || jsonb_build_object(
            'id', p_record_id::text,
            'idempotency_key', p_idempotency_key,
            'prior_hash', v_prior_hash,
            'integrity_hash', v_integrity_hash,
            'canonical_payload', v_canonical
        )
    );

    RETURN QUERY SELECT
        p_record_id, v_sequence, v_prior_hash, v_integrity_hash,
        v_canonical, false;
END;
$$;
"""


def upgrade():
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")
    op.execute("ALTER TABLE audit_log_metadata NO FORCE ROW LEVEL SECURITY")

    op.add_column(
        "audit_log_metadata",
        sa.Column("tenant_sequence", sa.BigInteger(), nullable=True),
    )
    op.add_column(
        "audit_log_metadata",
        sa.Column("idempotency_key", sa.Text(), nullable=True),
    )
    op.add_column(
        "audit_log_metadata",
        sa.Column("chain_version", sa.SmallInteger(), nullable=True),
    )
    op.add_column(
        "audit_log_metadata",
        sa.Column("canonical_payload", sa.Text(), nullable=True),
    )

    op.execute(
        """
        WITH sequenced AS (
            SELECT id,
                   row_number() OVER (
                       PARTITION BY tenant_id
                       ORDER BY created_at, record_id
                   ) AS tenant_sequence
            FROM audit_log_metadata
        )
        UPDATE audit_log_metadata AS audit
           SET tenant_sequence = sequenced.tenant_sequence,
               idempotency_key = 'legacy:' || audit.record_id::text,
               chain_version = 1,
               canonical_payload = jsonb_build_object(
                   'record_id', audit.record_id::text,
                   'tenant_id', audit.tenant_id::text,
                   'timestamp', to_char(
                       date_trunc('milliseconds', audit.created_at) AT TIME ZONE 'UTC',
                       'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
                   ),
                   'actor_id', COALESCE(audit.actor_id::text, ''),
                   'actor_type', COALESCE(audit.actor_type, 'gateway'),
                   'action', audit.action,
                   'policy_id', COALESCE(audit.policy_id::text, ''),
                   'provider', COALESCE(audit.provider, ''),
                   'model', COALESCE(audit.model, ''),
                   'reason', COALESCE(audit.reason, ''),
                   'prompt_count', COALESCE(audit.prompt_count, 0),
                   'request_size', COALESCE(audit.request_size, 0),
                   'response_status', COALESCE(audit.response_status, 0),
                   'duration_ms', COALESCE(audit.duration_ms, 0),
                   'frameworks_affected', to_jsonb(COALESCE(audit.frameworks_affected, ARRAY[]::varchar[])),
                   'execution_trace', COALESCE(audit.execution_trace, '[]'),
                   'request_id', COALESCE(audit.request_id, '')
               )::text
          FROM sequenced
         WHERE audit.id = sequenced.id
        """
    )

    op.alter_column("audit_log_metadata", "tenant_sequence", nullable=False)
    op.alter_column("audit_log_metadata", "idempotency_key", nullable=False)
    op.alter_column(
        "audit_log_metadata",
        "chain_version",
        nullable=False,
        server_default="2",
    )
    op.alter_column("audit_log_metadata", "canonical_payload", nullable=False)
    op.create_unique_constraint(
        "uq_audit_log_tenant_sequence",
        "audit_log_metadata",
        ["tenant_id", "tenant_sequence"],
    )
    op.create_unique_constraint(
        "uq_audit_log_tenant_idempotency",
        "audit_log_metadata",
        ["tenant_id", "idempotency_key"],
    )

    op.create_table(
        "audit_outbox",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id"),
            nullable=False,
        ),
        sa.Column(
            "record_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("audit_log_metadata.record_id"),
            nullable=False,
            unique=True,
        ),
        sa.Column("tenant_sequence", sa.BigInteger(), nullable=False),
        sa.Column("event_payload", postgresql.JSONB(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("publish_attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_error", sa.Text(), nullable=True),
    )
    op.create_index(
        "idx_audit_outbox_pending",
        "audit_outbox",
        ["published_at", "created_at"],
    )
    op.create_unique_constraint(
        "uq_audit_outbox_tenant_sequence",
        "audit_outbox",
        ["tenant_id", "tenant_sequence"],
    )
    op.execute("ALTER TABLE audit_outbox ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE audit_outbox FORCE ROW LEVEL SECURITY")
    op.execute(
        """
        CREATE POLICY audit_outbox_tenant_isolation
        ON audit_outbox
        USING (
            tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid
        )
        WITH CHECK (
            tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid
        )
        """
    )

    op.execute(APPEND_FUNCTION)
    op.execute(
        """
        CREATE OR REPLACE FUNCTION reject_audit_log_mutation()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            RAISE EXCEPTION 'audit records are immutable: % is not permitted', TG_OP
                USING ERRCODE = '55000';
        END;
        $$;
        """
    )
    op.execute(
        """
        CREATE TRIGGER audit_log_metadata_immutable
        BEFORE UPDATE OR DELETE ON audit_log_metadata
        FOR EACH ROW EXECUTE FUNCTION reject_audit_log_mutation()
        """
    )
    op.execute("ALTER TABLE audit_log_metadata FORCE ROW LEVEL SECURITY")


def downgrade():
    # ACL-21 rollback is deliberately additive: immutable evidence and its
    # sequencing columns are retained. Application writers can be reverted
    # without deleting audit rows or weakening their mutation guard.
    op.execute(
        """
        DROP FUNCTION IF EXISTS append_audit_event_v2(
            uuid, uuid, text, timestamptz, uuid, text, text, text, uuid,
            text, text, text, integer, integer, integer, integer, text[], jsonb
        )
        """
    )
