"""Harden tenant OIDC tenant and MFA context

Revision ID: 026
Revises: 025
"""

import json
import os

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "026"
down_revision = "025"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    active_tenants = [str(value) for value in bind.execute(
        sa.text("SELECT tenant_id FROM tenant_oidc_configs WHERE status = 'active'")
    ).scalars()]
    mappings = json.loads(os.getenv("AUTHCLAW_OIDC_TENANT_MAPPINGS", "{}"))
    if any(not mappings.get(tenant_id) for tenant_id in active_tenants):
        raise RuntimeError("AUTHCLAW_OIDC_TENANT_MAPPINGS must cover every active OIDC tenant")
    op.add_column("tenant_oidc_configs", sa.Column("tenant_claim", sa.String(length=100), nullable=False, server_default="tenant_id"))
    op.add_column("tenant_oidc_configs", sa.Column("tenant_claim_value", sa.String(length=255), nullable=True))
    op.add_column("tenant_oidc_configs", sa.Column("require_mfa", sa.Boolean(), nullable=False, server_default=sa.text("true")))
    op.add_column("tenant_oidc_configs", sa.Column("accepted_amr", postgresql.ARRAY(sa.String()), nullable=False, server_default=sa.text("ARRAY['mfa']")))
    op.add_column("tenant_oidc_configs", sa.Column("accepted_acr", postgresql.ARRAY(sa.String()), nullable=False, server_default=sa.text("ARRAY[]::varchar[]")))
    op.add_column("tenant_oidc_configs", sa.Column("max_auth_age_seconds", sa.Integer(), nullable=False, server_default="43200"))
    for tenant_id in active_tenants:
        bind.execute(
            sa.text("UPDATE tenant_oidc_configs SET tenant_claim_value = :value WHERE tenant_id = :tenant_id"),
            {"value": mappings[tenant_id], "tenant_id": tenant_id},
        )


def downgrade():
    op.drop_column("tenant_oidc_configs", "max_auth_age_seconds")
    op.drop_column("tenant_oidc_configs", "accepted_acr")
    op.drop_column("tenant_oidc_configs", "accepted_amr")
    op.drop_column("tenant_oidc_configs", "require_mfa")
    op.drop_column("tenant_oidc_configs", "tenant_claim_value")
    op.drop_column("tenant_oidc_configs", "tenant_claim")
