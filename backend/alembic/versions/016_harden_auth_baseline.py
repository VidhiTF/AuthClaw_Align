"""Harden API key and provider credential lifecycle

Revision ID: 016
Revises: 015
Create Date: 2026-06-30 12:30:00.000000
"""

from alembic import op
import sqlalchemy as sa


revision = "016"
down_revision = "015"
branch_labels = None
depends_on = None


def _columns(table_name: str) -> set[str]:
    bind = op.get_bind()
    rows = bind.execute(
        sa.text(
            """
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name = :table_name
            """
        ),
        {"table_name": table_name},
    )
    return {row[0] for row in rows}


def upgrade():
    api_columns = _columns("api_keys")
    provider_columns = _columns("provider_credentials")

    if "last_used_ip" not in api_columns:
        op.add_column("api_keys", sa.Column("last_used_ip", sa.String(length=64), nullable=True))
    if "last_used_user_agent" not in api_columns:
        op.add_column("api_keys", sa.Column("last_used_user_agent", sa.String(length=512), nullable=True))
    if "last_used_request_id" not in api_columns:
        op.add_column("api_keys", sa.Column("last_used_request_id", sa.String(length=255), nullable=True))
    if "revoked_at" not in api_columns:
        op.add_column("api_keys", sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True))
    if "rotated_at" not in api_columns:
        op.add_column("api_keys", sa.Column("rotated_at", sa.DateTime(timezone=True), nullable=True))
    if "rotated_from_id" not in api_columns:
        op.add_column("api_keys", sa.Column("rotated_from_id", sa.UUID(), nullable=True))
        op.create_foreign_key(
            "fk_api_keys_rotated_from_id_api_keys",
            "api_keys",
            "api_keys",
            ["rotated_from_id"],
            ["id"],
        )

    op.execute("UPDATE api_keys SET expires_at = NOW() + INTERVAL '90 days' WHERE expires_at IS NULL")
    op.alter_column(
        "api_keys",
        "expires_at",
        existing_type=sa.DateTime(timezone=True),
        nullable=False,
        server_default=sa.text("NOW() + INTERVAL '90 days'"),
    )

    if "revoked_at" not in provider_columns:
        op.add_column("provider_credentials", sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True))
    if "revoked_by" not in provider_columns:
        op.add_column("provider_credentials", sa.Column("revoked_by", sa.UUID(), nullable=True))
        op.create_foreign_key(
            "fk_provider_credentials_revoked_by_users",
            "provider_credentials",
            "users",
            ["revoked_by"],
            ["id"],
        )
    if "rotated_from_id" not in provider_columns:
        op.add_column("provider_credentials", sa.Column("rotated_from_id", sa.UUID(), nullable=True))
        op.create_foreign_key(
            "fk_provider_credentials_rotated_from_id",
            "provider_credentials",
            "provider_credentials",
            ["rotated_from_id"],
            ["id"],
        )
    if "version" not in provider_columns:
        op.add_column(
            "provider_credentials",
            sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        )

    op.create_index("idx_apikey_expires", "api_keys", ["expires_at"], if_not_exists=True)
    op.create_index("idx_apikey_revoked", "api_keys", ["revoked_at"], if_not_exists=True)
    op.create_index("idx_provider_credential_version", "provider_credentials", ["tenant_id", "provider", "version"], if_not_exists=True)

    op.execute(
        """
        CREATE OR REPLACE FUNCTION resolve_api_key(p_key_hash text)
        RETURNS TABLE (
            id uuid,
            tenant_id uuid,
            scopes varchar[],
            created_by uuid
        )
        SECURITY DEFINER
        AS $$
        BEGIN
            RETURN QUERY
            SELECT a.id, a.tenant_id, a.scopes::varchar[], a.created_by
            FROM api_keys a
            WHERE a.key_hash = p_key_hash
              AND a.is_active = true
              AND a.revoked_at IS NULL
              AND a.rotated_at IS NULL
              AND a.expires_at > NOW();
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute("GRANT EXECUTE ON FUNCTION resolve_api_key(text) TO PUBLIC")


def downgrade():
    op.execute(
        """
        CREATE OR REPLACE FUNCTION resolve_api_key(p_key_hash text)
        RETURNS TABLE (
            id uuid,
            tenant_id uuid,
            scopes varchar[],
            created_by uuid
        )
        SECURITY DEFINER
        AS $$
        BEGIN
            RETURN QUERY
            SELECT a.id, a.tenant_id, a.scopes::varchar[], a.created_by
            FROM api_keys a
            WHERE a.key_hash = p_key_hash
              AND a.is_active = true
              AND (a.expires_at IS NULL OR a.expires_at > NOW());
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute("GRANT EXECUTE ON FUNCTION resolve_api_key(text) TO PUBLIC")

    for index_name in [
        "idx_provider_credential_version",
        "idx_apikey_revoked",
        "idx_apikey_expires",
    ]:
        op.drop_index(index_name, table_name="provider_credentials" if "provider" in index_name else "api_keys", if_exists=True)

    provider_columns = _columns("provider_credentials")
    if "version" in provider_columns:
        op.drop_column("provider_credentials", "version")
    if "rotated_from_id" in provider_columns:
        op.drop_constraint("fk_provider_credentials_rotated_from_id", "provider_credentials", type_="foreignkey")
        op.drop_column("provider_credentials", "rotated_from_id")
    if "revoked_by" in provider_columns:
        op.drop_constraint("fk_provider_credentials_revoked_by_users", "provider_credentials", type_="foreignkey")
        op.drop_column("provider_credentials", "revoked_by")
    if "revoked_at" in provider_columns:
        op.drop_column("provider_credentials", "revoked_at")

    api_columns = _columns("api_keys")
    op.alter_column(
        "api_keys",
        "expires_at",
        existing_type=sa.DateTime(timezone=True),
        nullable=True,
        server_default=None,
    )
    if "rotated_from_id" in api_columns:
        op.drop_constraint("fk_api_keys_rotated_from_id_api_keys", "api_keys", type_="foreignkey")
        op.drop_column("api_keys", "rotated_from_id")
    for column_name in [
        "rotated_at",
        "revoked_at",
        "last_used_request_id",
        "last_used_user_agent",
        "last_used_ip",
    ]:
        if column_name in api_columns:
            op.drop_column("api_keys", column_name)
