"""Add regulatory RAG corpus tables

Revision ID: 018
Revises: 017
Create Date: 2026-06-30 16:20:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "018"
down_revision = "017"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "rag_corpus_versions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("corpus_key", sa.String(length=120), nullable=False),
        sa.Column("version", sa.String(length=80), nullable=False),
        sa.Column("checksum", sa.String(length=64), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("loaded_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.UniqueConstraint("corpus_key", "version", name="uq_rag_corpus_version"),
    )
    op.create_index("idx_rag_corpus_active", "rag_corpus_versions", ["corpus_key", "is_active"])

    op.create_table(
        "rag_corpus_chunks",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("corpus_version_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("rag_corpus_versions.id", ondelete="CASCADE"), nullable=False),
        sa.Column("framework", sa.String(length=50), nullable=False),
        sa.Column("section_id", sa.String(length=120), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("citation_label", sa.String(length=255), nullable=False),
        sa.Column("source_name", sa.String(length=255), nullable=False),
        sa.Column("source_url", sa.Text(), nullable=False),
        sa.Column("chunk_text", sa.Text(), nullable=False),
        sa.Column("keywords", postgresql.ARRAY(sa.String()), nullable=False, server_default=sa.text("'{}'::varchar[]")),
        sa.Column("chunk_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.UniqueConstraint("corpus_version_id", "section_id", name="uq_rag_chunk_version_section"),
    )
    op.create_index("idx_rag_chunk_framework", "rag_corpus_chunks", ["framework"])
    op.create_index("idx_rag_chunk_hash", "rag_corpus_chunks", ["chunk_hash"])


def downgrade():
    op.drop_index("idx_rag_chunk_hash", table_name="rag_corpus_chunks")
    op.drop_index("idx_rag_chunk_framework", table_name="rag_corpus_chunks")
    op.drop_table("rag_corpus_chunks")
    op.drop_index("idx_rag_corpus_active", table_name="rag_corpus_versions")
    op.drop_table("rag_corpus_versions")
