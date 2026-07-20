"""Add ACL-35 versioned legal-notice acceptance.

Revision ID: 033
Revises: 032
"""

from alembic import op
import sqlalchemy as sa


revision = "033"
down_revision = "032"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "onboarding_email_otps",
        sa.Column("terms_version", sa.String(length=32), nullable=True),
    )
    op.add_column(
        "onboarding_email_otps",
        sa.Column("terms_accepted_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "onboarding_email_otps",
        sa.Column("privacy_notice_version", sa.String(length=32), nullable=True),
    )
    op.add_column(
        "onboarding_email_otps",
        sa.Column(
            "privacy_notice_acknowledged_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )


def downgrade():
    op.drop_column("onboarding_email_otps", "privacy_notice_acknowledged_at")
    op.drop_column("onboarding_email_otps", "privacy_notice_version")
    op.drop_column("onboarding_email_otps", "terms_accepted_at")
    op.drop_column("onboarding_email_otps", "terms_version")
