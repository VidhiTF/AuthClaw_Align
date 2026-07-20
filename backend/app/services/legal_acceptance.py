"""Versioned legal-notice acceptance for controlled-beta onboarding."""

from __future__ import annotations


CURRENT_TERMS_VERSION = "2026-07-20"
CURRENT_PRIVACY_NOTICE_VERSION = "2026-07-20"


def validate_legal_acceptance(
    *,
    terms_accepted: bool,
    terms_version: str,
    privacy_notice_acknowledged: bool,
    privacy_notice_version: str,
) -> None:
    """Require affirmative acceptance of the exact currently published notices."""
    if not terms_accepted:
        raise ValueError("Terms of Use acceptance is required")
    if terms_version != CURRENT_TERMS_VERSION:
        raise ValueError("Terms of Use version is no longer current")
    if not privacy_notice_acknowledged:
        raise ValueError("Privacy Notice acknowledgement is required")
    if privacy_notice_version != CURRENT_PRIVACY_NOTICE_VERSION:
        raise ValueError("Privacy Notice version is no longer current")
