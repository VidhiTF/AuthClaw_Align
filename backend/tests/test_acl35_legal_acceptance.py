import pytest

from app.services.legal_acceptance import (
    CURRENT_PRIVACY_NOTICE_VERSION,
    CURRENT_TERMS_VERSION,
    validate_legal_acceptance,
)


def valid_acceptance():
    return {
        "terms_accepted": True,
        "terms_version": CURRENT_TERMS_VERSION,
        "privacy_notice_acknowledged": True,
        "privacy_notice_version": CURRENT_PRIVACY_NOTICE_VERSION,
    }


def test_current_legal_notice_acceptance_is_valid():
    validate_legal_acceptance(**valid_acceptance())


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("terms_accepted", False, "Terms of Use"),
        ("privacy_notice_acknowledged", False, "Privacy Notice"),
        ("terms_version", "superseded", "no longer current"),
        ("privacy_notice_version", "superseded", "no longer current"),
    ],
)
def test_missing_or_stale_legal_acceptance_is_rejected(field, value, message):
    acceptance = valid_acceptance()
    acceptance[field] = value

    with pytest.raises(ValueError, match=message):
        validate_legal_acceptance(**acceptance)
