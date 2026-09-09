"""Exercise password reset confirmation through the actual endpoint handler."""
from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.api.v1.endpoints import auth
from app.core import crypto


@pytest.mark.parametrize(
    "outcome,expected_status",
    [("verified", None), ("not_found", 404), ("locked", 429),
     ("expired", 400), ("invalid", 400)],
)
def test_confirmation_uses_key_ring_and_preserves_database_outcome(
    monkeypatch, outcome, expected_status
):
    db = MagicMock()
    db.execute.return_value.scalar_one.return_value = outcome
    monkeypatch.setattr(auth, "OwnerSessionLocal", lambda: db)
    monkeypatch.setenv("SESSION_SECRET", "reset-regression-secret")
    monkeypatch.setattr(auth, "hash_password", lambda password: "hashed-password")
    payload = auth.PasswordResetConfirmRequest(
        signup_id=uuid4(), otp="123456", password="StrongPassword123!"
    )

    if expected_status is None:
        assert auth.confirm_password_reset(payload).success is True
    else:
        with pytest.raises(HTTPException) as raised:
            auth.confirm_password_reset(payload)
        assert raised.value.status_code == expected_status

    params = db.execute.call_args.args[1]
    assert params["secrets"] == list(crypto.get_session_key_ring()[1].values())
    assert params["signup_id"] == str(payload.signup_id)
    assert params["otp"] == "123456"
    assert params["password_hash"] == "hashed-password"
    # Failed attempts must persist too, so the database's attempt limit works.
    db.commit.assert_called_once()
    db.close.assert_called_once()
