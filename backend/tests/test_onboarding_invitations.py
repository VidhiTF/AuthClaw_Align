import json
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from app.api.v1.endpoints import onboarding
from app.db.models import APIKey, OnboardingEmailOTP, Tenant, User
from app.schemas.models import OnboardingResendRequest, OnboardingVerifyRequest
from app.services.email_service import EmailDeliveryError
from tests.db_safety import destructive_test_urls


owner_url, _ = destructive_test_urls()
engine = create_engine(owner_url, pool_pre_ping=True)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
VALID_OTP = "123456"
REAL_EMIT_INVITATION_AUDIT = onboarding._emit_invitation_audit


@pytest.fixture(autouse=True)
def invitation_database(monkeypatch):
    with engine.begin() as connection:
        connection.execute(
            text(
                "TRUNCATE TABLE onboarding_status, onboarding_email_otps, "
                "api_keys, users, tenants CASCADE"
            )
        )
    events = []
    event_lock = threading.Lock()

    def capture(invitation, action, reason, request_id, response_status):
        with event_lock:
            events.append(
                {
                    "invite_id": str(invitation.id) if invitation else "",
                    "tenant_id": str(invitation.tenant_id) if invitation else "",
                    "action": action,
                    "reason": reason,
                    "request_id": request_id,
                    "response_status": response_status,
                }
            )

    monkeypatch.setattr(onboarding, "OwnerSessionLocal", TestingSessionLocal)
    monkeypatch.setattr(onboarding, "_enforce_onboarding_rate_limit", lambda *_args: None)
    monkeypatch.setattr(onboarding, "_emit_invitation_audit", capture)
    yield events
    engine.dispose()


def _request(request_id="invite-test"):
    return SimpleNamespace(
        headers={"x-request-id": request_id},
        client=SimpleNamespace(host="127.0.0.1"),
    )


def _payload(invite_id, otp=VALID_OTP):
    return OnboardingVerifyRequest(
        signup_id=invite_id,
        otp=otp,
        password="CorrectHorse!234",
        terms_accepted=True,
        terms_version="2026-07-20",
        privacy_notice_acknowledged=True,
        privacy_notice_version="2026-07-20",
    )


def _seed_invite(*, status="pending", expires_at=None, email="invitee@example.com"):
    tenant_id = uuid4()
    invite_id = uuid4()
    with TestingSessionLocal() as db:
        db.add(Tenant(id=tenant_id, name=f"Tenant-{tenant_id}", tier="starter", status="active"))
        db.flush()
        db.add(
            OnboardingEmailOTP(
                id=invite_id,
                email=email,
                tenant_name=f"Tenant-{tenant_id}",
                otp_hash=onboarding._otp_hash(email, VALID_OTP),
                status=status,
                expires_at=expires_at or datetime.now(timezone.utc) + timedelta(minutes=15),
                sent_at=datetime.now(timezone.utc) - timedelta(minutes=2),
                purpose="invite",
                invited_role="viewer",
                tenant_id=tenant_id,
            )
        )
        db.commit()
    return invite_id, tenant_id


def _stored(invite_id):
    with TestingSessionLocal() as db:
        invite = db.query(OnboardingEmailOTP).filter_by(id=invite_id).one()
        users = db.query(User).filter_by(tenant_id=invite.tenant_id).all()
        keys = db.query(APIKey).filter_by(tenant_id=invite.tenant_id).all()
        return invite.status, users, keys


def _assert_generic_rejection(invite_id, otp=VALID_OTP):
    with pytest.raises(HTTPException) as exc:
        onboarding.verify(_payload(invite_id, otp), _request())
    assert exc.value.detail == onboarding.INVALID_INVITATION_DETAIL
    return exc.value


def test_valid_invitation_redemption_is_atomic(invitation_database):
    invite_id, tenant_id = _seed_invite()

    response = onboarding.verify(_payload(invite_id), _request())

    status, users, keys = _stored(invite_id)
    assert response.tenant_id == tenant_id
    assert status == "verified"
    assert len(users) == 1 and users[0].tenant_id == tenant_id
    assert len(keys) == 1 and keys[0].created_by == users[0].id
    assert invitation_database[-1]["action"] == "InviteRedeemed"


def test_expired_invitation_is_rejected_and_recorded(invitation_database):
    invite_id, _ = _seed_invite(expires_at=datetime.now(timezone.utc) - timedelta(seconds=1))

    _assert_generic_rejection(invite_id)

    assert _stored(invite_id)[0] == "expired"
    assert [event["action"] for event in invitation_database[-2:]] == [
        "InviteExpired",
        "InviteRedemptionFailed",
    ]


@pytest.mark.parametrize("invite_status", ["cancelled", "verified"])
def test_revoked_or_redeemed_invitation_uses_generic_error(invite_status, invitation_database):
    invite_id, _ = _seed_invite(status=invite_status)

    _assert_generic_rejection(invite_id)

    assert invitation_database[-1]["action"] == "InviteRedemptionFailed"


def test_invalid_otp_does_not_create_access(invitation_database):
    invite_id, _ = _seed_invite()

    _assert_generic_rejection(invite_id, "654321")

    status, users, keys = _stored(invite_id)
    assert status == "pending"
    assert users == []
    assert keys == []
    assert invitation_database[-1]["reason"] == "invalid_verification_code"


def test_unknown_invitation_does_not_leak_state(invitation_database):
    _assert_generic_rejection(uuid4())
    assert invitation_database[-1]["action"] == "InviteRedemptionFailed"
    assert invitation_database[-1]["reason"] == "invitation_not_found"


def test_invitation_without_tenant_is_generic_and_audited(invitation_database):
    invite_id, tenant_id = _seed_invite()
    with TestingSessionLocal() as db:
        invite = db.query(OnboardingEmailOTP).filter_by(id=invite_id).one()
        invite.tenant_id = None
        db.commit()
        db.query(Tenant).filter_by(id=tenant_id).delete()
        db.commit()

    _assert_generic_rejection(invite_id)

    assert invitation_database[-1]["action"] == "InviteRedemptionFailed"
    assert invitation_database[-1]["reason"] == "invitation_tenant_unavailable"


def test_inactive_invitation_tenant_is_generic_and_audited(invitation_database):
    invite_id, tenant_id = _seed_invite()
    with TestingSessionLocal() as db:
        db.query(Tenant).filter_by(id=tenant_id).update({"status": "suspended"})
        db.commit()

    _assert_generic_rejection(invite_id)

    assert invitation_database[-1]["action"] == "InviteRedemptionFailed"
    assert invitation_database[-1]["reason"] == "invitation_tenant_unavailable"


def test_active_user_conflict_is_generic_and_audited(invitation_database):
    invite_id, tenant_id = _seed_invite()
    with TestingSessionLocal() as db:
        db.add(
            User(
                tenant_id=tenant_id,
                email="invitee@example.com",
                role="viewer",
                is_active=True,
            )
        )
        db.commit()

    _assert_generic_rejection(invite_id)

    assert invitation_database[-1]["action"] == "InviteRedemptionFailed"
    assert invitation_database[-1]["reason"] == "invitation_cannot_be_redeemed"


def test_invitation_cannot_provision_a_different_tenant(invitation_database):
    invite_id, invited_tenant_id = _seed_invite()
    other_tenant_id = uuid4()
    with TestingSessionLocal() as db:
        db.add(Tenant(id=other_tenant_id, name="Other tenant", tier="starter", status="active"))
        db.add(
            User(
                tenant_id=other_tenant_id,
                email="invitee@example.com",
                role="admin",
                is_active=False,
            )
        )
        db.commit()

    onboarding.verify(_payload(invite_id), _request())

    with TestingSessionLocal() as db:
        invited = db.query(User).filter_by(tenant_id=invited_tenant_id).one()
        other = db.query(User).filter_by(tenant_id=other_tenant_id).one()
        assert invited.role == "viewer"
        assert other.is_active is False


def test_replay_is_rejected_without_creating_duplicate_access(invitation_database):
    invite_id, _ = _seed_invite()
    onboarding.verify(_payload(invite_id), _request("first"))

    _assert_generic_rejection(invite_id)

    status, users, keys = _stored(invite_id)
    assert status == "verified"
    assert len(users) == 1
    assert len(keys) == 1


def test_concurrent_redemption_allows_exactly_one_consumer(invitation_database):
    invite_id, _ = _seed_invite()
    barrier = threading.Barrier(2)

    def redeem(index):
        barrier.wait()
        try:
            onboarding.verify(_payload(invite_id), _request(f"concurrent-{index}"))
            return "success"
        except HTTPException as exc:
            assert exc.detail == onboarding.INVALID_INVITATION_DETAIL
            return "rejected"

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(redeem, (1, 2)))

    assert sorted(results) == ["rejected", "success"]
    status, users, keys = _stored(invite_id)
    assert status == "verified"
    assert len(users) == 1
    assert len(keys) == 1


def test_transaction_rolls_back_when_redemption_fails(monkeypatch, invitation_database):
    invite_id, _ = _seed_invite()
    monkeypatch.setattr(
        onboarding,
        "hash_password",
        lambda _password: (_ for _ in ()).throw(RuntimeError("injected failure")),
    )

    with pytest.raises(RuntimeError, match="injected failure"):
        onboarding.verify(_payload(invite_id), _request())

    status, users, keys = _stored(invite_id)
    assert status == "pending"
    assert users == []
    assert keys == []


def test_integrity_error_is_generic_and_audited(monkeypatch, invitation_database):
    invite_id, _ = _seed_invite()
    db = TestingSessionLocal()

    def fail_commit():
        raise onboarding.IntegrityError("commit", {}, RuntimeError("conflict"))

    db.commit = fail_commit
    monkeypatch.setattr(onboarding, "OwnerSessionLocal", lambda: db)

    _assert_generic_rejection(invite_id)

    status, users, keys = _stored(invite_id)
    assert status == "pending"
    assert users == []
    assert keys == []
    assert invitation_database[-1]["action"] == "InviteRedemptionFailed"
    assert invitation_database[-1]["reason"] == "invitation_transaction_conflict"


def test_invitation_resend_records_success(monkeypatch, invitation_database):
    invite_id, _ = _seed_invite()
    monkeypatch.setattr(onboarding, "_deliver_otp", lambda *_args, **_kwargs: ("smtp", None))

    response = onboarding.resend(OnboardingResendRequest(signup_id=invite_id), _request())

    assert response.delivery == "smtp"
    assert invitation_database[-1]["action"] == "InviteDeliverySucceeded"


def test_invitation_resend_failure_is_generic_and_rolls_back(monkeypatch, invitation_database):
    invite_id, _ = _seed_invite()
    with TestingSessionLocal() as db:
        original_hash = db.query(OnboardingEmailOTP).filter_by(id=invite_id).one().otp_hash

    def fail_delivery(*_args, **_kwargs):
        raise EmailDeliveryError("provider detail")

    monkeypatch.setattr(onboarding, "_deliver_otp", fail_delivery)
    with pytest.raises(HTTPException) as exc:
        onboarding.resend(OnboardingResendRequest(signup_id=invite_id), _request())

    assert exc.value.detail == "Invitation delivery is temporarily unavailable"
    with TestingSessionLocal() as db:
        invite = db.query(OnboardingEmailOTP).filter_by(id=invite_id).one()
        assert invite.otp_hash == original_hash
    assert invitation_database[-1]["action"] == "InviteDeliveryFailed"


def test_invitation_audit_payload_excludes_sensitive_values(monkeypatch):
    invite_id, tenant_id = _seed_invite(email="sensitive@example.com")
    with TestingSessionLocal() as db:
        invitation = db.query(OnboardingEmailOTP).filter_by(id=invite_id).one()
        captured = []
        monkeypatch.setattr(onboarding.event_backbone, "make_kafka_producer", lambda: None)
        monkeypatch.setattr(
            onboarding.event_backbone,
            "publish_audit_event",
            lambda _producer, _tenant_id, event: captured.append(event),
        )
        onboarding._invitation_kafka_producer = None

        REAL_EMIT_INVITATION_AUDIT(
            invitation,
            "InviteRedemptionFailed",
            "invalid_verification_code",
            "audit-test",
            400,
        )

    serialized = json.dumps(captured)
    assert captured[0]["action"] == "invitation:InviteRedemptionFailed"
    assert captured[0]["reason"] == "invalid_verification_code"
    assert captured[0]["request_id"] == "audit-test"
    assert captured[0]["result"] == "failure"
    assert str(tenant_id) in serialized
    for secret in ("sensitive@example.com", VALID_OTP, "CorrectHorse!234", "cookie", "nonce"):
        assert secret not in serialized
