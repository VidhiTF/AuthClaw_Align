import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from app.api.v1.endpoints import onboarding, users
from app.core.auth import hash_key
from app.db.models import APIKey, OnboardingEmailOTP, Tenant, User
from app.schemas.models import UserInviteRequest
from app.services.email_service import EmailDeliveryError
from tests.db_safety import destructive_test_urls


owner_url, _ = destructive_test_urls()
engine = create_engine(owner_url, pool_pre_ping=True)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
REAL_INVITATION_AUDIT = users._emit_invitation_audit


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

    def capture(invitation, action, reason, request_id, response_status):
        events.append(
            {
                "invite_id": str(invitation.id),
                "tenant_id": str(invitation.tenant_id),
                "action": action,
                "reason": reason,
                "request_id": request_id,
                "response_status": response_status,
            }
        )

    monkeypatch.setattr(users, "_emit_invitation_audit", capture)
    monkeypatch.setattr(users, "_deliver_otp", lambda *_args, **_kwargs: ("smtp", None))
    yield events


def _request(tenant_id, user_id, role="owner", request_id="users-invite-test"):
    return SimpleNamespace(
        state=SimpleNamespace(
            tenant_id=tenant_id,
            user_id=user_id,
            user_role=role,
            scopes=["admin", "read", "write"],
        ),
        headers={"x-request-id": request_id},
    )


def _seed_actor(role="owner", *, tenant_id=None):
    tenant_id = tenant_id or uuid4()
    user_id = uuid4()
    with TestingSessionLocal() as db:
        tenant = db.query(Tenant).filter_by(id=tenant_id).first()
        if not tenant:
            db.add(Tenant(id=tenant_id, name=f"Tenant-{tenant_id}", tier="starter", status="active"))
        db.add(
            User(
                id=user_id,
                tenant_id=tenant_id,
                email=f"{role}-{user_id}@example.com",
                role=role,
                is_active=True,
            )
        )
        db.commit()
    return tenant_id, user_id


def _seed_invite(
    *,
    tenant_id,
    status="pending",
    role="viewer",
    email="invitee@example.com",
    user_platform_role="NONE",
):
    invite_id = uuid4()
    target_user_id = None
    raw_key = None
    with TestingSessionLocal() as db:
        if status == "verified":
            target_user_id = uuid4()
            db.add(
                User(
                    id=target_user_id,
                    tenant_id=tenant_id,
                    email=email,
                    role=role,
                    platform_role=user_platform_role,
                    is_active=True,
                )
            )
            db.flush()
            raw_key = f"acl_test_{uuid4().hex}"
            key = APIKey(
                tenant_id=tenant_id,
                key_hash=hash_key(raw_key),
                name="Existing Console Key",
                scopes=["read"],
                is_active=True,
                expires_at=datetime.now(timezone.utc) + timedelta(days=1),
                created_by=target_user_id,
            )
            db.add(key)
            db.flush()
            api_key_id = key.id
        else:
            api_key_id = None
        tenant = db.query(Tenant).filter_by(id=tenant_id).one()
        db.add(
            OnboardingEmailOTP(
                id=invite_id,
                email=email,
                tenant_name=tenant.name,
                otp_hash="not-sensitive",
                status=status,
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=15),
                purpose="invite",
                invited_role=role,
                tenant_id=tenant_id,
                api_key_id=api_key_id,
            )
        )
        db.commit()
    return invite_id, target_user_id, raw_key


def _route(path, method):
    return next(route for route in users.router.routes if route.path == path and method in route.methods)


def _check_dependencies(route, role):
    request = SimpleNamespace(
        state=SimpleNamespace(
            user_role=role,
            tenant_role=role,
            scopes=["admin", "read", "write"],
            platform_role="NONE",
            user_is_active=True,
        )
    )
    for dependency in route.dependencies:
        dependency.dependency(request)


@pytest.mark.parametrize("role", ["owner", "admin"])
def test_owner_and_admin_can_invite(role, invitation_database):
    tenant_id, actor_id = _seed_actor(role)
    with TestingSessionLocal() as db:
        response = users.invite_user(
            _request(tenant_id, actor_id, role),
            UserInviteRequest(email="new-user@example.com", role="viewer"),
            db,
        )

    assert response.invited_role == "viewer"
    assert [event["action"] for event in invitation_database] == [
        "InviteCreated",
        "InviteDeliverySucceeded",
    ]


@pytest.mark.parametrize("role", ["developer", "operator", "viewer"])
def test_non_administrative_roles_cannot_invite(role):
    with pytest.raises(HTTPException) as exc:
        _check_dependencies(_route("/invite", "POST"), role)
    assert exc.value.status_code == 403


def test_admin_cannot_invite_owner():
    tenant_id, actor_id = _seed_actor("admin")
    with TestingSessionLocal() as db, pytest.raises(HTTPException) as exc:
        users.invite_user(
            _request(tenant_id, actor_id, "admin"),
            UserInviteRequest(email="owner@example.com", role="owner"),
            db,
        )
    assert exc.value.status_code == 403


def test_revoke_pending_invitation(invitation_database):
    tenant_id, actor_id = _seed_actor()
    invite_id, _, _ = _seed_invite(tenant_id=tenant_id)
    with TestingSessionLocal() as db:
        users.cancel_invite(invite_id, _request(tenant_id, actor_id), db)
    with TestingSessionLocal() as db:
        assert db.query(OnboardingEmailOTP).filter_by(id=invite_id).one().status == "revoked"
    assert invitation_database[-1]["action"] == "InviteRevoked"


def test_revoke_redeemed_invitation_disables_user_and_keys(invitation_database):
    tenant_id, actor_id = _seed_actor()
    invite_id, target_user_id, raw_key = _seed_invite(tenant_id=tenant_id, status="verified")

    with TestingSessionLocal() as db:
        users.cancel_invite(invite_id, _request(tenant_id, actor_id), db)

    with TestingSessionLocal() as db:
        user = db.query(User).filter_by(id=target_user_id).one()
        key = db.query(APIKey).filter_by(key_hash=hash_key(raw_key)).one()
        resolved = db.query(APIKey).filter(
            APIKey.key_hash == hash_key(raw_key),
            APIKey.is_active == True,
            APIKey.revoked_at.is_(None),
            APIKey.expires_at > datetime.now(timezone.utc),
        ).first()
        assert user.is_active is False
        assert key.is_active is False
        assert key.revoked_at is not None
        assert resolved is None
    assert invitation_database[-1]["action"] == "InviteRevoked"


def test_already_revoked_invitation_is_rejected():
    tenant_id, actor_id = _seed_actor()
    invite_id, _, _ = _seed_invite(tenant_id=tenant_id, status="revoked")
    with TestingSessionLocal() as db, pytest.raises(HTTPException) as exc:
        users.cancel_invite(invite_id, _request(tenant_id, actor_id), db)
    assert exc.value.status_code == 404


def test_cross_tenant_invitation_revocation_is_denied():
    tenant_a, _ = _seed_actor()
    tenant_b, actor_b = _seed_actor()
    invite_id, _, _ = _seed_invite(tenant_id=tenant_a)
    with TestingSessionLocal() as db, pytest.raises(HTTPException) as exc:
        users.cancel_invite(invite_id, _request(tenant_b, actor_b), db)
    assert exc.value.status_code == 404


def test_last_owner_is_protected():
    tenant_id, actor_id = _seed_actor()
    invite_id, _, _ = _seed_invite(
        tenant_id=tenant_id,
        status="verified",
        role="owner",
        email="only-owner@example.com",
    )
    with TestingSessionLocal() as db:
        db.query(User).filter(User.id == actor_id).update({"is_active": False})
        db.commit()
    with TestingSessionLocal() as db, pytest.raises(HTTPException) as exc:
        users.cancel_invite(invite_id, _request(tenant_id, actor_id), db)
    assert exc.value.status_code == 400


def test_platform_admin_is_protected():
    tenant_id, actor_id = _seed_actor()
    invite_id, _, _ = _seed_invite(
        tenant_id=tenant_id,
        status="verified",
        user_platform_role="ADMIN",
    )
    with TestingSessionLocal() as db, pytest.raises(HTTPException) as exc:
        users.cancel_invite(invite_id, _request(tenant_id, actor_id), db)
    assert exc.value.status_code == 403


def test_admin_cannot_revoke_owner():
    tenant_id, actor_id = _seed_actor("admin")
    invite_id, _, _ = _seed_invite(
        tenant_id=tenant_id,
        status="verified",
        role="owner",
        email="tenant-owner@example.com",
    )
    with TestingSessionLocal() as db, pytest.raises(HTTPException) as exc:
        users.cancel_invite(invite_id, _request(tenant_id, actor_id, "admin"), db)
    assert exc.value.status_code == 403


def test_delivery_failure_rolls_back_and_is_audited(monkeypatch, invitation_database):
    tenant_id, actor_id = _seed_actor()

    def fail_delivery(*_args, **_kwargs):
        raise EmailDeliveryError("provider detail")

    monkeypatch.setattr(users, "_deliver_otp", fail_delivery)
    with TestingSessionLocal() as db, pytest.raises(HTTPException):
        users.invite_user(
            _request(tenant_id, actor_id),
            UserInviteRequest(email="failure@example.com", role="viewer"),
            db,
        )
    with TestingSessionLocal() as db:
        assert db.query(OnboardingEmailOTP).filter_by(email="failure@example.com").count() == 0
    assert invitation_database[-1]["action"] == "InviteDeliveryFailed"


@pytest.mark.parametrize("assertion", ["user", "api_key"])
def test_revocation_transaction_rolls_back_on_commit_failure(
    monkeypatch,
    invitation_database,
    assertion,
):
    tenant_id, actor_id = _seed_actor()
    invite_id, target_user_id, raw_key = _seed_invite(tenant_id=tenant_id, status="verified")
    db = TestingSessionLocal()

    def fail_commit():
        raise RuntimeError("injected commit failure")

    db.commit = fail_commit
    with pytest.raises(RuntimeError, match="injected commit failure"):
        users.cancel_invite(invite_id, _request(tenant_id, actor_id), db)
    db.rollback()
    db.close()

    with TestingSessionLocal() as verify_db:
        if assertion == "user":
            assert verify_db.query(User).filter_by(id=target_user_id).one().is_active is True
        else:
            assert verify_db.query(APIKey).filter_by(key_hash=hash_key(raw_key)).one().is_active is True
        assert verify_db.query(OnboardingEmailOTP).filter_by(id=invite_id).one().status == "verified"
    assert invitation_database == []


def test_user_invitation_audit_contains_no_sensitive_material(monkeypatch):
    tenant_id, actor_id = _seed_actor()
    captured = []
    monkeypatch.setattr(users, "_emit_invitation_audit", REAL_INVITATION_AUDIT)
    monkeypatch.setattr(onboarding.event_backbone, "make_kafka_producer", lambda: None)
    monkeypatch.setattr(
        onboarding.event_backbone,
        "publish_audit_event",
        lambda _producer, _tenant_id, event: captured.append(event),
    )
    onboarding._invitation_kafka_producer = None

    with TestingSessionLocal() as db:
        users.invite_user(
            _request(tenant_id, actor_id, request_id="safe-audit"),
            UserInviteRequest(email="sensitive@example.com", role="viewer"),
            db,
        )

    serialized = json.dumps(captured)
    assert {event["action"] for event in captured} == {
        "invitation:InviteCreated",
        "invitation:InviteDeliverySucceeded",
    }
    for value in (
        "sensitive@example.com",
        "otp",
        "jwt",
        "cookie",
        "oidc state",
        "nonce",
    ):
        assert value not in serialized.lower()
