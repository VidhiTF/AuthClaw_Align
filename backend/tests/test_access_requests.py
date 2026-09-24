from datetime import datetime, timedelta, timezone
import importlib.util
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, call
from uuid import uuid4

import pytest
import redis
from fastapi import HTTPException
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import Column

from app.api.v1.endpoints import access_requests as access_request_endpoints
from app.api.v1.endpoints import onboarding
from app.db.models import AccessRequest, AccessRequestHistory
from app.db.dependencies import get_db
from app.schemas.models import AccessRequestCreate
from app.services import access_requests
from app.services import event_backbone, privacy_lifecycle
from app.services.access_requests import (
    create_access_request,
    deliver_access_request_emails,
    transition_access_request,
)
from app.services.email_service import EmailDeliveryError
from main import app

VALID_REQUEST = {
    "name": "Ada Lovelace",
    "business_email": "ADA@EXAMPLE.COM",
    "company": "Analytical Engines",
    "role": "CTO",
    "use_case": "Govern AI traffic.",
    "requested_access": "EARLY_ACCESS",
    "consent": True,
    "source_page": "/security",
}


class FakeSession:
    def __init__(self):
        self.added = []
        self.commits = 0
        self.rollbacks = 0

    def add(self, value):
        self.added.append(value)

    def commit(self):
        self.commits += 1

    def flush(self):
        for value in self.added:
            if getattr(value, "id", None) is None:
                value.id = uuid4()

    def refresh(self, value):
        value.created_at = datetime.now(timezone.utc)

    def rollback(self):
        self.rollbacks += 1


@pytest.fixture(autouse=True)
def allow_access_request_rate_limit(monkeypatch):
    monkeypatch.setattr(
        access_request_endpoints,
        "_enforce_onboarding_rate_limit",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(
        access_request_endpoints,
        "deliver_access_request_emails",
        lambda request, db=None: None,
    )


@pytest.fixture
def client():
    db = FakeSession()

    def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    try:
        with TestClient(app) as test_client:
            yield test_client, db
    finally:
        app.dependency_overrides.clear()


def test_schema_normalizes_and_rejects_unapproved_input():
    payload = AccessRequestCreate(
        **{**VALID_REQUEST, "name": " Ada ", "company": " Engines "}
    )

    assert payload.name == "Ada"
    assert payload.company == "Engines"

    with pytest.raises(ValidationError):
        AccessRequestCreate(**{**VALID_REQUEST, "business_email": "not-an-email"})
    with pytest.raises(ValidationError):
        AccessRequestCreate(**{**VALID_REQUEST, "consent": False})
    with pytest.raises(ValidationError):
        AccessRequestCreate(**{**VALID_REQUEST, "unexpected": "value"})
    with pytest.raises(ValidationError):
        AccessRequestCreate(**{**VALID_REQUEST, "requested_access": "TRIAL"})


@pytest.mark.parametrize(
    ("source_page", "requested_access"),
    [("/demo", "DEMO"), ("/early-access", "EARLY_ACCESS")],
)
def test_schema_accepts_intake_routes(source_page, requested_access):
    payload = AccessRequestCreate(
        **{
            **VALID_REQUEST,
            "source_page": source_page,
            "requested_access": requested_access,
        }
    )

    assert payload.source_page == source_page
    assert payload.requested_access == requested_access


def test_service_persists_only_required_intake_fields(monkeypatch):
    db = FakeSession()
    payload = AccessRequestCreate(**VALID_REQUEST)
    metrics = []
    monkeypatch.setattr(
        event_backbone,
        "increment_metric",
        lambda name, value=1: metrics.append((name, value)),
    )

    record = create_access_request(db, payload)

    assert db.added[0] is record
    assert isinstance(db.added[1], AccessRequestHistory)
    assert db.added[1].event_type == "CREATED"
    assert db.added[1].new_status == "PENDING"
    assert db.added[1].event_metadata == {}
    assert ("access_request_submission_received_total", 1) in metrics
    assert db.commits == 1
    assert record.reference.startswith("AR-")
    assert len(record.reference) == 35
    assert record.business_email == "ada@example.com"
    assert record.status == "PENDING"
    assert record.consent_timestamp.tzinfo is not None
    assert record.notice_version == access_requests.settings.PRIVACY_NOTICE_VERSION
    assert record.source_page == VALID_REQUEST["source_page"]
    assert not hasattr(record, "consent")


def test_reference_is_unique_per_request():
    first = create_access_request(FakeSession(), AccessRequestCreate(**VALID_REQUEST))
    second = create_access_request(FakeSession(), AccessRequestCreate(**VALID_REQUEST))

    assert first.reference != second.reference


def test_service_rolls_back_failed_persistence():
    db = FakeSession()
    db.commit = MagicMock(side_effect=RuntimeError("database unavailable"))

    with pytest.raises(RuntimeError, match="database unavailable"):
        create_access_request(db, AccessRequestCreate(**VALID_REQUEST))

    assert db.rollbacks == 1


def test_public_endpoint_accepts_request_without_auth_and_returns_no_pii(
    client, caplog
):
    test_client, db = client

    response = test_client.post("/api/public/v1/access-requests", json=VALID_REQUEST)

    assert response.status_code == 202
    assert response.json()["status"] == "PENDING"
    assert response.json()["reference"].startswith("AR-")
    assert set(response.json()) == {"reference", "status", "created_at"}
    assert db.added[0].business_email == "ada@example.com"
    for pii in (
        "Ada Lovelace",
        "ADA@EXAMPLE.COM",
        "Analytical Engines",
        "Govern AI traffic.",
    ):
        assert pii not in caplog.text


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("name", ""),
        ("business_email", "invalid"),
        ("company", ""),
        ("role", ""),
        ("use_case", ""),
        ("requested_access", ""),
        ("consent", False),
        ("source_page", "/not-a-marketing-route"),
    ],
)
def test_public_endpoint_rejects_invalid_fields(client, field, value):
    test_client, db = client

    response = test_client.post(
        "/api/public/v1/access-requests",
        json={**VALID_REQUEST, field: value},
    )

    assert response.status_code == 422
    assert response.json() == {"detail": "Invalid request"}
    assert db.added == []


def test_client_cannot_supply_notice_version(client):
    test_client, db = client

    response = test_client.post(
        "/api/public/v1/access-requests",
        json={**VALID_REQUEST, "notice_version": "attacker-controlled"},
    )

    assert response.status_code == 422
    assert response.json() == {"detail": "Invalid request"}
    assert db.added == []


def test_status_and_retention_routes_require_authentication(client):
    test_client, _ = client

    list_response = test_client.get("/api/public/v1/access-requests")
    transition = test_client.patch(
        "/api/public/v1/access-requests/AR-TEST/status",
        params={"new_status": "APPROVED"},
    )
    retention = test_client.post("/api/public/v1/access-requests/retention/purge")

    assert list_response.status_code == 401
    assert transition.status_code == 401
    assert retention.status_code == 401


def test_rate_limit_returns_generic_error_and_rolls_back(client, monkeypatch):
    test_client, db = client

    def reject(*args, **kwargs):
        raise HTTPException(status_code=429, detail="internal limiter detail")

    monkeypatch.setattr(
        access_request_endpoints,
        "_enforce_onboarding_rate_limit",
        reject,
    )

    response = test_client.post("/api/public/v1/access-requests", json=VALID_REQUEST)

    assert response.status_code == 429
    assert response.json() == {"detail": "Request limit exceeded"}
    assert db.added == []
    assert db.rollbacks == 1


def test_rapid_duplicate_submissions_use_existing_email_limiter(client, monkeypatch):
    test_client, db = client

    class FakeRedis:
        counts = {}

        def eval(self, _script, _number_of_keys, key, _window_ms):
            self.counts[key] = self.counts.get(key, 0) + 1
            return [self.counts[key], 60_000]

    monkeypatch.setattr(onboarding, "_get_redis", lambda: FakeRedis())
    monkeypatch.setattr(
        access_request_endpoints,
        "_enforce_onboarding_rate_limit",
        onboarding._enforce_onboarding_rate_limit,
    )

    responses = [
        test_client.post("/api/public/v1/access-requests", json=VALID_REQUEST)
        for _ in range(onboarding.ONBOARDING_SIGNUP_EMAIL_PER_HOUR + 1)
    ]

    assert [response.status_code for response in responses] == (
        [202] * onboarding.ONBOARDING_SIGNUP_EMAIL_PER_HOUR + [429]
    )
    assert len(db.added) == onboarding.ONBOARDING_SIGNUP_EMAIL_PER_HOUR * 2


def test_oversized_and_malformed_payloads_are_rejected_generically(client):
    test_client, db = client

    oversized = test_client.post(
        "/api/public/v1/access-requests",
        json={**VALID_REQUEST, "use_case": "x" * 4001},
    )
    malformed = test_client.post(
        "/api/public/v1/access-requests",
        content=b'{"name":',
        headers={"content-type": "application/json"},
    )

    assert oversized.status_code == 422
    assert oversized.json() == {"detail": "Invalid request"}
    assert malformed.status_code == 422
    assert malformed.json() == {"detail": "Invalid request"}
    assert db.added == []


def test_redis_unavailable_fails_closed_without_pii(client, monkeypatch, caplog):
    test_client, db = client

    monkeypatch.setenv("AUTHCLAW_ENV", "production")
    monkeypatch.setattr(
        onboarding,
        "_get_redis",
        MagicMock(side_effect=redis.RedisError("redis host secret")),
    )
    monkeypatch.setattr(
        access_request_endpoints,
        "_enforce_onboarding_rate_limit",
        onboarding._enforce_onboarding_rate_limit,
    )

    response = test_client.post("/api/public/v1/access-requests", json=VALID_REQUEST)

    assert response.status_code == 503
    assert response.json() == {"detail": "Internal server error"}
    assert db.added == []
    assert db.rollbacks == 1
    assert "redis host secret" not in caplog.text
    for pii in (
        "Ada Lovelace",
        "ADA@EXAMPLE.COM",
        "Analytical Engines",
        "Govern AI traffic.",
    ):
        assert pii not in caplog.text


def test_persistence_failure_is_generic_and_rolls_back(client, caplog):
    test_client, db = client
    db.commit = MagicMock(
        side_effect=RuntimeError("SQL error for ADA@EXAMPLE.COM at Analytical Engines")
    )

    response = test_client.post("/api/public/v1/access-requests", json=VALID_REQUEST)

    assert response.status_code == 503
    assert response.json() == {"detail": "Internal server error"}
    assert db.rollbacks == 1
    assert "ADA@EXAMPLE.COM" not in caplog.text
    assert "Analytical Engines" not in caplog.text


def test_best_effort_emails_are_minimal_and_emit_metrics(monkeypatch):
    sent = []
    metrics = []
    request = SimpleNamespace(
        reference="AR-SAFE-REFERENCE",
        business_email="requester@example.com",
    )
    monkeypatch.setattr(
        access_requests.settings,
        "INTERNAL_LAUNCH_OWNER_EMAIL",
        "launch-owner@example.com",
    )
    monkeypatch.setattr(
        access_requests,
        "send_email",
        lambda recipient, subject, body: sent.append((recipient, subject, body)),
    )
    monkeypatch.setattr(
        event_backbone,
        "increment_metric",
        lambda name, value=1: metrics.append((name, value)),
    )

    deliver_access_request_emails(request)

    assert [message[0] for message in sent] == [
        "launch-owner@example.com",
        "requester@example.com",
    ]
    assert all("AR-SAFE-REFERENCE" in message[2] for message in sent)
    assert all("Analytical Engines" not in message[2] for message in sent)
    assert ("access_request_notification_sent_total", 1) in metrics
    assert ("access_request_confirmation_sent_total", 1) in metrics


def test_email_failure_is_best_effort_and_logs_no_pii(monkeypatch, caplog):
    attempts = []
    metrics = []
    request = SimpleNamespace(
        reference="AR-SAFE-REFERENCE",
        business_email="private@example.com",
    )
    monkeypatch.setattr(
        access_requests.settings,
        "INTERNAL_LAUNCH_OWNER_EMAIL",
        "launch-owner@example.com",
    )

    def fail(recipient, subject, body):
        attempts.append(recipient)
        raise EmailDeliveryError("SMTP private@example.com failed")

    monkeypatch.setattr(access_requests, "send_email", fail)
    monkeypatch.setattr(
        event_backbone,
        "increment_metric",
        lambda name, value=1: metrics.append((name, value)),
    )

    db = FakeSession()
    request.id = uuid4()
    deliver_access_request_emails(request, db)

    assert len(attempts) == 4
    assert metrics.count(("access_request_email_failures_total", 1)) == 2
    failures = [value for value in db.added if isinstance(value, AccessRequestHistory)]
    assert len(failures) == 2
    assert all(value.event_type == "NOTIFICATION_FAILED" for value in failures)
    assert db.commits == 1
    assert "private@example.com" not in caplog.text
    assert "launch-owner@example.com" not in caplog.text


def test_email_retry_recovers_without_failure_record(monkeypatch):
    attempts = []
    request = SimpleNamespace(
        id=uuid4(),
        reference="AR-SAFE-REFERENCE",
        business_email="requester@example.com",
    )
    db = FakeSession()
    monkeypatch.setattr(
        access_requests.settings,
        "INTERNAL_LAUNCH_OWNER_EMAIL",
        "launch-owner@example.com",
    )

    def retry_once(recipient, subject, body):
        attempts.append(recipient)
        if attempts.count(recipient) == 1:
            raise EmailDeliveryError("temporary failure")

    monkeypatch.setattr(access_requests, "send_email", retry_once)

    deliver_access_request_emails(request, db)

    assert attempts == [
        "launch-owner@example.com",
        "launch-owner@example.com",
        "requester@example.com",
        "requester@example.com",
    ]
    assert db.added == []
    assert db.commits == 0


@pytest.mark.parametrize("delivery_fails", [False, True])
def test_invitation_resend_does_not_reload_after_tenant_context_ends(monkeypatch, delivery_fails):
    payload = SimpleNamespace(signup_id=uuid4())
    db = MagicMock()
    db.execute.return_value.one.return_value = SimpleNamespace(outcome="valid")
    db.query.return_value.filter.return_value.with_for_update.return_value.first.return_value = SimpleNamespace(
        id=payload.signup_id, tenant_id=uuid4(), email="owner@example.com", tenant_name="Test", purpose="invite",
        status="pending", expires_at=datetime.now(timezone.utc) + timedelta(minutes=15), sent_at=datetime.now(timezone.utc),
    )
    monkeypatch.setattr(onboarding, "OwnerSessionLocal", lambda: db)
    monkeypatch.setattr(onboarding, "_enforce_onboarding_rate_limit", lambda *_: None)
    delivery = MagicMock(return_value=("local_outbox", None))
    if delivery_fails:
        delivery.side_effect = EmailDeliveryError("private provider detail")
    monkeypatch.setattr(onboarding, "_deliver_otp", delivery)
    audit = MagicMock(side_effect=lambda row, *_: (row.id, row.tenant_id, row.purpose))
    monkeypatch.setattr(onboarding, "_emit_invitation_audit", audit)
    if delivery_fails:
        with pytest.raises(HTTPException) as error:
            onboarding.resend(payload, SimpleNamespace(headers={}, client=None))
        assert error.value.status_code == 503
        assert error.value.detail == "Invitation delivery is temporarily unavailable"
    else:
        response = onboarding.resend(payload, SimpleNamespace(headers={}, client=None))
        assert response.signup_id == payload.signup_id
        assert response.delivery == "local_outbox"
    audit.assert_called_once()


@pytest.mark.parametrize("new_status", ["APPROVED", "REJECTED", "INVITED"])
def test_status_transition_records_history_and_rejects_invalid(monkeypatch, new_status):
    request = AccessRequest(
        id=uuid4(),
        reference="AR-TRANSITION",
        status="PENDING",
    )
    db = MagicMock()
    query = db.query.return_value
    query.filter.return_value = query
    query.with_for_update.return_value = query
    query.one_or_none.return_value = request
    metrics = []
    monkeypatch.setattr(
        event_backbone,
        "increment_metric",
        lambda name, value=1: metrics.append((name, value)),
    )

    result = transition_access_request(
        db,
        reference=request.reference,
        new_status=new_status,
        actor_id=uuid4(),
    )

    assert result.status == new_status
    history = db.add.call_args.args[0]
    assert isinstance(history, AccessRequestHistory)
    assert history.old_status == "PENDING"
    assert history.new_status == new_status
    assert ("access_request_status_changed_total", 1) in metrics

    with pytest.raises(ValueError, match="Invalid access request transition"):
        transition_access_request(
            db,
            reference=request.reference,
            new_status="REJECTED",
            actor_id=uuid4(),
        )


def test_retention_deletes_selected_records_and_preserves_history(monkeypatch):
    expired = [
        AccessRequest(id=uuid4(), status="PENDING"),
        AccessRequest(id=uuid4(), status="REJECTED"),
        AccessRequest(id=uuid4(), status="INVITED"),
    ]
    db = MagicMock()
    query = db.query.return_value
    query.filter.return_value = query
    query.all.return_value = expired
    metrics = []
    monkeypatch.setattr(
        event_backbone,
        "increment_metric",
        lambda name, value=1: metrics.append((name, value)),
    )

    deleted = privacy_lifecycle.purge_expired_access_requests(
        db,
        now=datetime.now(timezone.utc) + timedelta(days=100),
    )

    assert deleted == 3
    assert db.delete.call_count == 3
    histories = [call.args[0] for call in db.add.call_args_list]
    assert all(history.event_type == "DELETED" for history in histories)
    assert all(history.event_metadata == {"policy": "ACL-15"} for history in histories)
    assert ("access_request_deletion_completed_total", 1) in metrics
    assert ("access_request_records_deleted_total", 3) in metrics


def test_retention_failure_rolls_back_and_emits_failure_metric(monkeypatch):
    db = MagicMock()
    query = db.query.return_value
    query.filter.return_value = query
    query.all.return_value = [AccessRequest(id=uuid4(), status="REJECTED")]
    db.commit.side_effect = RuntimeError("database unavailable")
    metrics = []
    monkeypatch.setattr(
        event_backbone,
        "increment_metric",
        lambda name, value=1: metrics.append((name, value)),
    )

    with pytest.raises(RuntimeError, match="database unavailable"):
        privacy_lifecycle.purge_expired_access_requests(db)

    db.rollback.assert_called_once()
    assert ("access_request_deletion_failures_total", 1) in metrics


def test_migration_matches_access_request_model(monkeypatch):
    path = (
        Path(__file__).parents[1]
        / "alembic"
        / "versions"
        / "029_add_access_requests.py"
    )
    spec = importlib.util.spec_from_file_location("migration_027", path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    create_table = MagicMock()
    bind = MagicMock()
    bind.dialect.identifier_preparer.quote.return_value = '"authclaw_app"'
    monkeypatch.setattr(migration.op, "create_table", create_table)
    monkeypatch.setattr(migration.op, "create_index", MagicMock())
    monkeypatch.setattr(migration.op, "get_bind", lambda: bind)
    execute = MagicMock()
    monkeypatch.setattr(migration.op, "execute", execute)

    migration.upgrade()

    migration_columns = {
        item.name
        for item in create_table.call_args.args[1:]
        if isinstance(item, Column)
    }
    assert migration_columns == set(AccessRequest.__table__.columns.keys())
    execute.assert_called_once_with(
        'GRANT SELECT, INSERT ON access_requests TO "authclaw_app"'
    )


def test_history_migration_matches_model_and_grants_app_role(monkeypatch):
    path = (
        Path(__file__).parents[1]
        / "alembic"
        / "versions"
        / "030_add_access_request_history.py"
    )
    spec = importlib.util.spec_from_file_location("migration_028", path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    create_table = MagicMock()
    bind = MagicMock()
    bind.dialect.identifier_preparer.quote.return_value = '"authclaw_app"'
    monkeypatch.setattr(migration.op, "create_table", create_table)
    monkeypatch.setattr(migration.op, "create_index", MagicMock())
    monkeypatch.setattr(migration.op, "drop_index", MagicMock())
    monkeypatch.setattr(migration.op, "drop_table", MagicMock())
    monkeypatch.setattr(migration.op, "get_bind", lambda: bind)
    execute = MagicMock()
    monkeypatch.setattr(migration.op, "execute", execute)

    migration.upgrade()

    migration_columns = {
        item.name
        for item in create_table.call_args.args[1:]
        if isinstance(item, Column)
    }
    assert migration_columns == set(AccessRequestHistory.__table__.columns.keys())
    assert execute.call_args_list == [
        call(
            'GRANT SELECT, INSERT, UPDATE, DELETE ON access_requests TO "authclaw_app"'
        ),
        call('GRANT SELECT, INSERT ON access_request_history TO "authclaw_app"'),
        call('GRANT SELECT ON onboarding_email_otps TO "authclaw_app"'),
    ]

    execute.reset_mock()
    migration.downgrade()

    assert execute.call_args_list == [
        call('REVOKE SELECT ON onboarding_email_otps FROM "authclaw_app"'),
        call('REVOKE SELECT, INSERT ON access_request_history FROM "authclaw_app"'),
        call('REVOKE UPDATE, DELETE ON access_requests FROM "authclaw_app"'),
    ]


def test_onboarding_lookup_migration_is_symmetric(monkeypatch):
    path = (
        Path(__file__).parents[1]
        / "alembic"
        / "versions"
        / "032_add_access_request_onboarding_lookup.py"
    )
    spec = importlib.util.spec_from_file_location("migration_030", path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    bind = MagicMock()
    bind.dialect.identifier_preparer.quote.return_value = '"authclaw_app"'
    monkeypatch.setattr(migration.op, "get_bind", lambda: bind)
    execute = MagicMock()
    monkeypatch.setattr(migration.op, "execute", execute)

    migration.upgrade()
    assert execute.call_args_list[-3:] == [
        call(
            "REVOKE ALL ON FUNCTION "
            "access_request_onboarding_started(text, timestamptz) FROM PUBLIC"
        ),
        call(
            "GRANT EXECUTE ON FUNCTION "
            'access_request_onboarding_started(text, timestamptz) TO "authclaw_app"'
        ),
        call('REVOKE SELECT ON onboarding_email_otps FROM "authclaw_app"'),
    ]

    execute.reset_mock()
    migration.downgrade()
    assert execute.call_args_list == [
        call('GRANT SELECT ON onboarding_email_otps TO "authclaw_app"'),
        call(
            "REVOKE EXECUTE ON FUNCTION "
            'access_request_onboarding_started(text, timestamptz) FROM "authclaw_app"'
        ),
        call(
            "DROP FUNCTION IF EXISTS "
            "access_request_onboarding_started(text, timestamptz)"
        ),
    ]


def test_invite_onboarding_lookup_migration_preserves_f26_retention(monkeypatch):
    path = (
        Path(__file__).parents[1]
        / "alembic"
        / "versions"
        / "034_recognize_invite_onboarding.py"
    )
    spec = importlib.util.spec_from_file_location("migration_034", path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    execute = MagicMock()
    monkeypatch.setattr(migration.op, "execute", execute)

    migration.upgrade()
    assert "purpose IN ('signup', 'invite')" in execute.call_args.args[0]

    execute.reset_mock()
    migration.downgrade()
    assert "purpose = 'signup'" in execute.call_args.args[0]
