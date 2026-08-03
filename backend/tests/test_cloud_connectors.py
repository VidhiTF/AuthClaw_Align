from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.api.v1.endpoints import cloud as cloud_endpoint
from app.db.models import CloudConnector
from app.services import cloud_connectors


def test_provider_catalog_exposes_real_provider_actions():
    catalog = {item["provider"]: item for item in cloud_connectors.provider_catalog()}

    assert {"aws", "github", "gcp"} <= set(catalog)
    assert "security-alerts" in catalog["github"]["actions"]
    assert "pr-remediation" in catalog["github"]["actions"]
    assert "iam-scan" in catalog["gcp"]["actions"]
    assert "remediate" in catalog["gcp"]["actions"]


def test_validate_credentials_requires_known_provider_fields():
    with pytest.raises(ValueError):
        cloud_connectors.validate_credentials("github", {})

    with pytest.raises(ValueError):
        cloud_connectors.validate_credentials("unknown", {"token": "x"})

    cloud_connectors.validate_credentials("github", {"token": "ghp_demo"})


def test_serialize_connector_never_returns_encrypted_secret():
    connector = CloudConnector(
        id=uuid4(),
        tenant_id=uuid4(),
        provider="github",
        display_name="GitHub prod",
        auth_type="token",
        encrypted_secret="ciphertext",
        status="connected",
        last_verified_at=datetime.now(timezone.utc),
        metadata_json={"owner": "acme", "repo": "app", "token": "should-not-leak"},
    )

    payload = cloud_connectors.serialize_connector(connector)

    assert payload["display_name"] == "GitHub prod"
    assert payload["metadata"] == {"owner": "acme", "repo": "app"}
    assert "encrypted_secret" not in payload
    assert "token" not in payload


def test_cloud_action_sanitizes_provider_errors(monkeypatch, caplog):
    connector = SimpleNamespace(id=uuid4(), provider="aws")
    request = SimpleNamespace(
        state=SimpleNamespace(tenant_id=uuid4(), user_id=uuid4()),
        headers={"x-request-id": "req-1"},
    )
    provider_error = (
        "AccessDenied for arn:aws:iam::123456789012:user/example while calling ListBuckets"
    )

    monkeypatch.setattr(cloud_endpoint, "_get_connector", lambda *_: connector)
    monkeypatch.setattr(
        cloud_connectors,
        "run_action",
        lambda *_: (_ for _ in ()).throw(RuntimeError(provider_error)),
    )

    with pytest.raises(HTTPException) as caught:
        cloud_endpoint.run_cloud_connector_action(
            connector.id,
            "inventory",
            cloud_endpoint.CloudActionRequest(),
            request,
            SimpleNamespace(),
        )

    assert caught.value.status_code == 502
    assert caught.value.detail == (
        "Cloud provider action failed. Check connector permissions and try again."
    )
    assert "AccessDenied" not in caught.value.detail
    assert "arn:aws" not in caught.value.detail
    assert provider_error in caplog.text
