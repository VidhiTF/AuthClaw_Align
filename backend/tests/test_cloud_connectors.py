from datetime import datetime, timezone
from uuid import uuid4

import pytest

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
