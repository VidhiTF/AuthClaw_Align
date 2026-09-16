from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock
from uuid import uuid4
import pytest
from fastapi import HTTPException
from app.api.v1.endpoints import cloud
from app.services import cloud_connectors as connectors


def request(ip="192.0.2.1"):
    return SimpleNamespace(client=SimpleNamespace(host=ip), headers={},
                           state=SimpleNamespace(user_id=uuid4(), tenant_id=uuid4()))


@pytest.mark.parametrize("action", ["REMEDIATE", " Remediate ", "PR-REMEDIATION"])
def test_mutation_aliases_require_mfa_before_provider(monkeypatch, action):
    db = MagicMock()
    connector = SimpleNamespace(id=uuid4(), provider="aws")
    monkeypatch.setattr(cloud, "_get_connector", lambda *_: connector)
    monkeypatch.setattr(cloud, "_verify_mfa_if_enabled", MagicMock(side_effect=HTTPException(403)))
    provider = MagicMock()
    monkeypatch.setattr(connectors, "run_action", provider)
    with pytest.raises(HTTPException) as caught:
        cloud.run_cloud_connector_action(connector.id, action, cloud.CloudActionRequest(), request(), db)
    assert caught.value.status_code == 403
    provider.assert_not_called()


def test_authorized_mutation_dispatches_canonical_action(monkeypatch):
    connector = SimpleNamespace(id=uuid4(), provider="aws")
    monkeypatch.setattr(cloud, "_get_connector", lambda *_: connector)
    mfa = MagicMock(return_value=(True, datetime.now(timezone.utc)))
    monkeypatch.setattr(cloud, "_verify_mfa_if_enabled", mfa)
    provider = MagicMock(return_value={"status": "ok"})
    monkeypatch.setattr(connectors, "run_action", provider)
    assert cloud.run_cloud_connector_action(connector.id, " REMEDIATE ", cloud.CloudActionRequest(), request(), MagicMock()) == {"status": "ok"}
    mfa.assert_called_once()
    assert provider.call_args.args[2] == "remediate"


@pytest.mark.parametrize("status,revoked_at", [("revoked", None), ("connected", datetime.now(timezone.utc))])
def test_revoked_credentials_cannot_be_verified_or_used(monkeypatch, status, revoked_at):
    connector = SimpleNamespace(status=status, revoked_at=revoked_at)
    credentials = MagicMock()
    monkeypatch.setattr(connectors, "_credentials", credentials)
    with pytest.raises(ValueError, match="revoked"):
        connectors.verify_connector(MagicMock(), connector)
    with pytest.raises(ValueError, match="revoked"):
        connectors.run_action(MagicMock(), connector, "inventory", {}, uuid4())
    credentials.assert_not_called()
