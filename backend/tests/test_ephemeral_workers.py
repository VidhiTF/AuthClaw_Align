from datetime import datetime, timezone
from uuid import uuid4

from app.db.models import EphemeralWorkerToken
from app.services import ephemeral_workers


def test_worker_token_hash_does_not_store_raw_secret():
    raw = "ewt_demo_secret"

    digest = ephemeral_workers.hash_worker_token(raw)

    assert digest != raw
    assert len(digest) == 64
    assert digest == ephemeral_workers.hash_worker_token(raw)


def test_aws_boundary_allows_s3_sync_and_denies_unlisted_destructive_action():
    boundary = ephemeral_workers.build_permission_boundary(
        "aws",
        ["aws:s3:read", "aws:destructive:explicit"],
        allow_destructive=True,
        destructive_actions=["s3.delete_object"],
    )
    token = EphemeralWorkerToken(
        id=uuid4(),
        tenant_id=uuid4(),
        action_id="s3.sync",
        connector="aws",
        purpose="scan",
        scopes=["aws:s3:read", "aws:destructive:explicit"],
        permission_boundary=boundary,
        token_hash="hash",
        token_prefix="prefix",
        status="active",
        expires_at=datetime.now(tz=timezone.utc),
    )

    allowed, reason = ephemeral_workers.action_allowed(token, "s3.sync", "aws:s3:read", False)
    denied, denied_reason = ephemeral_workers.action_allowed(token, "iam.detach_policy", "aws:destructive:explicit", True)

    assert allowed is True
    assert reason == "worker token authorized"
    assert denied is False
    assert "outside the worker permission boundary" in denied_reason


def test_destructive_actions_are_denied_by_default_even_with_scope():
    boundary = ephemeral_workers.build_permission_boundary(
        "gcp",
        ["gcp:destructive:explicit"],
        allow_destructive=False,
        destructive_actions=["storage.object.delete"],
    )
    token = EphemeralWorkerToken(
        id=uuid4(),
        tenant_id=uuid4(),
        action_id="storage.object.delete",
        connector="gcp",
        purpose="remediation",
        scopes=["gcp:destructive:explicit"],
        permission_boundary=boundary,
        token_hash="hash",
        token_prefix="prefix",
        status="active",
        expires_at=datetime.now(tz=timezone.utc),
    )

    allowed, reason = ephemeral_workers.action_allowed(token, "storage.object.delete", "gcp:destructive:explicit", True)

    assert allowed is False
    assert "outside the worker permission boundary" in reason


def test_connector_catalog_includes_phase_25_foundations():
    connectors = {item["connector"]: item for item in ephemeral_workers.connector_catalog()}

    assert {"aws", "github", "gcp"} <= set(connectors)
    assert any(action["name"] == "repo.scan" for action in connectors["github"]["actions"])
    assert any(action["name"] == "asset.inventory" for action in connectors["gcp"]["actions"])
