from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.services import trust_center


def test_share_token_hash_is_stable_and_does_not_expose_token():
    _, token = trust_center.generate_share_token()

    first = trust_center.hash_share_token(token)
    second = trust_center.hash_share_token(token)

    assert token.startswith("tc_")
    assert first == second
    assert token not in first
    assert len(first) == 64


def test_normalize_frameworks_rejects_unknown_frameworks():
    assert trust_center.normalize_frameworks(["gdpr", "SOC2", "gdpr"]) == ["GDPR", "SOC2"]

    with pytest.raises(ValueError, match="PCI"):
        trust_center.normalize_frameworks(["SOC2", "PCI"])


def test_public_share_url_trims_console_origin():
    assert (
        trust_center.public_share_url("http://localhost:3001/", "tc_demo_secret")
        == "http://localhost:3001/trust-center/tc_demo_secret"
    )


def test_verification_guide_contains_offline_verifier_and_public_key_pin():
    guide = trust_center.verification_guide("public-key", "key-id")

    bodies = " ".join(item["body"] for item in guide)
    assert "verify_audit_export.py" in bodies
    assert "key-id" in bodies
    assert "public-key" in bodies


def test_build_share_export_enforces_framework_scope(monkeypatch):
    tenant_id = uuid4()
    share = SimpleNamespace(tenant_id=tenant_id, frameworks=["SOC2"])
    calls = []

    def fake_build_signed_audit_export(db, *, tenant_id, framework=None):
        calls.append((tenant_id, framework))
        return {"payload": {"framework": framework}}

    monkeypatch.setattr(trust_center, "build_signed_audit_export", fake_build_signed_audit_export)

    artifact = trust_center.build_share_export(object(), share, framework="SOC2")

    assert artifact["payload"]["framework"] == "SOC2"
    assert calls == [(str(tenant_id), "SOC2")]
    with pytest.raises(ValueError, match="not allowed"):
        trust_center.build_share_export(object(), share, framework="HIPAA")


def test_verify_artifact_wraps_audit_export_verifier(monkeypatch):
    monkeypatch.setattr(
        trust_center,
        "verify_signed_audit_export",
        lambda artifact: SimpleNamespace(as_dict=lambda: {"verified": artifact["ok"]}),
    )

    assert trust_center.verify_artifact({"ok": True}) == {"verified": True}
