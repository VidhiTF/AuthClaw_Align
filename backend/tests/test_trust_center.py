from types import SimpleNamespace
from datetime import timedelta
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
    with pytest.raises(ValueError, match="Full export"):
        trust_center.build_share_export(object(), share)


def test_auditor_otp_binds_access_to_email_and_share(monkeypatch):
    monkeypatch.setenv("SESSION_SECRET", "test-trust-center-secret-32-bytes!")
    monkeypatch.setenv("SESSION_SECRET_V1", "test-trust-center-secret-32-bytes!")
    monkeypatch.setenv("AUTHCLAW_SESSION_KEY_VERSION", "v1")
    delivered = {}

    def fake_send(email, otp, tenant_name, *, purpose):
        delivered.update(email=email, otp=otp, tenant_name=tenant_name, purpose=purpose)
        return SimpleNamespace(method="smtp")

    monkeypatch.setattr(trust_center, "send_otp_email", fake_send)
    db = SimpleNamespace(commit=lambda: None, refresh=lambda *_args, **_kwargs: None)
    share_token = "tc_demo_secret"
    share = SimpleNamespace(
        id=uuid4(),
        tenant_id=uuid4(),
        auditor_email="auditor@example.com",
        metadata_json={},
        status="active", revoked_at=None, expires_at=trust_center.now_utc() + timedelta(days=1),
    )

    issued = trust_center.issue_auditor_otp(db, share, "Acme")
    verified = trust_center.verify_auditor_otp(db, share, share_token, delivered["otp"])

    assert issued["email"] == "au*****@example.com"
    assert delivered["email"] == "auditor@example.com"
    monkeypatch.setenv("SESSION_SECRET_V2", "rotated-trust-center-secret-32-bytes")
    monkeypatch.setenv("AUTHCLAW_SESSION_KEY_VERSION", "v2")
    trust_center.verify_auditor_access(share, share_token, verified["access_token"])
    with pytest.raises(ValueError, match="does not match"):
        trust_center.verify_auditor_access(share, "tc_other_secret", verified["access_token"])


def test_verify_artifact_wraps_audit_export_verifier(monkeypatch):
    monkeypatch.setattr(
        trust_center,
        "verify_signed_audit_export",
        lambda artifact: SimpleNamespace(as_dict=lambda: {"verified": artifact["ok"]}),
    )

    assert trust_center.verify_artifact({"ok": True}) == {"verified": True}


def test_public_package_filters_trust_summary_and_recalculates_counts(monkeypatch):
    tenant_id = uuid4()
    tenant = SimpleNamespace(id=tenant_id, name="Example", tier="enterprise")
    share = SimpleNamespace(
        id=uuid4(), tenant_id=tenant_id, label="Review", auditor_email=None,
        frameworks=["SOC2"], permissions=["view_scores"], status="active",
        expires_at=None, created_at=None, last_accessed_at=None, access_count=0,
    )

    class Query:
        def filter(self, *_args):
            return self

        def first(self):
            return tenant

    class Database:
        def query(self, *_args):
            return Query()

    scores = {
        "overall_score": 80.0,
        "readiness_level": "monitor",
        "generated_at": "2026-07-16T00:00:00+00:00",
        "frameworks": [
            {"framework": "SOC2", "score": 90.0},
            {"framework": "GDPR", "score": 70.0},
        ],
        "trust_summary": {
            "generated_at": "2026-07-16T00:00:00+00:00",
            "counts": {"verified": 2, "in_progress": 1, "planned": 0},
            "verified": [
                {"framework": "SOC2", "id": "one"},
                {"framework": "GDPR", "id": "two"},
            ],
            "in_progress": [{"framework": "GDPR", "id": "three"}],
            "planned": [],
        },
    }
    monkeypatch.setattr(trust_center.compliance_scoring, "score_all_frameworks", lambda *_args, **_kwargs: scores)
    monkeypatch.setattr(
        trust_center,
        "signing_key_metadata",
        lambda: {"public_key": "public-key", "key_id": "key-id", "algorithm": "Ed25519"},
    )

    package = trust_center.build_public_package(Database(), share)

    assert [item["framework"] for item in package["scores"]["frameworks"]] == ["SOC2"]
    assert package["scores"]["trust_summary"]["counts"] == {
        "verified": 1,
        "in_progress": 0,
        "planned": 0,
    }
    assert package["scores"]["trust_summary"]["verified"][0]["id"] == "one"
