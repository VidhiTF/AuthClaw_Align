"""Exercise the imported trust publisher with real tenant context and tenant SQL."""

import importlib.util
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, text

from services.tenant_context import tenant_context


ROOT = Path(__file__).parents[1]


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def runtime(monkeypatch, tmp_path):
    database_path = tmp_path / "trust.sqlite"
    engine = create_engine(f"sqlite:///{database_path}")
    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE tenants (id INTEGER PRIMARY KEY, name TEXT, domain TEXT, status TEXT)"))
        conn.execute(text("INSERT INTO tenants VALUES (7,'A','a.test','active'), (9,'B','b.test','active'), (11,'C','c.test','inactive')"))
    monkeypatch.setitem(sys.modules, "database", SimpleNamespace(engine=engine))
    scoring = load_module("trust_boundary_scoring", "services/compliance_evidence_engine.py")
    monkeypatch.setattr(scoring.ComplianceEvidenceEngine, "calculate_scores", lambda _, tenant:
                        {**scoring.ComplianceEvidenceEngine.diagnostic_metadata(), "soc2": tenant, "gdpr": 80, "hipaa": 90})
    monkeypatch.setattr(scoring.ComplianceEvidenceEngine, "corpus_status", lambda _: {})
    monkeypatch.setitem(sys.modules, "services.compliance_evidence_engine", scoring)
    monkeypatch.setitem(sys.modules, "services.event_pipeline", SimpleNamespace(EventPipeline=lambda:
                        SimpleNamespace(delivery_metrics=lambda: {"streams": {"security_alert": {"delivered": 1}}, "checkpoints": []})))
    monkeypatch.setitem(sys.modules, "services.secret_manager", SimpleNamespace(SecretManager=lambda:
                        SimpleNamespace(selection_policy=lambda: {})))
    monkeypatch.setitem(sys.modules, "verify_audit", SimpleNamespace(
        verify_audit_chain=lambda **_: {"valid": True}, clickhouse_pipeline_enabled=lambda: False,
        create_signed_export_package=lambda payload, **kwargs: {
            "payload": payload, "manifest": {"tenant_id": kwargs["tenant_id"]}, "payload_b64": "test-signature"},
        verify_signed_export_package=lambda **_: {"valid": True},
    ))
    observer = load_module("trust_boundary_observer", "services/observability_service.py")
    monkeypatch.setitem(sys.modules, "services.observability_service", observer)
    module = load_module("trust_boundary_runtime", "services/trust_center_runtime.py")
    monkeypatch.setattr(module, "_metrics_summary", lambda tenant: {"total_requests": tenant})
    monkeypatch.setattr(module, "_provider_status", lambda tenant: {"tenant_id": tenant})
    yield module
    engine.dispose()
    database_path.unlink()


def test_tenant_selection_and_cache_never_cross_callers(runtime):
    for tenant, hit in [(9, False), (9, True), (7, False), (7, True), (9, False)]:
        with tenant_context(tenant, required=True):
            state = runtime.build_public_trust_state()
        assert state["payload"]["tenant_id"] == tenant
        assert state["manifest"]["tenant_id"] == tenant
        assert state["payload"]["framework_scores"]["soc2"] == tenant
        assert state["payload"]["runtime"]["metrics"]["total_requests"] == tenant
        assert state["cache"]["hit"] is hit


@pytest.mark.parametrize("tenant,status", [(None, 403), (11, 404), (999, 404)])
def test_warm_cache_does_not_bypass_missing_or_inactive_tenant(runtime, tenant, status):
    with tenant_context(7, required=True):
        runtime.build_public_trust_state()
    with tenant_context(tenant, required=True), pytest.raises(HTTPException) as denied:
        runtime.build_public_trust_state()
    assert denied.value.status_code == status


def test_concurrent_tenant_reads_keep_signed_payloads_separate(runtime):
    def read(tenant):
        with tenant_context(tenant, required=True):
            state = runtime.build_public_trust_state()
        assert state["payload"]["tenant_id"] == state["manifest"]["tenant_id"] == tenant
    with ThreadPoolExecutor(max_workers=2) as executor:
        list(executor.map(read, [7, 9] * 10))


def test_warm_cache_cannot_bypass_tenant_deactivation(runtime):
    with tenant_context(7, required=True):
        runtime.build_public_trust_state()
        with runtime.engine.begin() as conn:
            conn.execute(text("UPDATE tenants SET status='inactive' WHERE id=7"))
        with pytest.raises(HTTPException) as denied:
            runtime.build_public_trust_state()
        assert denied.value.status_code == 404
        with runtime.engine.begin() as conn:
            conn.execute(text("UPDATE tenants SET status='active' WHERE id=7"))
        assert runtime.build_public_trust_state()["payload"]["tenant_id"] == 7


def test_diagnostic_scores_never_make_trust_compliance_healthy(runtime):
    with tenant_context(7, required=True):
        state = runtime.trust_runtime_health()
    assert state["checks"]["publication"] == state["checks"]["audit"] == state["checks"]["queue"] == "healthy"
    assert state["checks"]["compliance_evidence"] == state["status"] == "unknown"


def test_source_outage_does_not_return_cached_success(runtime, monkeypatch):
    with tenant_context(7, required=True):
        runtime.build_public_trust_state()
        def fail(_):
            raise RuntimeError("private database details")
        monkeypatch.setattr(runtime, "_metrics_summary", fail)
        state = runtime.trust_runtime_health()
    assert state["status"] == "unavailable"
    assert "private" not in str(state)
