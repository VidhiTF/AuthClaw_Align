"""Exercise recorder, registrar and SQL aggregates with real SQLite storage."""
import importlib.util
import sqlite3
import sys
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest
from sqlalchemy import create_engine, text

AGENT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(AGENT))


def load_module(name, relative, dependencies):
    spec = importlib.util.spec_from_file_location(name, AGENT / relative)
    module = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, dependencies):
        spec.loader.exec_module(module)
    return module


@pytest.fixture
def telemetry(monkeypatch):
    monkeypatch.setitem(sqlite3.adapters, (datetime, sqlite3.PrepareProtocol), lambda value: value.isoformat(" "))
    engine = create_engine("sqlite://")
    with engine.begin() as conn:
        conn.execute(text("""CREATE TABLE gateway_requests (
            timestamp TEXT, created_at TEXT, risk_level TEXT, allowed BOOLEAN,
            status TEXT, request_id TEXT, tenant_id TEXT, route_id TEXT, provider TEXT,
            model TEXT, latency INTEGER, tokens_in INTEGER, tokens_out INTEGER,
            decision TEXT, duration_ms INTEGER, token_usage_recorded BOOLEAN DEFAULT FALSE,
            latency_recorded BOOLEAN DEFAULT FALSE)"""))
    dependencies = {"database": SimpleNamespace(engine=engine)}
    audit = load_module("token_audit", "verify_audit.py", dependencies)
    dependencies["verify_audit"] = audit
    service = load_module("token_observability", "services/observability_service.py", dependencies).ObservabilityService()
    mirrored = []
    with patch.dict(sys.modules, dependencies), patch.object(audit, "mirror_audit_event_to_clickhouse", mirrored.append):
        yield engine, audit, service, mirrored, dependencies
    engine.dispose()


@pytest.mark.parametrize("counts", [(None, None), (0, 0), (12, 0), (None, 7), (-1, True)])
def test_recorder_preserves_unknown_zero_and_mirror(counts, telemetry):
    engine, audit, service, mirrored, _ = telemetry
    expected = tuple(value if type(value) is int and value >= 0 else None for value in counts)
    audit.record_gateway_request("UNKNOWN", False, "provider_unavailable", tenant_id="7", tokens_in=counts[0], tokens_out=counts[1])
    with engine.connect() as conn:
        assert tuple(conn.execute(text("SELECT tokens_in, tokens_out FROM gateway_requests")).one()) == expected
        summary = service._gateway_summary(conn, "7")
        assert (summary["tokens_in"], summary["tokens_out"]) == expected
        assert summary["tokens_total"] == (sum(expected) if None not in expected else None)
    assert (mirrored[0]["tokens_in"], mirrored[0]["tokens_out"]) == expected
    assert mirrored[0]["duration_ms"] is None


def test_partial_unknown_and_legacy_never_become_complete_totals(telemetry):
    engine, audit, service, _, _ = telemetry
    with engine.connect() as conn:
        assert service._gateway_summary(conn, "7")["tokens_total"] == 0
    audit.record_gateway_request("LOW", True, "allowed", tenant_id="7", tokens_in=2, tokens_out=3)
    audit.record_gateway_request("LOW", True, "allowed", tenant_id="8")
    with engine.connect() as conn:
        assert service._gateway_summary(conn, "7")["tokens_total"] == 5
        assert service._gateway_summary(conn, "8")["tokens_total"] is None
    with engine.begin() as conn:
        conn.execute(text("INSERT INTO gateway_requests (tenant_id, provider, tokens_in, tokens_out) VALUES ('7', 'OpenAI', 105, 500)"))
        assert service._gateway_summary(conn, "7")["tokens_total"] is None
        assert service._provider_usage(conn, "7")[0]["tokens_total"] is None


def test_registrar_passes_measured_usage(telemetry):
    engine, audit, _, _, dependencies = telemetry
    registrar = load_module("token_registrar", "services/registrar_service.py", dependencies).RegistrarService()
    with patch.object(audit, "log_agent_event"):
        # The module imports the function directly, so replace its logging seam.
        registrar.register_gateway_request.__globals__["log_agent_event"] = lambda **_: None
        registrar.register_gateway_request(request_id="test", session_id="test", tenant_id=7,
            risk_level="LOW", allowed=True, status="allowed", route_id=None, provider="OpenAI",
            model="model", duration_ms=5, decision="ALLOW", tokens_in=0, tokens_out=4)
    with engine.connect() as conn:
        assert tuple(conn.execute(text("SELECT tokens_in, tokens_out FROM gateway_requests")).one()) == (0, 4)


@pytest.mark.parametrize("latency", [None, 0, 12, -1, True])
def test_latency_requires_recorded_measurement(telemetry, latency):
    engine, audit, service, mirrored, _ = telemetry
    expected = latency if type(latency) is int and latency >= 0 else None
    audit.record_gateway_request("LOW", True, "allowed", tenant_id="7", latency=latency)
    with engine.begin() as conn:
        assert service._gateway_summary(conn, "7")["avg_duration_ms"] == expected
        assert service._provider_usage(conn, "7")[0]["avg_duration_ms"] == expected
        conn.execute(text("INSERT INTO gateway_requests(tenant_id,provider,latency) VALUES ('7','OpenAI',0)"))
        assert service._gateway_summary(conn, "7")["avg_duration_ms"] is None
        assert service._provider_usage(conn, "7")[0]["avg_duration_ms"] is None
    assert mirrored[0]["duration_ms"] == expected


def assert_postgres_token_provenance(engine):
    """Run under the restricted runtime role; rollback isolated tenant test data."""
    from services.observability_service import ObservabilityService
    from services.tenant_context import tenant_context
    service = ObservabilityService()
    with tenant_context(7, request_id="token-provenance", required=True), engine.connect() as conn:
        conn.execute(text("DELETE FROM gateway_requests WHERE tenant_id = '7'"))
        assert service._gateway_summary(conn, "7")["tokens_total"] == 0
        conn.execute(text("""INSERT INTO gateway_requests (timestamp,tenant_id,provider,tokens_in,tokens_out,token_usage_recorded)
            VALUES (CURRENT_TIMESTAMP,'7','test',0,0,TRUE)"""))
        assert service._gateway_summary(conn, "7")["tokens_total"] == 0
        conn.execute(text("""INSERT INTO gateway_requests (timestamp,tenant_id,provider,tokens_in,tokens_out,token_usage_recorded)
            VALUES (CURRENT_TIMESTAMP,'7','test',2,3,TRUE)"""))
        assert service._gateway_summary(conn, "7")["tokens_total"] == 5
        for recorded, token_in, token_out in ((True, None, 1), (False, 105, 500)):
            with conn.begin_nested() as savepoint:
                conn.execute(text("""INSERT INTO gateway_requests (timestamp,tenant_id,provider,tokens_in,tokens_out,token_usage_recorded)
                    VALUES (CURRENT_TIMESTAMP,'7','test',:i,:o,:recorded)"""), {"i": token_in, "o": token_out, "recorded": recorded})
                assert service._gateway_summary(conn, "7")["tokens_total"] is None
                assert service._provider_usage(conn, "7")[0]["tokens_total"] is None
                savepoint.rollback()
        conn.execute(text("DELETE FROM gateway_requests WHERE tenant_id = '7'"))
        assert service._gateway_summary(conn, "7")["avg_duration_ms"] is None
        conn.execute(text("INSERT INTO gateway_requests(timestamp,tenant_id,provider,latency,latency_recorded) VALUES (CURRENT_TIMESTAMP,'7','test',0,TRUE)"))
        assert service._gateway_summary(conn, "7")["avg_duration_ms"] == 0
        conn.execute(text("INSERT INTO gateway_requests(timestamp,tenant_id,provider,latency) VALUES (CURRENT_TIMESTAMP,'7','test',0)"))
        assert service._gateway_summary(conn, "7")["avg_duration_ms"] is None
        assert service._provider_usage(conn, "7")[0]["avg_duration_ms"] is None
        conn.rollback()


@pytest.mark.parametrize("approval", [False, True])
@pytest.mark.parametrize("failure", [False, True])
def test_gateway_usage_flows_through_real_registrar(telemetry, approval, failure):
    engine, _, _, _, dependencies = telemetry
    registrar = load_module("token_gateway_registrar", "services/registrar_service.py", dependencies)
    registrar.log_agent_event = lambda **_: None
    dependencies.update({
        "services.registrar_service": registrar,
        "memory": SimpleNamespace(add_message=lambda *_: None),
        "services.canonical_agent_service": SimpleNamespace(build_agent_execution_context=lambda **values: values),
    })
    gateway = load_module("token_gateway", "services/gateway_service.py", dependencies)
    graph = Mock()
    graph.invoke.return_value = {"allowed": True, "tokens_in": 0, "tokens_out": 9}
    if failure:
        graph.invoke.side_effect = ConnectionError("provider unreachable")
    service = gateway.GatewayService(graph, lambda *_: 7, lambda *_: {})
    with patch.object(service, "get_trace", return_value=[]), patch.object(service, "persist_latest_message_trace"), patch.object(gateway, "log_agent_event"):
        kwargs = {"authorization": None, "x_api_key": None}
        if approval:
            invoke = lambda: service.execute_approval(
                approval_record={"tenant_id": 7, "query": "test", "approval_id": "a"},
                idempotency_key="token-truthfulness-approval",
                **kwargs,
            )
        else:
            invoke = lambda: service.execute_chat(message="test", session_id="test", **kwargs)
        if failure:
            with pytest.raises(gateway.GatewayProviderUnavailableError):
                invoke()
        else:
            invoke()
    with engine.connect() as conn:
        assert tuple(conn.execute(text("SELECT tokens_in, tokens_out FROM gateway_requests")).one()) == ((None, None) if failure else (0, 9))
