from datetime import datetime, timedelta, timezone
import os
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, text

from app.api.v1.endpoints import audit


def test_metrics_source_failure_is_unavailable():
    class Unavailable:
        def execute(self, *_args, **_kwargs):
            raise RuntimeError("synthetic outage")

    with pytest.raises(HTTPException) as failure:
        audit.get_audit_metrics(SimpleNamespace(state=SimpleNamespace(tenant_id=uuid4())), db=Unavailable(), hours=24)
    assert failure.value.status_code == 503
    assert "synthetic" not in failure.value.detail


@pytest.mark.skipif(not os.getenv("ENT019_TEST_DATABASE_URL"), reason="isolated PostgreSQL URL required")
def test_metrics_cover_full_window_and_only_tenant_gateway_requests(monkeypatch):
    engine = create_engine(os.environ["ENT019_TEST_DATABASE_URL"])
    tenant, other = str(uuid4()), str(uuid4())
    now = datetime.now(timezone.utc)
    try:
        with engine.connect() as conn, conn.begin():
            # Isolated temporary table; no persistent application table is modified.
            conn.execute(text("""CREATE TEMP TABLE audit_log_metadata (
                tenant_id uuid, actor_type text, request_id text, idempotency_key text,
                action text, duration_ms integer, created_at timestamptz
            ) ON COMMIT DROP"""))
            records = [{"tenant": tenant, "actor": "gateway", "request": f"request-{i}",
                        "key": f"gateway:request-{i}:provider_outcome", "action": "allow", "duration": i,
                        "created": now - timedelta(minutes=1)} for i in range(201)]
            records += [dict(record, key=f"gateway:{record['request']}:provider_attempt", action="provider_attempt", duration=0)
                        for record in records[:]]
            records += [dict(records[0], key="gateway:request-0:decision:redact", action="redact", duration=1),
                        dict(records[0], key="gateway:request-0:decision:redact-again", action="redact", duration=1),
                        dict(records[0], tenant=other, request="other", duration=99999),
                        dict(records[0], actor="backend", request="admin", duration=99999),
                        dict(records[0], request="old", created=now-timedelta(days=2), duration=99999),
                        dict(records[0], request="future", created=now+timedelta(days=1), duration=99999)]
            conn.execute(text("""INSERT INTO audit_log_metadata VALUES
                (:tenant, :actor, :request, :key, :action, :duration, :created)"""), records)
            monkeypatch.setenv("CLICKHOUSE_HOST", "configured-mirror")
            monkeypatch.setattr(audit, "_get_clickhouse_client", lambda: pytest.fail("Canonical metrics must not depend on a truncated mirror page"))
            request = SimpleNamespace(state=SimpleNamespace(tenant_id=tenant))
            result = audit.get_audit_metrics(request, db=conn, hours=24)
            assert result["source"] == "postgres"
            assert result["complete"] is True
            assert result["totalRequests"] == 201
            assert result["redactions24h"] == 1
            assert result["p99LatencyMs"] == 198
            assert result["requestsPerSec"] == pytest.approx(201 / 86400)
            conn.execute(text("DELETE FROM audit_log_metadata WHERE tenant_id = :tenant"), {"tenant": tenant})
            result = audit.get_audit_metrics(request, db=conn, hours=24)
            assert result["totalRequests"] == result["requestsPerSec"] == result["redactions24h"] == 0
            assert result["p99LatencyMs"] is None
            conn.execute(text("""INSERT INTO audit_log_metadata VALUES
                (:tenant, 'gateway', 'measured-zero', 'gateway:measured-zero:provider_outcome', 'allow', 0, :created),
                (:tenant, 'gateway', 'decision-only', 'gateway:decision-only:decision:block', 'block', 99999, :created)
            """), {"tenant": tenant, "created": now})
            result = audit.get_audit_metrics(request, db=conn, hours=24)
            assert result["totalRequests"] == 2
            assert result["p99LatencyMs"] == 0
            conn.execute(text("""INSERT INTO audit_log_metadata VALUES
                (:tenant, 'gateway', NULL, 'legacy', 'allow', 0, :created)
            """), {"tenant": tenant, "created": now})
            result = audit.get_audit_metrics(request, db=conn, hours=24)
            assert result["complete"] is False
            assert result["totalRequests"] is result["redactions24h"] is result["requestsPerSec"] is None
    finally:
        engine.dispose()
