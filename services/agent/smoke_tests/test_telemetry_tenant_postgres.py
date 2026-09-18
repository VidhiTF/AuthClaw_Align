"""Real agent middleware, scoring, worker and restricted-role RLS regression.

Runs in a subprocess and a new disposable database, never the application DB.
ENT019_TEST_DATABASE_URL must point to a loopback PostgreSQL test database.
"""
import json
import io
import os
import socket
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from threading import Event, Thread
from datetime import datetime, timezone
from unittest.mock import patch

from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError

ROOT = Path(__file__).resolve().parents[3]
AGENT = ROOT / "services/agent"


class TenantTelemetryPostgresTests(unittest.TestCase):
    @unittest.skipUnless(os.getenv("ENT019_TEST_DATABASE_URL"), "requires isolated PostgreSQL")
    def test_real_agent_tenant_boundary(self):
        result = subprocess.run(
            [sys.executable, str(Path(__file__).resolve()), "--integration"],
            capture_output=True, text=True, timeout=120,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("tenant telemetry integration passed", result.stdout)


def run_integration():
    base = make_url(os.environ["ENT019_TEST_DATABASE_URL"]).set(drivername="postgresql+psycopg2")
    assert base.host in {"localhost", "127.0.0.1"} and base.database.endswith("_test")
    name = "ent019_" + uuid.uuid4().hex + "_test"
    admin = create_engine(base, isolation_level="AUTOCOMMIT")
    with admin.connect() as conn:
        conn.execute(text(f'CREATE DATABASE "{name}"'))
    owner_url = base.set(database=name)
    runtime_url = owner_url.set(username="ent019_runtime", password="ent019-test-only")
    os.environ.update(
        DATABASE_URL=runtime_url.render_as_string(hide_password=False),
        MIGRATION_DATABASE_URL=owner_url.render_as_string(hide_password=False),
        AUTHCLAW_RUNTIME_DB_ROLE="ent019_runtime", AUTHCLAW_ENV="isolated-test",
        AUTHCLAW_SECRET_BACKEND="local_env", AWS_SECRETS_MANAGER_ENABLED="false",
        JWT_SECRET="ent019-test-only-signing-secret-32bytes",
        AGENT_RLS_CONTEXT_SECRET="ent019-test-only-context-secret-32bytes",
        AUTHCLAW_DATABASE_SCHEMA="agent", AUTHCLAW_ENABLE_RBAC_ENFORCEMENT="true",
        AUTHCLAW_RATE_LIMIT_ENABLED="true", AUTHCLAW_ALLOW_MEMORY_RATE_LIMIT="true",
        AUTHCLAW_RATE_LIMIT_PER_MINUTE="1000", AUTHCLAW_RATE_LIMIT_USER_RPM="1000",
        AUTHCLAW_RATE_LIMIT_KEY_RPM="1000", AUTHCLAW_RATE_LIMIT_EXPENSIVE_MODEL_RPM="1000",
        REDIS_URL="", SMTP_HOST="", SKIP_EMAIL_DELIVERY_FOR_TESTING="true",
        AUTHCLAW_CLICKHOUSE_ENABLED="false",
    )
    sys.path.insert(0, str(AGENT))
    sys.path.insert(0, str(ROOT / "backend/scripts"))
    owner = create_engine(owner_url)
    try:
        from bootstrap_database_security import Role, ensure_agent_auth_definer_role, secure_agent_authentication_boundary
        from database import engine, validate_database_security
        from database.migrations import run_startup_migrations
        with owner.begin() as conn:
            conn.execute(text("CREATE SCHEMA agent; CREATE EXTENSION pgcrypto"))
            if not conn.execute(text("SELECT 1 FROM pg_roles WHERE rolname='ent019_runtime'")).scalar():
                conn.execute(text("CREATE ROLE ent019_runtime LOGIN PASSWORD 'ent019-test-only' NOSUPERUSER NOBYPASSRLS"))
            ensure_agent_auth_definer_role(conn)
            # Characterize upgrade from legacy tables with unattributed rows.
            conn.execute(text("""
                CREATE TABLE agent.compliance_score_history
                    (id SERIAL PRIMARY KEY, timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                     framework VARCHAR(50) NOT NULL, score INTEGER NOT NULL, details TEXT);
                INSERT INTO agent.compliance_score_history(framework,score) VALUES ('SOC2',99);
                CREATE TABLE agent.compliance_drift_alerts
                    (id SERIAL PRIMARY KEY, timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                     framework VARCHAR(50) NOT NULL, score_drop INTEGER NOT NULL,
                     previous_score INTEGER NOT NULL, current_score INTEGER NOT NULL, details TEXT NOT NULL);
                INSERT INTO agent.compliance_drift_alerts(framework,score_drop,previous_score,current_score,details)
                    VALUES ('SOC2',20,99,79,'unattributed legacy alert');
            """))
        run_startup_migrations()
        run_startup_migrations()  # Idempotent migration with retained history.
        with owner.begin() as conn:
            conn.execute(text("GRANT USAGE ON SCHEMA agent TO ent019_runtime"))
            conn.execute(text("GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA agent TO ent019_runtime"))
            conn.execute(text("GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA agent TO ent019_runtime"))
            secure_agent_authentication_boundary(conn, Role(base.username, "", "agent"), Role("ent019_runtime", "", "agent"))
            conn.execute(text("INSERT INTO agent.tenants(id,name,status,subscription_tier,plan,tier) VALUES (7,'Tenant A','active','professional','professional','professional'),(8,'Tenant B','active','professional','professional','professional')"))
        validate_database_security()
        from services.tenant_context import tenant_context
        from document_processing import drift, reports, monitoring, alerts
        from services.compliance_evidence_engine import CONTROL_CATALOG
        from services import observability_service
        import verify_audit
        import main
        from fastapi import HTTPException
        from fastapi.testclient import TestClient
        from pypdf import PdfReader

        with engine.connect() as conn:
            assert tuple(conn.execute(text("SELECT rolsuper,rolbypassrls FROM pg_roles WHERE rolname=current_user")).one()) == (False, False)
            conn.execute(text("SET LOCAL app.tenant_id='7'; SET LOCAL app.current_tenant_id='7'"))
            assert conn.execute(text("SELECT count(*) FROM compliance_score_history")).scalar() == 0
        for tenant in (7, 8):
            with tenant_context(tenant, request_id="integration-seed", required=True), engine.begin() as conn:
                conn.execute(text("INSERT INTO documents(id,tenant_id,filename,source,size_bytes,status) VALUES (:id,:id,:name,'s3',1,'scanned')"), {"id": tenant, "name": f"private-{tenant}.txt"})
                if tenant == 7:
                    for control in CONTROL_CATALOG:
                        conn.execute(text("INSERT INTO compliance_evidence(tenant_id,name,category,framework,control_id,collected_at,file_path,hash) VALUES (:tenant,:name,:fw,:fw,:control,:at,'/evidence/tenant-7/test',:control)"),
                                     {"tenant": tenant, "name": control["title"], "fw": control["framework"], "control": control["control_id"], "at": "2026-09-18T00:00:00Z"})
                else:
                    conn.execute(text("INSERT INTO document_findings(tenant_id,document_id,finding_type,matched_pattern,matched_text,risk_level,recommendation) VALUES (8,8,'Regulatory','SOC2 GDPR HIPAA','private-8','CRITICAL','fix')"))

        # Independent database boundary: omit application WHERE predicates on purpose.
        for tenant in (7, 8):
            with tenant_context(tenant, request_id="rls-negative", required=True):
                for table in ("compliance_score_history", "compliance_drift_alerts"):
                    with engine.begin() as conn:
                        assert conn.execute(text(f"SELECT count(*) FROM {table}")).scalar() == 0
                        assert conn.execute(text(f"UPDATE {table} SET tenant_id=:id"), {"id": tenant}).rowcount == 0
                        assert conn.execute(text(f"DELETE FROM {table}")).rowcount == 0
                    for other in (None, 15 - tenant):
                        try:
                            with engine.begin() as conn:
                                conn.execute(text(f"INSERT INTO {table}(tenant_id,framework,details) VALUES (:id,'SOC2','denied')"), {"id": other})
                        except DBAPIError as exc:
                            assert exc.orig.pgcode == "42501", str(exc)
                        else:
                            raise AssertionError("RLS accepted unbound/cross-tenant insert")
        with tempfile.TemporaryDirectory(prefix="ent019-telemetry-") as temporary:
            with patch.object(alerts, "ALERTS_LOG", str(Path(temporary) / "alerts.log")):
                # Real scoring, real snapshot SQL, real chained audit; alternate tenants.
                for tenant in (7, 8, 7):
                    with tenant_context(tenant, request_id="snapshot-worker", required=True):
                        drift.record_compliance_snapshot(tenant)
                with tenant_context(7, request_id="tenant-a", required=True), engine.begin() as conn:
                    assert conn.execute(text("SELECT count(*) FROM compliance_drift_alerts")).scalar() == 0
                    assert set(conn.execute(text("SELECT score FROM compliance_score_history")).scalars()) == {100}
                    conn.execute(text("INSERT INTO document_findings(tenant_id,document_id,finding_type,matched_pattern,matched_text,risk_level,recommendation) VALUES (7,7,'Regulatory','SOC2 GDPR HIPAA','private-7','CRITICAL','fix')"))
                with tenant_context(7, request_id="drop-worker", required=True):
                    drift.record_compliance_snapshot(7)
                    with engine.connect() as conn:
                        rows = conn.execute(text("SELECT tenant_id,previous_score,current_score FROM compliance_drift_alerts")).all()
                        assert len(rows) == 3 and all(row[0] == 7 and row[1] == 100 and row[2] < 100 for row in rows)
                # Missing/mismatched application context must fail before any source access.
                for bound in (None, 8):
                    with tenant_context(bound, request_id="wrong-tenant", required=True):
                        for call in (lambda: drift.record_compliance_snapshot(7), lambda: drift.get_current_framework_scores(7),
                                     lambda: reports.generate_executive_summary_report("json", 7),
                                     lambda: reports.generate_technical_findings_report("json", 7),
                                     lambda: reports.generate_auditor_evidence_report("json", 7)):
                            try:
                                call()
                            except HTTPException as exc:
                                assert exc.status_code == 403
                            else:
                                raise AssertionError("missing/mismatched context was accepted")

                client = TestClient(main.app)  # No lifespan: do not start provider/cloud workers.
                assert client.get("/reports/executive/json").status_code == 401
                tokens = {tenant: {"Authorization": "Bearer " + main.create_jwt({"tenant_id": tenant, "sub": f"auditor-{tenant}", "role": "owner", "exp": int(time.time()) + 300})} for tenant in (7, 8)}
                for endpoint in ("/metrics", "/analytics/governance"):
                    response = client.get(endpoint, headers=tokens[7])
                    assert response.status_code == 200, response.text
                    assert response.json()["status"] == "unknown", response.text
                healthy_queue = {"streams": {}, "checkpoints": [{"stream": "audit", "lag_seconds": 0,
                    "pending_events": 0, "dead_letter_count": 0, "updated_at": datetime.now(timezone.utc).isoformat()}]}
                for valid, queue, expected in ((None, healthy_queue, "unknown"), (True, {}, "unknown"),
                                               (True, healthy_queue, "healthy"), (False, {}, "degraded")):
                    with patch.object(verify_audit, "verify_audit_chain", return_value={"valid": valid}), patch.object(observability_service, "verify_audit_chain", return_value={"valid": valid}), patch.object(observability_service.EventPipeline, "delivery_metrics", return_value=queue):
                        for endpoint in ("/metrics", "/analytics/governance"):
                            response = client.get(endpoint, headers=tokens[7])
                            assert response.status_code == 200 and response.json()["status"] == expected, response.text
                verify_clickhouse_outages(client, tokens, engine, tenant_context)
                for tenant in (7, 8):
                    for kind in ("executive", "technical", "auditor"):
                        for fmt in ("json", "csv", "pdf"):
                            response = client.get(f"/reports/{kind}/{fmt}", headers=tokens[tenant])
                            assert response.status_code == 200, response.text
                            assert response.headers["x-tenant-id"] == str(tenant)
                            assert f"private-{15-tenant}" not in response.text
                            if fmt == "pdf":
                                assert response.content.startswith(b"%PDF")
                                rendered_text = "\n".join(page.extract_text() for page in PdfReader(io.BytesIO(response.content)).pages)
                                assert f"private-{15-tenant}" not in rendered_text
                                if kind == "technical":
                                    assert f"private-{tenant}" in rendered_text
                            if kind == "executive" and fmt == "json":
                                assert response.json()["total_documents"] == 1
                            if kind == "auditor" and fmt == "json":
                                assert all(f"auditor-{15-tenant}" not in str(row) for row in response.json()["audit_logs"])
                # Global sequence gaps caused by B's records are not corruption of A.
                previous = {7: verify_audit.GENESIS_HASH, 8: verify_audit.GENESIS_HASH}
                for tenant in (7, 8, 7):
                    with tenant_context(tenant, request_id="chain-fixture", required=True), engine.begin() as conn:
                        row = conn.execute(text("INSERT INTO audit_logs(tenant_id,user_query,response,allowed,created_at,risk_level,approval_status) VALUES (:tenant,'fixture','ok',true,NOW(),'LOW','N/A') RETURNING id AS record_id,user_query,response,allowed,created_at,risk_level,approval_status"), {"tenant": tenant}).mappings().one()
                        digest = verify_audit.calculate_record_hash(row, previous[tenant])
                        conn.execute(text("UPDATE audit_logs SET integrity_hash=:digest,previous_hash=:previous WHERE id=:id"), {"digest": digest, "previous": previous[tenant], "id": row["record_id"]})
                        previous[tenant] = digest
                with tenant_context(7, request_id="verify-chain", required=True):
                    assert json.loads(reports.generate_auditor_evidence_report("json", 7))["chain_verification"] == "VALID"
                response = client.get("/metrics", headers=tokens[7])
                assert response.json()["audit_chain_status"]["valid"] is True, response.text
                response = client.get("/analytics/governance", headers=tokens[7])
                assert response.json()["audit"]["valid"] is True, response.text
                # Database denies moving/deleting/reading B's real snapshot under A.
                with tenant_context(7, request_id="rls-existing", required=True), engine.begin() as conn:
                    assert conn.execute(text("SELECT count(*) FROM compliance_score_history WHERE tenant_id=8")).scalar() == 0
                    assert conn.execute(text("UPDATE compliance_score_history SET score=0 WHERE tenant_id=8")).rowcount == 0
                    assert conn.execute(text("DELETE FROM compliance_score_history WHERE tenant_id=8")).rowcount == 0
                with tenant_context(8, request_id="rls-alerts", required=True), engine.begin() as conn:
                    assert conn.execute(text("SELECT count(*) FROM compliance_drift_alerts WHERE tenant_id=7")).scalar() == 0
                    assert conn.execute(text("UPDATE compliance_drift_alerts SET details='tampered' WHERE tenant_id=7")).rowcount == 0
                    assert conn.execute(text("DELETE FROM compliance_drift_alerts WHERE tenant_id=7")).rowcount == 0
                # Execute the real background cloud-deletion path and its snapshot caller.
                with tenant_context(8, request_id="monitor-worker", required=True), patch.object(monitoring, "WATCH_DIR", str(Path(temporary) / "watch")), patch.object(monitoring, "list_cloud_source_files", return_value=[]), patch.object(monitoring, "is_real_connectors_enabled", return_value=False):
                    monitoring.sync_sources()
                    with engine.connect() as conn:
                        assert conn.execute(text("SELECT status FROM documents WHERE id=8")).scalar() == "s3_deleted"
                        assert conn.execute(text("SELECT count(*) FROM compliance_score_history")).scalar() == 6
                with owner.connect() as conn:
                    assert conn.execute(text("SELECT count(*) FROM agent.compliance_score_history WHERE tenant_id IS NULL")).scalar() == 1
                    assert conn.execute(text("SELECT count(*) FROM agent.compliance_drift_alerts WHERE tenant_id IS NULL")).scalar() == 1
        verify_atomic_scoring(engine, drift, tenant_context)
        print("tenant telemetry integration passed: middleware, reports, worker, migration, restricted-role RLS, concurrent scoring and rollback")
    finally:
        if "database" in sys.modules:
            sys.modules["database"].engine.dispose()
            sys.modules["database"].migration_engine.dispose()
        owner.dispose()
        with admin.connect() as conn:
            conn.execute(text(f'DROP DATABASE "{name}" WITH (FORCE)'))
        admin.dispose()


def verify_clickhouse_outages(client, tokens, engine, tenant_context):
    for tenant in (7, 8):
        with tenant_context(tenant, request_id="gateway-fixture", required=True), engine.begin() as conn:
            for number in range(tenant - 6):
                conn.execute(text("INSERT INTO gateway_requests(tenant_id,request_id,timestamp,allowed,duration_ms) VALUES (:tenant,:request,NOW(),true,17)"),
                             {"tenant": str(tenant), "request": f"clickhouse-{tenant}-{number}"})

    def check_fallback():
        for tenant in (7, 8):
            response = client.get("/analytics/governance", headers=tokens[tenant])
            assert response.status_code == 200, response.text
            payload = response.json()
            assert payload["status"] == payload["clickhouse_pipeline"]["status"] == "unavailable", payload
            assert payload["clickhouse_pipeline"]["enabled"] is True
            assert payload["gateway"]["source"] == "postgresql"
            assert payload["gateway"]["total_requests"] == tenant - 6
            assert payload["gateway"]["avg_duration_ms"] == 17
            assert "private-source-error" not in response.text

    # A bound, non-listening socket reserves a closed port without a port-reuse race.
    with socket.socket() as unavailable:
        unavailable.bind(("127.0.0.1", 0))
        with patch.dict(os.environ, AUTHCLAW_CLICKHOUSE_ENABLED="true", CLICKHOUSE_HTTP_URL=f"http://127.0.0.1:{unavailable.getsockname()[1]}"):
            check_fallback()

    class ClickHouseStub(BaseHTTPRequestHandler):
        mode = "probe_failure"
        queries = []

        def do_GET(self):
            health = "SELECT%201%20AS%20ok" in self.path
            self.queries.append("probe" if health else "aggregate")
            status, body = 200, {"ok": 1}
            if self.mode == "probe_failure" or (not health and self.mode == "query_failure"):
                status, body = 503, {"error": "private-source-error"}
            elif not health:
                body = {} if self.mode == "malformed" else dict(total_requests=0, allowed_requests=0,
                    blocked_requests=0, pending_requests=0, tokens_in=0, tokens_out=0, avg_duration_ms=None)
            self.send_response(status)
            self.end_headers()
            self.wfile.write(json.dumps(body).encode())

        def log_message(self, *args):
            pass

    with ThreadingHTTPServer(("127.0.0.1", 0), ClickHouseStub) as server:
        worker = Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            with patch.dict(os.environ, AUTHCLAW_CLICKHOUSE_ENABLED="true", CLICKHOUSE_HTTP_URL=f"http://127.0.0.1:{server.server_port}"):
                for mode in ("probe_failure", "query_failure", "malformed"):
                    ClickHouseStub.mode, ClickHouseStub.queries = mode, []
                    check_fallback()
                    assert ClickHouseStub.queries == (["probe"] if mode == "probe_failure" else ["probe", "aggregate"]) * 2
                ClickHouseStub.mode = "healthy"
                response = client.get("/analytics/governance", headers=tokens[7])
                assert response.status_code == 200, response.text
                payload = response.json()
                assert payload["clickhouse_pipeline"]["status"] == "healthy"
                assert payload["gateway"]["source"] == "clickhouse" and payload["gateway"]["total_requests"] == 0
                assert payload["gateway"]["avg_duration_ms"] is None
                ClickHouseStub.mode, ClickHouseStub.queries = "probe_failure", []
                failed_summary = Event()

                def fail_summary(conn, cursor, statement, parameters, context, executemany):
                    if "COUNT(*) AS total_requests" in statement and "FROM gateway_requests" in statement:
                        failed_summary.set()
                        cursor.execute("SELECT 1/0")

                event.listen(engine, "before_cursor_execute", fail_summary)
                try:
                    response = client.get("/analytics/governance", headers=tokens[7])
                    assert response.status_code == 503 and "division by zero" not in response.text
                    assert failed_summary.is_set() and ClickHouseStub.queries == ["probe"]
                finally:
                    event.remove(engine, "before_cursor_execute", fail_summary)
                with patch.dict(os.environ, AUTHCLAW_CLICKHOUSE_ENABLED="false"):
                    response = client.get("/analytics/governance", headers=tokens[7])
                    assert response.status_code == 200, response.text
                    assert response.json()["clickhouse_pipeline"]["status"] == "not_applicable"
                    assert response.json()["gateway"]["source"] == "postgresql"
                    assert ClickHouseStub.queries == ["probe"]
        finally:
            server.shutdown()
            worker.join(timeout=5)


def verify_atomic_scoring(engine, drift, tenant_context):
    from services.compliance_evidence_engine import ComplianceEvidenceEngine

    service = ComplianceEvidenceEngine()
    deleted, competing, release = Event(), Event(), Event()

    def pause_delete(conn, cursor, statement, parameters, context, executemany):
        if statement.startswith("DELETE FROM compliance_control_evidence") and not deleted.is_set():
            deleted.set()
            assert release.wait(10), "concurrent refresh did not start"

    def observe_lock(conn, cursor, statement, parameters, context, executemany):
        if "pg_advisory_xact_lock" in statement and deleted.is_set():
            competing.set()

    def refresh():
        with tenant_context(7, request_id="concurrent-refresh", required=True):
            return service.calculate_scores(7)

    event.listen(engine, "after_cursor_execute", pause_delete)
    event.listen(engine, "before_cursor_execute", observe_lock)
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(refresh)
            try:
                assert deleted.wait(10)
                second = pool.submit(refresh)
                assert competing.wait(10)
                assert not second.done(), "competing refresh bypassed tenant lock"
            finally:
                release.set()
            left, right = first.result(15), second.result(15)
            assert left["soc2"] == right["soc2"]
    finally:
        event.remove(engine, "after_cursor_execute", pause_delete)
        event.remove(engine, "before_cursor_execute", observe_lock)

    with tenant_context(7, request_id="atomic-scoring", required=True):
        with engine.connect() as conn:
            assert conn.execute(text("SELECT count(*) FROM (SELECT framework,control_id,source_type,source_id FROM compliance_control_evidence GROUP BY 1,2,3,4 HAVING count(*)>1) duplicates")).scalar() == 0
            before = conn.execute(text("SELECT row_to_json(s)::text FROM compliance_control_scores s ORDER BY framework,control_id")).scalars().all()
            history = conn.execute(text("SELECT count(*) FROM compliance_score_changes")).scalar()
        persist = service._persist_control_score
        calls = 0

        def fail_midway(*args, **kwargs):
            nonlocal calls
            calls += 1
            persist(*args, **kwargs)
            if calls == 2:
                raise RuntimeError("injected mid-score outage")

        with patch.object(service, "_persist_control_score", side_effect=fail_midway):
            try:
                service.calculate_scores(7)
            except RuntimeError:
                pass
            else:
                raise AssertionError("injected score failure was swallowed")
        with engine.connect() as conn:
            assert conn.execute(text("SELECT row_to_json(s)::text FROM compliance_control_scores s ORDER BY framework,control_id")).scalars().all() == before
            assert conn.execute(text("SELECT count(*) FROM compliance_score_changes")).scalar() == history

        def database_outage(tenant, connection):
            connection.execute(text("SELECT 1/0"))

        with patch.object(drift, "get_current_framework_scores", side_effect=database_outage), patch("document_processing.alerts.trigger_security_alert"), patch("document_processing.auditor.create_document_audit"):
            try:
                drift.record_compliance_snapshot(7)
            except DBAPIError:
                pass
            else:
                raise AssertionError("source outage was swallowed")
        with engine.connect() as conn:
            latest = conn.execute(text("SELECT score,details FROM compliance_score_history ORDER BY id DESC LIMIT 3")).all()
            assert len(latest) == 3 and all(score is None and json.loads(details)["status"] == "unavailable" for score, details in latest)
            assert conn.execute(text("SELECT count(*) FROM compliance_drift_alerts WHERE current_score IS NULL")).scalar() == 3


if __name__ == "__main__":
    run_integration() if "--integration" in sys.argv else unittest.main()
