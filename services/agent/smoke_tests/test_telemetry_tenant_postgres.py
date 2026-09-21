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
from urllib.parse import parse_qs, urlparse
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
        AUTHCLAW_CONNECTOR_TENANT_ID="8",
    )
    sys.path.insert(0, str(AGENT))
    sys.path.insert(0, str(ROOT / "backend/scripts"))
    owner = create_engine(owner_url)
    try:
        from bootstrap_database_security import Role, ensure_agent_auth_definer_role, secure_agent_authentication_boundary
        from database import engine, validate_database_security
        from database.migrations import run_startup_migrations
        from smoke_tests.checkpoint_tenant_checks import seed_legacy_checkpoint, assert_tenant_checkpoints, assert_restricted_migration_upgrade
        with owner.begin() as conn:
            conn.execute(text("CREATE SCHEMA agent; CREATE EXTENSION pgcrypto"))
            if not conn.execute(text("SELECT 1 FROM pg_roles WHERE rolname='ent019_runtime'")).scalar():
                conn.execute(text("CREATE ROLE ent019_runtime LOGIN PASSWORD 'ent019-test-only' NOSUPERUSER NOBYPASSRLS"))
            ensure_agent_auth_definer_role(conn)
            seed_legacy_checkpoint(conn)
            conn.execute(text("""
                CREATE TABLE agent.gateway_requests (id SERIAL PRIMARY KEY,
                    timestamp TIMESTAMP, tenant_id VARCHAR(50), latency INTEGER DEFAULT 0);
                INSERT INTO agent.gateway_requests(timestamp,tenant_id) VALUES (NOW(),'7');
            """))
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
        with owner.begin() as conn:
            assert tuple(conn.execute(text("SELECT latency,latency_recorded FROM agent.gateway_requests")).one()) == (0, False)
            assert conn.execute(text("INSERT INTO agent.gateway_requests(timestamp,tenant_id) VALUES (NOW(),'7') RETURNING latency")).scalar() is None
            conn.execute(text("DELETE FROM agent.gateway_requests"))
            conn.execute(text("INSERT INTO agent.tenants(id,name,status,subscription_tier,plan,tier) VALUES (7,'Tenant A','active','professional','professional','professional'),(8,'Tenant B','active','professional','professional','professional'),(9,'Empty tenant','active','professional','professional','professional')"))
            conn.execute(text("""
                INSERT INTO agent.compliance_control_scores
                    (tenant_id,framework,control_id,score,status,evidence_count,reason)
                VALUES (9,'SOC2','legacy-empty-zero',0,'failing',0,'legacy baseline'),
                       (9,'SOC2','legacy-empty-high',100,'passing',0,'legacy baseline'),
                       (9,'SOC2','measured-zero',0,'unassessed',1,'measured zero');
            """))
            measured_before = conn.execute(text("SELECT row_to_json(s)::text FROM agent.compliance_control_scores s WHERE tenant_id=9 AND control_id='measured-zero'")).scalar_one()
        run_startup_migrations()  # Upgrade stored legacy scores, retain genuine zero.
        with owner.begin() as conn:
            legacy = conn.execute(text("SELECT score,status,reason FROM agent.compliance_control_scores WHERE tenant_id=9 AND control_id IN ('legacy-empty-zero','legacy-empty-high')")).all()
            assert len(legacy) == 2
            assert all(score is None and status == "unknown" and "no evidence" in reason.lower() and "unknown" in reason.lower() for score, status, reason in legacy)
            assert conn.execute(text("SELECT row_to_json(s)::text FROM agent.compliance_control_scores s WHERE tenant_id=9 AND control_id='measured-zero'")).scalar_one() == measured_before
            assert tuple(conn.execute(text("SELECT relrowsecurity,relforcerowsecurity FROM pg_class WHERE oid='agent.compliance_control_scores'::regclass")).one()) == (True, True)
            conn.execute(text("DELETE FROM agent.compliance_control_scores WHERE tenant_id=9 AND control_id IN ('legacy-empty-zero','legacy-empty-high','measured-zero')"))
            conn.execute(text("GRANT USAGE ON SCHEMA agent TO ent019_runtime"))
            conn.execute(text("GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA agent TO ent019_runtime"))
            conn.execute(text("GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA agent TO ent019_runtime"))
            secure_agent_authentication_boundary(conn, Role(base.username, "", "agent"), Role("ent019_runtime", "", "agent"))
        validate_database_security()
        assert_restricted_migration_upgrade(owner)
        assert_tenant_checkpoints(owner, engine)
        from smoke_tests.test_token_truthfulness import assert_postgres_token_provenance
        assert_postgres_token_provenance(engine)
        from services.tenant_context import tenant_context
        from document_processing import drift, reports, monitoring, alerts
        from services.compliance_evidence_engine import CONTROL_CATALOG, ComplianceEvidenceEngine
        from services import observability_service
        import verify_audit
        import main
        from fastapi import HTTPException
        from fastapi.testclient import TestClient
        from pypdf import PdfReader

        with tenant_context(9, request_id="empty-diagnostics", required=True):
            scores = ComplianceEvidenceEngine().calculate_scores(9)
            assert all(scores[framework] is None for framework in ("soc2", "gdpr", "hipaa"))
            assert scores["authoritative"] is False and scores["status"] == "unassessed"
            with engine.connect() as conn:
                controls = conn.execute(text("SELECT score,status,evidence_count FROM compliance_control_scores WHERE tenant_id=9")).all()
                assert len(controls) == len(CONTROL_CATALOG)
                assert all(score is None and status == "unknown" and count == 0 for score, status, count in controls)
                assert conn.execute(text("SELECT count(*) FROM compliance_score_changes WHERE current_score IS NOT NULL")).scalar() == 0

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

        from rag import embeddings
        with tenant_context(7, request_id="failed-rag-upload", required=True), \
                patch.object(main, "resolve_tenant", return_value=7), \
                patch.object(embeddings, "generate_embedding", side_effect=RuntimeError("embedding unavailable")):
            with unittest.TestCase().assertRaisesRegex(RuntimeError, "embedding unavailable"):
                main.create_document(main.DocumentUploadRequest(
                    name="failed-index.txt", type="TXT", size_bytes=1))
            with engine.connect() as conn:
                assert conn.execute(text("SELECT count(*) FROM knowledge_documents WHERE name='failed-index.txt'")).scalar() == 0

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

        # Old binaries omit tenant_id: the secure default binds to authenticated
        # context, while original unattributed rows remain quarantined.
        legacy_inserts = (
            "INSERT INTO compliance_score_history(framework,score,details) VALUES ('SOC2',84,'legacy writer') RETURNING tenant_id",
            "INSERT INTO compliance_drift_alerts(framework,score_drop,previous_score,current_score,details) VALUES ('SOC2',10,84,74,'legacy writer') RETURNING tenant_id",
        )
        for tenant in (7, 8):
            with tenant_context(tenant, request_id="rolling-old-writer", required=True), engine.begin() as conn:
                for statement in legacy_inserts:
                    assert conn.execute(text(statement)).scalar_one() == tenant
        for statement in legacy_inserts:
            try:
                with engine.begin() as conn:
                    conn.execute(text(statement))
            except DBAPIError as exc:
                assert exc.orig.pgcode == "42501", str(exc)
            else:
                raise AssertionError("legacy writer inserted without authenticated context")
        with tempfile.TemporaryDirectory(prefix="ent019-telemetry-") as temporary:
            with tenant_context(None, required=True):
                # Diagnostic scoring is tenant-bound and never authoritative;
                # the retired legacy snapshot hook must leave stored history intact.
                for tenant in (7, 8, 7):
                    with tenant_context(tenant, request_id="snapshot-worker", required=True):
                        scores = ComplianceEvidenceEngine().calculate_scores(tenant)
                        assert scores["authoritative"] is False and scores["status"] == "unassessed"
                        assert all(score is None or 0 <= score <= 84 for score in (scores["soc2"], scores["gdpr"], scores["hipaa"]))
                        drift.record_compliance_snapshot(tenant)
                with tenant_context(7, request_id="tenant-a", required=True), engine.begin() as conn:
                    assert conn.execute(text("SELECT count(*) FROM compliance_drift_alerts")).scalar() == 1
                    assert conn.execute(text("SELECT score FROM compliance_score_history")).scalars().all() == [84]
                    conn.execute(text("INSERT INTO document_findings(tenant_id,document_id,finding_type,matched_pattern,matched_text,risk_level,recommendation) VALUES (7,7,'Regulatory','SOC2 GDPR HIPAA','private-7','CRITICAL','fix')"))
                with tenant_context(7, request_id="drop-worker", required=True):
                    with patch("document_processing.auditor.create_document_audit") as audit, patch.object(alerts, "trigger_security_alert") as alert:
                        drift.record_compliance_snapshot(7)
                        audit.assert_not_called()
                        alert.assert_not_called()
                    with engine.connect() as conn:
                        rows = conn.execute(text("SELECT tenant_id,previous_score,current_score FROM compliance_drift_alerts")).all()
                        assert [tuple(row) for row in rows] == [(7, 84, 74)]
                # Missing/mismatched application context must fail before any source access.
                for bound in (None, 8):
                    with tenant_context(bound, request_id="wrong-tenant", required=True):
                        assert drift.record_compliance_snapshot(7) is None
                        assert drift.get_current_framework_scores(7) == {}
                        for call in (lambda: reports.generate_executive_summary_report("json", 7),
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
                for tenant in (7, 8, 7):
                    response = client.get("/trust/public", headers=tokens[tenant])
                    assert response.status_code == 200, response.text
                    assert response.json()["payload"]["tenant_id"] == tenant, response.text
                    assert response.json()["manifest"]["tenant"] == str(tenant)
                    health = client.get("/trust/public/health", headers=tokens[tenant])
                    assert health.json()["checks"]["compliance_evidence"] == "unknown", health.text
                    assert client.get("/metrics", headers=tokens[tenant]).json()["active_tenants"] == 1
                assert client.get("/trust/public").status_code == 401
                with owner.begin() as conn:
                    conn.execute(text("UPDATE agent.tenants SET status='inactive' WHERE id=7"))
                revoked = client.get("/trust/public", headers=tokens[7])
                # Restricted DB tenant binding rejects inactive tenants in quota middleware first.
                assert revoked.status_code == 503 and revoked.json() == {"error": "rate_limit_unavailable"}, revoked.text
                with owner.begin() as conn:
                    conn.execute(text("UPDATE agent.tenants SET status='active' WHERE id=7"))
                assert client.get("/trust/public", headers=tokens[7]).status_code == 200
                for endpoint in ("/metrics", "/analytics/governance"):
                    response = client.get(endpoint, headers=tokens[7])
                    assert response.status_code == 200, response.text
                    assert response.json()["status"] == "unknown", response.text
                healthy_queue = {"streams": {}, "checkpoints": [{"stream": "audit", "lag_seconds": 0,
                    "pending_events": 0, "dead_letter_count": 0, "updated_at": datetime.now(timezone.utc).isoformat()}]}
                for valid, queue, expected in ((None, healthy_queue, "unknown"), (True, {}, "unknown"),
                                               (True, None, "unknown"), (True, {"streams": {}, "checkpoints": [None]}, "unknown"),
                                               (True, healthy_queue, "healthy"), (False, {}, "degraded")):
                    with patch.object(verify_audit, "verify_audit_chain", return_value={"valid": valid}), patch.object(observability_service, "verify_audit_chain", return_value={"valid": valid}), patch.object(observability_service.EventPipeline, "delivery_metrics", return_value=queue):
                        for endpoint in ("/metrics", "/analytics/governance"):
                            response = client.get(endpoint, headers=tokens[7])
                            assert response.status_code == 200 and response.json()["status"] == expected, response.text
                with patch.dict(os.environ, AUTHCLAW_QUEUE_LAG_ALERT_SECONDS="invalid"):
                    response = client.get("/metrics", headers=tokens[7])
                    assert response.status_code == 200 and response.json()["queue_status"] == "unavailable", response.text
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
                                assert response.json()["compliance_score"] is None
                                assert response.json()["compliance_status"] == "unassessed"
                                assert response.json()["compliance_authoritative"] is False
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
                # Execute real cloud deletion; its retired snapshot hook cannot
                # create new aggregate compliance measurements.
                for tenant in (7, 8):
                    with tenant_context(tenant, request_id="bucket-recovery-seed", required=True), engine.begin() as conn:
                        conn.execute(text("INSERT INTO documents(id,tenant_id,filename,source,size_bytes,status) VALUES (:id,:tenant,'s3://one/configuration','s3_config',0,'completed')"), {"id": tenant * 1000, "tenant": tenant})
                        conn.execute(text("INSERT INTO document_findings(tenant_id,document_id,finding_type,matched_pattern,matched_text,risk_level,recommendation) VALUES (:tenant,:id,'Regulatory','prior bucket finding','test','HIGH','fix')"), {"id": tenant * 1000, "tenant": tenant})
                with tenant_context(8, request_id="bucket-recovery", required=True), patch.object(monitoring, "get_watched_directory"), patch.object(monitoring.os, "listdir", return_value=[]), patch.object(monitoring, "is_real_connectors_enabled", return_value=True), patch.object(monitoring, "discover_s3_buckets", return_value=["one"]), patch.object(monitoring, "scan_s3_bucket_security", return_value=[]), patch.object(monitoring, "list_cloud_source_files", side_effect=ConnectionError("inventory unavailable")):
                    try:
                        monitoring.sync_sources()
                    except RuntimeError:
                        pass
                    else:
                        raise AssertionError("Failed inventory was treated as a successful sync")
                for tenant in (7, 8):
                    with tenant_context(tenant, request_id="bucket-recovery-check", required=True), engine.connect() as conn:
                        assert conn.execute(text("SELECT count(*) FROM document_findings WHERE document_id=:id"), {"id": tenant * 1000}).scalar() == (1 if tenant == 7 else 0)
                with tenant_context(8, request_id="sync-lock", required=True), engine.begin() as guard:
                    guard.execute(text("SELECT pg_advisory_xact_lock(hashtextextended('document-sync:8',0))"))
                    with patch.object(monitoring, "_sync_sources") as work:
                        response = client.post("/cloud/connectors/sync", headers=tokens[8])
                        assert response.status_code == 503, response.text
                        work.assert_not_called()
                        assert client.post("/cloud/connectors/sync", headers=tokens[7]).status_code == 403
                        work.assert_not_called()
                with patch.object(monitoring, "_sync_sources") as work:
                    assert client.post("/cloud/connectors/sync", headers=tokens[8]).status_code == 200
                    work.assert_called_once_with("8")
                with tenant_context(8, request_id="monitor-worker", required=True), patch.object(monitoring, "WATCH_DIR", str(Path(temporary) / "watch")), patch.object(monitoring, "list_cloud_source_files", return_value=[]), patch.object(monitoring, "is_real_connectors_enabled", return_value=False):
                    with patch.object(monitoring, "list_cloud_source_files", side_effect=ConnectionError("source unavailable")):
                        response = client.post("/cloud/connectors/sync", headers=tokens[8])
                        assert response.status_code == 503 and response.json()["status"] == "unavailable", response.text
                        with engine.connect() as conn:
                            assert conn.execute(text("SELECT status FROM documents WHERE id=8")).scalar() == "scanned"
                    monitoring.sync_sources()
                    with engine.connect() as conn:
                        assert conn.execute(text("SELECT status FROM documents WHERE id=8")).scalar() == "s3_deleted"
                        assert conn.execute(text("SELECT count(*) FROM compliance_score_history")).scalar() == 1
                with patch("document_processing.connectors.is_real_connectors_enabled", return_value=True), patch("document_processing.connectors.list_cloud_source_files", side_effect=ConnectionError("source unavailable")):
                    response = client.get("/cloud/connectors/status", headers=tokens[7])
                    assert response.status_code == 200, response.text
                    assert all(item["status"] == "unavailable" and item["files_count"] is None and item["files"] is None for item in response.json()["connectors"])
                with owner.connect() as conn:
                    assert conn.execute(text("SELECT count(*) FROM agent.compliance_score_history WHERE tenant_id IS NULL")).scalar() == 1
                    assert conn.execute(text("SELECT count(*) FROM agent.compliance_drift_alerts WHERE tenant_id IS NULL")).scalar() == 1
        verify_alert_outage_and_retry(client, tokens, engine, tenant_context)
        verify_atomic_scoring(engine, tenant_context)
        print("tenant telemetry integration passed: middleware, reports, worker, migration, restricted-role RLS, concurrent scoring and rollback")
    finally:
        if "database" in sys.modules:
            sys.modules["database"].engine.dispose()
            sys.modules["database"].migration_engine.dispose()
        owner.dispose()
        with admin.connect() as conn:
            conn.execute(text(f'DROP DATABASE "{name}" WITH (FORCE)'))
        admin.dispose()


def verify_alert_outage_and_retry(client, tokens, engine, tenant_context):
    from document_processing import orchestrator, alerts
    from services.event_pipeline import EventPipeline
    from services.observability_service import ObservabilityService
    from unittest.mock import MagicMock

    smtp = MagicMock()
    smtp.return_value.__enter__.return_value.send_message.return_value = {}
    with tenant_context(7, request_id="alert-fixture-a", required=True), engine.begin() as conn:
        for email, role, verified in (("verified@tenant-a.test", "Admin", True),
                                      ("unverified@tenant-a.test", "Admin", False),
                                      ("viewer@tenant-a.test", "Viewer", True)):
            conn.execute(text("""INSERT INTO tenant_users(tenant_id,email,password_hash,role,email_verified,status)
                VALUES (7,:email,'test-only',:role,:verified,'active')"""), {"email": email, "role": role, "verified": verified})
    with tenant_context(8, request_id="alert-fixture-b", required=True), engine.begin() as conn:
        conn.execute(text("""INSERT INTO tenant_users(tenant_id,email,password_hash,role,email_verified,status)
            VALUES (8,'private@tenant-b.test','test-only','Admin',TRUE,'active')"""))

    finding = {"finding_type": "Secret", "matched_pattern": "TEST_SECRET", "matched_text": "never-email-this-secret", "risk_level": "CRITICAL"}
    with tenant_context(7, request_id="alert-worker", required=True), patch.dict(os.environ, GOOGLE_API_KEY="", SMTP_HOST="smtp.test.invalid", SKIP_EMAIL_DELIVERY_FOR_TESTING="false"), patch.object(alerts.smtplib, "SMTP", smtp):
        smtp.side_effect = OSError("private-transport-error")
        with patch.object(orchestrator, "extract_document_text", return_value="test"), patch.object(orchestrator, "extract_file_metadata", return_value={}), patch.object(orchestrator, "split_text_into_chunks", return_value=[]), patch.object(orchestrator, "scan_text_for_sensitive_data", return_value=[finding]), patch("rag.vector_store.save_document_chunks"), patch.object(orchestrator, "create_approval"):
            result = orchestrator.run_document_scan_pipeline(7, b"test", "never-email-this-filename", tenant_id=7)
        assert result["status"] == "alert_delivery_failed" and result["alert_delivery"]["status"] == "dead_letter"
        event_id = result["alert_delivery"]["event_id"]
        with engine.connect() as conn:
            assert conn.execute(text("SELECT status FROM documents WHERE id=7")).scalar() == "alert_delivery_failed"
            scan = conn.execute(text("SELECT status,outputs_json FROM document_scans WHERE document_id=7 ORDER BY id DESC LIMIT 1")).one()
            assert scan.status == "alert_delivery_failed" and json.loads(scan.outputs_json)["alert_delivery"]["event_id"] == event_id
            assert json.loads(scan.outputs_json)["health"] == "degraded"
            record = conn.execute(text("SELECT payload,error_message,status FROM event_delivery_records WHERE event_id=:id"), {"id": event_id}).one()
            assert "never-email" not in record.payload and "private-transport" not in record.error_message
        metrics = EventPipeline().delivery_metrics()
        assert metrics["security_alerts"]["status"] == "unavailable"
        assert ObservabilityService()._queue_lag(metrics)["status"] == "degraded"
        assert client.get("/documents/7", headers=tokens[7]).json()["status"] == "alert_delivery_failed"
        assert client.get("/metrics", headers=tokens[7]).json()["event_pipeline"]["security_alerts"]["status"] == "unavailable"
        with tenant_context(8, request_id="alert-other-tenant", required=True):
            assert EventPipeline().deliver_event(event_id)["status"] == "missing"
            assert EventPipeline().retry_dead_letters()["retried"] == 0
        smtp.side_effect = None
        assert EventPipeline().retry_dead_letters()["delivered"] == 1
        message = smtp.return_value.__enter__.return_value.send_message.call_args.args[0]
        assert message["To"] == "verified@tenant-a.test"
        assert "never-email" not in str(message) and "tenant-b" not in str(message)
        sent = smtp.return_value.__enter__.return_value.send_message.call_count
        assert EventPipeline().deliver_event(event_id)["status"] == "delivered"
        assert smtp.return_value.__enter__.return_value.send_message.call_count == sent
        with engine.connect() as conn:
            assert conn.execute(text("SELECT status FROM documents WHERE id=7")).scalar() == "pending_approval"
            assert json.loads(conn.execute(text("SELECT outputs_json FROM document_scans WHERE document_id=7 ORDER BY id DESC LIMIT 1")).scalar())["health"] == "healthy"
            assert conn.execute(text("SELECT resolved_at IS NOT NULL FROM event_dead_letters WHERE event_id=:id"), {"id": event_id}).scalar() is True
        assert EventPipeline().delivery_metrics()["security_alerts"]["status"] == "healthy"
        assert ObservabilityService()._queue_lag(EventPipeline().delivery_metrics())["status"] == "healthy"
        assert client.get("/metrics", headers=tokens[7]).json()["queue_status"] == "healthy"

        # A retry immediately after commit sees the scan, not an unlinked event.
        original_delivery = EventPipeline.deliver_event
        def retry_first(pipeline, identifier, **kwargs):
            with engine.connect() as conn:
                assert conn.execute(text("SELECT count(*) FROM document_scans WHERE outputs_json::jsonb #>> '{alert_delivery,event_id}'=:id"), {"id": identifier}).scalar() == 1
            original_delivery(pipeline, identifier, retry=True)
            return original_delivery(pipeline, identifier, **kwargs)
        with patch.object(orchestrator, "extract_document_text", return_value="test"), patch.object(orchestrator, "extract_file_metadata", return_value={}), patch.object(orchestrator, "split_text_into_chunks", return_value=[]), patch.object(orchestrator, "scan_text_for_sensitive_data", return_value=[finding]), patch("rag.vector_store.save_document_chunks"), patch.object(orchestrator, "create_approval"), patch.object(EventPipeline, "deliver_event", retry_first):
            result = orchestrator.run_document_scan_pipeline(7, b"test", "concurrent-scan", tenant_id=7)
        assert result["status"] == "pending_approval" and result["alert_delivery"]["status"] == "delivered"
        assert smtp.return_value.__enter__.return_value.send_message.call_count == sent + 1

        # A committed outbox survives a dispatcher/finalization crash and revocation.
        with patch.object(EventPipeline, "deliver_event", side_effect=RuntimeError("private-dispatch-error")), patch.object(orchestrator, "extract_document_text", return_value="test"), patch.object(orchestrator, "create_approval"), patch("rag.vector_store.save_document_chunks"):
            response = client.post("/documents/upload", headers=tokens[7], files={"file": ("retryable.txt", b"test", "text/plain")})
        assert response.status_code == 503 and "private-dispatch" not in response.text
        with engine.begin() as conn:
            assert conn.execute(text("SELECT status FROM documents WHERE filename='retryable.txt'")).scalar() == "alert_delivery_pending"
            conn.execute(text("UPDATE tenant_users SET email_verified=FALSE WHERE email='verified@tenant-a.test'"))
        sent = smtp.return_value.__enter__.return_value.send_message.call_count
        assert EventPipeline().retry_dead_letters()["failed"] == 1
        assert smtp.return_value.__enter__.return_value.send_message.call_count == sent
        with engine.begin() as conn:
            conn.execute(text("UPDATE tenant_users SET email_verified=TRUE WHERE email='verified@tenant-a.test'"))
            conn.execute(text("""UPDATE document_scans SET outputs_json=(outputs_json::jsonb - 'provider_review' - 'scan_health')::text
                WHERE document_id=(SELECT id FROM documents WHERE filename='retryable.txt')"""))
        assert EventPipeline().retry_dead_letters()["delivered"] == 1
        with engine.connect() as conn:
            assert conn.execute(text("SELECT status FROM documents WHERE filename='retryable.txt'")).scalar() == "pending_approval"
            assert conn.execute(text("""SELECT outputs_json::jsonb ->> 'health' FROM document_scans
                WHERE document_id=(SELECT id FROM documents WHERE filename='retryable.txt')""")).scalar() == "unknown"
        with engine.connect() as conn:
            assert conn.execute(text("SELECT status FROM document_scans WHERE document_id=7 ORDER BY id DESC LIMIT 1")).scalar() == "pending_approval"

        # Durable insertion failure must never produce an indexed/clean scan.
        with patch.object(EventPipeline, "record_event", side_effect=RuntimeError("private-persistence-error")), patch.object(orchestrator, "extract_document_text", return_value="test"), patch.object(orchestrator, "create_approval"), patch("rag.vector_store.save_document_chunks"):
            response = client.post("/documents/upload", headers=tokens[7], files={"file": ("outage.txt", b"test", "text/plain")})
        assert response.status_code == 503 and "private-persistence" not in response.text, response.text
        with engine.connect() as conn:
            assert conn.execute(text("SELECT status FROM documents WHERE filename='outage.txt'")).scalar() == "scan_failed"
            assert conn.execute(text("SELECT count(*) FROM document_scans JOIN documents ON documents.id=document_scans.document_id WHERE filename='outage.txt'")).scalar() == 0

        # Two independent retry workers serialize at the durable record.
        queued = EventPipeline().record_event({"event_type": "document_security_alert", "event_id": str(uuid.uuid4()), "tenant_id": 7, "document_id": 7}, "security_alert")
        entered, release = Event(), Event()
        def send_once(message):
            entered.set()
            assert release.wait(5)
            return {}
        def deliver():
            with tenant_context(7, request_id="concurrent-alert-worker", required=True):
                return EventPipeline().deliver_event(queued)
        smtp.return_value.__enter__.return_value.send_message.side_effect = send_once
        sent = smtp.return_value.__enter__.return_value.send_message.call_count
        with ThreadPoolExecutor(max_workers=2) as workers:
            first = workers.submit(deliver)
            assert entered.wait(5)
            second = workers.submit(deliver)
            release.set()
            assert first.result()["status"] == second.result()["status"] == "delivered"
        assert smtp.return_value.__enter__.return_value.send_message.call_count == sent + 1


def verify_clickhouse_outages(client, tokens, engine, tenant_context):
    for tenant in (7, 8):
        with tenant_context(tenant, request_id="gateway-fixture", required=True), engine.begin() as conn:
            for number in range(tenant - 6):
                conn.execute(text("INSERT INTO gateway_requests(tenant_id,request_id,timestamp,allowed,duration_ms,latency_recorded) VALUES (:tenant,:request,NOW(),true,17,true)"),
                             {"tenant": str(tenant), "request": f"clickhouse-{tenant}-{number}"})

    def check_fallback(expected="unavailable"):
        for tenant in (7, 8):
            response = client.get("/analytics/governance", headers=tokens[tenant])
            assert response.status_code == 200, response.text
            payload = response.json()
            assert payload["status"] == payload["clickhouse_pipeline"]["status"] == expected, payload
            assert payload["clickhouse_pipeline"]["enabled"] is True
            assert payload["clickhouse_pipeline"]["alertable"] is True
            assert payload["gateway"]["source"] == "postgresql"
            assert payload["gateway"]["coverage"] == "persisted_gateway_events_only"
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
                if self.mode == "caught_up":
                    query = parse_qs(urlparse(self.path).query)["query"][0]
                    count = 1 if "= '7'" in query else 2
                    body.update(total_requests=count, allowed_requests=count, avg_duration_ms=17)
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
                # A responding server can still have a stalled, empty mirror.
                ClickHouseStub.mode = "stalled"
                check_fallback("degraded")
                # Matching aggregates do not prove complete ingestion either.
                ClickHouseStub.mode = "caught_up"
                check_fallback("unknown")
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


def verify_atomic_scoring(engine, tenant_context):
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

        with patch.object(service, "map_evidence", side_effect=database_outage):
            try:
                service.calculate_scores(7)
            except DBAPIError:
                pass
            else:
                raise AssertionError("source outage was swallowed")
        with engine.connect() as conn:
            assert conn.execute(text("SELECT row_to_json(s)::text FROM compliance_control_scores s ORDER BY framework,control_id")).scalars().all() == before
            assert conn.execute(text("SELECT count(*) FROM compliance_score_changes")).scalar() == history
        recovered = service.calculate_scores(7)
        assert recovered["status"] == "unassessed" and recovered["authoritative"] is False


if __name__ == "__main__":
    run_integration() if "--integration" in sys.argv else unittest.main()
