from datetime import datetime, timezone
import json
import os
from typing import Any, Dict, List
import urllib.parse
import urllib.request

from database import engine
from services.event_pipeline import EventPipeline
from sqlalchemy import text
from verify_audit import clickhouse_pipeline_enabled, verify_audit_chain


def _iso(value: Any) -> str:
    if value is None:
        return None
    return value.isoformat() if hasattr(value, "isoformat") else str(value)


def _int(value: Any) -> int:
    return int(value or 0)


def _float(value: Any) -> float:
    return round(float(value or 0), 2)


class ObservabilityService:
    def governance_analytics(self, tenant_id: int) -> Dict[str, Any]:
        tenant_id_text = str(tenant_id)
        clickhouse_status = self._clickhouse_status()

        with engine.connect() as conn:
            gateway = self._safe(
                lambda: self._clickhouse_gateway_summary(tenant_id_text) or self._gateway_summary(conn, tenant_id_text),
                self._empty_gateway(),
            )
            providers = self._safe(lambda: self._provider_usage(conn, tenant_id_text), [])
            blocked = self._safe(lambda: self._blocked_requests(conn, tenant_id_text), {"by_risk_level": {}, "recent": []})
            redactions = self._safe(lambda: self._redaction_summary(conn, tenant_id, tenant_id_text), self._empty_redactions())
            approvals = self._safe(lambda: self._approval_summary(conn, tenant_id), self._empty_approvals())
            approval_latency = self._safe(lambda: self._approval_latency(conn, tenant_id), {"avg_seconds": 0, "p95_seconds": 0})
            provider_errors = self._safe(lambda: self._provider_errors(conn, tenant_id_text), {"total": 0, "by_provider": {}})
            rate_limits = self._safe(
                lambda: self._rate_limit_summary(conn, tenant_id),
                {"allowed": 0, "blocked": 0, "backend": "none", "min_remaining": None, "last_seen": None},
            )
            worker_throttle = self._safe(lambda: self._worker_throttle_summary(conn, tenant_id), {"by_type": {}})
            recent_requests = self._safe(lambda: self._recent_requests(conn, tenant_id_text), [])
            latest_hash = self._safe(lambda: self._latest_audit_hash(conn, tenant_id), None)

        verification = self._safe(lambda: verify_audit_chain(tenant_id=tenant_id), {"valid": True, "records_checked": 0})
        pipeline = self._safe(lambda: EventPipeline().delivery_metrics(), {"checkpoints": []})
        audit = {
            "valid": bool(verification.get("valid", True)),
            "records_checked": _int(verification.get("records_checked")),
            "chain_started_at": verification.get("chain_started_at"),
            "failed_record_id": verification.get("failed_record_id"),
            "reason": verification.get("reason"),
            "latest_hash": latest_hash,
            "export_endpoints": {
                "csv": "/audit/export/csv",
                "pdf": "/audit/export/pdf",
            },
        }

        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "tenant_id": tenant_id,
            "gateway": gateway,
            "providers": providers,
            "provider_errors": provider_errors,
            "blocked_requests": blocked,
            "redactions": redactions,
            "approvals": approvals,
            "approval_latency": approval_latency,
            "audit": audit,
            "event_pipeline": pipeline,
            "queue_lag": self._queue_lag(pipeline),
            "rate_limits": rate_limits,
            "worker_throttle": worker_throttle,
            "recent_requests": recent_requests,
            "clickhouse_pipeline": clickhouse_status,
        }

    def _safe(self, loader, fallback):
        try:
            return loader()
        except Exception:
            return fallback

    def _empty_gateway(self) -> Dict[str, Any]:
        return {
            "total_requests": 0,
            "allowed_requests": 0,
            "blocked_requests": 0,
            "pending_requests": 0,
            "avg_duration_ms": 0,
            "tokens_in": 0,
            "tokens_out": 0,
            "tokens_total": 0,
        }

    def _empty_redactions(self) -> Dict[str, Any]:
        return {
            "total_fields": 0,
            "document_findings": 0,
            "agent_redaction_events": 0,
            "audit_redaction_records": 0,
            "redacted_gateway_requests": 0,
            "by_type": {},
        }

    def _empty_approvals(self) -> Dict[str, Any]:
        return {
            "total": 0,
            "pending": 0,
            "approved": 0,
            "rejected": 0,
            "executed": 0,
            "expired": 0,
            "by_status": {},
        }

    def _clickhouse_status(self) -> Dict[str, Any]:
        enabled = clickhouse_pipeline_enabled()
        if not enabled:
            return {
                "enabled": False,
                "status": "disabled",
                "message": "ClickHouse analytics mirror is disabled by configuration.",
            }
        try:
            self._clickhouse_query_json("SELECT 1 AS ok FORMAT JSONEachRow", timeout=0.5)
            return {
                "enabled": True,
                "status": "connected",
                "message": "ClickHouse analytics mirror is enabled and reachable.",
            }
        except Exception:
            return {
                "enabled": True,
                "status": "fallback",
                "message": "ClickHouse analytics mirror is enabled; PostgreSQL RLS-backed analytics are serving as fallback.",
            }

    def _clickhouse_query_json(self, query: str, *, timeout: float = 1.5) -> List[Dict[str, Any]]:
        base_url = os.getenv("CLICKHOUSE_HTTP_URL", "http://127.0.0.1:8123").rstrip("/")
        url = f"{base_url}/?query={urllib.parse.quote(query)}"
        with urllib.request.urlopen(url, timeout=timeout) as response:  # nosec B310
            if response.status < 200 or response.status >= 300:
                raise RuntimeError(f"ClickHouse returned {response.status}")
            rows = []
            for line in response.read().decode("utf-8").splitlines():
                if line.strip():
                    rows.append(json.loads(line))
            return rows

    def _clickhouse_gateway_summary(self, tenant_id_text: str) -> Dict[str, Any]:
        if not clickhouse_pipeline_enabled():
            return None
        database = os.getenv("CLICKHOUSE_DATABASE", "authclaw")
        view = os.getenv("CLICKHOUSE_GATEWAY_METRICS_VIEW", "gateway_metrics_view")
        tenant = tenant_id_text.replace("'", "''")
        query = f"""
            SELECT
                count() AS total_requests,
                countIf(allowed = 1 OR upper(coalesce(decision, '')) = 'ALLOW') AS allowed_requests,
                countIf(allowed = 0 OR upper(coalesce(decision, status, '')) = 'BLOCK') AS blocked_requests,
                countIf(upper(coalesce(decision, status, '')) IN ('REQUIRE_APPROVAL', 'PENDING_APPROVAL')) AS pending_requests,
                avg(coalesce(duration_ms, 0)) AS avg_duration_ms,
                sum(coalesce(tokens_in, 0)) AS tokens_in,
                sum(coalesce(tokens_out, 0)) AS tokens_out
            FROM {database}.{view}
            WHERE toString(tenant_id) = '{tenant}'
            FORMAT JSONEachRow
        """  # nosec B608
        try:
            rows = self._clickhouse_query_json(query)
            if not rows:
                return None
            row = rows[0]
            return {
                "total_requests": _int(row.get("total_requests")),
                "allowed_requests": _int(row.get("allowed_requests")),
                "blocked_requests": _int(row.get("blocked_requests")),
                "pending_requests": _int(row.get("pending_requests")),
                "avg_duration_ms": _float(row.get("avg_duration_ms")),
                "tokens_in": _int(row.get("tokens_in")),
                "tokens_out": _int(row.get("tokens_out")),
                "tokens_total": _int(row.get("tokens_in")) + _int(row.get("tokens_out")),
            }
        except Exception:
            return None

    def _gateway_summary(self, conn, tenant_id_text: str) -> Dict[str, Any]:
        row = conn.execute(
            text(
                """
                SELECT
                    COUNT(*) AS total_requests,
                    SUM(CASE WHEN allowed = TRUE OR upper(COALESCE(decision, '')) = 'ALLOW' THEN 1 ELSE 0 END) AS allowed_requests,
                    SUM(CASE WHEN allowed = FALSE OR upper(COALESCE(decision, status, '')) = 'BLOCK' THEN 1 ELSE 0 END) AS blocked_requests,
                    SUM(CASE WHEN upper(COALESCE(decision, status, '')) IN ('REQUIRE_APPROVAL', 'PENDING_APPROVAL') THEN 1 ELSE 0 END) AS pending_requests,
                    AVG(COALESCE(duration_ms, latency, 0)) AS avg_duration_ms,
                    SUM(COALESCE(tokens_in, 0)) AS tokens_in,
                    SUM(COALESCE(tokens_out, 0)) AS tokens_out
                FROM gateway_requests
                WHERE tenant_id = :tenant_id
                """
            ),
            {"tenant_id": tenant_id_text},
        ).fetchone()

        return {
            "total_requests": _int(row[0]),
            "allowed_requests": _int(row[1]),
            "blocked_requests": _int(row[2]),
            "pending_requests": _int(row[3]),
            "avg_duration_ms": _float(row[4]),
            "tokens_in": _int(row[5]),
            "tokens_out": _int(row[6]),
            "tokens_total": _int(row[5]) + _int(row[6]),
        }

    def _provider_usage(self, conn, tenant_id_text: str) -> List[Dict[str, Any]]:
        rows = conn.execute(
            text(
                """
                SELECT
                    COALESCE(NULLIF(provider, ''), 'unknown') AS provider_name,
                    COUNT(*) AS request_count,
                    SUM(CASE WHEN allowed = FALSE OR upper(COALESCE(decision, status, '')) = 'BLOCK' THEN 1 ELSE 0 END) AS blocked_count,
                    AVG(COALESCE(duration_ms, latency, 0)) AS avg_duration_ms,
                    SUM(COALESCE(tokens_in, 0) + COALESCE(tokens_out, 0)) AS tokens_total,
                    MAX(COALESCE(created_at, timestamp)) AS last_seen
                FROM gateway_requests
                WHERE tenant_id = :tenant_id
                GROUP BY COALESCE(NULLIF(provider, ''), 'unknown')
                ORDER BY request_count DESC, provider_name ASC
                """
            ),
            {"tenant_id": tenant_id_text},
        ).fetchall()

        return [
            {
                "provider": row[0],
                "requests": _int(row[1]),
                "blocked": _int(row[2]),
                "avg_duration_ms": _float(row[3]),
                "tokens_total": _int(row[4]),
                "last_seen": _iso(row[5]),
            }
            for row in rows
        ]

    def _blocked_requests(self, conn, tenant_id_text: str) -> Dict[str, Any]:
        risk_rows = conn.execute(
            text(
                """
                SELECT COALESCE(NULLIF(upper(risk_level), ''), 'UNKNOWN') AS risk_level, COUNT(*)
                FROM gateway_requests
                WHERE tenant_id = :tenant_id
                  AND (allowed = FALSE OR upper(COALESCE(decision, status, '')) = 'BLOCK')
                GROUP BY COALESCE(NULLIF(upper(risk_level), ''), 'UNKNOWN')
                ORDER BY COUNT(*) DESC, risk_level ASC
                """
            ),
            {"tenant_id": tenant_id_text},
        ).fetchall()
        recent_rows = conn.execute(
            text(
                """
                SELECT request_id, provider, model, risk_level, decision, status, COALESCE(created_at, timestamp)
                FROM gateway_requests
                WHERE tenant_id = :tenant_id
                  AND (allowed = FALSE OR upper(COALESCE(decision, status, '')) = 'BLOCK')
                ORDER BY COALESCE(created_at, timestamp) DESC
                LIMIT 8
                """
            ),
            {"tenant_id": tenant_id_text},
        ).fetchall()

        return {
            "by_risk_level": {row[0]: _int(row[1]) for row in risk_rows},
            "recent": [
                {
                    "request_id": row[0],
                    "provider": row[1],
                    "model": row[2],
                    "risk_level": row[3],
                    "decision": row[4],
                    "status": row[5],
                    "timestamp": _iso(row[6]),
                }
                for row in recent_rows
            ],
        }

    def _redaction_summary(self, conn, tenant_id: int, tenant_id_text: str) -> Dict[str, Any]:
        doc_rows = conn.execute(
            text(
                """
                SELECT COALESCE(NULLIF(finding_type, ''), 'Unknown') AS finding_type, COUNT(*)
                FROM document_findings
                WHERE tenant_id = :tenant_id
                GROUP BY COALESCE(NULLIF(finding_type, ''), 'Unknown')
                ORDER BY COUNT(*) DESC, finding_type ASC
                """
            ),
            {"tenant_id": tenant_id},
        ).fetchall()
        agent_redactions = conn.execute(
            text(
                """
                SELECT COUNT(*)
                FROM agent_events
                WHERE tenant_id = :tenant_id
                  AND (
                    upper(event_type) LIKE '%REDACT%'
                    OR upper(event_type) LIKE '%PII_DETECTED%'
                    OR upper(event_type) LIKE '%SECRET%'
                  )
                """
            ),
            {"tenant_id": tenant_id},
        ).scalar()
        audit_redactions = conn.execute(
            text(
                """
                SELECT COUNT(*)
                FROM audit_logs
                WHERE tenant_id = :tenant_id
                  AND redacted_value IS NOT NULL
                  AND redacted_value <> ''
                """
            ),
            {"tenant_id": tenant_id},
        ).scalar()
        redacted_gateway_requests = conn.execute(
            text(
                """
                SELECT COUNT(*)
                FROM gateway_requests
                WHERE tenant_id = :tenant_id
                  AND lower(COALESCE(status, decision, '')) LIKE '%redact%'
                """
            ),
            {"tenant_id": tenant_id_text},
        ).scalar()

        by_type = {row[0]: _int(row[1]) for row in doc_rows}
        return {
            "total_fields": sum(by_type.values()) + _int(audit_redactions),
            "document_findings": sum(by_type.values()),
            "agent_redaction_events": _int(agent_redactions),
            "audit_redaction_records": _int(audit_redactions),
            "redacted_gateway_requests": _int(redacted_gateway_requests),
            "by_type": by_type,
        }

    def _approval_summary(self, conn, tenant_id: int) -> Dict[str, Any]:
        rows = conn.execute(
            text(
                """
                SELECT COALESCE(NULLIF(lower(status), ''), 'unknown') AS status, COUNT(*)
                FROM gateway_approvals
                WHERE tenant_id = :tenant_id
                GROUP BY COALESCE(NULLIF(lower(status), ''), 'unknown')
                """
            ),
            {"tenant_id": tenant_id},
        ).fetchall()
        by_status = {row[0]: _int(row[1]) for row in rows}
        return {
            "total": sum(by_status.values()),
            "pending": by_status.get("pending", 0),
            "approved": by_status.get("approved", 0),
            "rejected": by_status.get("rejected", 0),
            "executed": by_status.get("executed", 0),
            "expired": by_status.get("expired", 0),
            "by_status": by_status,
        }

    def _approval_latency(self, conn, tenant_id: int) -> Dict[str, Any]:
        row = conn.execute(
            text(
                """
                SELECT
                    AVG(EXTRACT(EPOCH FROM (COALESCE(executed_at, approved_at, rejected_at, last_action_at, NOW()) - created_at))) AS avg_seconds,
                    PERCENTILE_CONT(0.95) WITHIN GROUP (
                        ORDER BY EXTRACT(EPOCH FROM (COALESCE(executed_at, approved_at, rejected_at, last_action_at, NOW()) - created_at))
                    ) AS p95_seconds
                FROM gateway_approvals
                WHERE tenant_id = :tenant_id
                  AND created_at IS NOT NULL
                """
            ),
            {"tenant_id": tenant_id},
        ).fetchone()
        return {"avg_seconds": _float(row[0] if row else 0), "p95_seconds": _float(row[1] if row else 0)}

    def _provider_errors(self, conn, tenant_id_text: str) -> Dict[str, Any]:
        rows = conn.execute(
            text(
                """
                SELECT COALESCE(NULLIF(provider, ''), 'unknown') AS provider_name, COUNT(*)
                FROM gateway_requests
                WHERE tenant_id = :tenant_id
                  AND (
                    lower(COALESCE(status, decision, '')) LIKE '%error%'
                    OR lower(COALESCE(status, decision, '')) LIKE '%fail%'
                    OR lower(COALESCE(status, decision, '')) LIKE '%unavailable%'
                    OR lower(COALESCE(status, decision, '')) LIKE '%timeout%'
                  )
                GROUP BY COALESCE(NULLIF(provider, ''), 'unknown')
                ORDER BY COUNT(*) DESC
                """
            ),
            {"tenant_id": tenant_id_text},
        ).fetchall()
        total = sum(_int(row[1]) for row in rows)
        return {"total": total, "by_provider": {row[0]: _int(row[1]) for row in rows}}

    def _rate_limit_summary(self, conn, tenant_id: int) -> Dict[str, Any]:
        rows = conn.execute(
            text(
                """
                SELECT backend, allowed, COUNT(*), MIN(remaining), MAX(created_at)
                FROM rate_limit_events
                WHERE tenant_id = :tenant_id
                  AND created_at >= NOW() - INTERVAL '1 hour'
                GROUP BY backend, allowed
                """
            ),
            {"tenant_id": tenant_id},
        ).fetchall()
        summary = {"allowed": 0, "blocked": 0, "backend": "none", "min_remaining": None, "last_seen": None}
        for row in rows:
            if row[1]:
                summary["allowed"] += _int(row[2])
            else:
                summary["blocked"] += _int(row[2])
            summary["backend"] = row[0] or summary["backend"]
            if summary["min_remaining"] is None:
                summary["min_remaining"] = _int(row[3])
            else:
                summary["min_remaining"] = min(summary["min_remaining"], _int(row[3]))
            summary["last_seen"] = _iso(row[4])
        return summary

    def _worker_throttle_summary(self, conn, tenant_id: int) -> Dict[str, Any]:
        rows = conn.execute(
            text(
                """
                SELECT worker_type, allowed, COUNT(*), MAX(active_count), MAX(limit_count), MAX(created_at)
                FROM worker_throttle_events
                WHERE tenant_id = :tenant_id
                  AND created_at >= NOW() - INTERVAL '1 hour'
                GROUP BY worker_type, allowed
                """
            ),
            {"tenant_id": tenant_id},
        ).fetchall()
        by_type: Dict[str, Dict[str, Any]] = {}
        for row in rows:
            item = by_type.setdefault(row[0], {"allowed": 0, "blocked": 0, "active_count": 0, "limit_count": 0, "last_seen": None})
            if row[1]:
                item["allowed"] += _int(row[2])
            else:
                item["blocked"] += _int(row[2])
            item["active_count"] = max(item["active_count"], _int(row[3]))
            item["limit_count"] = max(item["limit_count"], _int(row[4]))
            item["last_seen"] = _iso(row[5])
        return {"by_type": by_type}

    def _queue_lag(self, pipeline: Dict[str, Any]) -> Dict[str, Any]:
        max_lag = 0
        dead_letters = 0
        pending = 0
        for checkpoint in pipeline.get("checkpoints", []):
            max_lag = max(max_lag, _int(checkpoint.get("lag_seconds")))
            dead_letters += _int(checkpoint.get("dead_letter_count"))
            pending += _int(checkpoint.get("pending_events"))
        return {
            "max_lag_seconds": max_lag,
            "pending_events": pending,
            "dead_letter_count": dead_letters,
            "alertable": max_lag > int(os.getenv("AUTHCLAW_QUEUE_LAG_ALERT_SECONDS", "300")) or dead_letters > 0,
        }

    def _recent_requests(self, conn, tenant_id_text: str) -> List[Dict[str, Any]]:
        rows = conn.execute(
            text(
                """
                SELECT request_id, provider, model, risk_level, decision, status,
                       COALESCE(duration_ms, latency, 0), COALESCE(created_at, timestamp)
                FROM gateway_requests
                WHERE tenant_id = :tenant_id
                ORDER BY COALESCE(created_at, timestamp) DESC
                LIMIT 10
                """
            ),
            {"tenant_id": tenant_id_text},
        ).fetchall()
        return [
            {
                "request_id": row[0],
                "provider": row[1],
                "model": row[2],
                "risk_level": row[3],
                "decision": row[4],
                "status": row[5],
                "duration_ms": _int(row[6]),
                "timestamp": _iso(row[7]),
            }
            for row in rows
        ]

    def _latest_audit_hash(self, conn, tenant_id: int) -> str:
        row = conn.execute(
            text(
                """
                SELECT integrity_hash
                FROM audit_logs
                WHERE tenant_id = :tenant_id
                  AND integrity_hash IS NOT NULL
                ORDER BY id DESC
                LIMIT 1
                """
            ),
            {"tenant_id": tenant_id},
        ).fetchone()
        return row[0] if row else None
