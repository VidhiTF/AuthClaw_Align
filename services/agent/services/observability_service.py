from datetime import datetime, timezone
import json
import os
from typing import Any, Dict, List
import urllib.parse
import urllib.request

from database import engine
from fastapi import HTTPException
from services.event_pipeline import EventPipeline
from sqlalchemy import text
from verify_audit import clickhouse_pipeline_enabled, verify_audit_chain


def _iso(value: Any) -> str | None:
    if value is None:
        return None
    return value.isoformat() if hasattr(value, "isoformat") else str(value)


def _int(value: Any) -> int:
    return int(value or 0)


def _float(value: Any) -> float | None:
    return round(float(value), 2) if value is not None else None


def aggregate_health(*states: str) -> str:
    """Failure wins over missing observation; disabled checks cannot imply health."""
    precedence = ("unavailable", "degraded", "unknown", "healthy", "not_applicable")
    observed = {state if state in precedence else "unknown" for state in states}
    return next((state for state in precedence if state in observed), "unknown")


class ObservabilityService:
    def governance_analytics(self, tenant_id: int) -> Dict[str, Any]:
        tenant_id_text = str(tenant_id)
        clickhouse_status = self._clickhouse_status()
        with self._safe(engine.connect) as conn:
            gateway = self._safe(lambda: self._gateway_summary(conn, tenant_id_text))
            providers = self._safe(lambda: self._provider_usage(conn, tenant_id_text))
            blocked = self._safe(lambda: self._blocked_requests(conn, tenant_id_text))
            redactions = self._safe(lambda: self._redaction_summary(conn, tenant_id, tenant_id_text))
            approvals = self._safe(lambda: self._approval_summary(conn, tenant_id))
            approval_latency = self._safe(lambda: self._approval_latency(conn, tenant_id))
            provider_errors = self._safe(lambda: self._provider_errors(conn, tenant_id_text))
            rate_limits = self._safe(
                lambda: self._rate_limit_summary(conn, tenant_id),
            )
            worker_throttle = self._safe(lambda: self._worker_throttle_summary(conn, tenant_id))
            recent_requests = self._safe(lambda: self._recent_requests(conn, tenant_id_text))
            latest_hash = self._safe(lambda: self._latest_audit_hash(conn, tenant_id))

        if clickhouse_status["status"] == "unknown":
            try:
                mirror = self._clickhouse_gateway_summary(tenant_id_text)
                if any(mirror[key] != gateway[key] for key in gateway if not key.startswith("tokens_")):
                    clickhouse_status.update(status="degraded", message="ClickHouse mirror differs from PostgreSQL observations; ingestion may be delayed or incomplete.")
            except HTTPException:
                clickhouse_status.update(status="unavailable", message="ClickHouse analytics query failed; PostgreSQL observations remain available.")
        gateway.update(source="postgresql", coverage="persisted_gateway_events_only")
        verification = self._safe(lambda: verify_audit_chain(tenant_id=tenant_id))
        pipeline = self._safe(lambda: EventPipeline().delivery_metrics())
        queue = self._queue_lag(pipeline)
        audit = {
            "valid": verification.get("valid"),
            "status": "unknown" if verification.get("valid") is None else "healthy" if verification["valid"] else "degraded",
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
            "status": aggregate_health(audit["status"], queue["status"], clickhouse_status["status"]),
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
            "queue_lag": queue,
            "rate_limits": rate_limits,
            "worker_throttle": worker_throttle,
            "recent_requests": recent_requests,
            "clickhouse_pipeline": clickhouse_status,
        }

    def _safe(self, loader):
        try:
            return loader()
        except Exception as exc:
            raise HTTPException(status_code=503, detail="Telemetry source unavailable") from exc

    def _clickhouse_status(self) -> Dict[str, Any]:
        enabled = clickhouse_pipeline_enabled()
        if not enabled:
            return {
                "enabled": False,
                "status": "not_applicable",
                "alertable": False,
                "message": "ClickHouse analytics mirror is disabled by configuration.",
            }
        try:
            if self._clickhouse_query_json("SELECT 1 AS ok FORMAT JSONEachRow", timeout=0.5) != [{"ok": 1}]:
                raise ValueError("Invalid ClickHouse health response")
            return {
                "enabled": True,
                "status": "unknown",
                "alertable": True,
                "message": "ClickHouse is reachable; ingestion coverage is unverified. PostgreSQL observations are used.",
            }
        except Exception:
            return {
                "enabled": True,
                "status": "unavailable",
                "alertable": True,
                "message": "ClickHouse analytics mirror check failed; PostgreSQL analytics must be checked independently.",
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

    def _clickhouse_gateway_summary(self, tenant_id_text: str) -> Dict[str, Any] | None:
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
                avgOrNull(duration_ms) AS avg_duration_ms
            FROM {database}.{view}
            WHERE toString(tenant_id) = '{tenant}'
            FORMAT JSONEachRow
        """  # nosec B608
        try:
            rows = self._clickhouse_query_json(query)
            if len(rows) != 1:
                raise ValueError("Missing ClickHouse aggregate")
            row = rows[0]
            if any(row.get(key) is None for key in ("total_requests", "allowed_requests", "blocked_requests", "pending_requests")) or "avg_duration_ms" not in row:
                raise ValueError("Incomplete ClickHouse aggregate")
            return {
                "total_requests": _int(row.get("total_requests")),
                "allowed_requests": _int(row.get("allowed_requests")),
                "blocked_requests": _int(row.get("blocked_requests")),
                "pending_requests": _int(row.get("pending_requests")),
                "avg_duration_ms": _float(row.get("avg_duration_ms")),
                "tokens_in": None,
                "tokens_out": None,
                "tokens_total": None,
            }
        except Exception as exc:
            raise HTTPException(status_code=503, detail="Analytics source unavailable") from exc

    def _gateway_summary(self, conn, tenant_id_text: str) -> Dict[str, Any]:
        row = conn.execute(
            text(
                """
                SELECT
                    COUNT(*) AS total_requests,
                    SUM(CASE WHEN allowed = TRUE OR upper(COALESCE(decision, '')) = 'ALLOW' THEN 1 ELSE 0 END) AS allowed_requests,
                    SUM(CASE WHEN allowed = FALSE OR upper(COALESCE(decision, status, '')) = 'BLOCK' THEN 1 ELSE 0 END) AS blocked_requests,
                    SUM(CASE WHEN upper(COALESCE(decision, status, '')) IN ('REQUIRE_APPROVAL', 'PENDING_APPROVAL') THEN 1 ELSE 0 END) AS pending_requests,
                    CASE WHEN COUNT(*) = COUNT(CASE WHEN latency_recorded THEN COALESCE(duration_ms, latency) END) THEN AVG(COALESCE(duration_ms, latency)) END AS avg_duration_ms,
                    CASE WHEN COUNT(*) = COUNT(CASE WHEN token_usage_recorded THEN tokens_in END) THEN COALESCE(SUM(tokens_in), 0) END AS tokens_in,
                    CASE WHEN COUNT(*) = COUNT(CASE WHEN token_usage_recorded THEN tokens_out END) THEN COALESCE(SUM(tokens_out), 0) END AS tokens_out
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
            "tokens_in": int(row[5]) if row[5] is not None else None,
            "tokens_out": int(row[6]) if row[6] is not None else None,
            "tokens_total": int(row[5]) + int(row[6]) if row[5] is not None and row[6] is not None else None,
        }

    def _provider_usage(self, conn, tenant_id_text: str) -> List[Dict[str, Any]]:
        rows = conn.execute(
            text(
                """
                SELECT
                    COALESCE(NULLIF(provider, ''), 'unknown') AS provider_name,
                    COUNT(*) AS request_count,
                    SUM(CASE WHEN allowed = FALSE OR upper(COALESCE(decision, status, '')) = 'BLOCK' THEN 1 ELSE 0 END) AS blocked_count,
                    CASE WHEN COUNT(*) = COUNT(CASE WHEN latency_recorded THEN COALESCE(duration_ms, latency) END) THEN AVG(COALESCE(duration_ms, latency)) END AS avg_duration_ms,
                    CASE WHEN COUNT(*) = COUNT(CASE WHEN token_usage_recorded THEN tokens_in + tokens_out END) THEN SUM(tokens_in + tokens_out) END AS tokens_total,
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
                "tokens_total": int(row[4]) if row[4] is not None else None,
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
        return {"avg_seconds": _float(row[0] if row else None), "p95_seconds": _float(row[1] if row else None)}

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
        unknown = {"status": "unknown", "max_lag_seconds": None, "pending_events": None,
                   "dead_letter_count": None, "alertable": True}
        try:
            threshold = int(os.getenv("AUTHCLAW_QUEUE_LAG_ALERT_SECONDS", "300"))
            if threshold <= 0:
                raise ValueError("Invalid queue threshold")
        except ValueError:
            return {**unknown, "status": "unavailable", "reason": "Invalid queue lag configuration"}
        if not isinstance(pipeline, dict):
            return unknown
        checkpoints = pipeline.get("checkpoints", [])
        streams = pipeline.get("streams")
        if not isinstance(streams, dict):
            return unknown
        try:
            live_counts = [(counts.get("queued", 0), counts.get("dead_letter", 0)) for counts in streams.values()]
            if any(type(value) is not int or value < 0 for counts in live_counts for value in counts):
                return unknown
            # Current delivery failures remain measured even when checkpoint lag is unknown.
            unknown["pending_events"] = sum(queued + dead for queued, dead in live_counts)
            unknown["dead_letter_count"] = sum(dead for _, dead in live_counts)
            if unknown["dead_letter_count"]:
                unknown["status"] = "degraded"
        except AttributeError:
            return unknown
        # SMTP deliveries have no Kafka checkpoint. Completed alerts must not
        # prevent recovery; pending/failed alerts still lack a measured lag.
        pending_alert = False
        if "security_alert" in streams:
            pending_alert = bool(streams["security_alert"].get("queued", 0) or streams["security_alert"].get("dead_letter", 0))
            streams = {name: counts for name, counts in streams.items() if name != "security_alert"}
            if not pending_alert and not streams and checkpoints == []:
                return {**unknown, "status": "healthy", "max_lag_seconds": 0, "alertable": False}
        if not isinstance(checkpoints, list) or not checkpoints or any(not isinstance(cp, dict) or not isinstance(cp.get("stream"), str) or not cp["stream"] for cp in checkpoints):
            return unknown
        if set(streams) - {cp["stream"] for cp in checkpoints}:
            return unknown
        max_lag = dead_letters = pending = 0
        for checkpoint in checkpoints:
            try:
                updated = datetime.fromisoformat(str(checkpoint["updated_at"]))
                age = (datetime.now(timezone.utc) - updated.replace(tzinfo=updated.tzinfo or timezone.utc)).total_seconds()
                lag, dead, queued = (checkpoint[key] for key in ("lag_seconds", "dead_letter_count", "pending_events"))
                if any(type(value) is not int or value < 0 for value in (lag, dead, queued)) or not 0 <= age <= threshold:
                    return unknown
                counts = streams.get(checkpoint["stream"], {})
                if int(counts.get("dead_letter", 0)) != dead or int(counts.get("queued", 0)) + dead != queued:
                    return unknown
            except (KeyError, TypeError, ValueError, OverflowError):
                return unknown
            max_lag = max(max_lag, lag)
            dead_letters += dead
            pending += queued
        alertable = max_lag > threshold or dead_letters > 0
        if pending_alert:
            if alertable:
                unknown["status"] = "degraded"
            return unknown
        return {
            "status": "degraded" if alertable else "healthy",
            "max_lag_seconds": max_lag,
            "pending_events": pending,
            "dead_letter_count": dead_letters,
            "alertable": alertable,
        }

    def _recent_requests(self, conn, tenant_id_text: str) -> List[Dict[str, Any]]:
        rows = conn.execute(
            text(
                """
                SELECT request_id, provider, model, risk_level, decision, status,
                       CASE WHEN latency_recorded THEN COALESCE(duration_ms, latency) END, COALESCE(created_at, timestamp)
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
                "duration_ms": _float(row[6]),
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
