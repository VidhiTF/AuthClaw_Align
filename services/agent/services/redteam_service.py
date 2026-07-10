import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from database import engine
from scripts.red_team_harness import run_harness


class RedTeamService:
    def run(self, tenant_id: int, actor: str = "system") -> Dict[str, Any]:
        report = run_harness()
        rows = []
        now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        try:
            with engine.connect() as conn:
                for case in report.get("cases", []):
                    passed = bool(case.get("passed"))
                    severity = "LOW" if passed else "HIGH"
                    category = str(case.get("name") or "redteam_probe")
                    payload = {
                        "probe": category,
                        "category": category,
                        "severity": severity,
                        "timestamp": now,
                        "result": "PASS" if passed else "FAIL",
                        "confidence": 0.95,
                        "evidence": case.get("detail"),
                        "regression_status": "clear" if passed else "regression",
                        "actor": actor,
                        "tenant_id": tenant_id,
                    }
                    storage_type = "redteam_probe"
                    vulnerability = "none" if passed else category[:30]
                    row = conn.execute(
                        text("""
                            INSERT INTO redteam_attacks (type, success, findings, vulnerability, timestamp)
                            VALUES (:type, :success, :findings, :vulnerability, :timestamp)
                            RETURNING id
                        """),
                        {
                            "type": storage_type,
                            "success": not passed,
                            "findings": json.dumps(payload, default=str),
                            "vulnerability": vulnerability,
                            "timestamp": now,
                        },
                    ).fetchone()
                    payload["id"] = row[0] if row else None
                    rows.append(payload)
                conn.commit()
        except SQLAlchemyError:
            rows = []
        return {
            "tenant_id": tenant_id,
            "status": report.get("status"),
            "generated_at": now,
            "stored": len(rows),
            "results": rows,
        }

    def history(self, tenant_id: int, limit: int = 100) -> List[Dict[str, Any]]:
        try:
            with engine.connect() as conn:
                rows = conn.execute(
                    text("""
                        SELECT id, type, success, findings, vulnerability, timestamp
                        FROM redteam_attacks
                        ORDER BY id DESC
                        LIMIT :limit
                    """),
                    {"limit": max(1, min(limit, 500))},
                ).fetchall()
        except SQLAlchemyError:
            return []
        records = []
        for row in rows:
            payload = self._decode(row.findings)
            if payload.get("tenant_id") not in {tenant_id, str(tenant_id), None}:
                continue
            records.append({
                "id": row.id,
                "probe": payload.get("probe") or row.type,
                "category": payload.get("category") or row.type,
                "severity": payload.get("severity") or ("HIGH" if row.success else "LOW"),
                "timestamp": payload.get("timestamp") or row.timestamp,
                "result": payload.get("result") or ("FAIL" if row.success else "PASS"),
                "confidence": payload.get("confidence", 0.8),
                "evidence": payload.get("evidence"),
                "regression_status": payload.get("regression_status") or ("regression" if row.success else "clear"),
                "vulnerability": row.vulnerability,
                "successful_attack": bool(row.success),
            })
        return records

    def report(self, tenant_id: int) -> Dict[str, Any]:
        records = self.history(tenant_id, limit=500)
        by_severity: Dict[str, int] = {}
        by_category: Dict[str, int] = {}
        failures = []
        for record in records:
            by_severity[record["severity"]] = by_severity.get(record["severity"], 0) + 1
            by_category[record["category"]] = by_category.get(record["category"], 0) + 1
            if record["result"] == "FAIL" or record["successful_attack"]:
                failures.append(record)
        return {
            "tenant_id": tenant_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_probes": len(records),
            "successful_attacks": len(failures),
            "by_severity": by_severity,
            "by_category": by_category,
            "failed_prompts": failures[:25],
            "regressions": [record for record in records if record["regression_status"] == "regression"][:25],
            "history": records[:100],
        }

    def _decode(self, raw: Optional[str]) -> Dict[str, Any]:
        if not raw:
            return {}
        try:
            return json.loads(raw)
        except Exception:
            return {"evidence": raw}
