import csv
import hashlib
import io
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import text

from database import engine


CONTROL_CATALOG = [
    {
        "control_id": "SOC2-CC6.1",
        "framework": "SOC2",
        "title": "Logical Access Controls",
        "description": "Access to systems and data is restricted to authorized users.",
        "weight": 15,
        "evidence_types": ["approval", "policy", "audit", "remediation"],
        "keywords": ["access", "rbac", "permission", "mfa", "iam"],
    },
    {
        "control_id": "SOC2-CC7.2",
        "framework": "SOC2",
        "title": "Security Monitoring",
        "description": "Security events are monitored, evaluated, and remediated.",
        "weight": 15,
        "evidence_types": ["gateway_event", "audit", "finding"],
        "keywords": ["security", "monitor", "gateway", "audit", "secret"],
    },
    {
        "control_id": "SOC2-CC8.1",
        "framework": "SOC2",
        "title": "Change Management",
        "description": "Production changes are authorized and auditable.",
        "weight": 10,
        "evidence_types": ["approval", "remediation", "audit"],
        "keywords": ["approval", "change", "execute", "remediation"],
    },
    {
        "control_id": "GDPR-ART5",
        "framework": "GDPR",
        "title": "Data Protection Principles",
        "description": "Personal data is processed lawfully, fairly, and with minimization.",
        "weight": 15,
        "evidence_types": ["policy", "redaction", "document"],
        "keywords": ["pii", "personal", "gdpr", "redact", "email"],
    },
    {
        "control_id": "GDPR-ART32",
        "framework": "GDPR",
        "title": "Security Of Processing",
        "description": "Technical and organizational measures protect personal data.",
        "weight": 15,
        "evidence_types": ["gateway_event", "finding", "remediation"],
        "keywords": ["encryption", "access", "secret", "security", "breach"],
    },
    {
        "control_id": "GDPR-ART30",
        "framework": "GDPR",
        "title": "Processing Records",
        "description": "Processing activity and evidence records are maintained.",
        "weight": 10,
        "evidence_types": ["evidence", "audit", "document"],
        "keywords": ["record", "evidence", "audit", "processing"],
    },
    {
        "control_id": "HIPAA-164.312A",
        "framework": "HIPAA",
        "title": "Access Control",
        "description": "Electronic PHI access is restricted and attributable.",
        "weight": 15,
        "evidence_types": ["approval", "policy", "audit"],
        "keywords": ["phi", "patient", "medical", "access", "mfa"],
    },
    {
        "control_id": "HIPAA-164.312B",
        "framework": "HIPAA",
        "title": "Audit Controls",
        "description": "System activity containing ePHI is recorded and reviewable.",
        "weight": 15,
        "evidence_types": ["audit", "gateway_event", "document"],
        "keywords": ["audit", "patient", "medical", "health", "trace"],
    },
    {
        "control_id": "HIPAA-164.312E",
        "framework": "HIPAA",
        "title": "Transmission Security",
        "description": "ePHI transmission is protected against unauthorized disclosure.",
        "weight": 10,
        "evidence_types": ["redaction", "policy", "finding"],
        "keywords": ["transmission", "redact", "phi", "medical", "secret"],
    },
    {
        "control_id": "ISO27001-A.5.15",
        "framework": "ISO27001",
        "title": "Access Control",
        "description": "Access to information and systems is managed according to business and security requirements.",
        "weight": 10,
        "evidence_types": ["approval", "policy", "audit"],
        "keywords": ["access", "rbac", "permission", "identity", "mfa"],
    },
    {
        "control_id": "ISO27001-A.8.12",
        "framework": "ISO27001",
        "title": "Data Leakage Prevention",
        "description": "Data leakage prevention measures are applied to systems and networks.",
        "weight": 10,
        "evidence_types": ["redaction", "gateway_event", "finding"],
        "keywords": ["redact", "leak", "pii", "secret", "exfiltrate"],
    },
    {
        "control_id": "PCI-DSS-3.4",
        "framework": "PCI_DSS",
        "title": "Protect Stored Account Data",
        "description": "Primary account numbers and related card data are protected from unauthorized disclosure.",
        "weight": 10,
        "evidence_types": ["redaction", "policy", "audit"],
        "keywords": ["credit card", "cardholder", "financial", "account number", "payment"],
    },
    {
        "control_id": "PCI-DSS-10.2",
        "framework": "PCI_DSS",
        "title": "Audit Logging",
        "description": "User and security events are logged and protected from tampering.",
        "weight": 10,
        "evidence_types": ["audit", "gateway_event", "evidence"],
        "keywords": ["audit", "hash", "ledger", "log", "integrity"],
    },
    {
        "control_id": "NIST-AC-2",
        "framework": "NIST",
        "title": "Account Management",
        "description": "Information system accounts are managed and reviewed.",
        "weight": 10,
        "evidence_types": ["approval", "policy", "audit"],
        "keywords": ["account", "access", "rbac", "user", "approval"],
    },
    {
        "control_id": "NIST-SI-4",
        "framework": "NIST",
        "title": "System Monitoring",
        "description": "The system is monitored to detect attacks, unauthorized activity, and policy violations.",
        "weight": 10,
        "evidence_types": ["gateway_event", "finding", "audit"],
        "keywords": ["monitor", "attack", "prompt injection", "security", "finding"],
    },
]


SEVERITY_PENALTY = {"CRITICAL": 30, "HIGH": 22, "MEDIUM": 12, "LOW": 6}


class ComplianceEvidenceEngine:
    corpus_version = "2026.07"

    def ensure_catalog(self) -> None:
        with engine.connect() as conn:
            conn.execute(
                text("""
                    INSERT INTO regulatory_corpus_versions (
                        version_id, description, frameworks, document_count,
                        embedding_backend, vector_backend, created_at, activated_at
                    )
                    VALUES (
                        :version_id, :description, :frameworks, :document_count,
                        :embedding_backend, :vector_backend, NOW(), NOW()
                    )
                    ON CONFLICT (version_id) DO UPDATE SET
                        description = EXCLUDED.description,
                        frameworks = EXCLUDED.frameworks,
                        document_count = EXCLUDED.document_count,
                        embedding_backend = EXCLUDED.embedding_backend,
                        vector_backend = EXCLUDED.vector_backend
                """),
                {
                    "version_id": self.corpus_version,
                    "description": "AuthClaw baseline SOC2/GDPR/HIPAA/ISO27001/PCI DSS/NIST regulatory control corpus.",
                    "frameworks": json.dumps(["SOC2", "GDPR", "HIPAA", "ISO27001", "PCI_DSS", "NIST"]),
                    "document_count": len(CONTROL_CATALOG),
                    "embedding_backend": os.getenv("AUTHCLAW_EMBEDDING_BACKEND", "deterministic-local"),
                    "vector_backend": os.getenv("AUTHCLAW_VECTOR_BACKEND", "postgres_json"),
                },
            )
            for control in CONTROL_CATALOG:
                conn.execute(
                    text("""
                        INSERT INTO compliance_control_catalog (
                            control_id, framework, title, description, weight,
                            evidence_types, corpus_version
                        )
                        VALUES (
                            :control_id, :framework, :title, :description, :weight,
                            :evidence_types, :corpus_version
                        )
                        ON CONFLICT (control_id) DO UPDATE SET
                            framework = EXCLUDED.framework,
                            title = EXCLUDED.title,
                            description = EXCLUDED.description,
                            weight = EXCLUDED.weight,
                            evidence_types = EXCLUDED.evidence_types,
                            corpus_version = EXCLUDED.corpus_version
                    """),
                    {
                        **{key: control[key] for key in ("control_id", "framework", "title", "description", "weight")},
                        "evidence_types": json.dumps(control["evidence_types"]),
                        "corpus_version": self.corpus_version,
                    },
                )
            conn.commit()

    def catalog(self, framework: Optional[str] = None) -> List[Dict[str, Any]]:
        self.ensure_catalog()
        controls = [dict(item) for item in CONTROL_CATALOG]
        if framework:
            controls = [item for item in controls if item["framework"].lower() == framework.lower()]
        return controls

    def map_evidence(self, tenant_id: int) -> int:
        self.ensure_catalog()
        rows = self._collect_source_events(tenant_id)
        mapped = 0
        with engine.connect() as conn:
            conn.execute(text("DELETE FROM compliance_control_evidence WHERE tenant_id = :tenant_id"), {"tenant_id": tenant_id})
            for event in rows:
                for control in self._matching_controls(event):
                    evidence_hash = self._event_hash(event)
                    conn.execute(
                        text("""
                            INSERT INTO compliance_control_evidence (
                                tenant_id, framework, control_id, source_type, source_id,
                                evidence_id, evidence_hash, reason, impact, created_at, metadata
                            )
                            VALUES (
                                :tenant_id, :framework, :control_id, :source_type, :source_id,
                                :evidence_id, :evidence_hash, :reason, :impact, NOW(), :metadata
                            )
                        """),
                        {
                            "tenant_id": tenant_id,
                            "framework": control["framework"],
                            "control_id": control["control_id"],
                            "source_type": event["source_type"],
                            "source_id": str(event.get("source_id") or ""),
                            "evidence_id": event.get("evidence_id"),
                            "evidence_hash": evidence_hash,
                            "reason": event["reason"],
                            "impact": event["impact"],
                            "metadata": json.dumps(event),
                        },
                    )
                    mapped += 1
            conn.commit()
        return mapped

    def calculate_scores(self, tenant_id: int) -> Dict[str, Any]:
        self.map_evidence(tenant_id)
        controls = self.catalog()
        with engine.connect() as conn:
            evidence_rows = conn.execute(
                text("""
                    SELECT framework, control_id, source_type, source_id, reason, impact, created_at, metadata
                    FROM compliance_control_evidence
                    WHERE tenant_id = :tenant_id
                """),
                {"tenant_id": tenant_id},
            ).fetchall()
            previous_rows = conn.execute(
                text("SELECT framework, control_id, score FROM compliance_control_scores WHERE tenant_id = :tenant_id"),
                {"tenant_id": tenant_id},
            ).fetchall()
        previous = {(row.framework, row.control_id): row.score for row in previous_rows}
        evidence_by_control: Dict[str, List[Dict[str, Any]]] = {}
        for row in evidence_rows:
            evidence_by_control.setdefault(row.control_id, []).append(dict(row._mapping))

        control_scores = []
        for control in controls:
            items = evidence_by_control.get(control["control_id"], [])
            negative = [item for item in items if int(item.get("impact") or 0) < 0]
            positive = [item for item in items if int(item.get("impact") or 0) >= 0]
            score = 100
            score += sum(int(item.get("impact") or 0) for item in negative)
            score = max(0, min(100, score))
            status = "passing" if score >= 85 else ("watch" if score >= 65 else "failing")
            reason = self._score_reason(control, positive, negative, score)
            source_event = items[-1]["source_type"] if items else "catalog_baseline"
            control_scores.append({
                "framework": control["framework"],
                "control_id": control["control_id"],
                "title": control["title"],
                "score": score,
                "status": status,
                "evidence_count": len(items),
                "negative_findings": len(negative),
                "reason": reason,
                "source_event": source_event,
                "evidence": items,
                "calculated_at": datetime.now(timezone.utc).isoformat(),
            })
            self._persist_control_score(tenant_id, control, score, status, len(items), len(negative), reason, source_event, previous)

        frameworks = {}
        for framework in sorted({item["framework"] for item in controls}):
            fw_controls = [item for item in control_scores if item["framework"] == framework]
            weighted_total = sum(self._control_weight(item["control_id"]) for item in fw_controls) or 1
            weighted_score = sum(item["score"] * self._control_weight(item["control_id"]) for item in fw_controls) / weighted_total
            frameworks[framework.lower()] = round(weighted_score)
            frameworks[f"{framework.lower()}_controls"] = {
                "passed": sum(1 for item in fw_controls if item["status"] == "passing"),
                "failed": sum(1 for item in fw_controls if item["status"] == "failing"),
                "watch": sum(1 for item in fw_controls if item["status"] == "watch"),
                "items": fw_controls,
            }
        frameworks["corpus_version"] = self.corpus_version
        return frameworks

    def evidence_export_rows(
        self,
        tenant_id: int,
        framework: Optional[str] = None,
        control_id: Optional[str] = None,
        *,
        refresh_scores: bool = True,
        limit: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        if refresh_scores:
            self.calculate_scores(tenant_id)
        sql = """
            SELECT framework, control_id, source_type, source_id, evidence_hash,
                   reason, impact, created_at, metadata
            FROM compliance_control_evidence
            WHERE tenant_id = :tenant_id
        """
        params = {"tenant_id": tenant_id}
        if framework:
            sql += " AND lower(framework) = lower(:framework)"
            params["framework"] = framework
        if control_id:
            sql += " AND control_id = :control_id"
            params["control_id"] = control_id
        sql += " ORDER BY framework, control_id, created_at DESC"
        if limit:
            sql += " LIMIT :limit"
            params["limit"] = max(1, min(int(limit), 1000))
        with engine.connect() as conn:
            rows = conn.execute(text(sql), params).fetchall()
        return [dict(row._mapping) for row in rows]

    def evidence_csv(self, tenant_id: int, framework: Optional[str] = None, control_id: Optional[str] = None) -> bytes:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["framework", "control_id", "source_type", "source_id", "evidence_hash", "reason", "impact", "created_at"])
        for row in self.evidence_export_rows(tenant_id, framework, control_id):
            writer.writerow([row["framework"], row["control_id"], row["source_type"], row["source_id"], row["evidence_hash"], row["reason"], row["impact"], row["created_at"]])
        return output.getvalue().encode("utf-8")

    def score_changes(self, tenant_id: int, framework: Optional[str] = None, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        params = {"tenant_id": tenant_id}
        sql = "SELECT * FROM compliance_score_changes WHERE tenant_id = :tenant_id"
        if framework:
            sql += " AND lower(framework) = lower(:framework)"
            params["framework"] = framework
        sql += " ORDER BY created_at DESC, id DESC"
        if limit:
            sql += " LIMIT :limit"
            params["limit"] = max(1, min(int(limit), 500))
        with engine.connect() as conn:
            rows = conn.execute(text(sql), params).fetchall()
        return [dict(row._mapping) for row in rows]

    def corpus_status(self) -> Dict[str, Any]:
        self.ensure_catalog()
        with engine.connect() as conn:
            row = conn.execute(
                text("SELECT * FROM regulatory_corpus_versions WHERE version_id = :version"),
                {"version": self.corpus_version},
            ).fetchone()
            chunk_count = conn.execute(
                text("SELECT COUNT(*) FROM knowledge_chunks WHERE COALESCE(corpus_version, :version) = :version"),
                {"version": self.corpus_version},
            ).scalar() or 0
        payload = dict(row._mapping) if row else {}
        payload["indexed_chunks"] = int(chunk_count)
        payload["production_vector_backend"] = os.getenv("AUTHCLAW_VECTOR_BACKEND", "postgres_json")
        return payload

    def _persist_control_score(self, tenant_id: int, control: Dict[str, Any], score: int, status: str, evidence_count: int, negative_findings: int, reason: str, source_event: str, previous: Dict[tuple, int]) -> None:
        key = (control["framework"], control["control_id"])
        previous_score = previous.get(key)
        metadata = {"title": control["title"], "corpus_version": self.corpus_version}
        with engine.connect() as conn:
            conn.execute(
                text("""
                    INSERT INTO compliance_control_scores (
                        tenant_id, framework, control_id, score, status, evidence_count,
                        negative_findings, reason, source_event, calculated_at, metadata
                    )
                    VALUES (
                        :tenant_id, :framework, :control_id, :score, :status, :evidence_count,
                        :negative_findings, :reason, :source_event, NOW(), :metadata
                    )
                    ON CONFLICT (tenant_id, framework, control_id) DO UPDATE SET
                        score = EXCLUDED.score,
                        status = EXCLUDED.status,
                        evidence_count = EXCLUDED.evidence_count,
                        negative_findings = EXCLUDED.negative_findings,
                        reason = EXCLUDED.reason,
                        source_event = EXCLUDED.source_event,
                        calculated_at = NOW(),
                        metadata = EXCLUDED.metadata
                """),
                {
                    "tenant_id": tenant_id,
                    "framework": control["framework"],
                    "control_id": control["control_id"],
                    "score": score,
                    "status": status,
                    "evidence_count": evidence_count,
                    "negative_findings": negative_findings,
                    "reason": reason,
                    "source_event": source_event,
                    "metadata": json.dumps(metadata),
                },
            )
            if previous_score is None or int(previous_score) != int(score):
                conn.execute(
                    text("""
                        INSERT INTO compliance_score_changes (
                            tenant_id, framework, control_id, previous_score, current_score,
                            reason, source_event, created_at, metadata
                        )
                        VALUES (
                            :tenant_id, :framework, :control_id, :previous_score, :current_score,
                            :reason, :source_event, NOW(), :metadata
                        )
                    """),
                    {
                        "tenant_id": tenant_id,
                        "framework": control["framework"],
                        "control_id": control["control_id"],
                        "previous_score": previous_score,
                        "current_score": score,
                        "reason": reason,
                        "source_event": source_event,
                        "metadata": json.dumps(metadata),
                    },
                )
            conn.commit()

    def _collect_source_events(self, tenant_id: int) -> List[Dict[str, Any]]:
        events: List[Dict[str, Any]] = []
        with engine.connect() as conn:
            evidence = conn.execute(
                text("SELECT id, name, category, file_path, hash, control_id, framework FROM compliance_evidence WHERE tenant_id = :tenant_id"),
                {"tenant_id": tenant_id},
            ).fetchall()
            document_findings = conn.execute(
                text("""
                    SELECT df.id, df.finding_type, df.matched_pattern, df.risk_level, df.recommendation, df.impact, df.location_evidence
                    FROM document_findings df
                    JOIN documents d ON d.id = df.document_id
                    WHERE COALESCE(df.tenant_id, d.tenant_id, :tenant_id) = :tenant_id
                      AND COALESCE(d.tenant_id, :tenant_id) = :tenant_id
                      AND d.status NOT IN ('deleted', 's3_deleted')
                """),
                {"tenant_id": tenant_id},
            ).fetchall()
            approvals = conn.execute(
                text("SELECT approval_id, status, reason, metadata, mfa_verified FROM gateway_approvals WHERE tenant_id = :tenant_id"),
                {"tenant_id": tenant_id},
            ).fetchall()
            audit_rows = conn.execute(
                text("SELECT id, risk_level, approval_status, policy_name, policy_type, matched_pattern, integrity_hash FROM audit_logs WHERE tenant_id = :tenant_id ORDER BY id DESC LIMIT 200"),
                {"tenant_id": tenant_id},
            ).fetchall()
            remediation = conn.execute(
                text("SELECT id, provider, finding_type, severity, status, approval_status, evidence FROM remediation_findings WHERE tenant_id = :tenant_id"),
                {"tenant_id": tenant_id},
            ).fetchall()

        for row in evidence:
            framework = row.framework or row.category
            events.append({
                "source_type": "evidence",
                "source_id": row.id,
                "evidence_id": row.id,
                "framework_hint": framework,
                "control_id": row.control_id,
                "text": f"{row.name} {row.category} {row.file_path}",
                "reason": f"Vaulted evidence '{row.name}' supports {framework}.",
                "impact": 8,
            })
        for row in document_findings:
            risk = str(row.risk_level or "LOW").upper()
            events.append({
                "source_type": "document_finding",
                "source_id": row.id,
                "text": f"{row.finding_type} {row.matched_pattern} {row.recommendation} {row.impact} {row.location_evidence}",
                "reason": f"Document finding {row.finding_type} with {risk} risk affects control scoring.",
                "impact": -SEVERITY_PENALTY.get(risk, 6),
            })
        for row in approvals:
            events.append({
                "source_type": "approval",
                "source_id": row.approval_id,
                "text": f"{row.status} {row.reason} {row.metadata}",
                "reason": f"Approval {row.approval_id} lifecycle event recorded as {row.status}.",
                "impact": 6 if row.status in {"approved", "executed"} and row.mfa_verified else 2,
            })
        for row in audit_rows:
            allowed_bonus = 4 if row.approval_status in {"approved", "executed", "N/A"} else 0
            events.append({
                "source_type": "audit",
                "source_id": row.id,
                "text": f"{row.risk_level} {row.approval_status} {row.policy_name} {row.policy_type} {row.matched_pattern}",
                "reason": f"Audit hash-chain record {row.id} contributes policy/audit evidence.",
                "impact": allowed_bonus,
            })
        for row in remediation:
            severity = str(row.severity or "LOW").upper()
            remediated = row.status == "remediated" or row.approval_status == "executed"
            events.append({
                "source_type": "remediation",
                "source_id": row.id,
                "text": f"{row.provider} {row.finding_type} {row.severity} {row.status} {row.evidence}",
                "reason": f"Remediation finding {row.finding_type} is {row.status}.",
                "impact": 10 if remediated else -SEVERITY_PENALTY.get(severity, 6),
            })
        return events

    def _matching_controls(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        if event.get("control_id"):
            return [control for control in CONTROL_CATALOG if control["control_id"] == event["control_id"]]
        text_value = str(event.get("text") or "").lower()
        framework_hint = str(event.get("framework_hint") or "").lower()
        matches = []
        for control in CONTROL_CATALOG:
            if framework_hint and control["framework"].lower() in framework_hint:
                matches.append(control)
                continue
            if control["framework"].lower() in text_value:
                matches.append(control)
                continue
            if any(keyword in text_value for keyword in control["keywords"]):
                matches.append(control)
        return matches or [control for control in CONTROL_CATALOG if control["framework"] == "SOC2"][:1]

    def _event_hash(self, event: Dict[str, Any]) -> str:
        canonical = json.dumps(event, sort_keys=True, default=str)
        return "sha256-" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def _control_weight(self, control_id: str) -> int:
        for control in CONTROL_CATALOG:
            if control["control_id"] == control_id:
                return int(control["weight"])
        return 10

    def _score_reason(self, control: Dict[str, Any], positive: List[Dict[str, Any]], negative: List[Dict[str, Any]], score: int) -> str:
        return (
            f"{control['control_id']} score {score} from {len(positive)} supporting evidence items "
            f"and {len(negative)} negative findings in corpus {self.corpus_version}."
        )
