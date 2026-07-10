import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import text

from database import engine
from document_processing.auditor import create_document_audit
from services.tenant_context import tenant_context


def _json_default(value: Any) -> str:
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return str(value)


def _safe_json(value: Any) -> str:
    return json.dumps(value, default=_json_default, ensure_ascii=True)


def _safe_matched_text(finding: Dict[str, Any]) -> str:
    token = finding.get("token_id") or finding.get("redacted_value") or finding.get("value_hash")
    if token:
        return str(token)
    field_type = str(finding.get("field_type") or finding.get("matched_pattern") or "sensitive")
    return f"[{field_type.upper()}]"


def persist_document_intelligence_result(
    *,
    tenant_id: Optional[int],
    request_id: str,
    filename: str,
    content_type: Optional[str],
    size_bytes: int,
    content_bytes: bytes,
    extraction,
    analysis: Dict[str, Any],
    decision: str,
    risk_level: str,
    username: str,
    duration_ms: int,
) -> Dict[str, Any]:
    """Persist a completed document redaction run without raw finding values."""
    document_uid = request_id
    scan_id = f"scan-{request_id}"
    content_sha256 = hashlib.sha256(content_bytes).hexdigest()
    findings: List[Dict[str, Any]] = list(analysis.get("findings") or [])
    compliance_summary = analysis.get("compliance_summary") or {}
    findings_report = analysis.get("findings_report") or {}
    metadata = dict(analysis.get("metadata") or {})
    metadata.setdefault("filename", filename)
    metadata.setdefault("content_type", content_type)
    metadata.setdefault("page_count", len(getattr(extraction, "pages", []) or []))
    metadata.setdefault("processed_at", datetime.now(timezone.utc).isoformat())

    status = "blocked" if decision == "BLOCK" else ("redacted" if findings else "clean")
    processing_history = [{
        "request_id": request_id,
        "scan_id": scan_id,
        "status": status,
        "decision": decision,
        "risk_level": risk_level,
        "duration_ms": duration_ms,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }]

    with tenant_context(tenant_id, request_id=request_id, required=tenant_id is not None), engine.connect() as conn:
        doc_id = conn.execute(
            text("""
                INSERT INTO documents (
                    filename, source, status, size_bytes, risk_score, severity,
                    tenant_id, document_uid, version, content_sha256, mime_type,
                    page_count, extraction_method, ocr_status, ocr_required,
                    metadata_json, original_extracted_text, redacted_text,
                    redacted_pdf_base64, findings_report, compliance_summary,
                    processing_history, progress, updated_at
                )
                VALUES (
                    :filename, 'gateway_upload', :status, :size_bytes, :risk_score, :severity,
                    :tenant_id, :document_uid, 1, :content_sha256, :mime_type,
                    :page_count, :extraction_method, :ocr_status, :ocr_required,
                    :metadata_json, :original_extracted_text, :redacted_text,
                    :redacted_pdf_base64, :findings_report, :compliance_summary,
                    :processing_history, 100, NOW()
                )
                RETURNING id
            """),
            {
                "filename": filename,
                "status": status,
                "size_bytes": size_bytes,
                "risk_score": 90 if risk_level == "HIGH" else (60 if risk_level == "MEDIUM" else 10),
                "severity": risk_level,
                "tenant_id": tenant_id,
                "document_uid": document_uid,
                "content_sha256": content_sha256,
                "mime_type": content_type or metadata.get("content_type") or "application/octet-stream",
                "page_count": len(getattr(extraction, "pages", []) or []),
                "extraction_method": extraction.extraction_method,
                "ocr_status": extraction.ocr_status,
                "ocr_required": bool(getattr(extraction, "ocr_required", False)),
                "metadata_json": _safe_json(metadata),
                "original_extracted_text": analysis.get("extracted_text") or extraction.text,
                "redacted_text": analysis.get("redacted_text") or "",
                "redacted_pdf_base64": analysis.get("redacted_pdf_base64") or "",
                "findings_report": _safe_json(findings_report),
                "compliance_summary": _safe_json(compliance_summary),
                "processing_history": _safe_json(processing_history),
            },
        ).scalar()

        scan_pk = conn.execute(
            text("""
                INSERT INTO document_scans (
                    document_id, tenant_id, scan_id, scan_duration_ms, raw_findings,
                    status, progress, extraction_method, ocr_status, ocr_required,
                    compliance_summary, outputs_json
                )
                VALUES (
                    :document_id, :tenant_id, :scan_id, :scan_duration_ms, :raw_findings,
                    :status, 100, :extraction_method, :ocr_status, :ocr_required,
                    :compliance_summary, :outputs_json
                )
                RETURNING id
            """),
            {
                "document_id": doc_id,
                "tenant_id": tenant_id,
                "scan_id": scan_id,
                "scan_duration_ms": duration_ms,
                "raw_findings": _safe_json(findings_report),
                "status": "completed",
                "extraction_method": extraction.extraction_method,
                "ocr_status": extraction.ocr_status,
                "ocr_required": bool(getattr(extraction, "ocr_required", False)),
                "compliance_summary": _safe_json(compliance_summary),
                "outputs_json": _safe_json({
                    "redacted_text": bool(analysis.get("redacted_text")),
                    "redacted_pdf_base64": bool(analysis.get("redacted_pdf_base64")),
                    "findings_report": True,
                }),
            },
        ).scalar()

        conn.execute(
            text("UPDATE documents SET latest_scan_id = :scan_id WHERE id = :document_id"),
            {"scan_id": scan_pk, "document_id": doc_id},
        )

        for finding in findings:
            field_type = str(finding.get("field_type") or finding.get("matched_pattern") or "sensitive")
            conn.execute(
                text("""
                    INSERT INTO document_findings (
                        document_id, tenant_id, finding_type, matched_pattern, matched_text,
                        risk_level, recommendation, impact, priority, location_evidence,
                        field_type, page_number, line_number, paragraph_number,
                        char_start, char_end, bbox, confidence, policy_violated,
                        explanation, action_taken, fingerprint
                    )
                    VALUES (
                        :document_id, :tenant_id, :finding_type, :matched_pattern, :matched_text,
                        :risk_level, :recommendation, :impact, :priority, :location_evidence,
                        :field_type, :page_number, :line_number, :paragraph_number,
                        :char_start, :char_end, :bbox, :confidence, :policy_violated,
                        :explanation, :action_taken, :fingerprint
                    )
                """),
                {
                    "document_id": doc_id,
                    "tenant_id": tenant_id,
                    "finding_type": str(finding.get("policy_type") or "PII"),
                    "matched_pattern": field_type,
                    "matched_text": _safe_matched_text(finding),
                    "risk_level": str(finding.get("severity") or risk_level),
                    "recommendation": str(finding.get("explanation") or "Review and keep redacted output."),
                    "impact": str(finding.get("policy_violated") or ""),
                    "priority": str(finding.get("severity") or risk_level),
                    "location_evidence": str(finding.get("location") or ""),
                    "field_type": field_type,
                    "page_number": finding.get("page_number") or finding.get("page"),
                    "line_number": finding.get("line_number"),
                    "paragraph_number": finding.get("paragraph_number"),
                    "char_start": finding.get("start"),
                    "char_end": finding.get("end"),
                    "bbox": _safe_json(finding.get("bounding_box")) if finding.get("bounding_box") else None,
                    "confidence": finding.get("confidence"),
                    "policy_violated": str(finding.get("policy_violated") or ""),
                    "explanation": str(finding.get("explanation") or ""),
                    "action_taken": str(finding.get("action_taken") or finding.get("action") or ""),
                    "fingerprint": str(finding.get("value_hash") or ""),
                },
            )
        conn.commit()

    create_document_audit(doc_id, "UPLOAD", username, f"Document uploaded through gateway request {request_id}", tenant_id=tenant_id)
    create_document_audit(doc_id, "SCAN", "Security Agent", f"Scanned {len(findings)} sensitive field(s)", tenant_id=tenant_id)
    create_document_audit(doc_id, "POLICY_DECISION", "Policy Agent", f"Document decision: {decision}", tenant_id=tenant_id)
    create_document_audit(doc_id, "REDACTION_EXPORT", "Audit Agent", "Redacted text, PDF, and findings report generated", tenant_id=tenant_id)

    return {
        "document_id": doc_id,
        "document_uid": document_uid,
        "scan_id": scan_id,
        "scan_pk": scan_pk,
        "content_sha256": content_sha256,
        "progress": 100,
    }
