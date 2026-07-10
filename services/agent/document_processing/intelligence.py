import base64
import io
from typing import Dict, List, Tuple

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Preformatted, Spacer

from document_processing.parsers import DocumentExtractionResult
from services.sensitive_data_detection import SensitiveDataDetector


def analyze_and_redact_document(
    extraction: DocumentExtractionResult,
    username: str,
    tenant_id=None,
) -> Dict[str, object]:
    detector = SensitiveDataDetector(tenant_id)
    redacted_pages = []
    findings = []

    for page in extraction.pages:
        page_redacted, page_findings = _redact_page(detector, page.text or "", page.page_number, page.source, username)
        redacted_pages.append({
            "page": page.page_number,
            "source": page.source,
            "text": page_redacted,
        })
        findings.extend(page_findings)

    redacted_text = "\n\n".join(page["text"] for page in redacted_pages if page["text"])
    extracted_text = extraction.text
    report = {
        "total_findings": len(findings),
        "fields": findings,
        "extraction_method": extraction.extraction_method,
        "ocr_status": extraction.ocr_status,
    }
    blocked = sum(1 for finding in findings if finding.get("action_taken") == "block")
    summary = {
        "total_findings": len(findings),
        "blocked_findings": blocked,
        "redacted_findings": len(findings) - blocked,
        "status": "blocked" if blocked else ("redacted" if findings else "clean"),
    }

    return {
        "extracted_text": extracted_text,
        "redacted_text": redacted_text,
        "redacted_pages": redacted_pages,
        "findings": findings,
        "findings_report": report,
        "metadata": {
            "page_count": len(extraction.pages),
            "extraction_method": extraction.extraction_method,
            "ocr_status": extraction.ocr_status,
            "ocr_error": extraction.ocr_error,
        },
        "compliance_summary": summary,
        "redacted_pdf_base64": base64.b64encode(
            generate_redacted_pdf(redacted_pages, findings, extraction.extraction_method)
        ).decode("ascii"),
    }


def _redact_page(
    detector: SensitiveDataDetector,
    text: str,
    page_number: int,
    source: str,
    username: str,
) -> Tuple[str, List[Dict[str, object]]]:
    findings = detector.inspect(text)
    redacted = text
    metadata: List[Dict[str, object]] = []

    for finding in sorted(findings, key=lambda item: item.start, reverse=True):
        action = detector.action_for(finding.entity_type, finding.confidence)
        replacement = detector.replacement_for(finding, action)
        redacted = redacted[:finding.start] + replacement + redacted[finding.end:]
        item = detector.to_policy_finding(finding, action, username)
        item.update({
            "field_type": finding.entity_type,
            "page": page_number,
            "location": f"page {page_number}, characters {finding.start}-{finding.end}",
            "start": finding.start,
            "end": finding.end,
            "source": source,
            "action_taken": action,
            "snippet": _safe_snippet(text, finding.start, finding.end),
        })
        metadata.append(item)

    metadata.reverse()
    return redacted, metadata


def _safe_snippet(text: str, start: int, end: int) -> str:
    before = text[max(0, start - 24):start]
    after = text[end:min(len(text), end + 24)]
    return f"{before}[SENSITIVE]{after}".replace("\n", " ").strip()


def generate_redacted_pdf(redacted_pages: List[Dict[str, object]], findings: List[Dict[str, object]], extraction_method: str) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, title="AuthClaw Redacted Document")
    styles = getSampleStyleSheet()
    story = [
        Paragraph("AuthClaw Redacted Document", styles["Title"]),
        Paragraph(f"Extraction method: {extraction_method}", styles["Normal"]),
        Paragraph(f"Sensitive findings redacted: {len(findings)}", styles["Normal"]),
        Spacer(1, 12),
    ]

    for page in redacted_pages:
        story.append(Paragraph(f"Page {page['page']}", styles["Heading2"]))
        text = str(page.get("text") or "No extractable text on this page.")
        story.append(Preformatted(text[:6000], styles["Code"]))
        story.append(Spacer(1, 12))

    doc.build(story)
    return buffer.getvalue()
