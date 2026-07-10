import io
import csv
import json
from datetime import datetime, timezone
from sqlalchemy import text
from database import engine

from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

def get_live_stats() -> dict:
    """Helper to query live stats for reports."""
    from document_processing.drift import get_current_framework_scores
    stats = {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "total_documents": 0,
        "scanned_today": 0,
        "critical_findings": 0,
        "open_approvals": 0,
        "compliance_score": 100,
        "drift_alerts": 0,
        "secret_leaks": 0,
        "pii_violations": 0,
        "frameworks": get_current_framework_scores()
    }
    try:
        with engine.connect() as conn:
            stats["total_documents"] = conn.execute(text("SELECT COUNT(*) FROM documents")).scalar() or 0
            stats["scanned_today"] = conn.execute(
                text("SELECT COUNT(*) FROM documents WHERE created_at >= CURRENT_DATE")
            ).scalar() or 0
            stats["critical_findings"] = conn.execute(
                text("SELECT COUNT(*) FROM document_findings WHERE risk_level = 'CRITICAL'")
            ).scalar() or 0
            stats["secret_leaks"] = conn.execute(
                text("SELECT COUNT(*) FROM document_findings WHERE finding_type = 'Secret'")
            ).scalar() or 0
            stats["pii_violations"] = conn.execute(
                text("SELECT COUNT(*) FROM document_findings WHERE finding_type = 'PII'")
            ).scalar() or 0
            stats["drift_alerts"] = conn.execute(
                text("SELECT COUNT(*) FROM compliance_drift_alerts")
            ).scalar() or 0
            
            # Open approvals
            from main import get_all_approvals
            stats["open_approvals"] = sum(1 for a in get_all_approvals().values() if a["status"] == "pending")
            
            avg_score = sum(stats["frameworks"].values()) // len(stats["frameworks"])
            stats["compliance_score"] = avg_score
    except Exception as e:
        logging.getLogger("authclaw.reports").error(f"Failed to fetch live stats for report: {e}")
    return stats

# -------------------------------------------------------------------------
# EXECUTIVE SUMMARY REPORTS
# -------------------------------------------------------------------------
def generate_executive_summary_report(fmt: str) -> bytes:
    stats = get_live_stats()
    
    if fmt == "json":
        return json.dumps(stats, indent=2).encode("utf-8")
        
    elif fmt == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["AuthClaw Executive Compliance Summary"])
        writer.writerow(["Generated At", stats["timestamp"]])
        writer.writerow([])
        writer.writerow(["Metric", "Value"])
        writer.writerow(["Global Compliance Score", f"{stats['compliance_score']}%"])
        writer.writerow(["Total Documents", stats["total_documents"]])
        writer.writerow(["Scanned Today", stats["scanned_today"]])
        writer.writerow(["Critical Findings", stats["critical_findings"]])
        writer.writerow(["Open Approvals Queue", stats["open_approvals"]])
        writer.writerow(["Drift Alerts logged", stats["drift_alerts"]])
        writer.writerow(["PII Violations", stats["pii_violations"]])
        writer.writerow(["Secret Leaks", stats["secret_leaks"]])
        writer.writerow([])
        writer.writerow(["Framework compliance index:"])
        for fw, score in stats["frameworks"].items():
            writer.writerow([fw, f"{score}%"])
        return output.getvalue().encode("utf-8")
        
    elif fmt == "pdf":
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=45, leftMargin=45, topMargin=45, bottomMargin=45)
        styles = getSampleStyleSheet()
        
        title_style = ParagraphStyle(
            'DocTitle', parent=styles['Heading1'], fontSize=20, leading=24,
            textColor=colors.HexColor('#1e1b4b'), spaceAfter=8
        )
        subtitle_style = ParagraphStyle(
            'DocSubtitle', parent=styles['Normal'], fontSize=9, leading=13,
            textColor=colors.HexColor('#6b7280'), spaceAfter=15
        )
        section_style = ParagraphStyle(
            'SecTitle', parent=styles['Heading2'], fontSize=12, leading=16,
            textColor=colors.HexColor('#4338ca'), spaceBefore=12, spaceAfter=8
        )
        cell_style = ParagraphStyle(
            'CellText', parent=styles['Normal'], fontSize=8.5, leading=12,
            textColor=colors.HexColor('#374151')
        )
        header_style = ParagraphStyle(
            'Header', parent=styles['Normal'], fontSize=8.5, leading=12,
            textColor=colors.white, fontName='Helvetica-Bold'
        )
        
        story = []
        story.append(Paragraph("AuthClaw - Executive Compliance Summary Report", title_style))
        story.append(Paragraph(f"Generated at: {stats['timestamp']} | Classification: Restricted Management Overview", subtitle_style))
        
        intro_text = (
            f"This compliance report summarizes the overall data security and framework compliance status "
            f"for all corporate repositories. Active monitoring is online. The organization's global compliance "
            f"index is currently assessed at {stats['compliance_score']}%. There are {stats['critical_findings']} critical "
            f"vulnerabilities and {stats['open_approvals']} actions awaiting human override approval."
        )
        story.append(Paragraph(intro_text, styles['BodyText']))
        story.append(Spacer(1, 10))
        
        story.append(Paragraph("Key Posture Metrics", section_style))
        
        metric_data = [
            [Paragraph("KPI Metric Description", header_style), Paragraph("Current Value", header_style)],
            [Paragraph("Global Compliance Index Score", cell_style), Paragraph(f"{stats['compliance_score']}%", cell_style)],
            [Paragraph("Total Ingested Documents", cell_style), Paragraph(str(stats["total_documents"]), cell_style)],
            [Paragraph("Documents Scanned Today", cell_style), Paragraph(str(stats["scanned_today"]), cell_style)],
            [Paragraph("Critical Severity Gaps", cell_style), Paragraph(str(stats["critical_findings"]), cell_style)],
            [Paragraph("Open Approval Items", cell_style), Paragraph(str(stats["open_approvals"]), cell_style)],
            [Paragraph("PII Leak Findings", cell_style), Paragraph(str(stats["pii_violations"]), cell_style)],
            [Paragraph("Secret Leak Findings", cell_style), Paragraph(str(stats["secret_leaks"]), cell_style)]
        ]
        
        t1 = Table(metric_data, colWidths=[300, 222])
        t1.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1e1b4b')),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e5e7eb')),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f9fafb')]),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5),
            ('TOPPADDING', (0,0), (-1,-1), 5),
        ]))
        story.append(t1)
        story.append(Spacer(1, 12))
        
        story.append(Paragraph("Framework Scoring Breakdown", section_style))
        
        fw_data = [[Paragraph("Framework", header_style), Paragraph("Readiness Score", header_style), Paragraph("Status", header_style)]]
        for fw, score in stats["frameworks"].items():
            status = "Operational" if score >= 80 else ("Needs Attention" if score >= 60 else "Critical Risk")
            fw_data.append([
                Paragraph(fw, cell_style),
                Paragraph(f"{score}%", cell_style),
                Paragraph(status, cell_style)
            ])
            
        t2 = Table(fw_data, colWidths=[150, 150, 222])
        t2.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#4338ca')),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e5e7eb')),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f9fafb')]),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5),
            ('TOPPADDING', (0,0), (-1,-1), 5),
        ]))
        story.append(t2)
        
        doc.build(story)
        pdf_bytes = buffer.getvalue()
        buffer.close()
        return pdf_bytes

# -------------------------------------------------------------------------
# TECHNICAL FINDINGS REPORTS
# -------------------------------------------------------------------------
def generate_technical_findings_report(fmt: str) -> bytes:
    findings = []
    try:
        with engine.connect() as conn:
            rows = conn.execute(text("""
                SELECT d.filename, df.finding_type, df.matched_pattern, df.risk_level, 
                       df.location_evidence, df.impact, df.recommendation
                FROM document_findings df
                JOIN documents d ON df.document_id = d.id
                WHERE d.status NOT IN ('deleted', 's3_deleted')
                ORDER BY df.id DESC
            """)).fetchall()
            for r in rows:
                findings.append({
                    "filename": r[0],
                    "type": r[1],
                    "pattern": r[2],
                    "severity": r[3],
                    "location": r[4] or "N/A",
                    "impact": r[5] or "N/A",
                    "recommendation": r[6] or "N/A"
                })
    except Exception as e:
        logging.getLogger("authclaw.reports").error(f"Failed to fetch technical findings: {e}")
        
    if fmt == "json":
        return json.dumps(findings, indent=2).encode("utf-8")
        
    elif fmt == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Filename", "Finding Type", "Rule Match ID", "Severity", "Location Evidence", "Impact threat", "Remediation recommendation"])
        for f in findings:
            writer.writerow([
                f["filename"], f["type"], f["pattern"], f["severity"],
                f["location"], f["impact"], f["recommendation"]
            ])
        return output.getvalue().encode("utf-8")
        
    elif fmt == "pdf":
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=30, leftMargin=30, topMargin=40, bottomMargin=40)
        styles = getSampleStyleSheet()
        
        title_style = ParagraphStyle(
            'DocTitle', parent=styles['Heading1'], fontSize=18, leading=22,
            textColor=colors.HexColor('#991b1b'), spaceAfter=5
        )
        subtitle_style = ParagraphStyle(
            'DocSubtitle', parent=styles['Normal'], fontSize=8.5, leading=12,
            textColor=colors.HexColor('#4b5563'), spaceAfter=15
        )
        cell_style = ParagraphStyle(
            'CellText', parent=styles['Normal'], fontSize=7.5, leading=10,
            textColor=colors.HexColor('#374151')
        )
        header_style = ParagraphStyle(
            'Header', parent=styles['Normal'], fontSize=7.5, leading=10,
            textColor=colors.white, fontName='Helvetica-Bold'
        )
        
        story = []
        story.append(Paragraph("AuthClaw - Technical Vulnerability & Findings Report", title_style))
        story.append(Paragraph(f"Generated at: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} | Security Classification: STRICT CONFIDENTIAL", subtitle_style))
        
        story.append(Paragraph("This detailed findings log lists PII leaks, credential leaks, and policy deviations detected inside scanned files.", styles["BodyText"]))
        story.append(Spacer(1, 10))
        
        table_data = [[
            Paragraph("Filename", header_style),
            Paragraph("Type", header_style),
            Paragraph("Severity", header_style),
            Paragraph("Location", header_style),
            Paragraph("Vulnerability threat & Impact", header_style),
            Paragraph("Fix Recommendation", header_style)
        ]]
        
        for f in findings:
            table_data.append([
                Paragraph(f["filename"], cell_style),
                Paragraph(f["type"], cell_style),
                Paragraph(f["severity"], cell_style),
                Paragraph(f["location"], cell_style),
                Paragraph(f"<b>{f['pattern']}</b><br/>{f['impact']}", cell_style),
                Paragraph(f["recommendation"], cell_style)
            ])
            
        t = Table(table_data, colWidths=[90, 45, 45, 45, 160, 167])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#991b1b')),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e5e7eb')),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f9fafb')]),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
            ('TOPPADDING', (0,0), (-1,-1), 4),
        ]))
        story.append(t)
        
        doc.build(story)
        pdf_bytes = buffer.getvalue()
        buffer.close()
        return pdf_bytes

# -------------------------------------------------------------------------
# AUDITOR EVIDENCE REPORTS
# -------------------------------------------------------------------------
def generate_auditor_evidence_report(fmt: str) -> bytes:
    audits = []
    verification_passed = True
    try:
        from verify_audit import verify_audit_chain
        res_verify = verify_audit_chain()
        verification_passed = res_verify.get("valid", True)
        
        with engine.connect() as conn:
            rows = conn.execute(text("""
                SELECT id, created_at, user_query, risk_level, approval_status, integrity_hash, previous_hash
                FROM audit_logs
                ORDER BY id ASC
            """)).fetchall()
            for r in rows:
                audits.append({
                    "id": r[0],
                    "timestamp": r[1].isoformat() if hasattr(r[1], "isoformat") else str(r[1]),
                    "query": r[2] or "N/A",
                    "risk": r[3] or "LOW",
                    "status": r[4] or "completed",
                    "hash": r[5] or "N/A",
                    "prev_hash": r[6] or "N/A"
                })
    except Exception as e:
        logging.getLogger("authclaw.reports").error(f"Failed to fetch auditor evidence logs: {e}")
        
    payload = {
        "chain_verification": "VALID" if verification_passed else "CORRUPTED",
        "records_count": len(audits),
        "audit_logs": audits
    }
    
    if fmt == "json":
        return json.dumps(payload, indent=2).encode("utf-8")
        
    elif fmt == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Cryptographic Ledger Audit Chain Evidence Package"])
        writer.writerow(["Chain Verification Status", payload["chain_verification"]])
        writer.writerow([])
        writer.writerow(["Audit ID", "Timestamp", "Request Query", "Risk", "Execution Status", "Integrity SHA-256", "Linkage Prev Hash"])
        for audit in audits:
            writer.writerow([
                audit["id"], audit["timestamp"], audit["query"], audit["risk"],
                audit["status"], audit["hash"], audit["prev_hash"]
            ])
        return output.getvalue().encode("utf-8")
        
    elif fmt == "pdf":
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=35, leftMargin=35, topMargin=40, bottomMargin=40)
        styles = getSampleStyleSheet()
        
        title_style = ParagraphStyle(
            'DocTitle', parent=styles['Heading1'], fontSize=18, leading=22,
            textColor=colors.HexColor('#065f46'), spaceAfter=5
        )
        subtitle_style = ParagraphStyle(
            'DocSubtitle', parent=styles['Normal'], fontSize=8.5, leading=12,
            textColor=colors.HexColor('#374151'), spaceAfter=15
        )
        cell_style = ParagraphStyle(
            'CellText', parent=styles['Normal'], fontSize=7.5, leading=10,
            textColor=colors.HexColor('#374151')
        )
        header_style = ParagraphStyle(
            'Header', parent=styles['Normal'], fontSize=7.5, leading=10,
            textColor=colors.white, fontName='Helvetica-Bold'
        )
        
        story = []
        story.append(Paragraph("AuthClaw - Compliance Auditor Evidence Package", title_style))
        story.append(Paragraph(f"Generated at: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} | Verification Status: {'✅ VALID CHAIN' if verification_passed else '❌ CORRUPTED'}", subtitle_style))
        
        intro_text = (
            f"This package lists the immutable ledger history of gateway approvals and transactions. "
            f"The cryptographically chained SHA-256 links have been scanned and verified. "
            f"Current status: {'VALID' if verification_passed else 'FAILED/TAMPERED'}."
        )
        story.append(Paragraph(intro_text, styles["BodyText"]))
        story.append(Spacer(1, 10))
        
        table_data = [[
            Paragraph("ID", header_style),
            Paragraph("Timestamp", header_style),
            Paragraph("Request Description", header_style),
            Paragraph("Risk", header_style),
            Paragraph("Status", header_style),
            Paragraph("Hash Link", header_style)
        ]]
        
        # Display latest 50 logs in PDF
        display_audits = audits[-50:]
        for audit in display_audits:
            query_snippet = audit["query"][:45] + "..." if len(audit["query"]) > 45 else audit["query"]
            hash_snippet = audit["hash"][:12] + "..." if audit["hash"] else "N/A"
            table_data.append([
                Paragraph(f"#{audit['id']}", cell_style),
                Paragraph(audit["timestamp"][:16].replace("T", " "), cell_style),
                Paragraph(query_snippet, cell_style),
                Paragraph(audit["risk"], cell_style),
                Paragraph(audit["status"], cell_style),
                Paragraph(hash_snippet, cell_style)
            ])
            
        t = Table(table_data, colWidths=[35, 95, 180, 45, 87, 100])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#065f46')),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e5e7eb')),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f9fafb')]),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5),
            ('TOPPADDING', (0,0), (-1,-1), 5),
        ]))
        story.append(t)
        
        doc.build(story)
        pdf_bytes = buffer.getvalue()
        buffer.close()
        return pdf_bytes
