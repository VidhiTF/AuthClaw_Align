import io
import csv
from datetime import datetime, timezone
from sqlalchemy import text
from database import engine

from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

def generate_audit_csv(tenant_id: int = None) -> bytes:
    """Generates a CSV byte stream of all audit logs."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Record ID", "Timestamp", "User Query", "Response", 
        "Allowed", "Risk Level", "Approval Status", 
        "Block Integrity Hash", "Previous Hash"
    ])
    
    with engine.connect() as conn:
        res = conn.execute(text("""
            SELECT id, created_at, user_query, response, allowed, risk_level, approval_status, integrity_hash, previous_hash 
            FROM audit_logs 
            WHERE (:tenant_id IS NULL OR tenant_id = :tenant_id)
            ORDER BY id ASC
        """), {"tenant_id": tenant_id})
        for row in res:
            allowed_str = "Allowed" if row[4] else "Blocked"
            created_at_str = row[1].isoformat() if hasattr(row[1], "isoformat") else str(row[1])
            writer.writerow([
                row[0], created_at_str, row[2], row[3],
                allowed_str, row[5], row[6], row[7], row[8]
            ])
            
    return output.getvalue().encode("utf-8")

def generate_evidence_csv(tenant_id: int = None) -> bytes:
    """Generates a CSV byte stream of all vaulted evidence."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Evidence ID", "Name", "Category", "File Path", "Collected At", "Verification Hash"
    ])
    
    with engine.connect() as conn:
        res = conn.execute(text("""
            SELECT id, name, category, file_path, collected_at, hash 
            FROM compliance_evidence 
            WHERE (:tenant_id IS NULL OR tenant_id = :tenant_id)
            ORDER BY id ASC
        """), {"tenant_id": tenant_id})
        for row in res:
            writer.writerow([
                row[0], row[1], row[2], row[3], row[4], row[5]
            ])
            
    return output.getvalue().encode("utf-8")

def generate_audit_pdf(tenant_id: int = None) -> bytes:
    """Generates a professional PDF compliance assessment report of the Audit Logs."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40
    )
    
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontSize=22,
        leading=26,
        textColor=colors.HexColor('#4c1d95'), # Violet 900
        spaceAfter=10
    )
    
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#6b7280'), # Gray 500
        spaceAfter=20
    )
    
    h2_style = ParagraphStyle(
        'DocH2',
        parent=styles['Heading2'],
        fontSize=14,
        leading=18,
        textColor=colors.HexColor('#111827'),
        spaceBefore=15,
        spaceAfter=10
    )
    
    cell_style = ParagraphStyle(
        'CellText',
        parent=styles['Normal'],
        fontSize=8,
        leading=10,
        textColor=colors.HexColor('#374151')
    )
    
    header_style = ParagraphStyle(
        'HeaderText',
        parent=styles['Normal'],
        fontSize=8,
        leading=10,
        textColor=colors.white,
        fontName='Helvetica-Bold'
    )

    story = []
    
    # Header Section
    story.append(Paragraph("AuthClaw Compliance Audit Ledger", title_style))
    story.append(Paragraph(f"Generated on: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} | Classification: Internal Confidential", subtitle_style))
    story.append(Spacer(1, 10))
    
    # Introduction / Executive Summary paragraph
    intro_text = (
        "This document contains a cryptographically verified ledger of security gateway request logs. "
        "Each log entry represents a query analyzed by the AuthClaw prompt firewall, showing the "
        "calculated risk score, allowed status, and the blockchain-style SHA-256 integrity hash "
        "validating that logs have not been tampered with or modified since creation."
    )
    story.append(Paragraph(intro_text, styles['BodyText']))
    story.append(Spacer(1, 15))
    
    # Fetch audit logs
    story.append(Paragraph("Ledger Records", h2_style))
    
    # Table headers
    table_data = [[
        Paragraph("ID", header_style),
        Paragraph("Timestamp", header_style),
        Paragraph("User Query", header_style),
        Paragraph("Risk Level", header_style),
        Paragraph("Status", header_style),
        Paragraph("Block Hash Link", header_style)
    ]]
    
    with engine.connect() as conn:
        res = conn.execute(text("""
            SELECT id, created_at, user_query, risk_level, approval_status, integrity_hash, allowed 
            FROM audit_logs 
            WHERE (:tenant_id IS NULL OR tenant_id = :tenant_id)
            ORDER BY id DESC 
            LIMIT 50
        """), {"tenant_id": tenant_id}).fetchall()
        
    for row in res:
        created_str = row[1].strftime('%Y-%m-%d %H:%M') if hasattr(row[1], "strftime") else str(row[1])[:16]
        query_snippet = row[2][:30] + "..." if len(row[2]) > 30 else row[2]
        hash_snippet = row[5][:10] + "..." if row[5] else "N/A"
        status_str = "Allowed" if row[6] else "Blocked"
        if row[4] == "PENDING_APPROVAL":
            status_str = "Pending Approval"
            
        table_data.append([
            Paragraph(f"#{row[0]}", cell_style),
            Paragraph(created_str, cell_style),
            Paragraph(query_snippet, cell_style),
            Paragraph(row[3] or "LOW", cell_style),
            Paragraph(status_str, cell_style),
            Paragraph(hash_snippet, cell_style)
        ])
        
    # Column widths (total width = 532 pt for letter size minus margins)
    col_widths = [40, 90, 140, 60, 100, 102]
    
    t = Table(table_data, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#4c1d95')), # Violet header
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('BOTTOMPADDING', (0,0), (-1,0), 6),
        ('TOPPADDING', (0,0), (-1,0), 6),
        ('BOTTOMPADDING', (0,1), (-1,-1), 5),
        ('TOPPADDING', (0,1), (-1,-1), 5),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e5e7eb')),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f9fafb')])
    ]))
    
    story.append(t)
    doc.build(story)
    
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes

def generate_evidence_pdf(tenant_id: int = None) -> bytes:
    """Generates a professional PDF compliance assessment report of the vaulted evidence."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=45, leftMargin=45, topMargin=45, bottomMargin=45
    )
    
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontSize=20,
        leading=24,
        textColor=colors.HexColor('#db2777'), # Pink 600
        spaceAfter=10
    )
    
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#6b7280'),
        spaceAfter=20
    )
    
    h2_style = ParagraphStyle(
        'DocH2',
        parent=styles['Heading2'],
        fontSize=13,
        leading=17,
        textColor=colors.HexColor('#1f2937'),
        spaceBefore=15,
        spaceAfter=8
    )
    
    cell_style = ParagraphStyle(
        'CellText',
        parent=styles['Normal'],
        fontSize=8,
        leading=11,
        textColor=colors.HexColor('#374151')
    )
    
    header_style = ParagraphStyle(
        'HeaderText',
        parent=styles['Normal'],
        fontSize=8.5,
        leading=11,
        textColor=colors.white,
        fontName='Helvetica-Bold'
    )

    story = []
    
    story.append(Paragraph("AuthClaw Compliance Evidence Vault", title_style))
    story.append(Paragraph(f"Generated on: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} | Security Classification: Restricted Confidential", subtitle_style))
    story.append(Spacer(1, 10))
    
    intro_text = (
        "This report aggregates all compliance evidence documents currently vaulted within the AuthClaw Platform. "
        "Each record registers the official description, associated compliance standard framework (e.g. SOC2, GDPR, HIPAA), "
        "system file location path, retrieval date, and the security verification hash seal."
    )
    story.append(Paragraph(intro_text, styles['BodyText']))
    story.append(Spacer(1, 15))
    
    story.append(Paragraph("Vaulted Evidence Registry", h2_style))
    
    table_data = [[
        Paragraph("ID", header_style),
        Paragraph("Evidence Description Name", header_style),
        Paragraph("Category", header_style),
        Paragraph("Mapped File Path", header_style),
        Paragraph("Collected At", header_style),
        Paragraph("Verification Hash", header_style)
    ]]
    
    with engine.connect() as conn:
        res = conn.execute(text("""
            SELECT id, name, category, file_path, collected_at, hash 
            FROM compliance_evidence 
            WHERE (:tenant_id IS NULL OR tenant_id = :tenant_id)
            ORDER BY id DESC
        """), {"tenant_id": tenant_id}).fetchall()
        
    for row in res:
        table_data.append([
            Paragraph(f"#{row[0]}", cell_style),
            Paragraph(row[1], cell_style),
            Paragraph(row[2], cell_style),
            Paragraph(row[3], cell_style),
            Paragraph(row[4], cell_style),
            Paragraph(row[5], cell_style)
        ])
        
    # Column widths (total = 522 pt for margins)
    col_widths = [35, 137, 60, 120, 70, 100]
    
    t = Table(table_data, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#db2777')), # Pink header
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('BOTTOMPADDING', (0,0), (-1,0), 6),
        ('TOPPADDING', (0,0), (-1,0), 6),
        ('BOTTOMPADDING', (0,1), (-1,-1), 5),
        ('TOPPADDING', (0,1), (-1,-1), 5),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e5e7eb')),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f9fafb')])
    ]))
    
    story.append(t)
    doc.build(story)
    
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes
