import io
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

def generate_history_pdf(scans, username='Auditor', safety_score=85):
    """
    Generates a beautifully branded PDF audit report from scan records using ReportLab.
    Returns bytes buffer.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=colors.HexColor('#0f172a'),
        alignment=TA_LEFT
    )

    subtitle_style = ParagraphStyle(
        'DocSub',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#64748b'),
        alignment=TA_LEFT
    )

    header_cell_style = ParagraphStyle(
        'HeaderCell',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=9,
        leading=11,
        textColor=colors.white,
        alignment=TA_CENTER
    )

    cell_style = ParagraphStyle(
        'CellText',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8,
        leading=10,
        textColor=colors.HexColor('#1e293b')
    )

    cell_center = ParagraphStyle(
        'CellCenter',
        parent=cell_style,
        alignment=TA_CENTER
    )

    story = []

    # 1. Header Banner Table
    banner_data = [
        [
            Paragraph("🛡️ <b>CYBERSEC TOOLKIT</b>", title_style),
            Paragraph(f"<b>Overall Safety Score:</b> {safety_score}/100", ParagraphStyle('Score', parent=title_style, fontSize=13, alignment=TA_RIGHT, textColor=colors.HexColor('#0d9488')))
        ],
        [
            Paragraph(f"Defensive Security Audit Log &bull; User: <b>{username}</b>", subtitle_style),
            Paragraph(f"Exported: {len(scans)} records", ParagraphStyle('SubR', parent=subtitle_style, alignment=TA_RIGHT))
        ]
    ]

    banner_table = Table(banner_data, colWidths=[360, 180])
    banner_table.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 2),
        ('TOPPADDING', (0,0), (-1,-1), 2),
    ]))
    story.append(banner_table)

    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#0d9488'), spaceAfter=14))

    # 2. Executive Summary Metrics Box
    safe_count = sum(1 for s in scans if 'Safe' in s.get('verdict', '') or 'Strong' in s.get('verdict', ''))
    susp_count = sum(1 for s in scans if 'Suspicious' in s.get('verdict', '') or 'Moderate' in s.get('verdict', ''))
    mal_count = len(scans) - safe_count - susp_count

    summary_data = [
        [
            Paragraph(f"<b>Total Scans</b><br/><font size=12 color='#0f172a'>{len(scans)}</font>", cell_center),
            Paragraph(f"<b>Safe / Strong</b><br/><font size=12 color='#10b981'>{safe_count}</font>", cell_center),
            Paragraph(f"<b>Suspicious</b><br/><font size=12 color='#f59e0b'>{susp_count}</font>", cell_center),
            Paragraph(f"<b>High Risk / Malicious</b><br/><font size=12 color='#ef4444'>{mal_count}</font>", cell_center)
        ]
    ]
    summary_table = Table(summary_data, colWidths=[135, 135, 135, 135])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f8fafc')),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#e2e8f0')),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
        ('TOPPADDING', (0,0), (-1,-1), 8),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 16))

    # 3. Main Scan Results Table
    table_headers = [
        Paragraph("Tool", header_cell_style),
        Paragraph("Target / Subject", header_cell_style),
        Paragraph("Risk Score", header_cell_style),
        Paragraph("Verdict", header_cell_style),
        Paragraph("Date & Time", header_cell_style)
    ]
    table_rows = [table_headers]

    for scan in scans:
        verdict = scan.get('verdict', 'Unknown')
        verdict_color = '#10b981' if ('Safe' in verdict or 'Strong' in verdict) else ('#f59e0b' if ('Suspicious' in verdict or 'Moderate' in verdict) else '#ef4444')
        
        target_display = scan.get('target', '')
        if len(target_display) > 42:
            target_display = target_display[:39] + '...'

        table_rows.append([
            Paragraph(scan.get('tool_type', '').upper(), cell_center),
            Paragraph(target_display, cell_style),
            Paragraph(f"{scan.get('risk_score', 0)}/100", cell_center),
            Paragraph(f"<font color='{verdict_color}'><b>{verdict}</b></font>", cell_center),
            Paragraph(scan.get('created_at', ''), cell_center)
        ])

    results_table = Table(table_rows, colWidths=[65, 230, 65, 80, 100])
    results_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1e293b')),
        ('ALIGN', (0,0), (-1,0), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f8fafc')]),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
    ]))
    story.append(results_table)

    story.append(Spacer(1, 20))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#cbd5e1'), spaceAfter=8))
    
    footer_text = Paragraph(
        "<i>Educational & Defensive Cybersecurity Toolkit &bull; Zero-Knowledge Local Analysis &bull; Confidential &bull; Generated automatically</i>",
        ParagraphStyle('Footer', parent=subtitle_style, alignment=TA_CENTER, fontSize=8)
    )
    story.append(footer_text)

    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()
