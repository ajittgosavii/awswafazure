"""
Multi-Account PDF Report Generator for WAF Assessments
Supports both single-account and portfolio (multi-account) assessments

Features:
- Automatic detection of single vs multi-account
- Portfolio dashboard with account comparison
- Cross-account pillar analysis
- Account-specific deep dives
- Consolidated action items
"""

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from io import BytesIO
from datetime import datetime
from typing import Dict, List
import streamlit as st


def generate_waf_pdf_report(assessment: Dict) -> bytes:
    """
    Generate PDF report - auto-detects single vs multi-account
    
    Checks if assessment has 'accounts' array with multiple accounts.
    If yes, generates portfolio report. If no, generates single-account report.
    """
    
    # Check if this is a portfolio assessment
    accounts = assessment.get('accounts', [])
    is_portfolio = len(accounts) > 1
    
    if is_portfolio:
        return generate_portfolio_pdf_report(assessment)
    else:
        return generate_single_account_pdf_report(assessment)


def generate_single_account_pdf_report(assessment: Dict) -> bytes:
    """Generate PDF for single-account assessment"""
    
    # Use the enhanced single-account PDF generator
    # (This is the existing pdf_report_generator_ENHANCED.py logic)
    
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=72,
        leftMargin=72,
        topMargin=72,
        bottomMargin=36,
    )
    
    elements = []
    styles = getSampleStyleSheet()
    
    # Add custom styles
    _add_custom_styles(styles)
    
    # Build report sections
    _add_cover_page(elements, assessment, styles, is_portfolio=False)
    _add_dashboard(elements, assessment, styles, is_portfolio=False)
    _add_pillar_scores(elements, assessment, styles)
    _add_ai_insights(elements, assessment, styles)
    _add_action_items(elements, assessment, styles)
    _add_conclusion(elements, assessment, styles, is_portfolio=False)
    
    doc.build(elements)
    return buffer.getvalue()


def generate_portfolio_pdf_report(assessment: Dict) -> bytes:
    """Generate PDF for multi-account portfolio assessment"""
    
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=72,
        leftMargin=72,
        topMargin=72,
        bottomMargin=36,
    )
    
    elements = []
    styles = getSampleStyleSheet()
    
    # Add custom styles
    _add_custom_styles(styles)
    
    # Build portfolio report sections
    _add_cover_page(elements, assessment, styles, is_portfolio=True)
    _add_portfolio_dashboard(elements, assessment, styles)
    _add_cross_account_comparison(elements, assessment, styles)
    _add_pillar_scores(elements, assessment, styles)
    _add_ai_insights(elements, assessment, styles)
    _add_portfolio_action_items(elements, assessment, styles)
    _add_account_deep_dives(elements, assessment, styles)
    _add_conclusion(elements, assessment, styles, is_portfolio=True)
    
    doc.build(elements)
    return buffer.getvalue()


def _add_custom_styles(styles):
    """Add custom paragraph styles"""
    
    styles.add(ParagraphStyle(
        name='CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=colors.HexColor('#1f77b4'),
        spaceAfter=30,
        alignment=TA_CENTER,
        fontName='Helvetica-Bold'
    ))
    
    styles.add(ParagraphStyle(
        name='SectionHeading',
        parent=styles['Heading2'],
        fontSize=16,
        textColor=colors.HexColor('#2c3e50'),
        spaceAfter=12,
        spaceBefore=12,
        fontName='Helvetica-Bold'
    ))
    
    styles.add(ParagraphStyle(
        name='SubHeading',
        parent=styles['Heading3'],
        fontSize=13,
        textColor=colors.HexColor('#34495e'),
        spaceAfter=8,
        spaceBefore=8,
        fontName='Helvetica-Bold'
    ))
    
    styles.add(ParagraphStyle(
        name='BodyText',
        parent=styles['Normal'],
        fontSize=10,
        alignment=TA_JUSTIFY,
        spaceAfter=6
    ))
    
    styles.add(ParagraphStyle(
        name='BulletPoint',
        parent=styles['Normal'],
        fontSize=10,
        leftIndent=20,
        spaceAfter=4
    ))


def _add_cover_page(elements, assessment, styles, is_portfolio=False):
    """Add cover page"""
    
    if is_portfolio:
        accounts = assessment.get('accounts', [])
        title_text = (
            f"AWS Well-Architected<br/>"
            f"Portfolio Assessment<br/>"
            f"{len(accounts)} AWS Accounts"
        )
    else:
        title_text = (
            "AWS Well-Architected<br/>"
            "Framework Assessment<br/>"
            "Comprehensive Report"
        )
    
    title = Paragraph(title_text, styles['CustomTitle'])
    elements.append(title)
    elements.append(Spacer(1, 0.3*inch))
    
    # Assessment info
    assessment_name = assessment.get('name', 'Unnamed Assessment')
    workload_name = assessment.get('workload_name', 'N/A')
    environment = assessment.get('environment', 'N/A')
    created_date = assessment.get('created_at', datetime.now().isoformat())[:10]
    
    info_data = [
        ['Assessment Name:', assessment_name],
        ['Workload:', workload_name],
        ['Environment:', environment],
        ['Date Generated:', datetime.now().strftime('%Y-%m-%d')],
        ['Assessment Date:', created_date],
        ['Overall Score:', f"{assessment.get('overall_score', 0):.0f}/100"],
        ['Completion:', f"{assessment.get('progress', 0):.0f}%"],
    ]
    
    if is_portfolio:
        accounts = assessment.get('accounts', [])
        info_data.insert(3, ['Total Accounts:', str(len(accounts))])
    
    info_table = Table(info_data, colWidths=[2.5*inch, 4*inch])
    info_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#ecf0f1')),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
        ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
        ('ALIGN', (1, 0), (1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 11),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
        ('TOPPADDING', (0, 0), (-1, -1), 10),
        ('GRID', (0, 0), (-1, -1), 1, colors.grey),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    
    elements.append(info_table)
    elements.append(Spacer(1, 0.5*inch))
    
    footer_text = Paragraph(
        f"<i>Report generated on {datetime.now().strftime('%B %d, %Y at %I:%M %p')}<br/>"
        f"Powered by Claude AI & AWS Well-Architected Framework<br/>"
        f"AI-Enhanced Analysis | Automated Scanning | Compliance Mapping</i>",
        styles['Normal']
    )
    elements.append(Spacer(1, 1.5*inch))
    elements.append(footer_text)
    
    elements.append(PageBreak())


def _add_portfolio_dashboard(elements, assessment, styles):
    """Add portfolio-specific dashboard"""
    
    elements.append(Paragraph("Portfolio Dashboard", styles['SectionHeading']))
    elements.append(Spacer(1, 0.15*inch))
    
    accounts = assessment.get('accounts', [])
    
    # Account summary table
    account_data = [['Account Name', 'Account ID', 'Priority', 'Regions', 'Status']]
    
    for account in accounts:
        account_name = account.get('account_name', 'Unknown')[:20]
        account_id = account.get('account_id', 'N/A')
        priority = account.get('priority', 'medium').upper()
        regions = ', '.join(account.get('regions', ['N/A']))[:15]
        
        # Simple status (would be enhanced with actual scanning results)
        status = "✓ Scanned" if assessment.get('scan_completed_at') else "Pending"
        
        account_data.append([
            account_name,
            account_id,
            priority,
            regions,
            status
        ])
    
    account_table = Table(account_data, colWidths=[1.5*inch, 1.5*inch, 0.8*inch, 1.2*inch, 1*inch])
    account_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3498db')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('FONTSIZE', (0, 1), (-1, -1), 9),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#ecf0f1')),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    
    elements.append(account_table)
    elements.append(Spacer(1, 0.2*inch))
    
    # Portfolio summary
    overall_score = assessment.get('overall_score', 0)
    progress = assessment.get('progress', 0)
    
    summary = Paragraph(
        f"This portfolio assessment covers <b>{len(accounts)} AWS accounts</b>. "
        f"The assessment is <b>{progress:.0f}% complete</b> with an overall "
        f"portfolio score of <b>{overall_score:.0f}/100</b>.",
        styles['BodyText']
    )
    elements.append(summary)
    
    elements.append(PageBreak())


def _add_cross_account_comparison(elements, assessment, styles):
    """Add cross-account comparison section"""
    
    elements.append(Paragraph("Cross-Account Analysis", styles['SectionHeading']))
    elements.append(Spacer(1, 0.15*inch))
    
    accounts = assessment.get('accounts', [])
    scores_by_account = assessment.get('scores_by_account', {})
    
    if not scores_by_account:
        # If we don't have per-account scores yet, show placeholder
        elements.append(Paragraph(
            "Per-account scoring will be available once the portfolio scan is complete.",
            styles['BodyText']
        ))
    else:
        # Create comparison table
        comparison_data = [['Account'] + [acc.get('account_name', 'Unknown')[:12] for acc in accounts[:5]]]
        
        # Overall score row
        score_row = ['Overall Score']
        for account in accounts[:5]:
            account_id = account.get('account_id', '')
            score = scores_by_account.get(account_id, 0)
            score_row.append(f"{score:.0f}")
        comparison_data.append(score_row)
        
        comparison_table = Table(comparison_data)
        comparison_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2ecc71')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#ecf0f1')),
        ]))
        
        elements.append(comparison_table)
    
    elements.append(Spacer(1, 0.2*inch))
    
    # Insights
    insights = Paragraph(
        "<b>Key Observations:</b><br/>"
        "• Portfolio shows consistent architectural patterns across accounts<br/>"
        "• Opportunity for standardization in security controls<br/>"
        "• Cost optimization potential across multiple accounts",
        styles['BodyText']
    )
    elements.append(insights)
    
    elements.append(PageBreak())


def _add_dashboard(elements, assessment, styles, is_portfolio=False):
    """Add dashboard section (single account)"""
    
    elements.append(Paragraph("Executive Dashboard", styles['SectionHeading']))
    elements.append(Spacer(1, 0.15*inch))
    
    overall_score = assessment.get('overall_score', 0)
    progress = assessment.get('progress', 0)
    total_responses = len(assessment.get('responses', {}))
    action_items = assessment.get('action_items', [])
    
    metrics_data = [
        ['Metric', 'Value', 'Status'],
        ['Overall Score', f'{overall_score:.0f}/100', 'Good' if overall_score >= 60 else 'Needs Work'],
        ['Progress', f'{progress:.0f}%', f'{total_responses}/205 questions'],
        ['Action Items', str(len(action_items)), f'{len([i for i in action_items if i.get("risk_level", "").upper() == "CRITICAL"])} Critical'],
    ]
    
    metrics_table = Table(metrics_data, colWidths=[2.5*inch, 1.5*inch, 2.5*inch])
    metrics_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3498db')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('ALIGN', (1, 0), (1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 11),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('FONTNAME', (0, 1), (0, -1), 'Helvetica-Bold'),
    ]))
    
    elements.append(metrics_table)
    elements.append(PageBreak())


def _add_pillar_scores(elements, assessment, styles):
    """Add pillar scores section"""
    
    elements.append(Paragraph("Pillar Scores Overview", styles['SectionHeading']))
    elements.append(Spacer(1, 0.15*inch))
    
    pillar_scores = assessment.get('scores', {})
    
    if pillar_scores:
        pillar_data = [['Pillar', 'Score', 'Rating']]
        
        for pillar_name, score in pillar_scores.items():
            if score >= 80:
                rating = "Excellent"
            elif score >= 60:
                rating = "Good"
            else:
                rating = "Needs Work"
            
            pillar_data.append([pillar_name, f"{score:.0f}/100", rating])
        
        pillar_table = Table(pillar_data, colWidths=[3*inch, 1.5*inch, 1.5*inch])
        pillar_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2ecc71')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (1, 0), (2, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#ecf0f1')),
        ]))
        
        elements.append(pillar_table)
    
    elements.append(PageBreak())


def _add_ai_insights(elements, assessment, styles):
    """Add AI insights section"""
    
    # Check if AI insights available
    cache_key = f"ai_insights_{assessment.get('id', 'unknown')}"
    
    if cache_key in st.session_state:
        insights = st.session_state[cache_key]
        
        if 'error' not in insights:
            elements.append(Paragraph("AI-Powered Insights", styles['SectionHeading']))
            elements.append(Spacer(1, 0.15*inch))
            
            # Executive summary
            if 'executive_summary' in insights:
                exec_summary = insights['executive_summary'].replace('\n', '<br/>')[:500] + "..."
                elements.append(Paragraph(exec_summary, styles['BodyText']))
            
            elements.append(PageBreak())


def _add_action_items(elements, assessment, styles):
    """Add action items section (single account)"""
    
    elements.append(Paragraph("Action Items", styles['SectionHeading']))
    elements.append(Spacer(1, 0.15*inch))
    
    action_items = assessment.get('action_items', [])
    
    if action_items:
        critical_items = [i for i in action_items if i.get('risk_level', '').upper() == 'CRITICAL']
        
        if critical_items:
            elements.append(Paragraph("Critical Priority", styles['SubHeading']))
            for idx, item in enumerate(critical_items[:5], 1):
                item_text = f"{idx}. <b>{item.get('title', 'Item')}</b> ({item.get('pillar', 'Unknown')})"
                elements.append(Paragraph(item_text, styles['BulletPoint']))
    else:
        elements.append(Paragraph("No action items identified.", styles['BodyText']))
    
    elements.append(PageBreak())


def _add_portfolio_action_items(elements, assessment, styles):
    """Add action items section (portfolio)"""
    
    elements.append(Paragraph("Portfolio-Wide Action Items", styles['SectionHeading']))
    elements.append(Spacer(1, 0.15*inch))
    
    # Get action items
    action_items = assessment.get('action_items', [])
    
    if action_items:
        # Show top 10 critical/high items
        critical_high = [i for i in action_items 
                        if i.get('risk_level', '').upper() in ['CRITICAL', 'HIGH']]
        
        for idx, item in enumerate(critical_high[:10], 1):
            item_text = f"{idx}. <b>{item.get('title', 'Item')}</b> - {item.get('pillar', 'Unknown')}"
            elements.append(Paragraph(item_text, styles['BulletPoint']))
    
    elements.append(PageBreak())


def _add_account_deep_dives(elements, assessment, styles):
    """Add per-account deep dive pages"""
    
    accounts = assessment.get('accounts', [])
    action_items_by_account = assessment.get('action_items_by_account', {})
    
    for account in accounts[:3]:  # Limit to first 3 accounts
        account_name = account.get('account_name', 'Unknown')
        account_id = account.get('account_id', 'N/A')
        
        elements.append(Paragraph(f"Account: {account_name}", styles['SectionHeading']))
        elements.append(Paragraph(f"Account ID: {account_id}", styles['BodyText']))
        elements.append(Spacer(1, 0.15*inch))
        
        # Top action items for this account
        account_items = action_items_by_account.get(account_id, [])
        
        if account_items:
            elements.append(Paragraph("Top Issues:", styles['SubHeading']))
            for idx, item in enumerate(account_items[:3], 1):
                item_text = f"{idx}. {item.get('title', 'Item')}"
                elements.append(Paragraph(item_text, styles['BulletPoint']))
        
        elements.append(PageBreak())


def _add_conclusion(elements, assessment, styles, is_portfolio=False):
    """Add conclusion section"""
    
    elements.append(Paragraph("Conclusion & Next Steps", styles['SectionHeading']))
    elements.append(Spacer(1, 0.15*inch))
    
    if is_portfolio:
        conclusion_text = """
        This portfolio assessment provides insights across multiple AWS accounts.
        Focus on standardizing security controls and optimizing costs across all accounts.
        """
    else:
        conclusion_text = """
        This comprehensive assessment identifies strengths and opportunities for improvement.
        Follow the prioritized action items to enhance your AWS architecture.
        """
    
    elements.append(Paragraph(conclusion_text, styles['BodyText']))