"""
Multi-Account PDF Report Generator - Production Ready
Auto-detects single vs multi-account assessments and generates appropriate report

Features:
- Single account: Standard comprehensive report
- Multi-account: Portfolio report with cross-account comparison
- Defensive coding: Handles missing data gracefully
- Professional formatting throughout
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
    Main entry point - Auto-detects single vs multi-account
    
    Checks for:
    - 'is_portfolio' flag
    - 'accounts' array with multiple entries
    
    Returns appropriate PDF based on assessment type
    """
    
    # Check if this is a portfolio assessment
    is_portfolio = assessment.get('is_portfolio', False)
    accounts = assessment.get('accounts', [])
    
    # If accounts array has 2+ entries, treat as portfolio
    if not is_portfolio and len(accounts) > 1:
        is_portfolio = True
    
    if is_portfolio and len(accounts) > 1:
        return _generate_portfolio_pdf(assessment, accounts)
    else:
        return _generate_single_account_pdf(assessment)


def _generate_single_account_pdf(assessment: Dict) -> bytes:
    """Generate standard single-account PDF"""
    
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
    styles = _get_styles()
    
    # Build single-account report
    _add_cover_page(elements, assessment, styles, is_portfolio=False)
    _add_executive_dashboard(elements, assessment, styles)
    _add_pillar_scores(elements, assessment, styles)
    _add_ai_insights_section(elements, assessment, styles)
    _add_action_items_section(elements, assessment, styles)
    _add_conclusion(elements, assessment, styles, is_portfolio=False)
    
    doc.build(elements)
    return buffer.getvalue()


def _generate_portfolio_pdf(assessment: Dict, accounts: List[Dict]) -> bytes:
    """Generate portfolio PDF for multiple accounts"""
    
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
    styles = _get_styles()
    
    # Build portfolio report
    _add_cover_page(elements, assessment, styles, is_portfolio=True, account_count=len(accounts))
    _add_portfolio_dashboard(elements, assessment, styles, accounts)
    _add_cross_account_comparison(elements, assessment, styles, accounts)
    _add_pillar_scores(elements, assessment, styles)
    _add_ai_insights_section(elements, assessment, styles)
    _add_portfolio_action_items(elements, assessment, styles, accounts)
    _add_account_deep_dives(elements, assessment, styles, accounts)
    _add_conclusion(elements, assessment, styles, is_portfolio=True)
    
    doc.build(elements)
    return buffer.getvalue()


def _get_styles():
    """Get or create paragraph styles with defensive coding"""
    styles = getSampleStyleSheet()
    
    # Only add if not already defined
    if 'CustomTitle' not in styles:
        styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1f77b4'),
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))
    
    if 'SectionHeading' not in styles:
        styles.add(ParagraphStyle(
            name='SectionHeading',
            parent=styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#2c3e50'),
            spaceAfter=12,
            spaceBefore=12,
            fontName='Helvetica-Bold'
        ))
    
    if 'SubHeading' not in styles:
        styles.add(ParagraphStyle(
            name='SubHeading',
            parent=styles['Heading3'],
            fontSize=13,
            textColor=colors.HexColor('#34495e'),
            spaceAfter=8,
            spaceBefore=8,
            fontName='Helvetica-Bold'
        ))
    
    if 'BodyText' not in styles:
        styles.add(ParagraphStyle(
            name='BodyText',
            parent=styles['Normal'],
            fontSize=10,
            alignment=TA_JUSTIFY,
            spaceAfter=6
        ))
    
    if 'BulletPoint' not in styles:
        styles.add(ParagraphStyle(
            name='BulletPoint',
            parent=styles['Normal'],
            fontSize=10,
            leftIndent=20,
            spaceAfter=4
        ))
    
    return styles


def _add_cover_page(elements, assessment, styles, is_portfolio=False, account_count=0):
    """Add cover page"""
    
    if is_portfolio:
        title_text = (
            f"AWS Well-Architected<br/>"
            f"Portfolio Assessment<br/>"
            f"<font size='18'>{account_count} AWS Accounts</font>"
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
    
    # Assessment metadata
    assessment_name = assessment.get('name', 'Unnamed Assessment')
    workload_name = assessment.get('workload_name', 'N/A')
    environment = assessment.get('environment', 'N/A')
    overall_score = assessment.get('overall_score', 0)
    progress = assessment.get('progress', 0)
    
    info_data = [
        ['Assessment Name:', assessment_name],
        ['Workload:', workload_name],
        ['Environment:', environment],
        ['Overall Score:', f"{overall_score:.0f}/100"],
        ['Completion:', f"{progress:.0f}%"],
        ['Generated:', datetime.now().strftime('%Y-%m-%d %H:%M')],
    ]
    
    if is_portfolio:
        info_data.insert(3, ['Total Accounts:', str(account_count)])
    
    info_table = Table(info_data, colWidths=[2.5*inch, 4*inch])
    info_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#ecf0f1')),
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
    
    # Footer
    footer = Paragraph(
        f"<i>Powered by Claude AI & AWS Well-Architected Framework<br/>"
        f"AI-Enhanced Analysis | Automated Scanning | Compliance Mapping</i>",
        styles['Normal']
    )
    elements.append(Spacer(1, 1.5*inch))
    elements.append(footer)
    elements.append(PageBreak())


def _add_portfolio_dashboard(elements, assessment, styles, accounts):
    """Add portfolio-specific dashboard with account comparison"""
    
    elements.append(Paragraph("Portfolio Dashboard", styles['SectionHeading']))
    elements.append(Spacer(1, 0.15*inch))
    
    # Account summary table
    account_data = [['Account Name', 'Account ID', 'Priority', 'Status']]
    
    scores_by_account = assessment.get('scores_by_account', {})
    
    for account in accounts:
        account_name = account.get('account_name', 'Unknown')[:25]
        account_id = account.get('account_id', 'N/A')
        priority = account.get('priority', 'medium').upper()
        
        # Get score if available
        score = scores_by_account.get(account_id, 0)
        if score >= 80:
            status = f"{score:.0f} - Excellent ✓"
        elif score >= 60:
            status = f"{score:.0f} - Good"
        elif score > 0:
            status = f"{score:.0f} - Needs Work"
        else:
            status = "Not Scored"
        
        account_data.append([account_name, account_id, priority, status])
    
    account_table = Table(account_data, colWidths=[2*inch, 1.8*inch, 1*inch, 1.7*inch])
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
        f"This portfolio assessment covers <b>{len(accounts)} AWS accounts</b> across your "
        f"organization. The portfolio achieves an aggregate score of <b>{overall_score:.0f}/100</b> "
        f"with <b>{progress:.0f}% completion</b>. Review individual account sections for "
        f"detailed findings and recommendations.",
        styles['BodyText']
    )
    elements.append(summary)
    elements.append(PageBreak())


def _add_cross_account_comparison(elements, assessment, styles, accounts):
    """Add cross-account comparison section"""
    
    elements.append(Paragraph("Cross-Account Analysis", styles['SectionHeading']))
    elements.append(Spacer(1, 0.15*inch))
    
    scores_by_account = assessment.get('scores_by_account', {})
    
    if not scores_by_account:
        elements.append(Paragraph(
            "Per-account scoring will be available once all accounts are assessed. "
            "Complete the assessment to see comparative analysis across accounts.",
            styles['BodyText']
        ))
    else:
        # Build comparison table (show up to 5 accounts)
        comparison_data = [['Metric'] + [acc.get('account_name', 'Unknown')[:12] for acc in accounts[:5]]]
        
        # Overall scores
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
        
        # Key insights
        insights = Paragraph(
            "<b>Key Observations:</b><br/>"
            "• Portfolio demonstrates consistent architectural patterns<br/>"
            "• Opportunities for standardization across accounts<br/>"
            "• Consider cross-account governance policies",
            styles['BodyText']
        )
        elements.append(insights)
    
    elements.append(PageBreak())


def _add_executive_dashboard(elements, assessment, styles):
    """Add executive dashboard for single account"""
    
    elements.append(Paragraph("Executive Dashboard", styles['SectionHeading']))
    elements.append(Spacer(1, 0.15*inch))
    
    overall_score = assessment.get('overall_score', 0)
    progress = assessment.get('progress', 0)
    total_responses = len(assessment.get('responses', {}))
    
    # Safe action items retrieval
    raw_action_items = assessment.get('action_items', [])
    action_items = [item for item in raw_action_items if isinstance(item, dict)]
    critical_count = len([i for i in action_items if isinstance(i, dict) and i.get('risk_level', '').upper() == 'CRITICAL'])
    
    metrics_data = [
        ['Metric', 'Value', 'Status'],
        ['Overall Score', f'{overall_score:.0f}/100', 'Good' if overall_score >= 60 else 'Needs Improvement'],
        ['Progress', f'{progress:.0f}%', f'{total_responses}/205 questions'],
        ['Action Items', str(len(action_items)), f'{critical_count} Critical'],
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
    
    elements.append(Paragraph("Pillar Scores", styles['SectionHeading']))
    elements.append(Spacer(1, 0.15*inch))
    
    pillar_scores = assessment.get('scores', {})
    
    if pillar_scores:
        pillar_data = [['Pillar', 'Score', 'Rating']]
        
        pillar_icons = {
            'Operational Excellence': '⚙️',
            'Security': '🔒',
            'Reliability': '🛡️',
            'Performance Efficiency': '⚡',
            'Cost Optimization': '💰',
            'Sustainability': '🌱'
        }
        
        for pillar_name, score in pillar_scores.items():
            icon = pillar_icons.get(pillar_name, '')
            
            if score >= 80:
                rating = "Excellent"
            elif score >= 60:
                rating = "Good"
            else:
                rating = "Needs Work"
            
            pillar_data.append([f"{icon} {pillar_name}", f"{score:.0f}/100", rating])
        
        pillar_table = Table(pillar_data, colWidths=[3.5*inch, 1.5*inch, 1.5*inch])
        pillar_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2ecc71')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (1, 0), (2, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#ecf0f1')),
        ]))
        
        elements.append(pillar_table)
    else:
        elements.append(Paragraph("Complete the assessment to see pillar scores.", styles['BodyText']))
    
    elements.append(PageBreak())


def _add_ai_insights_section(elements, assessment, styles):
    """Add AI insights if available"""
    
    cache_key = f"ai_insights_{assessment.get('id', 'unknown')}"
    
    if cache_key in st.session_state:
        insights = st.session_state[cache_key]
        
        if 'error' not in insights and 'executive_summary' in insights:
            elements.append(Paragraph("AI-Powered Insights", styles['SectionHeading']))
            elements.append(Spacer(1, 0.15*inch))
            
            # Executive summary (truncated for PDF)
            exec_summary = insights.get('executive_summary', '')[:800]
            if exec_summary:
                elements.append(Paragraph(exec_summary.replace('\n', '<br/>'), styles['BodyText']))
                elements.append(Spacer(1, 0.15*inch))
            
            # Key strengths
            if 'overall_assessment' in insights and 'strengths' in insights['overall_assessment']:
                elements.append(Paragraph("Key Strengths", styles['SubHeading']))
                for strength in insights['overall_assessment']['strengths'][:3]:
                    elements.append(Paragraph(f"✓ {strength}", styles['BulletPoint']))
                elements.append(Spacer(1, 0.1*inch))
            
            elements.append(PageBreak())


def _add_action_items_section(elements, assessment, styles):
    """Add action items section with defensive coding"""
    
    elements.append(Paragraph("Action Items", styles['SectionHeading']))
    elements.append(Spacer(1, 0.15*inch))
    
    # Safe retrieval and filtering
    raw_action_items = assessment.get('action_items', [])
    action_items = [item for item in raw_action_items if isinstance(item, dict)]
    
    if action_items:
        critical_items = [i for i in action_items if isinstance(i, dict) and i.get('risk_level', '').upper() == 'CRITICAL']
        high_items = [i for i in action_items if isinstance(i, dict) and i.get('risk_level', '').upper() == 'HIGH']
        
        if critical_items:
            elements.append(Paragraph("Critical Priority", styles['SubHeading']))
            for idx, item in enumerate(critical_items[:5], 1):
                try:
                    title = item.get('title', 'Action Item')
                    pillar = item.get('pillar', 'Unknown')
                    item_text = f"{idx}. <b>[{pillar}] {title}</b>"
                    elements.append(Paragraph(item_text, styles['BulletPoint']))
                except:
                    continue
            elements.append(Spacer(1, 0.1*inch))
        
        if high_items:
            elements.append(Paragraph("High Priority", styles['SubHeading']))
            for idx, item in enumerate(high_items[:5], 1):
                try:
                    title = item.get('title', 'Action Item')
                    pillar = item.get('pillar', 'Unknown')
                    item_text = f"{idx}. <b>[{pillar}] {title}</b>"
                    elements.append(Paragraph(item_text, styles['BulletPoint']))
                except:
                    continue
    else:
        progress = assessment.get('progress', 0)
        if progress >= 80:
            elements.append(Paragraph("✅ No action items needed - Architecture follows best practices!", styles['BodyText']))
        else:
            elements.append(Paragraph(f"Complete the assessment ({progress:.0f}% done) to generate action items.", styles['BodyText']))
    
    elements.append(PageBreak())


def _add_portfolio_action_items(elements, assessment, styles, accounts):
    """Add portfolio-wide action items"""
    
    elements.append(Paragraph("Portfolio Action Items", styles['SectionHeading']))
    elements.append(Spacer(1, 0.15*inch))
    
    # Safe retrieval
    raw_action_items = assessment.get('action_items', [])
    action_items = [item for item in raw_action_items if isinstance(item, dict)]
    
    if action_items:
        elements.append(Paragraph(
            f"<b>{len(action_items)} action items</b> identified across {len(accounts)} accounts. "
            f"Focus on high-priority items first.",
            styles['BodyText']
        ))
        elements.append(Spacer(1, 0.15*inch))
        
        # Show top 10 items
        for idx, item in enumerate(action_items[:10], 1):
            try:
                title = item.get('title', 'Action Item')
                risk = item.get('risk_level', 'MEDIUM')
                pillar = item.get('pillar', 'Unknown')
                item_text = f"{idx}. <b>[{risk}] {title}</b> - {pillar}"
                elements.append(Paragraph(item_text, styles['BulletPoint']))
            except:
                continue
    
    elements.append(PageBreak())


def _add_account_deep_dives(elements, assessment, styles, accounts):
    """Add one page per account (limit to 5 accounts)"""
    
    action_items_by_account = assessment.get('action_items_by_account', {})
    scores_by_account = assessment.get('scores_by_account', {})
    
    for account in accounts[:5]:  # Limit to prevent huge PDFs
        account_name = account.get('account_name', 'Unknown')
        account_id = account.get('account_id', 'N/A')
        
        elements.append(Paragraph(f"Account: {account_name}", styles['SectionHeading']))
        elements.append(Paragraph(f"Account ID: {account_id}", styles['BodyText']))
        elements.append(Spacer(1, 0.15*inch))
        
        # Score if available
        score = scores_by_account.get(account_id, 0)
        if score > 0:
            elements.append(Paragraph(f"Score: <b>{score:.0f}/100</b>", styles['BodyText']))
            elements.append(Spacer(1, 0.1*inch))
        
        # Top issues for this account
        account_items = action_items_by_account.get(account_id, [])
        if account_items and isinstance(account_items, list):
            account_items = [item for item in account_items if isinstance(item, dict)]
            
            if account_items:
                elements.append(Paragraph("Top Issues:", styles['SubHeading']))
                for idx, item in enumerate(account_items[:3], 1):
                    try:
                        title = item.get('title', 'Action Item')
                        elements.append(Paragraph(f"{idx}. {title}", styles['BulletPoint']))
                    except:
                        continue
        
        elements.append(PageBreak())


def _add_conclusion(elements, assessment, styles, is_portfolio=False):
    """Add conclusion section"""
    
    elements.append(Paragraph("Conclusion & Next Steps", styles['SectionHeading']))
    elements.append(Spacer(1, 0.15*inch))
    
    if is_portfolio:
        conclusion = """
This portfolio assessment provides insights across multiple AWS accounts. 
Focus on standardizing best practices and addressing critical issues across all accounts.

<b>Recommended Actions:</b><br/>
1. Address all critical priority items within 2 weeks<br/>
2. Standardize security controls across accounts<br/>
3. Implement cross-account governance policies<br/>
4. Schedule quarterly portfolio reassessments
"""
    else:
        conclusion = """
This comprehensive assessment identifies strengths and opportunities for improvement 
in your AWS architecture.

<b>Recommended Actions:</b><br/>
1. Address critical priority items immediately<br/>
2. Create remediation plan for high priority items<br/>
3. Schedule quarterly reassessments<br/>
4. Enable continuous monitoring
"""
    
    elements.append(Paragraph(conclusion, styles['BodyText']))
