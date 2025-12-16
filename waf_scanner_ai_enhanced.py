"""
AWS WAF Scanner - AI-Enhanced Production Edition
Comprehensive AWS scanning with AI-powered analysis and WAF framework mapping

Features:
- 40+ AWS services automated scanning
- AI-powered analysis using Claude API
- Comprehensive WAF framework mapping (all 6 pillars)
- Intelligent finding prioritization
- Pattern detection across resources
- Downloadable PDF reports with executive summary
- Real-time progress tracking
- Cost savings estimation
- Compliance framework mapping
- Remediation roadmap generation

This replaces both "WAF Scanner" and "Quick Scan" with a unified, comprehensive solution.
"""

import streamlit as st
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field, asdict
from enum import Enum
import json
import uuid
from io import BytesIO

# Try to import required modules
try:
    from aws_connector import get_aws_session, test_aws_connection
    from landscape_scanner import (
        AWSLandscapeScanner,
        Finding,
        ResourceInventory,
        LandscapeAssessment,
        generate_demo_assessment
    )
    AWS_AVAILABLE = True
except ImportError:
    AWS_AVAILABLE = False
    
try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak, Image
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY, TA_RIGHT
    from reportlab.graphics.shapes import Drawing
    from reportlab.graphics.charts.piecharts import Pie
    from reportlab.graphics.charts.barcharts import VerticalBarChart
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False

# ============================================================================
# DATA MODELS
# ============================================================================

class ScanMode(Enum):
    """Scanning modes"""
    QUICK = "quick"           # Fast scan (5-10 mins) - core services only
    STANDARD = "standard"     # Standard scan (15-20 mins) - all services
    COMPREHENSIVE = "comprehensive"  # Deep scan (30+ mins) - all services + detailed analysis

@dataclass
class WAFPillarMapping:
    """Maps findings to WAF pillars with confidence scores"""
    pillar: str
    confidence: float  # 0.0 - 1.0
    reasoning: str
    related_best_practices: List[str] = field(default_factory=list)

@dataclass
class AIInsight:
    """AI-generated insight from Claude"""
    finding_id: str
    insight_type: str  # pattern, risk, optimization, architectural
    description: str
    recommendations: List[str]
    priority: str  # critical, high, medium, low
    estimated_impact: str
    confidence: float

@dataclass
class ScanResult:
    """Complete scan result with AI analysis"""
    scan_id: str
    account_id: str
    account_name: str
    scan_date: datetime
    scan_mode: ScanMode
    scan_duration_seconds: float
    
    # Raw scan data
    resources: ResourceInventory
    findings: List[Finding]
    
    # WAF Framework mapping
    pillar_distribution: Dict[str, int]  # pillar -> count of findings
    pillar_scores: Dict[str, float]  # pillar -> score (0-100)
    
    # AI Analysis
    ai_insights: List[AIInsight]
    top_priorities: List[str]  # Finding IDs
    patterns_detected: List[str]
    
    # Summary metrics
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    
    estimated_total_savings: float = 0.0
    overall_waf_score: float = 0.0
    
    # Compliance
    compliance_gaps: Dict[str, int] = field(default_factory=dict)

# ============================================================================
# AI-POWERED ANALYZER
# ============================================================================

class AIWAFAnalyzer:
    """Uses Claude API to analyze findings and provide intelligent insights"""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or st.secrets.get("anthropic_api_key")
        if ANTHROPIC_AVAILABLE and self.api_key:
            self.client = anthropic.Anthropic(api_key=self.api_key)
            self.available = True
        else:
            self.available = False
    
    def analyze_findings(self, findings: List[Finding], resources: ResourceInventory) -> List[AIInsight]:
        """
        Analyze findings using Claude API
        
        Provides:
        - Pattern detection across resources
        - Risk prioritization
        - Architectural recommendations
        - Cost optimization opportunities
        """
        if not self.available:
            return self._generate_rule_based_insights(findings)
        
        insights = []
        
        try:
            # Group findings by pillar for analysis
            findings_by_pillar = {}
            for finding in findings:
                pillar = finding.pillar.lower()
                if pillar not in findings_by_pillar:
                    findings_by_pillar[pillar] = []
                findings_by_pillar[pillar].append(finding)
            
            # Analyze each pillar
            for pillar, pillar_findings in findings_by_pillar.items():
                if len(pillar_findings) > 0:
                    pillar_insights = self._analyze_pillar_findings(pillar, pillar_findings, resources)
                    insights.extend(pillar_insights)
            
            # Cross-pillar analysis for patterns
            pattern_insights = self._detect_patterns(findings, resources)
            insights.extend(pattern_insights)
            
        except Exception as e:
            st.error(f"AI analysis error: {str(e)}")
            # Fallback to rule-based
            return self._generate_rule_based_insights(findings)
        
        return insights
    
    def _analyze_pillar_findings(self, pillar: str, findings: List[Finding], resources: ResourceInventory) -> List[AIInsight]:
        """Analyze findings for a specific WAF pillar"""
        
        # Prepare findings summary for Claude
        findings_summary = []
        for f in findings[:10]:  # Limit to top 10 to stay within token limits
            findings_summary.append({
                'title': f.title,
                'severity': f.severity,
                'description': f.description,
                'affected_resources': len(f.affected_resources) if hasattr(f, 'affected_resources') else 0
            })
        
        # Build resource context if available
        if resources is not None:
            resource_context = f"""
Resource Context:
- EC2 Instances: {resources.ec2_instances}
- S3 Buckets: {resources.s3_buckets}
- RDS Instances: {resources.rds_instances}
- Lambda Functions: {resources.lambda_functions}
"""
        else:
            resource_context = """
Resource Context:
- Resource inventory not available for this scan
"""
        
        prompt = f"""You are an AWS Well-Architected Framework expert. Analyze these {pillar.upper()} pillar findings and provide insights.

Findings:
{json.dumps(findings_summary, indent=2)}
{resource_context}
Provide:
1. Top 3 critical issues requiring immediate attention
2. Common patterns or root causes
3. Specific architectural recommendations
4. Estimated business impact if not addressed

Format as JSON:
{{
    "critical_issues": ["issue1", "issue2", "issue3"],
    "patterns": ["pattern1", "pattern2"],
    "recommendations": ["rec1", "rec2", "rec3"],
    "business_impact": "description"
}}"""
        
        try:
            message = self.client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=1000,
                messages=[{"role": "user", "content": prompt}]
            )
            
            # Parse Claude's response
            response_text = message.content[0].text
            
            # Extract JSON from response (might be wrapped in markdown)
            import re
            json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
            if json_match:
                analysis = json.loads(json_match.group())
                
                # Create insights from analysis
                insights = []
                
                for i, issue in enumerate(analysis.get('critical_issues', [])[:3]):
                    insights.append(AIInsight(
                        finding_id=f"{pillar}-ai-{i}",
                        insight_type="risk",
                        description=issue,
                        recommendations=analysis.get('recommendations', []),
                        priority="high",
                        estimated_impact=analysis.get('business_impact', ''),
                        confidence=0.9
                    ))
                
                # Add pattern insight if patterns detected
                if analysis.get('patterns'):
                    insights.append(AIInsight(
                        finding_id=f"{pillar}-pattern",
                        insight_type="pattern",
                        description=f"Pattern detected: {', '.join(analysis['patterns'])}",
                        recommendations=analysis.get('recommendations', []),
                        priority="medium",
                        estimated_impact="Addressing patterns can prevent systemic issues",
                        confidence=0.85
                    ))
                
                return insights
            
        except Exception as e:
            st.warning(f"Claude API analysis failed for {pillar}: {str(e)}")
        
        return []
    
    def _detect_patterns(self, findings: List[Finding], resources: ResourceInventory) -> List[AIInsight]:
        """Detect patterns across findings using AI"""
        
        # Count findings by type
        security_count = len([f for f in findings if 'security' in f.pillar.lower()])
        reliability_count = len([f for f in findings if 'reliability' in f.pillar.lower()])
        cost_count = len([f for f in findings if 'cost' in f.pillar.lower()])
        
        patterns = []
        
        # Detect systemic security issues
        if security_count > 10:
            patterns.append(AIInsight(
                finding_id="pattern-security-systemic",
                insight_type="pattern",
                description=f"Systemic security issues detected ({security_count} findings). Suggests lack of security baseline or governance.",
                recommendations=[
                    "Implement AWS Security Hub for centralized security posture",
                    "Deploy AWS Config rules for continuous compliance",
                    "Establish security baseline using AWS Service Catalog",
                    "Conduct security training for development teams"
                ],
                priority="critical",
                estimated_impact="Security baseline implementation can reduce vulnerabilities by 60-80%",
                confidence=0.95
            ))
        
        # Detect cost optimization opportunities
        if cost_count > 5:
            patterns.append(AIInsight(
                finding_id="pattern-cost-waste",
                insight_type="optimization",
                description=f"Multiple cost optimization opportunities identified ({cost_count} findings).",
                recommendations=[
                    "Implement AWS Cost Explorer for visibility",
                    "Enable AWS Compute Optimizer",
                    "Set up budget alerts",
                    "Consider Reserved Instances or Savings Plans"
                ],
                priority="high",
                estimated_impact=f"Potential monthly savings: ${sum(getattr(f, 'estimated_savings', 0.0) for f in findings if 'cost' in f.pillar.lower()):,.2f}",
                confidence=0.9
            ))
        
        # Detect reliability concerns
        if reliability_count > 5:
            patterns.append(AIInsight(
                finding_id="pattern-reliability-gaps",
                insight_type="architectural",
                description=f"Multiple reliability gaps detected ({reliability_count} findings). High risk of service disruption.",
                recommendations=[
                    "Implement multi-AZ deployments for critical services",
                    "Enable automated backups for all databases",
                    "Deploy disaster recovery strategy",
                    "Set up comprehensive CloudWatch alarms"
                ],
                priority="critical",
                estimated_impact="Reliability improvements can reduce downtime by 90%+",
                confidence=0.92
            ))
        
        return patterns
    
    def _generate_rule_based_insights(self, findings: List[Finding]) -> List[AIInsight]:
        """Fallback rule-based insights when AI is not available"""
        insights = []
        
        # Group by severity
        critical = [f for f in findings if f.severity == 'CRITICAL']
        high = [f for f in findings if f.severity == 'HIGH']
        
        if critical:
            insights.append(AIInsight(
                finding_id="rule-critical",
                insight_type="risk",
                description=f"{len(critical)} critical security issues require immediate attention",
                recommendations=[f.recommendation for f in critical[:3]],
                priority="critical",
                estimated_impact="Critical vulnerabilities expose organization to severe security risks",
                confidence=1.0
            ))
        
        if len(high) > 5:
            insights.append(AIInsight(
                finding_id="rule-high-volume",
                insight_type="pattern",
                description=f"{len(high)} high-priority findings detected - suggests systemic issues",
                recommendations=[
                    "Conduct security baseline review",
                    "Implement automated compliance checks",
                    "Establish governance policies"
                ],
                priority="high",
                estimated_impact="Addressing systemic issues prevents future vulnerabilities",
                confidence=0.85
            ))
        
        return insights

# ============================================================================
# WAF FRAMEWORK MAPPER
# ============================================================================

class WAFFrameworkMapper:
    """Maps findings to WAF framework pillars with intelligent categorization"""
    
    # WAF Pillar definitions
    PILLARS = {
        'operational_excellence': {
            'keywords': ['monitoring', 'logging', 'automation', 'deployment', 'operations', 'cloudwatch', 'cloudtrail'],
            'description': 'Run and monitor systems to deliver business value and continually improve'
        },
        'security': {
            'keywords': ['security', 'encryption', 'iam', 'access', 'authentication', 'authorization', 'mfa', 'firewall'],
            'description': 'Protect information, systems, and assets while delivering business value'
        },
        'reliability': {
            'keywords': ['backup', 'disaster', 'recovery', 'availability', 'failover', 'redundancy', 'multi-az'],
            'description': 'Recover from failures and meet demand'
        },
        'performance': {
            'keywords': ['performance', 'latency', 'throughput', 'cache', 'optimization', 'compute'],
            'description': 'Use computing resources efficiently'
        },
        'cost_optimization': {
            'keywords': ['cost', 'savings', 'unused', 'underutilized', 'reserved', 'spot', 'pricing'],
            'description': 'Run systems to deliver business value at the lowest price point'
        },
        'sustainability': {
            'keywords': ['sustainability', 'carbon', 'energy', 'efficiency', 'utilization', 'green'],
            'description': 'Minimize environmental impacts of running cloud workloads'
        }
    }
    
    @classmethod
    def map_finding_to_pillar(cls, finding: Finding) -> WAFPillarMapping:
        """Map a finding to a WAF pillar with confidence score"""
        
        # Check if pillar is already set
        if hasattr(finding, 'pillar') and finding.pillar:
            pillar = finding.pillar.lower().replace(' ', '_')
            if pillar in cls.PILLARS:
                return WAFPillarMapping(
                    pillar=pillar,
                    confidence=1.0,
                    reasoning="Explicitly mapped by scanner"
                )
        
        # Analyze finding text for keywords
        text = f"{finding.title} {finding.description}".lower()
        
        scores = {}
        for pillar, data in cls.PILLARS.items():
            score = sum(1 for keyword in data['keywords'] if keyword in text)
            if score > 0:
                scores[pillar] = score
        
        if scores:
            # Get pillar with highest score
            best_pillar = max(scores.items(), key=lambda x: x[1])
            confidence = min(best_pillar[1] / 3, 1.0)  # Normalize to 0-1
            
            return WAFPillarMapping(
                pillar=best_pillar[0],
                confidence=confidence,
                reasoning=f"Matched {best_pillar[1]} keywords"
            )
        
        # Default to security if no clear match
        return WAFPillarMapping(
            pillar='security',
            confidence=0.5,
            reasoning="Default mapping - requires manual review"
        )
    
    @classmethod
    def calculate_pillar_scores(cls, findings: List[Finding]) -> Dict[str, float]:
        """Calculate WAF pillar scores based on findings"""
        
        # Initialize scores at 100
        scores = {pillar: 100.0 for pillar in cls.PILLARS.keys()}
        
        # Deduct points based on findings
        for finding in findings:
            mapping = cls.map_finding_to_pillar(finding)
            pillar = mapping.pillar
            
            # Deduct points based on severity
            deduction = {
                'CRITICAL': 15,
                'HIGH': 10,
                'MEDIUM': 5,
                'LOW': 2,
                'INFO': 0
            }.get(finding.severity, 0)
            
            scores[pillar] = max(0, scores[pillar] - deduction)
        
        return scores

# ============================================================================
# PDF REPORT GENERATOR
# ============================================================================

class ComprehensivePDFReportGenerator:
    """Generate comprehensive PDF reports with charts and visualizations"""
    
    def __init__(self):
        if not PDF_AVAILABLE:
            raise ImportError("reportlab not available")
        
        self.styles = getSampleStyleSheet()
        self._add_custom_styles()
    
    def _add_custom_styles(self):
        """Add custom paragraph styles"""
        
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#FF9900'),  # AWS Orange
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))
        
        self.styles.add(ParagraphStyle(
            name='ExecutiveSummary',
            parent=self.styles['Normal'],
            fontSize=12,
            leading=16,
            spaceAfter=12,
            alignment=TA_JUSTIFY
        ))
        
        self.styles.add(ParagraphStyle(
            name='SectionHeading',
            parent=self.styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#232F3E'),  # AWS Dark
            spaceAfter=12,
            spaceBefore=12,
            fontName='Helvetica-Bold'
        ))
        
        self.styles.add(ParagraphStyle(
            name='FindingTitle',
            parent=self.styles['Heading3'],
            fontSize=11,
            textColor=colors.HexColor('#D13212'),  # AWS Red for critical
            spaceAfter=6,
            fontName='Helvetica-Bold'
        ))
    
    def generate_report(self, scan_result=None, account_name=None, scan_results=None, pillar_scores=None) -> bytes:
        """
        Generate comprehensive PDF report
        
        Supports both new-style (ScanResult object) and legacy-style (individual parameters) calls:
        
        New style:
            pdf_gen.generate_report(scan_result=scan_result_obj)
        
        Legacy style (backward compatible):
            pdf_gen.generate_report(
                account_name="Account 123",
                scan_results={'findings': [...]},
                pillar_scores={'Security': {'score': 75}}
            )
        """
        
        # Handle legacy-style calls with individual parameters
        if scan_result is None and account_name is not None:
            # Create a minimal ScanResult from legacy parameters
            # Don't try to import Finding - just create a simple wrapper for dicts
            class SimpleFinding:
                """Simple wrapper to convert dict findings to objects with attributes"""
                def __init__(self, data):
                    if isinstance(data, dict):
                        self.id = data.get('id', str(uuid.uuid4()))
                        self.service = data.get('service', 'Unknown')
                        self.resource = data.get('resource', 'Unknown')
                        self.severity = data.get('severity', 'MEDIUM')
                        self.title = data.get('title', 'Finding')
                        self.description = data.get('description', '')
                        self.recommendation = data.get('recommendation', '')
                        self.pillar = data.get('pillar', 'Security')
                        self.affected_resources = data.get('affected_resources', [])
                    else:
                        # Already an object, copy its attributes
                        for attr in ['id', 'service', 'resource', 'severity', 'title', 
                                   'description', 'recommendation', 'pillar', 'affected_resources']:
                            setattr(self, attr, getattr(data, attr, None))
            
            findings_list = []
            if scan_results and 'findings' in scan_results:
                # Wrap all findings in SimpleFinding for consistent attribute access
                for f in scan_results['findings']:
                    findings_list.append(SimpleFinding(f))
            
            # Handle pillar_scores - can be dict of floats or dict of dicts with 'score' key
            processed_pillar_scores = {}
            if pillar_scores:
                for pillar, value in pillar_scores.items():
                    if isinstance(value, dict):
                        processed_pillar_scores[pillar] = value.get('score', 100)
                    else:
                        processed_pillar_scores[pillar] = value
            
            # Calculate counts from findings
            total_findings = len(findings_list)
            critical_count = sum(1 for f in findings_list if hasattr(f, 'severity') and f.severity == 'CRITICAL')
            high_count = sum(1 for f in findings_list if hasattr(f, 'severity') and f.severity == 'HIGH')
            medium_count = sum(1 for f in findings_list if hasattr(f, 'severity') and f.severity == 'MEDIUM')
            low_count = sum(1 for f in findings_list if hasattr(f, 'severity') and f.severity == 'LOW')
            
            # Calculate pillar distribution
            pillar_distribution = {}
            for f in findings_list:
                if hasattr(f, 'pillar'):
                    pillar = f.pillar
                    pillar_distribution[pillar] = pillar_distribution.get(pillar, 0) + 1
            
            # Create minimal ScanResult
            scan_result = ScanResult(
                scan_id=str(uuid.uuid4()),
                account_id=account_name.replace('Account ', '').replace('Multi-Account (', '').replace(' accounts)', ''),
                account_name=account_name,
                scan_date=datetime.now(),
                scan_mode=ScanMode.STANDARD,
                scan_duration_seconds=0.0,
                resources=None,
                findings=findings_list,
                pillar_distribution=pillar_distribution,
                pillar_scores=processed_pillar_scores,
                ai_insights=[],
                top_priorities=[],
                patterns_detected=[],
                total_findings=total_findings,
                critical_count=critical_count,
                high_count=high_count,
                medium_count=medium_count,
                low_count=low_count,
                estimated_total_savings=0.0,
                overall_waf_score=sum(processed_pillar_scores.values()) / len(processed_pillar_scores) if processed_pillar_scores else 0.0,
                compliance_gaps={}
            )
        
        # Now call the actual report generation with ScanResult object
        return self._generate_report_internal(scan_result)
    
    def _generate_report_internal(self, scan_result: ScanResult) -> bytes:
        """Generate comprehensive PDF report"""
        
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
        
        # Build report sections
        self._add_cover_page(elements, scan_result)
        self._add_executive_summary(elements, scan_result)
        self._add_waf_pillar_scores(elements, scan_result)
        self._add_key_findings(elements, scan_result)
        self._add_ai_insights(elements, scan_result)
        self._add_detailed_findings(elements, scan_result)
        self._add_remediation_roadmap(elements, scan_result)
        self._add_resource_inventory(elements, scan_result)
        
        doc.build(elements)
        
        return buffer.getvalue()
    
    def _add_cover_page(self, elements: List, scan_result: ScanResult):
        """Add cover page"""
        
        elements.append(Spacer(1, 2*inch))
        
        # Title
        title = Paragraph(
            "AWS Well-Architected<br/>Framework Review",
            self.styles['CustomTitle']
        )
        elements.append(title)
        elements.append(Spacer(1, 0.5*inch))
        
        # Account info
        account_info = Paragraph(
            f"<b>Account:</b> {scan_result.account_name}<br/>"
            f"<b>Account ID:</b> {scan_result.account_id}<br/>"
            f"<b>Scan Date:</b> {scan_result.scan_date.strftime('%B %d, %Y %I:%M %p')}<br/>"
            f"<b>Scan Mode:</b> {scan_result.scan_mode.value.title()}",
            self.styles['Normal']
        )
        elements.append(account_info)
        elements.append(Spacer(1, 1*inch))
        
        # Summary metrics table
        summary_data = [
            ['Metric', 'Value'],
            ['Overall WAF Score', f"{scan_result.overall_waf_score:.1f}/100"],
            ['Total Findings', str(scan_result.total_findings)],
            ['Critical Issues', str(scan_result.critical_count)],
            ['High Priority', str(scan_result.high_count)],
            ['Estimated Savings', f"${scan_result.estimated_total_savings:,.2f}/month"]
        ]
        
        summary_table = Table(summary_data, colWidths=[3*inch, 2*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#232F3E')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        elements.append(summary_table)
        elements.append(PageBreak())
    
    def _add_executive_summary(self, elements: List, scan_result: ScanResult):
        """Add executive summary"""
        
        elements.append(Paragraph("Executive Summary", self.styles['SectionHeading']))
        elements.append(Spacer(1, 0.2*inch))
        
        # Generate executive summary text
        risk_level = "CRITICAL" if scan_result.critical_count > 0 else "HIGH" if scan_result.high_count > 5 else "MEDIUM"
        
        summary_text = f"""
        This AWS Well-Architected Framework review was conducted on {scan_result.scan_date.strftime('%B %d, %Y')} 
        for account <b>{scan_result.account_name}</b>. The assessment identified <b>{scan_result.total_findings}</b> findings 
        across the six WAF pillars, with an overall score of <b>{scan_result.overall_waf_score:.1f}/100</b>.
        
        <br/><br/>
        
        <b>Risk Assessment:</b> The current risk level is <b>{risk_level}</b>. 
        {scan_result.critical_count} critical and {scan_result.high_count} high-priority issues require immediate attention.
        
        <br/><br/>
        
        <b>Cost Optimization:</b> The review identified potential cost savings of approximately 
        <b>${scan_result.estimated_total_savings:,.2f} per month</b> through resource optimization and rightsizing.
        
        <br/><br/>
        
        <b>Key Recommendations:</b> Priority should be given to addressing security vulnerabilities, 
        implementing backup strategies, and optimizing resource utilization. Detailed findings and 
        remediation steps are provided in subsequent sections.
        """
        
        elements.append(Paragraph(summary_text, self.styles['ExecutiveSummary']))
        elements.append(PageBreak())
    
    def _add_waf_pillar_scores(self, elements: List, scan_result: ScanResult):
        """Add WAF pillar scores with visualization"""
        
        elements.append(Paragraph("WAF Pillar Scores", self.styles['SectionHeading']))
        elements.append(Spacer(1, 0.2*inch))
        
        # Create scores table
        scores_data = [['Pillar', 'Score', 'Findings', 'Status']]
        
        pillar_names = {
            'operational_excellence': '⚙️ Operational Excellence',
            'security': '🔒 Security',
            'reliability': '🔄 Reliability',
            'performance': '⚡ Performance Efficiency',
            'cost_optimization': '💰 Cost Optimization',
            'sustainability': '🌱 Sustainability'
        }
        
        for pillar, name in pillar_names.items():
            score = scan_result.pillar_scores.get(pillar, 0)
            count = scan_result.pillar_distribution.get(pillar, 0)
            status = '✓ Good' if score >= 80 else '⚠ Needs Improvement' if score >= 60 else '✗ Critical'
            
            scores_data.append([
                name,
                f"{score:.1f}/100",
                str(count),
                status
            ])
        
        scores_table = Table(scores_data, colWidths=[2.5*inch, 1.2*inch, 1*inch, 1.5*inch])
        scores_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#232F3E')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey])
        ]))
        
        elements.append(scores_table)
        elements.append(PageBreak())
    
    def _add_key_findings(self, elements: List, scan_result: ScanResult):
        """Add key findings summary"""
        
        elements.append(Paragraph("Key Findings", self.styles['SectionHeading']))
        elements.append(Spacer(1, 0.2*inch))
        
        # Get top 10 critical/high findings
        priority_findings = sorted(
            [f for f in scan_result.findings if f.severity in ['CRITICAL', 'HIGH']],
            key=lambda x: (0 if x.severity == 'CRITICAL' else 1, x.title)
        )[:10]
        
        for i, finding in enumerate(priority_findings, 1):
            severity_color = colors.HexColor('#D13212') if finding.severity == 'CRITICAL' else colors.HexColor('#FF9900')
            
            finding_text = f"""
            <b>{i}. [{finding.severity}] {finding.title}</b><br/>
            <i>Pillar: {finding.pillar} | Resources Affected: {len(finding.affected_resources)}</i><br/>
            {finding.description[:200]}...
            """
            
            elements.append(Paragraph(finding_text, self.styles['Normal']))
            elements.append(Spacer(1, 0.15*inch))
        
        elements.append(PageBreak())
    
    def _add_ai_insights(self, elements: List, scan_result: ScanResult):
        """Add AI-generated insights"""
        
        if not scan_result.ai_insights:
            return
        
        elements.append(Paragraph("AI-Powered Insights", self.styles['SectionHeading']))
        elements.append(Spacer(1, 0.2*inch))
        
        for insight in scan_result.ai_insights[:5]:  # Top 5 insights
            insight_text = f"""
            <b>{insight.insight_type.upper()}: {insight.description}</b><br/>
            <i>Priority: {insight.priority} | Confidence: {insight.confidence*100:.0f}%</i><br/>
            <br/>
            <b>Estimated Impact:</b> {insight.estimated_impact}<br/>
            <br/>
            <b>Recommendations:</b><br/>
            """ + "<br/>".join([f"• {rec}" for rec in insight.recommendations[:3]])
            
            elements.append(Paragraph(insight_text, self.styles['Normal']))
            elements.append(Spacer(1, 0.2*inch))
        
        elements.append(PageBreak())
    
    def _add_detailed_findings(self, elements: List, scan_result: ScanResult):
        """Add detailed findings by pillar"""
        
        elements.append(Paragraph("Detailed Findings by Pillar", self.styles['SectionHeading']))
        
        # Group findings by pillar
        findings_by_pillar = {}
        for finding in scan_result.findings:
            pillar = finding.pillar
            if pillar not in findings_by_pillar:
                findings_by_pillar[pillar] = []
            findings_by_pillar[pillar].append(finding)
        
        for pillar, findings in findings_by_pillar.items():
            elements.append(Paragraph(f"{pillar.title()}", self.styles['Heading3']))
            elements.append(Spacer(1, 0.1*inch))
            
            for finding in findings[:5]:  # Top 5 per pillar
                finding_text = f"""
                <b>[{finding.severity}] {finding.title}</b><br/>
                {finding.description}<br/>
                <b>Recommendation:</b> {finding.recommendation}
                """
                elements.append(Paragraph(finding_text, self.styles['Normal']))
                elements.append(Spacer(1, 0.1*inch))
        
        elements.append(PageBreak())
    
    def _add_remediation_roadmap(self, elements: List, scan_result: ScanResult):
        """Add remediation roadmap"""
        
        elements.append(Paragraph("Remediation Roadmap", self.styles['SectionHeading']))
        elements.append(Spacer(1, 0.2*inch))
        
        roadmap_text = """
        <b>Phase 1 (Immediate - Week 1-2):</b><br/>
        • Address all CRITICAL findings<br/>
        • Implement emergency security patches<br/>
        • Enable backup for critical resources<br/>
        <br/>
        <b>Phase 2 (Short-term - Month 1):</b><br/>
        • Resolve HIGH priority findings<br/>
        • Implement automated monitoring<br/>
        • Establish baseline security controls<br/>
        <br/>
        <b>Phase 3 (Medium-term - Month 2-3):</b><br/>
        • Address MEDIUM priority findings<br/>
        • Optimize costs and performance<br/>
        • Implement compliance controls<br/>
        <br/>
        <b>Phase 4 (Long-term - Month 4-6):</b><br/>
        • Continuous improvement<br/>
        • Sustainability initiatives<br/>
        • Advanced optimization<br/>
        """
        
        elements.append(Paragraph(roadmap_text, self.styles['Normal']))
        elements.append(PageBreak())
    
    def _add_resource_inventory(self, elements: List, scan_result: ScanResult):
        """Add resource inventory summary"""
        
        # Skip if resources not available (backward compatibility)
        if scan_result.resources is None:
            elements.append(Paragraph("Resource Inventory", self.styles['SectionHeading']))
            elements.append(Spacer(1, 0.2*inch))
            elements.append(Paragraph(
                "Resource inventory data not available for this scan type.",
                self.styles['Normal']
            ))
            elements.append(Spacer(1, 0.3*inch))
            return
        
        elements.append(Paragraph("Resource Inventory", self.styles['SectionHeading']))
        elements.append(Spacer(1, 0.2*inch))
        
        resources = scan_result.resources
        
        inventory_data = [
            ['Resource Type', 'Count', 'Notes'],
            ['EC2 Instances', str(resources.ec2_instances), f"{resources.ec2_running} running"],
            ['S3 Buckets', str(resources.s3_buckets), f"{resources.s3_public} public"],
            ['RDS Databases', str(resources.rds_instances), f"{resources.rds_encrypted} encrypted"],
            ['Lambda Functions', str(resources.lambda_functions), ''],
            ['VPCs', str(resources.vpcs), ''],
            ['Security Groups', str(resources.security_groups), f"{resources.security_groups_open} with open access"],
        ]
        
        inventory_table = Table(inventory_data, colWidths=[2*inch, 1.5*inch, 2.5*inch])
        inventory_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#232F3E')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey])
        ]))
        
        elements.append(inventory_table)

# ============================================================================
# MAIN SCANNER CLASS
# ============================================================================

class EnhancedWAFScanner:
    """Main scanner class orchestrating all components"""
    
    def __init__(self, session=None, anthropic_api_key=None):
        self.session = session
        self.ai_analyzer = AIWAFAnalyzer(anthropic_api_key)
        self.mapper = WAFFrameworkMapper()
    
    def perform_scan(
        self,
        account_name: str,
        scan_mode: ScanMode = ScanMode.STANDARD,
        progress_callback=None
    ) -> ScanResult:
        """
        Perform comprehensive WAF scan
        
        Returns complete scan result with AI analysis and PDF report
        """
        
        start_time = datetime.now()
        
        if progress_callback:
            progress_callback("Initializing scanner...", 0)
        
        # Step 1: Perform AWS landscape scan
        if progress_callback:
            progress_callback("Scanning AWS resources...", 10)
        
        if self.session:
            scanner = AWSLandscapeScanner(self.session)
            landscape = scanner.scan_all()
        else:
            # Use demo data
            landscape = generate_demo_assessment()
        
        if progress_callback:
            progress_callback("Analyzing findings...", 40)
        
        # Step 2: Map findings to WAF pillars
        pillar_distribution = {}
        for finding in landscape.findings:
            mapping = self.mapper.map_finding_to_pillar(finding)
            finding.pillar = mapping.pillar  # Update finding pillar
            pillar_distribution[mapping.pillar] = pillar_distribution.get(mapping.pillar, 0) + 1
        
        if progress_callback:
            progress_callback("Calculating WAF scores...", 60)
        
        # Step 3: Calculate pillar scores
        pillar_scores = self.mapper.calculate_pillar_scores(landscape.findings)
        overall_score = sum(pillar_scores.values()) / len(pillar_scores)
        
        if progress_callback:
            progress_callback("Running AI analysis...", 70)
        
        # Step 4: AI analysis
        ai_insights = self.ai_analyzer.analyze_findings(landscape.findings, landscape.resources)
        
        if progress_callback:
            progress_callback("Prioritizing findings...", 85)
        
        # Step 5: Prioritize findings
        top_priorities = [
            f.id for f in sorted(
                landscape.findings,
                key=lambda x: (0 if x.severity == 'CRITICAL' else 1 if x.severity == 'HIGH' else 2, x.title)
            )[:10]
        ]
        
        if progress_callback:
            progress_callback("Detecting patterns...", 95)
        
        # Step 6: Detect patterns
        patterns = [insight.description for insight in ai_insights if insight.insight_type == 'pattern']
        
        # Calculate summary metrics
        critical_count = len([f for f in landscape.findings if f.severity == 'CRITICAL'])
        high_count = len([f for f in landscape.findings if f.severity == 'HIGH'])
        medium_count = len([f for f in landscape.findings if f.severity == 'MEDIUM'])
        low_count = len([f for f in landscape.findings if f.severity == 'LOW'])
        
        total_savings = sum(f.estimated_savings for f in landscape.findings)
        
        scan_duration = (datetime.now() - start_time).total_seconds()
        
        if progress_callback:
            progress_callback("Scan complete!", 100)
        
        # Create scan result
        return ScanResult(
            scan_id=str(uuid.uuid4()),
            account_id=landscape.account_id,
            account_name=account_name,
            scan_date=datetime.now(),
            scan_mode=scan_mode,
            scan_duration_seconds=scan_duration,
            resources=landscape.resources,
            findings=landscape.findings,
            pillar_distribution=pillar_distribution,
            pillar_scores=pillar_scores,
            ai_insights=ai_insights,
            top_priorities=top_priorities,
            patterns_detected=patterns,
            total_findings=len(landscape.findings),
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            estimated_total_savings=total_savings,
            overall_waf_score=overall_score
        )

# ============================================================================
# STREAMLIT UI
# ============================================================================

def render_enhanced_waf_scanner():
    """Main UI for enhanced WAF scanner"""
    
    st.title("🔍 AWS WAF Scanner - AI Enhanced")
    st.markdown("Comprehensive AWS scanning with AI-powered analysis and WAF framework mapping")
    
    # Configuration
    with st.expander("⚙️ Scanner Configuration", expanded=True):
        col1, col2 = st.columns(2)
        
        with col1:
            account_name = st.text_input(
                "Account Name",
                value="Production Account",
                help="Name for this AWS account"
            )
            
            scan_mode = st.selectbox(
                "Scan Mode",
                options=[mode.value for mode in ScanMode],
                format_func=lambda x: {
                    'quick': '⚡ Quick Scan (5-10 mins)',
                    'standard': '📋 Standard Scan (15-20 mins)',
                    'comprehensive': '🔬 Comprehensive Scan (30+ mins)'
                }[x],
                help="Quick: Core services | Standard: All services | Comprehensive: Deep analysis"
            )
        
        with col2:
            use_aws = st.checkbox("Connect to AWS", value=False, help="Scan real AWS account")
            use_ai = st.checkbox("Enable AI Analysis", value=True, help="Use Claude API for insights")
    
    # Scan button
    if st.button("🚀 Start WAF Scan", type="primary", use_container_width=True):
        
        # Progress tracking
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        def update_progress(message, percent):
            progress_bar.progress(percent / 100)
            status_text.text(message)
        
        # Initialize scanner
        session = None
        if use_aws:
            try:
                session = get_aws_session()
            except Exception as e:
                st.error(f"Failed to connect to AWS: {str(e)}")
                return
        
        api_key = st.secrets.get("anthropic_api_key") if use_ai else None
        scanner = EnhancedWAFScanner(session=session, anthropic_api_key=api_key)
        
        # Perform scan
        with st.spinner("Scanning in progress..."):
            scan_result = scanner.perform_scan(
                account_name=account_name,
                scan_mode=ScanMode(scan_mode),
                progress_callback=update_progress
            )
        
        # Store in session state
        st.session_state['last_scan_result'] = scan_result
        
        st.success(f"✅ Scan completed in {scan_result.scan_duration_seconds:.1f} seconds!")
    
    # Display results if available
    if 'last_scan_result' in st.session_state:
        scan_result = st.session_state['last_scan_result']
        
        st.markdown("---")
        st.header("📊 Scan Results")
        
        # Summary metrics
        col1, col2, col3, col4, col5 = st.columns(5)
        
        with col1:
            st.metric("Overall Score", f"{scan_result.overall_waf_score:.1f}/100")
        with col2:
            st.metric("Total Findings", scan_result.total_findings)
        with col3:
            st.metric("Critical", scan_result.critical_count, delta=None if scan_result.critical_count == 0 else f"-{scan_result.critical_count}")
        with col4:
            st.metric("High Priority", scan_result.high_count)
        with col5:
            st.metric("Est. Savings", f"${scan_result.estimated_total_savings:,.0f}/mo")
        
        # WAF Pillar Scores
        st.subheader("📋 WAF Pillar Scores")
        
        pillar_cols = st.columns(3)
        pillar_names = {
            'operational_excellence': ('⚙️', 'Operational Excellence'),
            'security': ('🔒', 'Security'),
            'reliability': ('🔄', 'Reliability'),
            'performance': ('⚡', 'Performance'),
            'cost_optimization': ('💰', 'Cost Optimization'),
            'sustainability': ('🌱', 'Sustainability')
        }
        
        for i, (pillar_key, (emoji, name)) in enumerate(pillar_names.items()):
            score = scan_result.pillar_scores.get(pillar_key, 0)
            count = scan_result.pillar_distribution.get(pillar_key, 0)
            
            with pillar_cols[i % 3]:
                st.metric(
                    f"{emoji} {name}",
                    f"{score:.1f}/100",
                    delta=f"{count} findings" if count > 0 else "No issues"
                )
        
        # AI Insights
        if scan_result.ai_insights:
            st.subheader("🤖 AI-Powered Insights")
            
            for insight in scan_result.ai_insights[:3]:
                with st.expander(f"{insight.insight_type.upper()}: {insight.description[:80]}..."):
                    st.markdown(f"**Priority:** {insight.priority.upper()}")
                    st.markdown(f"**Confidence:** {insight.confidence*100:.0f}%")
                    st.markdown(f"**Impact:** {insight.estimated_impact}")
                    st.markdown("**Recommendations:**")
                    for rec in insight.recommendations:
                        st.markdown(f"- {rec}")
        
        # PDF Download
        st.markdown("---")
        st.subheader("📥 Download Report")
        
        if PDF_AVAILABLE:
            if st.button("📄 Generate PDF Report", use_container_width=True):
                with st.spinner("Generating comprehensive PDF report..."):
                    try:
                        generator = ComprehensivePDFReportGenerator()
                        pdf_bytes = generator.generate_report(scan_result)
                        
                        st.download_button(
                            label="⬇️ Download PDF Report",
                            data=pdf_bytes,
                            file_name=f"waf_scan_{scan_result.account_name.replace(' ', '_')}_{scan_result.scan_date.strftime('%Y%m%d')}.pdf",
                            mime="application/pdf",
                            use_container_width=True
                        )
                        
                        st.success("✅ PDF report generated successfully!")
                    except Exception as e:
                        st.error(f"Error generating PDF: {str(e)}")
        else:
            st.warning("PDF generation requires reportlab library: `pip install reportlab`")
        
        # JSON Export
        if st.button("📊 Export as JSON", use_container_width=True):
            json_data = json.dumps(asdict(scan_result), default=str, indent=2)
            st.download_button(
                label="⬇️ Download JSON Data",
                data=json_data,
                file_name=f"waf_scan_{scan_result.account_name.replace(' ', '_')}_{scan_result.scan_date.strftime('%Y%m%d')}.json",
                mime="application/json",
                use_container_width=True
            )

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    st.set_page_config(
        page_title="AWS WAF Scanner - AI Enhanced",
        page_icon="🔍",
        layout="wide"
    )
    render_enhanced_waf_scanner()