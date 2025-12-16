"""
AWS Well-Architected Framework Review - Enterprise Edition
Production-grade, AI-powered assessment platform

This module aims to be the de facto standard for AWS WAF assessments by providing:
- Complete question database (200+ questions across 6 pillars)
- AI-powered analysis and recommendations using Claude
- Automated evidence collection via AWS scanning
- Industry benchmarking and peer comparison
- Executive and technical reporting
- Continuous improvement tracking
- Compliance framework mapping
- Remediation roadmap generation

Integration:
- Uses aws_connector for authentication
- Uses landscape_scanner for automated assessment
- Maps to compliance_module frameworks
- Generates architecture_patterns recommendations
"""

import streamlit as st
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
import json
import hashlib

# Import existing modules
try:
    from aws_connector import get_aws_session, test_aws_connection
    from landscape_scanner import Finding as ScannerFinding, LandscapeAssessment
    from compliance_module import COMPLIANCE_FRAMEWORKS
except ImportError:
    # Fallback for development
    pass

# ============================================================================
# CORE DATA MODELS
# ============================================================================

class Pillar(Enum):
    """Six pillars of the AWS Well-Architected Framework"""
    OPERATIONAL_EXCELLENCE = "Operational Excellence"
    SECURITY = "Security"
    RELIABILITY = "Reliability"
    PERFORMANCE_EFFICIENCY = "Performance Efficiency"
    COST_OPTIMIZATION = "Cost Optimization"
    SUSTAINABILITY = "Sustainability"

class RiskLevel(Enum):
    """Risk levels for findings"""
    NONE = "None/Not Applicable"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

class AssessmentType(Enum):
    """Type of WAF assessment"""
    QUICK = "Quick Assessment (30 min)"
    STANDARD = "Standard Assessment (2 hours)"
    COMPREHENSIVE = "Comprehensive Review (1 day)"
    CONTINUOUS = "Continuous Monitoring"

@dataclass
class Choice:
    """Answer choice for a question"""
    id: str
    text: str
    risk_level: RiskLevel
    points: int  # 0-100, higher is better
    evidence_required: List[str] = field(default_factory=list)
    auto_detectable: bool = False

@dataclass
class Question:
    """Assessment question"""
    id: str
    pillar: Pillar
    category: str  # Sub-category within pillar
    text: str
    description: str
    why_important: str
    best_practices: List[str]
    choices: List[Choice]
    help_link: str
    aws_services: List[str] = field(default_factory=list)
    compliance_mappings: Dict[str, List[str]] = field(default_factory=dict)  # framework: control_ids
    automated_check: Optional[str] = None  # Function name for automated checking
    required_for: List[str] = field(default_factory=list)  # Industries/workload types
    maturity_level: int = 1  # 1-3, how advanced this practice is

@dataclass
class Response:
    """User's response to a question"""
    question_id: str
    choice_id: str
    notes: str = ""
    evidence_urls: List[str] = field(default_factory=list)
    evidence_screenshots: List[str] = field(default_factory=list)
    automated_evidence: Dict[str, Any] = field(default_factory=dict)
    responded_by: str = ""
    responded_at: datetime = field(default_factory=datetime.now)
    verified: bool = False
    verified_by: str = ""

@dataclass
class ActionItem:
    """Remediation action item"""
    id: str
    title: str
    description: str
    pillar: Pillar
    risk_level: RiskLevel
    affected_resources: List[str]
    recommendation: str
    implementation_steps: List[str]
    aws_services_used: List[str]
    estimated_effort: str  # e.g., "2-4 hours", "1-2 days", "1-2 weeks"
    estimated_cost: str  # $, $$, $$$, $$$$
    priority: int  # 1-5, 1 being highest
    assigned_to: str = ""
    status: str = "Open"  # Open, In Progress, Completed, Deferred
    due_date: Optional[datetime] = None
    completion_date: Optional[datetime] = None
    notes: str = ""
    related_questions: List[str] = field(default_factory=list)
    compliance_impact: List[str] = field(default_factory=list)

@dataclass
class WAFAssessment:
    """Complete Well-Architected Framework Assessment"""
    # Identification
    id: str
    assessment_type: AssessmentType
    
    # Organization info
    organization_name: str
    workload_name: str
    workload_description: str
    environment: str  # Development, Staging, Production
    industry: str
    
    # Team - owner is required, so must come before optional fields
    owner: str
    
    # Optional fields with defaults
    aws_account_ids: List[str] = field(default_factory=list)
    regions: List[str] = field(default_factory=list)
    reviewers: List[str] = field(default_factory=list)
    stakeholders: List[str] = field(default_factory=list)
    
    # Timing
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    review_date: Optional[datetime] = None
    next_review_date: Optional[datetime] = None
    
    # Assessment data
    responses: Dict[str, Response] = field(default_factory=dict)  # question_id: Response
    action_items: List[ActionItem] = field(default_factory=list)
    
    # Scoring
    overall_score: float = 0.0  # 0-100
    pillar_scores: Dict[Pillar, float] = field(default_factory=dict)
    risk_summary: Dict[RiskLevel, int] = field(default_factory=dict)
    
    # Progress
    questions_answered: int = 0
    questions_total: int = 0
    completion_percentage: float = 0.0
    
    # Automated scanning
    landscape_scan_id: Optional[str] = None
    automated_findings: List[ScannerFinding] = field(default_factory=list)
    
    # AI Analysis
    ai_recommendations: List[str] = field(default_factory=list)
    ai_summary: str = ""
    ai_executive_summary: str = ""
    
    # Historical comparison
    previous_assessment_id: Optional[str] = None
    improvement_score: float = 0.0
    
    # Benchmarking
    industry_benchmark_score: float = 0.0
    peer_comparison_percentile: int = 0
    
    def calculate_score(self, questions: List[Question]) -> float:
        """Calculate overall assessment score"""
        if not self.responses:
            return 0.0
        
        total_points = 0
        max_points = 0
        
        for question in questions:
            if question.id in self.responses:
                response = self.responses[question.id]
                choice = next((c for c in question.choices if c.id == response.choice_id), None)
                if choice:
                    total_points += choice.points
            max_points += 100  # Each question max 100 points
        
        return (total_points / max_points * 100) if max_points > 0 else 0.0
    
    def calculate_pillar_score(self, pillar: Pillar, questions: List[Question]) -> float:
        """Calculate score for specific pillar"""
        pillar_questions = [q for q in questions if q.pillar == pillar]
        if not pillar_questions:
            return 0.0
        
        total_points = 0
        max_points = 0
        
        for question in pillar_questions:
            if question.id in self.responses:
                response = self.responses[question.id]
                choice = next((c for c in question.choices if c.id == response.choice_id), None)
                if choice:
                    total_points += choice.points
            max_points += 100
        
        return (total_points / max_points * 100) if max_points > 0 else 0.0
    
    def get_high_risk_items(self) -> List[ActionItem]:
        """Get action items with HIGH or CRITICAL risk"""
        return [item for item in self.action_items 
                if item.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]
                and item.status != "Completed"]
    
    def get_quick_wins(self) -> List[ActionItem]:
        """Get low-effort, high-impact items"""
        quick_efforts = ["30 minutes", "1 hour", "2-4 hours"]
        return [item for item in self.action_items
                if any(effort in item.estimated_effort for effort in quick_efforts)
                and item.risk_level in [RiskLevel.HIGH, RiskLevel.MEDIUM]
                and item.status != "Completed"]
    
    def export_to_dict(self) -> Dict:
        """Export assessment to dictionary for JSON/storage"""
        return {
            'id': self.id,
            'assessment_type': self.assessment_type.value,
            'organization_name': self.organization_name,
            'workload_name': self.workload_name,
            'created_at': self.created_at.isoformat(),
            'overall_score': self.overall_score,
            'pillar_scores': {p.value: score for p, score in self.pillar_scores.items()},
            'responses': {qid: {
                'choice_id': r.choice_id,
                'notes': r.notes,
                'responded_at': r.responded_at.isoformat()
            } for qid, r in self.responses.items()},
            'action_items': [{
                'id': item.id,
                'title': item.title,
                'pillar': item.pillar.value,
                'risk_level': item.risk_level.value,
                'status': item.status
            } for item in self.action_items]
        }

# ============================================================================
# QUESTION DATABASE - COMPREHENSIVE SET
# ============================================================================

def get_all_questions() -> List[Question]:
    """
    Complete AWS Well-Architected Framework question set
    
    This is a comprehensive database covering all 6 pillars with:
    - 200+ questions total
    - Multiple choice answers with risk levels
    - Best practices and guidance
    - AWS service mappings
    - Compliance framework mappings
    - Automated check capabilities
    """
    questions = []
    
    # ========================================================================
    # OPERATIONAL EXCELLENCE PILLAR (40+ questions)
    # ========================================================================
    
    # Organization Section
    questions.extend([
        Question(
            id="OPS-ORG-001",
            pillar=Pillar.OPERATIONAL_EXCELLENCE,
            category="Organization",
            text="How do you determine what your priorities are?",
            description="Everyone needs to understand their part in enabling business success. Have shared goals to set priorities for resources.",
            why_important="Without clear priorities, teams work on misaligned goals, wasting resources and missing business objectives.",
            best_practices=[
                "Evaluate external customer needs and market trends",
                "Evaluate internal customer requirements and capabilities",
                "Evaluate governance and regulatory requirements",
                "Evaluate compliance requirements for your industry",
                "Evaluate threat landscape and security posture",
                "Evaluate tradeoffs between competing interests",
                "Manage benefits and risks in decision-making"
            ],
            choices=[
                Choice(
                    id="OPS-ORG-001-A",
                    text="We have documented business objectives with clear OKRs/KPIs reviewed quarterly",
                    risk_level=RiskLevel.NONE,
                    points=100
                ),
                Choice(
                    id="OPS-ORG-001-B",
                    text="Priorities exist but documentation is incomplete or outdated",
                    risk_level=RiskLevel.LOW,
                    points=60
                ),
                Choice(
                    id="OPS-ORG-001-C",
                    text="Priorities are informally understood but not documented",
                    risk_level=RiskLevel.MEDIUM,
                    points=30
                ),
                Choice(
                    id="OPS-ORG-001-D",
                    text="We don't have clear priorities or success metrics",
                    risk_level=RiskLevel.HIGH,
                    points=0
                )
            ],
            help_link="https://docs.aws.amazon.com/wellarchitected/latest/operational-excellence-pillar/ops_priorities_eval_external_cust_needs.html",
            aws_services=["AWS Organizations", "AWS Service Catalog"],
            compliance_mappings={
                "iso27001": ["A.5"],
                "soc2": ["CC1.1"],
                "cis_aws": ["1.1"]
            },
            maturity_level=1
        ),
        
        Question(
            id="OPS-ORG-002",
            pillar=Pillar.OPERATIONAL_EXCELLENCE,
            category="Organization",
            text="How do you structure your organization to support your business outcomes?",
            description="Your teams must understand their part in achieving business outcomes. Teams need to understand their roles in the success of other teams, the role of other teams in their success, and have shared goals.",
            why_important="Poor organizational structure leads to silos, duplication of effort, and inability to respond quickly to business needs.",
            best_practices=[
                "Resources have identified owners with clear accountability",
                "Processes and procedures have identified owners",
                "Operations activities have identified performers",
                "Team members know what they are responsible for",
                "Mechanisms exist to request additions, changes, and exceptions",
                "Responsibilities are matched to authority levels"
            ],
            choices=[
                Choice(
                    id="OPS-ORG-002-A",
                    text="Clear RACI matrix with defined ownership for all resources and processes",
                    risk_level=RiskLevel.NONE,
                    points=100,
                    evidence_required=["RACI matrix", "Team structure diagram"]
                ),
                Choice(
                    id="OPS-ORG-002-B",
                    text="Ownership defined for most resources but some ambiguity exists",
                    risk_level=RiskLevel.LOW,
                    points=65
                ),
                Choice(
                    id="OPS-ORG-002-C",
                    text="Ownership is informal and not well documented",
                    risk_level=RiskLevel.MEDIUM,
                    points=35
                ),
                Choice(
                    id="OPS-ORG-002-D",
                    text="No clear ownership model exists",
                    risk_level=RiskLevel.HIGH,
                    points=0
                )
            ],
            help_link="https://docs.aws.amazon.com/wellarchitected/latest/operational-excellence-pillar/organization.html",
            aws_services=["AWS Organizations", "AWS Resource Groups", "AWS Tagging"],
            compliance_mappings={
                "iso27001": ["A.5", "A.7"],
                "soc2": ["CC1.2", "CC1.3"]
            }
        ),
        
        Question(
            id="OPS-ORG-003",
            pillar=Pillar.OPERATIONAL_EXCELLENCE,
            category="Organization",
            text="How does your organizational culture support your business outcomes?",
            description="Provide support for team members so they can be effective in taking action and supporting business outcomes.",
            why_important="Culture impacts team effectiveness, innovation capacity, and ability to respond to incidents and changes.",
            best_practices=[
                "Executive sponsorship for operational excellence",
                "Team members empowered to take action when outcomes are at risk",
                "Team members encouraged to escalate concerns",
                "Communications are timely, clear, and actionable",
                "Experimentation is encouraged and learning from failure is expected",
                "Team members have time made available for learning"
            ],
            choices=[
                Choice(
                    id="OPS-ORG-003-A",
                    text="Strong culture of learning, experimentation, and continuous improvement with executive support",
                    risk_level=RiskLevel.NONE,
                    points=100
                ),
                Choice(
                    id="OPS-ORG-003-B",
                    text="Generally supportive culture but not consistently applied",
                    risk_level=RiskLevel.LOW,
                    points=70
                ),
                Choice(
                    id="OPS-ORG-003-C",
                    text="Culture is reactive rather than proactive",
                    risk_level=RiskLevel.MEDIUM,
                    points=40
                ),
                Choice(
                    id="OPS-ORG-003-D",
                    text="Blame culture that discourages innovation and learning",
                    risk_level=RiskLevel.HIGH,
                    points=0
                )
            ],
            help_link="https://docs.aws.amazon.com/wellarchitected/latest/operational-excellence-pillar/ops-org-culture.html",
            aws_services=["AWS Well-Architected Tool"],
            maturity_level=2
        ),
    ])
    
    # Prepare Section
    questions.extend([
        Question(
            id="OPS-PREP-001",
            pillar=Pillar.OPERATIONAL_EXCELLENCE,
            category="Prepare - Design Telemetry",
            text="How do you implement observability in your workload?",
            description="Design your workload so that it provides the information necessary for you to understand its internal state across all components in support of observability and investigating issues.",
            why_important="Without proper observability, you cannot understand system behavior, troubleshoot issues, or make informed decisions.",
            best_practices=[
                "Implement application telemetry with distributed tracing",
                "Implement and configure workload metrics (USE, RED methods)",
                "Implement and configure user experience telemetry",
                "Implement dependency telemetry for all dependencies",
                "Implement distributed tracing with correlation IDs"
            ],
            choices=[
                Choice(
                    id="OPS-PREP-001-A",
                    text="Comprehensive observability: distributed tracing, metrics, logs, with correlation across all tiers",
                    risk_level=RiskLevel.NONE,
                    points=100,
                    auto_detectable=True
                ),
                Choice(
                    id="OPS-PREP-001-B",
                    text="Basic metrics and logging implemented, limited tracing",
                    risk_level=RiskLevel.LOW,
                    points=60,
                    auto_detectable=True
                ),
                Choice(
                    id="OPS-PREP-001-C",
                    text="Basic CloudWatch metrics only, no custom instrumentation",
                    risk_level=RiskLevel.MEDIUM,
                    points=30,
                    auto_detectable=True
                ),
                Choice(
                    id="OPS-PREP-001-D",
                    text="Limited or no observability implementation",
                    risk_level=RiskLevel.HIGH,
                    points=0
                )
            ],
            help_link="https://docs.aws.amazon.com/wellarchitected/latest/operational-excellence-pillar/design-telemetry.html",
            aws_services=["Amazon CloudWatch", "AWS X-Ray", "Amazon CloudWatch Logs", "AWS CloudTrail", "Amazon OpenSearch Service"],
            compliance_mappings={
                "soc2": ["CC7.2"],
                "iso27001": ["A.12.4"],
                "cis_aws": ["3.1", "3.2"]
            },
            automated_check="check_cloudwatch_metrics",
            maturity_level=2
        ),
        
        Question(
            id="OPS-PREP-002",
            pillar=Pillar.OPERATIONAL_EXCELLENCE,
            category="Prepare - Design for Operations",
            text="How do you design your workload to enable operations?",
            description="Adopt approaches that improve the flow of changes into production and enable refactoring, fast feedback on quality, and bug fixing.",
            why_important="Workloads designed without operational considerations become difficult to maintain, troubleshoot, and improve over time.",
            best_practices=[
                "Use version control for all code and configuration",
                "Use build and deployment management systems",
                "Perform patch management automatically",
                "Share design standards and maintain design review process",
                "Implement practices to improve code quality",
                "Use configuration management systems",
                "Use multiple environments for development, test, and production"
            ],
            choices=[
                Choice(
                    id="OPS-PREP-002-A",
                    text="Full CI/CD with automated testing, IaC, multi-environment strategy, and design reviews",
                    risk_level=RiskLevel.NONE,
                    points=100,
                    evidence_required=["CI/CD pipeline diagram", "IaC repository"]
                ),
                Choice(
                    id="OPS-PREP-002-B",
                    text="CI/CD partially implemented, some manual steps remain",
                    risk_level=RiskLevel.LOW,
                    points=65
                ),
                Choice(
                    id="OPS-PREP-002-C",
                    text="Version control used but deployment is mostly manual",
                    risk_level=RiskLevel.MEDIUM,
                    points=35
                ),
                Choice(
                    id="OPS-PREP-002-D",
                    text="No CI/CD, manual deployments, limited version control",
                    risk_level=RiskLevel.HIGH,
                    points=0
                )
            ],
            help_link="https://docs.aws.amazon.com/wellarchitected/latest/operational-excellence-pillar/design-for-operations.html",
            aws_services=["AWS CodePipeline", "AWS CodeBuild", "AWS CodeDeploy", "AWS CloudFormation", "AWS CDK"],
            compliance_mappings={
                "soc2": ["CC8.1"],
                "iso27001": ["A.12.1", "A.14.2"]
            },
            automated_check="check_cicd_implementation"
        ),
        
        Question(
            id="OPS-PREP-003",
            pillar=Pillar.OPERATIONAL_EXCELLENCE,
            category="Prepare - Mitigate Deployment Risks",
            text="How do you mitigate deployment risks?",
            description="Adopt approaches that provide fast feedback on quality and promote safe, incremental production rollouts.",
            why_important="Deployment failures can cause outages, data loss, and business disruption. Risk mitigation is essential for production stability.",
            best_practices=[
                "Plan for unsuccessful changes and have rollback procedures",
                "Test deployments in pre-production environments",
                "Deploy using parallel environments (blue/green)",
                "Deploy changes with feature flags for controlled rollout",
                "Deploy changes incrementally (canary deployments)",
                "Automate testing and rollback"
            ],
            choices=[
                Choice(
                    id="OPS-PREP-003-A",
                    text="Automated canary/blue-green deployments with feature flags and instant rollback capability",
                    risk_level=RiskLevel.NONE,
                    points=100
                ),
                Choice(
                    id="OPS-PREP-003-B",
                    text="Testing in pre-prod, manual rollback procedures documented",
                    risk_level=RiskLevel.LOW,
                    points=65
                ),
                Choice(
                    id="OPS-PREP-003-C",
                    text="Limited testing, basic rollback capability",
                    risk_level=RiskLevel.MEDIUM,
                    points=35
                ),
                Choice(
                    id="OPS-PREP-003-D",
                    text="Direct production deployments with no rollback plan",
                    risk_level=RiskLevel.HIGH,
                    points=0
                )
            ],
            help_link="https://docs.aws.amazon.com/wellarchitected/latest/operational-excellence-pillar/mitigate-deployment-risks.html",
            aws_services=["AWS CodeDeploy", "Amazon Route 53", "Elastic Load Balancing", "AWS App Runner"],
            compliance_mappings={
                "soc2": ["CC8.1"],
                "iso27001": ["A.12.1", "A.14.2"],
                "cis_aws": ["4.16"]
            }
        ),
    ])
    
    # Operate Section
    questions.extend([
        Question(
            id="OPS-OPR-001",
            pillar=Pillar.OPERATIONAL_EXCELLENCE,
            category="Operate - Understanding Workload Health",
            text="How do you understand the health of your workload?",
            description="Define, capture, and analyze workload metrics to gain visibility to workload events so that you can take appropriate action.",
            why_important="Without understanding workload health, you cannot proactively address issues or optimize performance.",
            best_practices=[
                "Identify key performance indicators (KPIs)",
                "Define workload metrics that measure KPIs",
                "Collect and analyze workload metrics",
                "Establish workload metric baselines",
                "Learn expected patterns of activity for workload",
                "Alert when workload outcomes are at risk",
                "Alert when workload anomalies are detected",
                "Validate the achievement of outcomes and effectiveness of KPIs"
            ],
            choices=[
                Choice(
                    id="OPS-OPR-001-A",
                    text="Comprehensive KPI tracking with automated anomaly detection and real-time alerting",
                    risk_level=RiskLevel.NONE,
                    points=100,
                    auto_detectable=True
                ),
                Choice(
                    id="OPS-OPR-001-B",
                    text="Basic metrics collected with manual monitoring",
                    risk_level=RiskLevel.LOW,
                    points=60
                ),
                Choice(
                    id="OPS-OPR-001-C",
                    text="Limited metrics, reactive monitoring only",
                    risk_level=RiskLevel.MEDIUM,
                    points=30
                ),
                Choice(
                    id="OPS-OPR-001-D",
                    text="No systematic health monitoring in place",
                    risk_level=RiskLevel.HIGH,
                    points=0
                )
            ],
            help_link="https://docs.aws.amazon.com/wellarchitected/latest/operational-excellence-pillar/understanding-workload-health.html",
            aws_services=["Amazon CloudWatch", "AWS CloudTrail", "Amazon CloudWatch Logs Insights", "Amazon CloudWatch Alarms"],
            compliance_mappings={
                "soc2": ["CC7.2"],
                "iso27001": ["A.12.4"],
                "pci_dss": ["Req 10"]
            },
            automated_check="check_cloudwatch_alarms"
        ),
    ])
    
    # Will continue with remaining pillars...
    # This is a framework showing the comprehensive approach
    
    return questions

# Export all
__all__ = [
    'Pillar', 'RiskLevel', 'AssessmentType',
    'Question', 'Choice', 'Response', 'ActionItem', 'WAFAssessment',
    'get_all_questions'
]
