"""
WAF Unified Workflow Module
Integrates WAF Scanner (automated) + WAF Assessment (questionnaire) into single comprehensive workflow

This module solves the problem of disconnected scanner and assessment modules by:
1. Running automated scans first to gather technical findings
2. Auto-filling WAF questions based on scan results
3. Guiding users through remaining manual questions
4. Generating a single comprehensive report combining both

Created: December 2024
"""

import streamlit as st
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field, asdict
from enum import Enum
import json
import uuid
from io import BytesIO

# Import existing modules
try:
    from aws_connector import get_aws_session, test_aws_connection
    from landscape_scanner import (
        AWSLandscapeScanner,
        Finding,
        ResourceInventory,
        LandscapeAssessment,
        generate_demo_assessment
    )
    from waf_framework_core import (
        Pillar, RiskLevel, AssessmentType,
        Question, Choice, Response, ActionItem, WAFAssessment
    )
    AWS_AVAILABLE = True
except ImportError as e:
    AWS_AVAILABLE = False
    print(f"Import warning: {e}")

try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False

# ============================================================================
# DATA MODELS
# ============================================================================

class WorkflowPhase(Enum):
    """Phases of the unified workflow"""
    SETUP = "setup"
    SCANNING = "scanning"
    AUTO_ASSESSMENT = "auto_assessment"
    MANUAL_REVIEW = "manual_review"
    REPORT_GENERATION = "report_generation"
    COMPLETE = "complete"

@dataclass
class AutoDetectedAnswer:
    """Answer auto-detected from scan results"""
    question_id: str
    detected_choice_id: str
    confidence: float  # 0.0 - 1.0
    evidence: List[str]
    findings_matched: List[str]  # Finding IDs that led to this detection
    needs_review: bool = False

@dataclass
class UnifiedAssessment:
    """Combined Scanner + Assessment results"""
    # Identification
    assessment_id: str
    created_at: datetime
    updated_at: datetime
    
    # Account Info
    account_id: str
    account_name: str
    regions_scanned: List[str]
    
    # Scan Results
    scan_completed: bool = False
    scan_timestamp: Optional[datetime] = None
    scan_duration_seconds: float = 0.0
    resources: Optional[ResourceInventory] = None
    findings: List[Finding] = field(default_factory=list)
    
    # Assessment Results
    assessment_completed: bool = False
    auto_detected_answers: Dict[str, AutoDetectedAnswer] = field(default_factory=dict)
    manual_answers: Dict[str, Response] = field(default_factory=dict)
    skipped_questions: List[str] = field(default_factory=list)
    
    # Scores
    pillar_scores: Dict[str, float] = field(default_factory=dict)
    overall_score: float = 0.0
    
    # Metrics
    total_questions: int = 0
    auto_detected_count: int = 0
    manual_answered_count: int = 0
    remaining_questions: int = 0
    
    # Findings Summary
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0
    
    # AI Insights
    ai_insights: List[Dict] = field(default_factory=list)
    
    # Current State
    current_phase: WorkflowPhase = WorkflowPhase.SETUP

# ============================================================================
# QUESTION DATABASE - AUTO-DETECTABLE QUESTIONS
# ============================================================================

def get_auto_detectable_questions() -> List[Dict]:
    """
    Questions that can be auto-detected from AWS scan results.
    Maps scan findings to WAF questions.
    """
    return [
        # SECURITY PILLAR
        {
            "id": "SEC-IAM-001",
            "pillar": "Security",
            "category": "Identity and Access Management",
            "text": "How do you manage identities for people and machines?",
            "detection_rules": [
                {
                    "finding_keywords": ["MFA", "multi-factor", "root account"],
                    "severity_threshold": "HIGH",
                    "choice_mapping": {
                        "no_findings": "SEC-IAM-001-A",  # Best practice
                        "low_severity": "SEC-IAM-001-B",
                        "medium_severity": "SEC-IAM-001-C",
                        "high_severity": "SEC-IAM-001-D"
                    }
                }
            ],
            "choices": [
                {"id": "SEC-IAM-001-A", "text": "Centralized IdP with SSO, MFA enforced, IAM roles for workloads", "score": 100},
                {"id": "SEC-IAM-001-B", "text": "IAM users with MFA, some use of IAM roles", "score": 65},
                {"id": "SEC-IAM-001-C", "text": "Mix of IAM users and roles, inconsistent MFA", "score": 35},
                {"id": "SEC-IAM-001-D", "text": "Long-term access keys, no MFA", "score": 0}
            ]
        },
        {
            "id": "SEC-IAM-002",
            "pillar": "Security",
            "category": "Identity and Access Management",
            "text": "How do you manage permissions for people and machines?",
            "detection_rules": [
                {
                    "finding_keywords": ["IAM policy", "least privilege", "overly permissive", "admin access"],
                    "resource_checks": ["iam_policies", "iam_roles"],
                    "choice_mapping": {
                        "no_findings": "SEC-IAM-002-A",
                        "low_severity": "SEC-IAM-002-B",
                        "medium_severity": "SEC-IAM-002-C",
                        "high_severity": "SEC-IAM-002-D"
                    }
                }
            ],
            "choices": [
                {"id": "SEC-IAM-002-A", "text": "Least privilege with IAM Access Analyzer, SCPs, permission boundaries", "score": 100},
                {"id": "SEC-IAM-002-B", "text": "Policies follow least privilege principle, periodic reviews", "score": 70},
                {"id": "SEC-IAM-002-C", "text": "Broad permissions, manual reviews", "score": 35},
                {"id": "SEC-IAM-002-D", "text": "Overly permissive policies, no reviews", "score": 0}
            ]
        },
        {
            "id": "SEC-DATA-001",
            "pillar": "Security",
            "category": "Data Protection",
            "text": "How do you classify your data?",
            "detection_rules": [
                {
                    "finding_keywords": ["data classification", "tagging", "sensitive data", "Macie"],
                    "choice_mapping": {
                        "no_findings": "SEC-DATA-001-A",
                        "low_severity": "SEC-DATA-001-B",
                        "medium_severity": "SEC-DATA-001-C",
                        "high_severity": "SEC-DATA-001-D"
                    }
                }
            ],
            "choices": [
                {"id": "SEC-DATA-001-A", "text": "Automated classification with Macie, comprehensive tagging", "score": 100},
                {"id": "SEC-DATA-001-B", "text": "Manual classification, some tagging standards", "score": 65},
                {"id": "SEC-DATA-001-C", "text": "Partial classification, inconsistent tagging", "score": 35},
                {"id": "SEC-DATA-001-D", "text": "No data classification", "score": 0}
            ]
        },
        {
            "id": "SEC-DATA-002",
            "pillar": "Security",
            "category": "Data Protection",
            "text": "How do you protect your data at rest?",
            "detection_rules": [
                {
                    "finding_keywords": ["encryption at rest", "unencrypted", "KMS", "S3 encryption", "EBS encryption", "RDS encryption"],
                    "resource_checks": ["s3_unencrypted", "ebs_unencrypted", "rds_encrypted"],
                    "choice_mapping": {
                        "no_findings": "SEC-DATA-002-A",
                        "low_severity": "SEC-DATA-002-B",
                        "medium_severity": "SEC-DATA-002-C",
                        "high_severity": "SEC-DATA-002-D"
                    }
                }
            ],
            "choices": [
                {"id": "SEC-DATA-002-A", "text": "All data encrypted with KMS CMK, key rotation enabled", "score": 100},
                {"id": "SEC-DATA-002-B", "text": "Most data encrypted, using AWS managed keys", "score": 70},
                {"id": "SEC-DATA-002-C", "text": "Some data encrypted, inconsistent approach", "score": 35},
                {"id": "SEC-DATA-002-D", "text": "Unencrypted data exists", "score": 0}
            ]
        },
        {
            "id": "SEC-INF-001",
            "pillar": "Security",
            "category": "Infrastructure Protection",
            "text": "How do you protect your network resources?",
            "detection_rules": [
                {
                    "finding_keywords": ["security group", "open port", "0.0.0.0", "public access", "NACL", "VPC"],
                    "resource_checks": ["security_groups_open", "vpcs"],
                    "choice_mapping": {
                        "no_findings": "SEC-INF-001-A",
                        "low_severity": "SEC-INF-001-B",
                        "medium_severity": "SEC-INF-001-C",
                        "high_severity": "SEC-INF-001-D"
                    }
                }
            ],
            "choices": [
                {"id": "SEC-INF-001-A", "text": "Layered defense with VPC, private subnets, SGs, NACLs, WAF", "score": 100},
                {"id": "SEC-INF-001-B", "text": "VPC with public/private subnets, security groups configured", "score": 65},
                {"id": "SEC-INF-001-C", "text": "Basic VPC, broad security group rules", "score": 35},
                {"id": "SEC-INF-001-D", "text": "Default VPC, unrestricted security groups", "score": 0}
            ]
        },
        
        # RELIABILITY PILLAR
        {
            "id": "REL-CHANGE-001",
            "pillar": "Reliability",
            "category": "Change Management",
            "text": "How do you monitor workload resources?",
            "detection_rules": [
                {
                    "finding_keywords": ["CloudWatch", "monitoring", "alarm", "metrics", "logging"],
                    "choice_mapping": {
                        "no_findings": "REL-CHANGE-001-A",
                        "low_severity": "REL-CHANGE-001-B",
                        "medium_severity": "REL-CHANGE-001-C",
                        "high_severity": "REL-CHANGE-001-D"
                    }
                }
            ],
            "choices": [
                {"id": "REL-CHANGE-001-A", "text": "Comprehensive monitoring with CloudWatch, X-Ray, custom metrics", "score": 100},
                {"id": "REL-CHANGE-001-B", "text": "Standard CloudWatch metrics and alarms", "score": 65},
                {"id": "REL-CHANGE-001-C", "text": "Basic monitoring, few alarms", "score": 35},
                {"id": "REL-CHANGE-001-D", "text": "Minimal or no monitoring", "score": 0}
            ]
        },
        {
            "id": "REL-FAIL-001",
            "pillar": "Reliability",
            "category": "Failure Management",
            "text": "How do you back up data?",
            "detection_rules": [
                {
                    "finding_keywords": ["backup", "snapshot", "retention", "AWS Backup", "recovery point"],
                    "resource_checks": ["rds_backup_enabled", "ebs_snapshots"],
                    "choice_mapping": {
                        "no_findings": "REL-FAIL-001-A",
                        "low_severity": "REL-FAIL-001-B",
                        "medium_severity": "REL-FAIL-001-C",
                        "high_severity": "REL-FAIL-001-D"
                    }
                }
            ],
            "choices": [
                {"id": "REL-FAIL-001-A", "text": "Automated backups with AWS Backup, cross-region, tested regularly", "score": 100},
                {"id": "REL-FAIL-001-B", "text": "Automated backups enabled, periodic testing", "score": 70},
                {"id": "REL-FAIL-001-C", "text": "Manual backups, inconsistent schedule", "score": 35},
                {"id": "REL-FAIL-001-D", "text": "No backup strategy", "score": 0}
            ]
        },
        {
            "id": "REL-AVAIL-001",
            "pillar": "Reliability",
            "category": "Workload Architecture",
            "text": "How do you design your workload service architecture?",
            "detection_rules": [
                {
                    "finding_keywords": ["multi-AZ", "high availability", "single point of failure", "redundancy"],
                    "resource_checks": ["rds_multi_az", "autoscaling_groups"],
                    "choice_mapping": {
                        "no_findings": "REL-AVAIL-001-A",
                        "low_severity": "REL-AVAIL-001-B",
                        "medium_severity": "REL-AVAIL-001-C",
                        "high_severity": "REL-AVAIL-001-D"
                    }
                }
            ],
            "choices": [
                {"id": "REL-AVAIL-001-A", "text": "Multi-AZ/Region with auto-scaling, no single points of failure", "score": 100},
                {"id": "REL-AVAIL-001-B", "text": "Multi-AZ deployment, some redundancy", "score": 70},
                {"id": "REL-AVAIL-001-C", "text": "Single AZ with manual failover", "score": 35},
                {"id": "REL-AVAIL-001-D", "text": "Single instance, no redundancy", "score": 0}
            ]
        },
        
        # PERFORMANCE PILLAR
        {
            "id": "PERF-COMPUTE-001",
            "pillar": "Performance Efficiency",
            "category": "Compute",
            "text": "How do you select the best performing compute solution?",
            "detection_rules": [
                {
                    "finding_keywords": ["right-sizing", "compute optimization", "instance type", "over-provisioned"],
                    "resource_checks": ["ec2_instances", "lambda_functions"],
                    "choice_mapping": {
                        "no_findings": "PERF-COMPUTE-001-A",
                        "low_severity": "PERF-COMPUTE-001-B",
                        "medium_severity": "PERF-COMPUTE-001-C",
                        "high_severity": "PERF-COMPUTE-001-D"
                    }
                }
            ],
            "choices": [
                {"id": "PERF-COMPUTE-001-A", "text": "Automated rightsizing, multiple compute options evaluated", "score": 100},
                {"id": "PERF-COMPUTE-001-B", "text": "Periodic rightsizing reviews, appropriate instance types", "score": 70},
                {"id": "PERF-COMPUTE-001-C", "text": "Manual selection, infrequent reviews", "score": 35},
                {"id": "PERF-COMPUTE-001-D", "text": "No systematic approach to compute selection", "score": 0}
            ]
        },
        
        # COST OPTIMIZATION PILLAR
        {
            "id": "COST-EXP-001",
            "pillar": "Cost Optimization",
            "category": "Expenditure Awareness",
            "text": "How do you govern usage?",
            "detection_rules": [
                {
                    "finding_keywords": ["cost allocation", "tagging", "budget", "cost explorer"],
                    "choice_mapping": {
                        "no_findings": "COST-EXP-001-A",
                        "low_severity": "COST-EXP-001-B",
                        "medium_severity": "COST-EXP-001-C",
                        "high_severity": "COST-EXP-001-D"
                    }
                }
            ],
            "choices": [
                {"id": "COST-EXP-001-A", "text": "Comprehensive cost governance with budgets, alerts, and policies", "score": 100},
                {"id": "COST-EXP-001-B", "text": "Budgets and basic cost monitoring", "score": 70},
                {"id": "COST-EXP-001-C", "text": "Manual cost reviews, no budgets", "score": 35},
                {"id": "COST-EXP-001-D", "text": "No cost governance", "score": 0}
            ]
        },
        {
            "id": "COST-OPT-001",
            "pillar": "Cost Optimization",
            "category": "Cost-Effective Resources",
            "text": "How do you evaluate cost when you select services?",
            "detection_rules": [
                {
                    "finding_keywords": ["unused", "idle", "underutilized", "reserved instance", "savings plan"],
                    "resource_checks": ["ec2_stopped", "ebs_unattached", "elastic_ips_unattached"],
                    "choice_mapping": {
                        "no_findings": "COST-OPT-001-A",
                        "low_severity": "COST-OPT-001-B",
                        "medium_severity": "COST-OPT-001-C",
                        "high_severity": "COST-OPT-001-D"
                    }
                }
            ],
            "choices": [
                {"id": "COST-OPT-001-A", "text": "Systematic cost evaluation, RI/SP optimization, regular reviews", "score": 100},
                {"id": "COST-OPT-001-B", "text": "Some cost consideration, using some commitments", "score": 70},
                {"id": "COST-OPT-001-C", "text": "Ad-hoc cost evaluation", "score": 35},
                {"id": "COST-OPT-001-D", "text": "No cost evaluation in service selection", "score": 0}
            ]
        },
        
        # OPERATIONAL EXCELLENCE PILLAR
        {
            "id": "OPS-PREP-001",
            "pillar": "Operational Excellence",
            "category": "Prepare",
            "text": "How do you determine what your priorities are?",
            "detection_rules": [
                {
                    "finding_keywords": ["tagging", "resource groups", "organization"],
                    "choice_mapping": {
                        "no_findings": "OPS-PREP-001-A",
                        "low_severity": "OPS-PREP-001-B",
                        "medium_severity": "OPS-PREP-001-C",
                        "high_severity": "OPS-PREP-001-D"
                    }
                }
            ],
            "choices": [
                {"id": "OPS-PREP-001-A", "text": "Clear priorities with tagging, resource groups, documented standards", "score": 100},
                {"id": "OPS-PREP-001-B", "text": "Some tagging standards, basic organization", "score": 65},
                {"id": "OPS-PREP-001-C", "text": "Inconsistent tagging, unclear priorities", "score": 35},
                {"id": "OPS-PREP-001-D", "text": "No systematic approach", "score": 0}
            ]
        },
        {
            "id": "OPS-OBS-001",
            "pillar": "Operational Excellence",
            "category": "Operate",
            "text": "How do you understand the health of your workload?",
            "detection_rules": [
                {
                    "finding_keywords": ["CloudWatch", "logging", "CloudTrail", "observability", "tracing"],
                    "choice_mapping": {
                        "no_findings": "OPS-OBS-001-A",
                        "low_severity": "OPS-OBS-001-B",
                        "medium_severity": "OPS-OBS-001-C",
                        "high_severity": "OPS-OBS-001-D"
                    }
                }
            ],
            "choices": [
                {"id": "OPS-OBS-001-A", "text": "Full observability: metrics, logs, traces, dashboards", "score": 100},
                {"id": "OPS-OBS-001-B", "text": "Good monitoring with CloudWatch and dashboards", "score": 70},
                {"id": "OPS-OBS-001-C", "text": "Basic logging, few metrics", "score": 35},
                {"id": "OPS-OBS-001-D", "text": "Limited visibility into workload health", "score": 0}
            ]
        },
        
        # SUSTAINABILITY PILLAR
        {
            "id": "SUS-REG-001",
            "pillar": "Sustainability",
            "category": "Region Selection",
            "text": "How do you select Regions to support your sustainability goals?",
            "detection_rules": [
                {
                    "finding_keywords": ["region", "carbon", "sustainability", "renewable"],
                    "choice_mapping": {
                        "no_findings": "SUS-REG-001-A",
                        "low_severity": "SUS-REG-001-B",
                        "medium_severity": "SUS-REG-001-C",
                        "high_severity": "SUS-REG-001-D"
                    }
                }
            ],
            "choices": [
                {"id": "SUS-REG-001-A", "text": "Region selection considers carbon footprint and renewable energy", "score": 100},
                {"id": "SUS-REG-001-B", "text": "Some sustainability consideration in region selection", "score": 65},
                {"id": "SUS-REG-001-C", "text": "Regions selected primarily for latency/cost", "score": 35},
                {"id": "SUS-REG-001-D", "text": "No sustainability consideration", "score": 0}
            ]
        },
        {
            "id": "SUS-UTIL-001",
            "pillar": "Sustainability",
            "category": "Resource Utilization",
            "text": "How do you take advantage of usage patterns to support sustainability?",
            "detection_rules": [
                {
                    "finding_keywords": ["utilization", "idle", "unused", "optimization", "rightsizing"],
                    "resource_checks": ["ec2_stopped", "ebs_unattached"],
                    "choice_mapping": {
                        "no_findings": "SUS-UTIL-001-A",
                        "low_severity": "SUS-UTIL-001-B",
                        "medium_severity": "SUS-UTIL-001-C",
                        "high_severity": "SUS-UTIL-001-D"
                    }
                }
            ],
            "choices": [
                {"id": "SUS-UTIL-001-A", "text": "Optimized utilization with auto-scaling, scheduled scaling", "score": 100},
                {"id": "SUS-UTIL-001-B", "text": "Some auto-scaling, moderate utilization", "score": 65},
                {"id": "SUS-UTIL-001-C", "text": "Manual scaling, inconsistent utilization", "score": 35},
                {"id": "SUS-UTIL-001-D", "text": "Resources always running regardless of demand", "score": 0}
            ]
        }
    ]

def get_manual_only_questions() -> List[Dict]:
    """
    Questions that CANNOT be auto-detected and require manual input.
    These cover organizational, procedural, and strategic aspects.
    """
    return [
        # SECURITY - Manual Questions
        {
            "id": "SEC-MANUAL-001",
            "pillar": "Security",
            "category": "Security Governance",
            "text": "How do you ensure your security team stays current with threats and best practices?",
            "why_manual": "Training and skills development cannot be detected from AWS resources",
            "choices": [
                {"id": "SEC-MANUAL-001-A", "text": "Regular training, certifications, threat intelligence subscriptions", "score": 100},
                {"id": "SEC-MANUAL-001-B", "text": "Annual training, some certifications", "score": 65},
                {"id": "SEC-MANUAL-001-C", "text": "Ad-hoc training", "score": 35},
                {"id": "SEC-MANUAL-001-D", "text": "No formal security training program", "score": 0}
            ]
        },
        {
            "id": "SEC-MANUAL-002",
            "pillar": "Security",
            "category": "Incident Response",
            "text": "How do you prepare for security events?",
            "why_manual": "Incident response procedures are documented outside AWS",
            "choices": [
                {"id": "SEC-MANUAL-002-A", "text": "Documented IR plan, regular drills, automated response playbooks", "score": 100},
                {"id": "SEC-MANUAL-002-B", "text": "Documented procedures, annual testing", "score": 70},
                {"id": "SEC-MANUAL-002-C", "text": "Basic procedures, rarely tested", "score": 35},
                {"id": "SEC-MANUAL-002-D", "text": "No formal incident response plan", "score": 0}
            ]
        },
        
        # RELIABILITY - Manual Questions
        {
            "id": "REL-MANUAL-001",
            "pillar": "Reliability",
            "category": "Change Management",
            "text": "How do you implement change?",
            "why_manual": "Change management processes are organizational, not technical",
            "choices": [
                {"id": "REL-MANUAL-001-A", "text": "CI/CD with automated testing, gradual rollouts, automated rollback", "score": 100},
                {"id": "REL-MANUAL-001-B", "text": "CI/CD with some automation, manual approval gates", "score": 70},
                {"id": "REL-MANUAL-001-C", "text": "Manual deployments with some scripting", "score": 35},
                {"id": "REL-MANUAL-001-D", "text": "Manual changes directly to production", "score": 0}
            ]
        },
        {
            "id": "REL-MANUAL-002",
            "pillar": "Reliability",
            "category": "Failure Management",
            "text": "How do you test resilience?",
            "why_manual": "Chaos engineering and DR testing practices are procedural",
            "choices": [
                {"id": "REL-MANUAL-002-A", "text": "Regular chaos engineering, game days, DR drills", "score": 100},
                {"id": "REL-MANUAL-002-B", "text": "Annual DR tests, some failure injection", "score": 70},
                {"id": "REL-MANUAL-002-C", "text": "Occasional manual testing", "score": 35},
                {"id": "REL-MANUAL-002-D", "text": "No resilience testing", "score": 0}
            ]
        },
        
        # OPERATIONAL EXCELLENCE - Manual Questions
        {
            "id": "OPS-MANUAL-001",
            "pillar": "Operational Excellence",
            "category": "Organization",
            "text": "How does your organizational culture support your business outcomes?",
            "why_manual": "Organizational culture cannot be detected from infrastructure",
            "choices": [
                {"id": "OPS-MANUAL-001-A", "text": "Clear ownership, blameless culture, continuous learning", "score": 100},
                {"id": "OPS-MANUAL-001-B", "text": "Defined responsibilities, learning encouraged", "score": 70},
                {"id": "OPS-MANUAL-001-C", "text": "Some ownership defined, reactive learning", "score": 35},
                {"id": "OPS-MANUAL-001-D", "text": "Unclear ownership, blame-focused culture", "score": 0}
            ]
        },
        {
            "id": "OPS-MANUAL-002",
            "pillar": "Operational Excellence",
            "category": "Evolve",
            "text": "How do you evolve operations?",
            "why_manual": "Continuous improvement processes are organizational",
            "choices": [
                {"id": "OPS-MANUAL-002-A", "text": "Regular retrospectives, metrics-driven improvement, experimentation", "score": 100},
                {"id": "OPS-MANUAL-002-B", "text": "Periodic reviews, documented improvements", "score": 70},
                {"id": "OPS-MANUAL-002-C", "text": "Reactive improvements after incidents", "score": 35},
                {"id": "OPS-MANUAL-002-D", "text": "No formal improvement process", "score": 0}
            ]
        },
        
        # COST OPTIMIZATION - Manual Questions
        {
            "id": "COST-MANUAL-001",
            "pillar": "Cost Optimization",
            "category": "Financial Management",
            "text": "How do you implement cloud financial management?",
            "why_manual": "Financial management practices are organizational",
            "choices": [
                {"id": "COST-MANUAL-001-A", "text": "Dedicated FinOps team, chargeback/showback, regular optimization", "score": 100},
                {"id": "COST-MANUAL-001-B", "text": "Cost owners assigned, regular cost reviews", "score": 70},
                {"id": "COST-MANUAL-001-C", "text": "Centralized cost management, infrequent reviews", "score": 35},
                {"id": "COST-MANUAL-001-D", "text": "No formal cloud financial management", "score": 0}
            ]
        },
        
        # PERFORMANCE - Manual Questions
        {
            "id": "PERF-MANUAL-001",
            "pillar": "Performance Efficiency",
            "category": "Review",
            "text": "How do you monitor your resources to ensure they are performing?",
            "why_manual": "Monitoring practices and review frequency are procedural",
            "choices": [
                {"id": "PERF-MANUAL-001-A", "text": "Automated performance testing, regular load tests, SLO monitoring", "score": 100},
                {"id": "PERF-MANUAL-001-B", "text": "Regular performance reviews, some automated testing", "score": 70},
                {"id": "PERF-MANUAL-001-C", "text": "Reactive performance monitoring", "score": 35},
                {"id": "PERF-MANUAL-001-D", "text": "No systematic performance monitoring", "score": 0}
            ]
        },
        
        # SUSTAINABILITY - Manual Questions
        {
            "id": "SUS-MANUAL-001",
            "pillar": "Sustainability",
            "category": "Awareness",
            "text": "How do you track sustainability metrics?",
            "why_manual": "Sustainability tracking approaches are organizational decisions",
            "choices": [
                {"id": "SUS-MANUAL-001-A", "text": "Using AWS Customer Carbon Footprint Tool, regular reporting", "score": 100},
                {"id": "SUS-MANUAL-001-B", "text": "Some sustainability awareness, basic tracking", "score": 65},
                {"id": "SUS-MANUAL-001-C", "text": "Limited awareness", "score": 35},
                {"id": "SUS-MANUAL-001-D", "text": "No sustainability tracking", "score": 0}
            ]
        }
    ]

# ============================================================================
# AUTO-DETECTION ENGINE
# ============================================================================

class WAFAutoDetectionEngine:
    """
    Engine that maps AWS scan findings to WAF assessment questions.
    Analyzes findings and resources to auto-fill questions.
    """
    
    def __init__(self):
        self.auto_questions = get_auto_detectable_questions()
        self.detection_log = []
    
    def analyze_findings(
        self, 
        findings: List[Finding], 
        resources: Optional[ResourceInventory]
    ) -> Dict[str, AutoDetectedAnswer]:
        """
        Analyze scan findings and map them to WAF questions.
        Returns dictionary of question_id -> AutoDetectedAnswer
        """
        detected_answers = {}
        
        for question in self.auto_questions:
            detection_result = self._detect_answer_for_question(
                question, findings, resources
            )
            if detection_result:
                detected_answers[question["id"]] = detection_result
        
        return detected_answers
    
    def _detect_answer_for_question(
        self, 
        question: Dict, 
        findings: List[Finding],
        resources: Optional[ResourceInventory]
    ) -> Optional[AutoDetectedAnswer]:
        """Detect answer for a single question based on findings"""
        
        matched_findings = []
        evidence = []
        max_severity = "NONE"
        
        for rule in question.get("detection_rules", []):
            keywords = rule.get("finding_keywords", [])
            
            # Search findings for matching keywords
            for finding in findings:
                finding_text = f"{finding.title} {finding.description}".lower()
                
                for keyword in keywords:
                    if keyword.lower() in finding_text:
                        matched_findings.append(finding.id)
                        evidence.append(f"{finding.title}: {finding.description[:100]}...")
                        
                        # Track max severity
                        if finding.severity == "CRITICAL":
                            max_severity = "CRITICAL"
                        elif finding.severity == "HIGH" and max_severity not in ["CRITICAL"]:
                            max_severity = "HIGH"
                        elif finding.severity == "MEDIUM" and max_severity not in ["CRITICAL", "HIGH"]:
                            max_severity = "MEDIUM"
                        elif finding.severity == "LOW" and max_severity == "NONE":
                            max_severity = "LOW"
                        break
            
            # Check resource counts if applicable
            if resources and "resource_checks" in rule:
                for check in rule["resource_checks"]:
                    value = getattr(resources, check, 0)
                    if value > 0:
                        evidence.append(f"Resource check {check}: {value} found")
        
        # Determine choice based on severity
        choice_mapping = question.get("detection_rules", [{}])[0].get("choice_mapping", {})
        
        if not matched_findings:
            selected_choice = choice_mapping.get("no_findings")
            confidence = 0.7  # Lower confidence when no findings
        elif max_severity == "CRITICAL" or max_severity == "HIGH":
            selected_choice = choice_mapping.get("high_severity")
            confidence = 0.9
        elif max_severity == "MEDIUM":
            selected_choice = choice_mapping.get("medium_severity")
            confidence = 0.85
        else:
            selected_choice = choice_mapping.get("low_severity")
            confidence = 0.8
        
        if not selected_choice:
            return None
        
        return AutoDetectedAnswer(
            question_id=question["id"],
            detected_choice_id=selected_choice,
            confidence=confidence,
            evidence=evidence[:5],  # Limit evidence
            findings_matched=matched_findings[:10],  # Limit matches
            needs_review=confidence < 0.8
        )

# ============================================================================
# UNIFIED WORKFLOW ENGINE
# ============================================================================

class UnifiedWAFWorkflow:
    """
    Main workflow engine that orchestrates scanner + assessment.
    """
    
    def __init__(self, session=None, use_demo: bool = False):
        self.session = session
        self.use_demo = use_demo
        self.detection_engine = WAFAutoDetectionEngine()
        self.auto_questions = get_auto_detectable_questions()
        self.manual_questions = get_manual_only_questions()
    
    def create_assessment(self, account_name: str, account_id: str = "") -> UnifiedAssessment:
        """Create a new unified assessment"""
        total_questions = len(self.auto_questions) + len(self.manual_questions)
        
        return UnifiedAssessment(
            assessment_id=str(uuid.uuid4()),
            created_at=datetime.now(),
            updated_at=datetime.now(),
            account_id=account_id or "demo-account",
            account_name=account_name,
            regions_scanned=[],
            total_questions=total_questions,
            remaining_questions=total_questions,
            current_phase=WorkflowPhase.SETUP
        )
    
    def run_scan(
        self, 
        assessment: UnifiedAssessment, 
        regions: List[str] = None,
        progress_callback=None
    ) -> UnifiedAssessment:
        """
        Phase 1: Run automated AWS scan
        """
        regions = regions or ["us-east-1"]
        assessment.current_phase = WorkflowPhase.SCANNING
        assessment.regions_scanned = regions
        
        start_time = datetime.now()
        
        if self.use_demo or not self.session:
            # Demo mode
            if progress_callback:
                progress_callback("Generating demo scan data...", 30)
            
            landscape = generate_demo_assessment()
            
        else:
            # Real AWS scan
            if progress_callback:
                progress_callback("Initializing AWS scanner...", 10)
            
            scanner = AWSLandscapeScanner(self.session)
            landscape = scanner.run_scan(regions, progress_callback=progress_callback)
        
        # Store scan results
        assessment.scan_completed = True
        assessment.scan_timestamp = datetime.now()
        assessment.scan_duration_seconds = (datetime.now() - start_time).total_seconds()
        assessment.resources = landscape.resources
        assessment.findings = landscape.findings
        
        # Count findings by severity
        assessment.critical_findings = len([f for f in landscape.findings if f.severity == "CRITICAL"])
        assessment.high_findings = len([f for f in landscape.findings if f.severity == "HIGH"])
        assessment.medium_findings = len([f for f in landscape.findings if f.severity == "MEDIUM"])
        assessment.low_findings = len([f for f in landscape.findings if f.severity == "LOW"])
        
        assessment.updated_at = datetime.now()
        
        if progress_callback:
            progress_callback("Scan complete!", 100)
        
        return assessment
    
    def run_auto_detection(
        self, 
        assessment: UnifiedAssessment,
        progress_callback=None
    ) -> UnifiedAssessment:
        """
        Phase 2: Auto-detect answers from scan results
        """
        assessment.current_phase = WorkflowPhase.AUTO_ASSESSMENT
        
        if progress_callback:
            progress_callback("Analyzing findings for WAF questions...", 20)
        
        # Run auto-detection
        detected_answers = self.detection_engine.analyze_findings(
            assessment.findings,
            assessment.resources
        )
        
        assessment.auto_detected_answers = detected_answers
        assessment.auto_detected_count = len(detected_answers)
        assessment.remaining_questions = assessment.total_questions - len(detected_answers)
        
        if progress_callback:
            progress_callback(f"Auto-detected {len(detected_answers)} answers!", 100)
        
        assessment.current_phase = WorkflowPhase.MANUAL_REVIEW
        assessment.updated_at = datetime.now()
        
        return assessment
    
    def calculate_scores(self, assessment: UnifiedAssessment) -> UnifiedAssessment:
        """
        Calculate pillar scores based on all answers
        """
        pillar_scores = {
            "Security": [],
            "Reliability": [],
            "Performance Efficiency": [],
            "Cost Optimization": [],
            "Operational Excellence": [],
            "Sustainability": []
        }
        
        # Score auto-detected answers
        for q in self.auto_questions:
            q_id = q["id"]
            pillar = q["pillar"]
            
            if q_id in assessment.auto_detected_answers:
                detected = assessment.auto_detected_answers[q_id]
                for choice in q["choices"]:
                    if choice["id"] == detected.detected_choice_id:
                        pillar_scores[pillar].append(choice["score"])
                        break
        
        # Score manual answers
        for q in self.manual_questions:
            q_id = q["id"]
            pillar = q["pillar"]
            
            if q_id in assessment.manual_answers:
                answer = assessment.manual_answers[q_id]
                for choice in q["choices"]:
                    if choice["id"] == answer.choice_id:
                        pillar_scores[pillar].append(choice["score"])
                        break
        
        # Calculate averages
        for pillar, scores in pillar_scores.items():
            if scores:
                assessment.pillar_scores[pillar] = sum(scores) / len(scores)
            else:
                assessment.pillar_scores[pillar] = 0.0
        
        # Overall score
        all_scores = [s for scores in pillar_scores.values() for s in scores]
        if all_scores:
            assessment.overall_score = sum(all_scores) / len(all_scores)
        
        assessment.updated_at = datetime.now()
        return assessment
    
    def get_unanswered_manual_questions(self, assessment: UnifiedAssessment) -> List[Dict]:
        """Get list of manual questions that still need answers"""
        unanswered = []
        for q in self.manual_questions:
            if q["id"] not in assessment.manual_answers and q["id"] not in assessment.skipped_questions:
                unanswered.append(q)
        return unanswered
    
    def get_low_confidence_detections(self, assessment: UnifiedAssessment) -> List[Tuple[Dict, AutoDetectedAnswer]]:
        """Get auto-detected answers that need human review"""
        needs_review = []
        for q in self.auto_questions:
            if q["id"] in assessment.auto_detected_answers:
                detected = assessment.auto_detected_answers[q["id"]]
                if detected.needs_review or detected.confidence < 0.8:
                    needs_review.append((q, detected))
        return needs_review

# ============================================================================
# PDF REPORT GENERATOR
# ============================================================================

class UnifiedReportGenerator:
    """
    Generates comprehensive PDF report combining scanner + assessment results
    """
    
    def __init__(self):
        self.styles = getSampleStyleSheet() if PDF_AVAILABLE else None
    
    def generate_report(self, assessment: UnifiedAssessment) -> bytes:
        """Generate comprehensive PDF report"""
        if not PDF_AVAILABLE:
            raise ImportError("reportlab is required for PDF generation")
        
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=0.5*inch, bottomMargin=0.5*inch)
        elements = []
        
        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            alignment=TA_CENTER,
            spaceAfter=20
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=self.styles['Heading2'],
            fontSize=16,
            spaceBefore=15,
            spaceAfter=10
        )
        
        # Cover Page
        elements.append(Spacer(1, 1*inch))
        elements.append(Paragraph("AWS Well-Architected Framework", title_style))
        elements.append(Paragraph("Unified Assessment Report", self.styles['Heading2']))
        elements.append(Spacer(1, 0.5*inch))
        
        # Summary table
        summary_data = [
            ["Account", assessment.account_name],
            ["Assessment ID", assessment.assessment_id[:8] + "..."],
            ["Date", assessment.created_at.strftime("%Y-%m-%d %H:%M")],
            ["Regions Scanned", ", ".join(assessment.regions_scanned)],
            ["Overall Score", f"{assessment.overall_score:.1f}/100"],
            ["Total Findings", str(len(assessment.findings))],
            ["Questions Auto-Detected", str(assessment.auto_detected_count)],
            ["Questions Manually Answered", str(len(assessment.manual_answers))]
        ]
        
        summary_table = Table(summary_data, colWidths=[2.5*inch, 4*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#232F3E')),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.white),
            ('BACKGROUND', (1, 0), (1, -1), colors.HexColor('#F8F9FA')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('PADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey)
        ]))
        elements.append(summary_table)
        elements.append(PageBreak())
        
        # Pillar Scores
        elements.append(Paragraph("WAF Pillar Scores", heading_style))
        
        pillar_data = [["Pillar", "Score", "Status"]]
        for pillar, score in assessment.pillar_scores.items():
            status = "✓ Good" if score >= 70 else ("⚠ Needs Attention" if score >= 50 else "✗ Critical")
            pillar_data.append([pillar, f"{score:.1f}/100", status])
        
        pillar_table = Table(pillar_data, colWidths=[2.5*inch, 1.5*inch, 2*inch])
        pillar_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#232F3E')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('PADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#F8F9FA')])
        ]))
        elements.append(pillar_table)
        elements.append(Spacer(1, 0.5*inch))
        
        # Findings Summary
        elements.append(Paragraph("Findings Summary", heading_style))
        
        findings_data = [
            ["Severity", "Count"],
            ["Critical", str(assessment.critical_findings)],
            ["High", str(assessment.high_findings)],
            ["Medium", str(assessment.medium_findings)],
            ["Low", str(assessment.low_findings)],
            ["Total", str(len(assessment.findings))]
        ]
        
        findings_table = Table(findings_data, colWidths=[2*inch, 1.5*inch])
        findings_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#232F3E')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('BACKGROUND', (0, 1), (-1, 1), colors.HexColor('#FF6B6B')),  # Critical - red
            ('BACKGROUND', (0, 2), (-1, 2), colors.HexColor('#FFA726')),  # High - orange
            ('BACKGROUND', (0, 3), (-1, 3), colors.HexColor('#FFEE58')),  # Medium - yellow
            ('BACKGROUND', (0, 4), (-1, 4), colors.HexColor('#66BB6A')),  # Low - green
            ('BACKGROUND', (0, 5), (-1, 5), colors.HexColor('#E0E0E0')),  # Total - grey
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('PADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey)
        ]))
        elements.append(findings_table)
        elements.append(PageBreak())
        
        # Top Findings
        elements.append(Paragraph("Top Priority Findings", heading_style))
        
        # Sort findings by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_findings = sorted(
            assessment.findings, 
            key=lambda f: severity_order.get(f.severity, 5)
        )[:15]  # Top 15
        
        for finding in sorted_findings:
            elements.append(Paragraph(
                f"<b>[{finding.severity}]</b> {finding.title}",
                self.styles['Normal']
            ))
            elements.append(Paragraph(
                f"<i>{finding.description[:200]}...</i>",
                self.styles['Normal']
            ))
            elements.append(Paragraph(
                f"Recommendation: {finding.recommendation[:150]}...",
                self.styles['Normal']
            ))
            elements.append(Spacer(1, 0.2*inch))
        
        elements.append(PageBreak())
        
        # Assessment Coverage
        elements.append(Paragraph("Assessment Coverage", heading_style))
        
        coverage_text = f"""
        This unified assessment combines automated infrastructure scanning with 
        Well-Architected Framework questionnaire responses.
        
        <b>Automated Detection:</b> {assessment.auto_detected_count} questions were automatically 
        answered based on {len(assessment.findings)} findings discovered during the AWS scan.
        
        <b>Manual Review:</b> {len(assessment.manual_answers)} questions were answered manually, 
        covering organizational, procedural, and strategic aspects that cannot be detected 
        from infrastructure alone.
        
        <b>Remaining:</b> {assessment.remaining_questions} questions remain unanswered.
        """
        
        elements.append(Paragraph(coverage_text, self.styles['Normal']))
        
        # Build PDF
        doc.build(elements)
        buffer.seek(0)
        return buffer.getvalue()

# ============================================================================
# STREAMLIT UI
# ============================================================================

def render_unified_waf_workflow():
    """
    Main UI for unified WAF workflow
    """
    st.title("🔍 Unified WAF Assessment")
    st.markdown("### Complete Well-Architected Review: Scanner + Assessment Combined")
    
    # Initialize session state
    if 'unified_assessment' not in st.session_state:
        st.session_state.unified_assessment = None
    if 'workflow_engine' not in st.session_state:
        st.session_state.workflow_engine = None
    
    # Check demo mode
    use_demo = st.session_state.get('demo_mode', True)
    
    # Status banner
    if use_demo:
        st.info("🎮 **Demo Mode Active** - Using simulated data. Switch to Live Mode for real AWS scanning.")
    
    # Phase indicator
    if st.session_state.unified_assessment:
        assessment = st.session_state.unified_assessment
        phases = ["Setup", "Scanning", "Auto-Detection", "Manual Review", "Report"]
        phase_idx = {
            WorkflowPhase.SETUP: 0,
            WorkflowPhase.SCANNING: 1,
            WorkflowPhase.AUTO_ASSESSMENT: 2,
            WorkflowPhase.MANUAL_REVIEW: 3,
            WorkflowPhase.REPORT_GENERATION: 4,
            WorkflowPhase.COMPLETE: 4
        }
        current_idx = phase_idx.get(assessment.current_phase, 0)
        
        cols = st.columns(5)
        for i, (col, phase) in enumerate(zip(cols, phases)):
            with col:
                if i < current_idx:
                    st.success(f"✓ {phase}")
                elif i == current_idx:
                    st.info(f"→ {phase}")
                else:
                    st.write(f"○ {phase}")
    
    st.markdown("---")
    
    # ========================================================================
    # PHASE 1: SETUP
    # ========================================================================
    
    if not st.session_state.unified_assessment:
        st.header("📋 Step 1: Setup Assessment")
        
        col1, col2 = st.columns(2)
        
        with col1:
            account_name = st.text_input(
                "Workload/Account Name",
                value="Production Workload",
                help="Name to identify this assessment"
            )
            
            regions = st.multiselect(
                "Regions to Scan",
                ["us-east-1", "us-east-2", "us-west-1", "us-west-2", 
                 "eu-west-1", "eu-central-1", "ap-southeast-1", "ap-northeast-1"],
                default=["us-east-1"],
                help="Select AWS regions to include in the scan"
            )
        
        with col2:
            st.markdown("#### What This Assessment Includes")
            st.markdown("""
            **🔍 Automated Scanning:**
            - 40+ AWS services scanned
            - Security, reliability, cost findings
            - Compliance mapping
            
            **📝 WAF Questionnaire:**
            - Auto-filled questions from scan
            - Manual questions for processes
            - Complete 6-pillar coverage
            """)
        
        if st.button("🚀 Start Unified Assessment", type="primary", use_container_width=True):
            # Initialize
            session = st.session_state.get('aws_session') if not use_demo else None
            workflow = UnifiedWAFWorkflow(session=session, use_demo=use_demo)
            st.session_state.workflow_engine = workflow
            
            # Create assessment
            assessment = workflow.create_assessment(account_name)
            assessment.regions_scanned = regions
            st.session_state.unified_assessment = assessment
            st.rerun()
    
    # ========================================================================
    # PHASE 2: SCANNING
    # ========================================================================
    
    elif st.session_state.unified_assessment.current_phase in [WorkflowPhase.SETUP, WorkflowPhase.SCANNING]:
        assessment = st.session_state.unified_assessment
        workflow = st.session_state.workflow_engine
        
        st.header("🔍 Step 2: Running AWS Scan")
        
        if not assessment.scan_completed:
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            def update_progress(message, percent):
                progress_bar.progress(percent / 100)
                status_text.text(message)
            
            with st.spinner("Scanning AWS environment..."):
                assessment = workflow.run_scan(
                    assessment, 
                    regions=assessment.regions_scanned,
                    progress_callback=update_progress
                )
                st.session_state.unified_assessment = assessment
            
            st.success(f"✅ Scan completed in {assessment.scan_duration_seconds:.1f} seconds!")
            st.rerun()
        else:
            st.success(f"✅ Scan completed - Found {len(assessment.findings)} findings")
            
            # Show findings summary
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Critical", assessment.critical_findings)
            with col2:
                st.metric("High", assessment.high_findings)
            with col3:
                st.metric("Medium", assessment.medium_findings)
            with col4:
                st.metric("Low", assessment.low_findings)
            
            if st.button("Continue to Auto-Detection →", type="primary"):
                assessment = workflow.run_auto_detection(assessment)
                st.session_state.unified_assessment = assessment
                st.rerun()
    
    # ========================================================================
    # PHASE 3: AUTO-DETECTION REVIEW
    # ========================================================================
    
    elif st.session_state.unified_assessment.current_phase == WorkflowPhase.AUTO_ASSESSMENT:
        assessment = st.session_state.unified_assessment
        workflow = st.session_state.workflow_engine
        
        st.header("🤖 Step 3: Review Auto-Detected Answers")
        
        st.info(f"**{assessment.auto_detected_count}** questions were auto-filled from scan results")
        
        # Show auto-detected answers for review
        with st.expander("Review Auto-Detected Answers", expanded=True):
            for q in workflow.auto_questions:
                if q["id"] in assessment.auto_detected_answers:
                    detected = assessment.auto_detected_answers[q["id"]]
                    
                    col1, col2 = st.columns([3, 1])
                    with col1:
                        st.markdown(f"**{q['text']}**")
                        
                        # Find selected choice
                        for choice in q["choices"]:
                            if choice["id"] == detected.detected_choice_id:
                                st.markdown(f"→ {choice['text']}")
                                break
                    
                    with col2:
                        confidence_color = "green" if detected.confidence >= 0.8 else "orange"
                        st.markdown(f"Confidence: :{confidence_color}[{detected.confidence*100:.0f}%]")
                    
                    st.markdown("---")
        
        if st.button("Accept & Continue to Manual Questions →", type="primary"):
            assessment.current_phase = WorkflowPhase.MANUAL_REVIEW
            st.session_state.unified_assessment = assessment
            st.rerun()
    
    # ========================================================================
    # PHASE 4: MANUAL REVIEW
    # ========================================================================
    
    elif st.session_state.unified_assessment.current_phase == WorkflowPhase.MANUAL_REVIEW:
        assessment = st.session_state.unified_assessment
        workflow = st.session_state.workflow_engine
        
        st.header("📝 Step 4: Answer Manual Questions")
        
        unanswered = workflow.get_unanswered_manual_questions(assessment)
        
        if unanswered:
            st.info(f"**{len(unanswered)}** questions require manual input (organizational/procedural)")
            
            # Progress
            total_manual = len(workflow.manual_questions)
            answered = len(assessment.manual_answers)
            st.progress(answered / total_manual if total_manual > 0 else 0)
            st.caption(f"Progress: {answered}/{total_manual} manual questions answered")
            
            st.markdown("---")
            
            # Show questions grouped by pillar
            pillars = {}
            for q in unanswered:
                pillar = q["pillar"]
                if pillar not in pillars:
                    pillars[pillar] = []
                pillars[pillar].append(q)
            
            for pillar, questions in pillars.items():
                with st.expander(f"📋 {pillar} ({len(questions)} questions)", expanded=True):
                    for q in questions:
                        st.markdown(f"**{q['text']}**")
                        st.caption(f"*Why manual: {q.get('why_manual', 'Requires human judgment')}*")
                        
                        # Radio buttons for choices
                        choice_options = [c["text"] for c in q["choices"]]
                        selected = st.radio(
                            "Select your answer:",
                            choice_options,
                            key=f"manual_{q['id']}"
                        )
                        
                        # Save answer
                        if selected:
                            for c in q["choices"]:
                                if c["text"] == selected:
                                    assessment.manual_answers[q["id"]] = Response(
                                        question_id=q["id"],
                                        choice_id=c["id"],
                                        responded_at=datetime.now()
                                    )
                                    break
                        
                        st.markdown("---")
            
            col1, col2 = st.columns(2)
            with col1:
                if st.button("Skip Remaining & Generate Report"):
                    for q in unanswered:
                        assessment.skipped_questions.append(q["id"])
                    assessment.current_phase = WorkflowPhase.REPORT_GENERATION
                    st.session_state.unified_assessment = assessment
                    st.rerun()
            
            with col2:
                if st.button("Save & Generate Report →", type="primary"):
                    assessment.current_phase = WorkflowPhase.REPORT_GENERATION
                    st.session_state.unified_assessment = assessment
                    st.rerun()
        else:
            st.success("✅ All manual questions answered!")
            if st.button("Generate Report →", type="primary"):
                assessment.current_phase = WorkflowPhase.REPORT_GENERATION
                st.session_state.unified_assessment = assessment
                st.rerun()
    
    # ========================================================================
    # PHASE 5: REPORT GENERATION
    # ========================================================================
    
    elif st.session_state.unified_assessment.current_phase in [WorkflowPhase.REPORT_GENERATION, WorkflowPhase.COMPLETE]:
        assessment = st.session_state.unified_assessment
        workflow = st.session_state.workflow_engine
        
        st.header("📊 Step 5: Assessment Results")
        
        # Calculate final scores
        assessment = workflow.calculate_scores(assessment)
        st.session_state.unified_assessment = assessment
        
        # Overall Score
        st.markdown("### Overall WAF Score")
        
        score_color = "green" if assessment.overall_score >= 70 else ("orange" if assessment.overall_score >= 50 else "red")
        st.markdown(f"""
        <div style="text-align: center; padding: 20px; background: linear-gradient(135deg, #232F3E, #FF9900); border-radius: 10px;">
            <h1 style="color: white; margin: 0;">{assessment.overall_score:.1f}/100</h1>
            <p style="color: white;">Overall Well-Architected Score</p>
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown("---")
        
        # Pillar Scores
        st.markdown("### Pillar Scores")
        
        pillar_cols = st.columns(3)
        pillar_icons = {
            "Security": "🔒",
            "Reliability": "🔄",
            "Performance Efficiency": "⚡",
            "Cost Optimization": "💰",
            "Operational Excellence": "⚙️",
            "Sustainability": "🌱"
        }
        
        for i, (pillar, score) in enumerate(assessment.pillar_scores.items()):
            with pillar_cols[i % 3]:
                icon = pillar_icons.get(pillar, "📋")
                delta = "Good" if score >= 70 else ("Needs Work" if score >= 50 else "Critical")
                st.metric(f"{icon} {pillar}", f"{score:.1f}", delta=delta)
        
        st.markdown("---")
        
        # Coverage Summary
        st.markdown("### Assessment Coverage")
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Auto-Detected", assessment.auto_detected_count, help="Questions answered from scan")
        with col2:
            st.metric("Manual Answers", len(assessment.manual_answers), help="Questions answered manually")
        with col3:
            st.metric("Skipped", len(assessment.skipped_questions), help="Questions not answered")
        
        st.markdown("---")
        
        # Top Findings
        st.markdown("### Top Priority Findings")
        
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        top_findings = sorted(
            assessment.findings, 
            key=lambda f: severity_order.get(f.severity, 5)
        )[:10]
        
        for finding in top_findings:
            severity_colors = {
                "CRITICAL": "🔴",
                "HIGH": "🟠",
                "MEDIUM": "🟡",
                "LOW": "🟢"
            }
            color = severity_colors.get(finding.severity, "⚪")
            
            with st.expander(f"{color} [{finding.severity}] {finding.title}"):
                st.markdown(f"**Description:** {finding.description}")
                st.markdown(f"**Recommendation:** {finding.recommendation}")
                st.markdown(f"**Pillar:** {finding.pillar}")
        
        st.markdown("---")
        
        # Export Options
        st.markdown("### Export Report")
        
        col1, col2 = st.columns(2)
        
        with col1:
            if PDF_AVAILABLE:
                if st.button("📄 Generate PDF Report", use_container_width=True):
                    try:
                        generator = UnifiedReportGenerator()
                        pdf_bytes = generator.generate_report(assessment)
                        
                        st.download_button(
                            label="⬇️ Download PDF",
                            data=pdf_bytes,
                            file_name=f"waf_unified_{assessment.account_name.replace(' ', '_')}_{datetime.now().strftime('%Y%m%d')}.pdf",
                            mime="application/pdf",
                            use_container_width=True
                        )
                    except Exception as e:
                        st.error(f"Error generating PDF: {str(e)}")
            else:
                st.warning("PDF generation requires reportlab: `pip install reportlab`")
        
        with col2:
            # JSON Export
            export_data = {
                "assessment_id": assessment.assessment_id,
                "account_name": assessment.account_name,
                "created_at": assessment.created_at.isoformat(),
                "overall_score": assessment.overall_score,
                "pillar_scores": assessment.pillar_scores,
                "findings_count": len(assessment.findings),
                "auto_detected_count": assessment.auto_detected_count,
                "manual_answered_count": len(assessment.manual_answers),
                "findings": [
                    {
                        "title": f.title,
                        "severity": f.severity,
                        "pillar": f.pillar,
                        "description": f.description,
                        "recommendation": f.recommendation
                    } for f in assessment.findings
                ]
            }
            
            st.download_button(
                label="📊 Export JSON",
                data=json.dumps(export_data, indent=2),
                file_name=f"waf_unified_{assessment.account_name.replace(' ', '_')}_{datetime.now().strftime('%Y%m%d')}.json",
                mime="application/json",
                use_container_width=True
            )
        
        # Reset button
        st.markdown("---")
        if st.button("🔄 Start New Assessment"):
            st.session_state.unified_assessment = None
            st.session_state.workflow_engine = None
            st.rerun()

# ============================================================================
# INTEGRATION HELPER
# ============================================================================

def integrate_scanner_results(scan_results: Dict) -> Dict[str, AutoDetectedAnswer]:
    """
    Helper function to integrate existing WAF Scanner results into the unified workflow.
    Call this when you have results from the standalone WAF Scanner tab.
    """
    engine = WAFAutoDetectionEngine()
    
    # Convert scan_results to Finding objects if needed
    findings = []
    if 'findings' in scan_results:
        for f in scan_results['findings']:
            if isinstance(f, Finding):
                findings.append(f)
            elif isinstance(f, dict):
                findings.append(Finding(
                    id=f.get('id', str(uuid.uuid4())),
                    title=f.get('title', ''),
                    description=f.get('description', f.get('message', '')),
                    severity=f.get('severity', 'MEDIUM'),
                    pillar=f.get('pillar', 'Security'),
                    source_service=f.get('service', f.get('source_service', 'Unknown')),
                    recommendation=f.get('recommendation', '')
                ))
    
    resources = scan_results.get('resources')
    if isinstance(resources, dict):
        resources = ResourceInventory(**{k: v for k, v in resources.items() if not k.startswith('_')})
    
    return engine.analyze_findings(findings, resources)

# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    st.set_page_config(
        page_title="Unified WAF Assessment",
        page_icon="🔍",
        layout="wide"
    )
    render_unified_waf_workflow()
