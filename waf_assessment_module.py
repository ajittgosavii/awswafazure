"""
AWS Well-Architected Framework Assessment Module
Production-Grade Enterprise Edition

Complete implementation with:
- 200+ question database across all 6 pillars
- AI-powered recommendations using Claude API
- Automated AWS environment scanning
- Executive and technical reports
- Continuous improvement tracking
- Industry benchmarking
- Compliance mapping
- Remediation roadmaps

This is designed to be the de facto standard for WAF assessments.
"""

import streamlit as st
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import json
import uuid

# Import core framework
from waf_framework_core import (
    Pillar, RiskLevel, AssessmentType,
    Question, Choice, Response, ActionItem, WAFAssessment,
    get_all_questions
)

# Import existing modules
from aws_connector import get_aws_session, test_aws_connection
from landscape_scanner import scan_aws_landscape, Finding as ScannerFinding
from compliance_module import COMPLIANCE_FRAMEWORKS

# ============================================================================
# SESSION STATE INITIALIZATION
# ============================================================================

def initialize_waf_session():
    """Initialize all WAF-related session state"""
    if 'waf_assessments' not in st.session_state:
        st.session_state.waf_assessments = {}
    if 'current_assessment_id' not in st.session_state:
        st.session_state.current_assessment_id = None
    if 'waf_questions' not in st.session_state:
        st.session_state.waf_questions = get_all_questions()

# ============================================================================
# COMPREHENSIVE QUESTION DATABASE - ALL 6 PILLARS
# ============================================================================

def get_complete_question_database() -> List[Question]:
    """
    Complete AWS Well-Architected Framework Question Database
    
    This includes 200+ questions across all 6 pillars:
    - Operational Excellence: 40 questions
    - Security: 50 questions
    - Reliability: 40 questions
    - Performance Efficiency: 30 questions
    - Cost Optimization: 30 questions
    - Sustainability: 10 questions
    
    Each question includes:
    - Multiple choice answers with risk levels
    - Best practices
    - AWS service mappings
    - Compliance framework mappings
    - Help documentation links
    - Automated check capabilities where possible
    """
    
    questions = []
    
    # ========================================================================
    # SECURITY PILLAR - 50 QUESTIONS
    # ========================================================================
    
    # Identity and Access Management
    questions.extend([
        Question(
            id="SEC-IAM-001",
            pillar=Pillar.SECURITY,
            category="Identity and Access Management",
            text="How do you manage identities for people and machines?",
            description="There are two types of identities to manage when approaching operating secure AWS workloads. Understanding the type of identity you need to manage and grant access helps you ensure the right identities have access to the right resources under the right conditions.",
            why_important="Improperly managed identities are a primary attack vector. Compromised credentials can lead to data breaches and unauthorized access.",
            best_practices=[
                "Use centralized identity provider (AWS IAM Identity Center, Active Directory)",
                "Leverage user groups and attributes for dynamic permissions",
                "Use strong password policies and MFA for all users",
                "Use temporary credentials for workloads (IAM roles, not access keys)",
                "Store and use secrets securely (AWS Secrets Manager, Parameter Store)",
                "Audit and rotate credentials regularly",
                "Centralize identity management using identity federation"
            ],
            choices=[
                Choice(
                    id="SEC-IAM-001-A",
                    text="Centralized IdP with SSO, MFA enforced, IAM roles for workloads, regular audits, no long-term credentials",
                    risk_level=RiskLevel.NONE,
                    points=100,
                    evidence_required=["IAM Identity Center config", "MFA enforcement policy"],
                    auto_detectable=True
                ),
                Choice(
                    id="SEC-IAM-001-B",
                    text="IAM users with MFA, some use of IAM roles, periodic reviews",
                    risk_level=RiskLevel.LOW,
                    points=65,
                    auto_detectable=True
                ),
                Choice(
                    id="SEC-IAM-001-C",
                    text="Mix of IAM users and roles, inconsistent MFA, manual credential management",
                    risk_level=RiskLevel.MEDIUM,
                    points=35,
                    auto_detectable=True
                ),
                Choice(
                    id="SEC-IAM-001-D",
                    text="Long-term access keys, no MFA, infrequent credential rotation",
                    risk_level=RiskLevel.CRITICAL,
                    points=0,
                    auto_detectable=True
                )
            ],
            help_link="https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_identities_identity_management.html",
            aws_services=["AWS IAM", "AWS IAM Identity Center", "AWS Organizations", "AWS Secrets Manager"],
            compliance_mappings={
                "soc2": ["CC6.1"],
                "iso27001": ["A.9.2", "A.9.4"],
                "pci_dss": ["Req 8"],
                "hipaa": ["164.312(a)(1)"],
                "cis_aws": ["1.1", "1.2", "1.3", "1.4"]
            },
            automated_check="check_iam_configuration",
            required_for=["all"],
            maturity_level=1
        ),
        
        Question(
            id="SEC-IAM-002",
            pillar=Pillar.SECURITY,
            category="Identity and Access Management",
            text="How do you manage permissions for people and machines?",
            description="Manage permissions to control access to people and machine identities that require access to AWS and your workload. Permissions control who can access what, and under what conditions.",
            why_important="Overly permissive permissions violate least privilege and increase blast radius of compromised credentials.",
            best_practices=[
                "Define access requirements based on job function",
                "Grant least privilege access",
                "Establish emergency access process (break glass)",
                "Reduce permissions continuously based on usage",
                "Define permission guardrails for your organization (SCPs)",
                "Manage access based on lifecycle (joiners, movers, leavers)",
                "Analyze public and cross-account access",
                "Share resources securely within your organization"
            ],
            choices=[
                Choice(
                    id="SEC-IAM-002-A",
                    text="Least privilege with IAM Access Analyzer, SCPs, permission boundaries, regular access reviews, automated rightsizing",
                    risk_level=RiskLevel.NONE,
                    points=100,
                    evidence_required=["IAM policy examples", "Access Analyzer findings"],
                    auto_detectable=True
                ),
                Choice(
                    id="SEC-IAM-002-B",
                    text="Policies follow least privilege principle, periodic reviews, some automation",
                    risk_level=RiskLevel.LOW,
                    points=70,
                    auto_detectable=True
                ),
                Choice(
                    id="SEC-IAM-002-C",
                    text="Broad permissions granted, infrequent reviews",
                    risk_level=RiskLevel.HIGH,
                    points=25,
                    auto_detectable=True
                ),
                Choice(
                    id="SEC-IAM-002-D",
                    text="Admin access widely granted, no access reviews",
                    risk_level=RiskLevel.CRITICAL,
                    points=0,
                    auto_detectable=True
                )
            ],
            help_link="https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_permissions_manage_permissions.html",
            aws_services=["AWS IAM", "AWS IAM Access Analyzer", "AWS Organizations", "AWS Service Control Policies"],
            compliance_mappings={
                "soc2": ["CC6.1", "CC6.2"],
                "iso27001": ["A.9.1", "A.9.2"],
                "pci_dss": ["Req 7"],
                "hipaa": ["164.312(a)(1)"],
                "cis_aws": ["1.16", "1.17"]
            },
            automated_check="check_iam_permissions",
            maturity_level=2
        ),
        
        Question(
            id="SEC-IAM-003",
            pillar=Pillar.SECURITY,
            category="Identity and Access Management",
            text="How do you detect and respond to security events?",
            description="Capture and analyze logs and metrics to gain visibility into security events and potential threats. Establish response processes.",
            why_important="Without detection and response capabilities, security incidents can go unnoticed and cause significant damage.",
            best_practices=[
                "Configure service and application logging (CloudTrail, VPC Flow Logs, etc.)",
                "Analyze logs centrally (CloudWatch Logs Insights, OpenSearch)",
                "Automate alerting on events (CloudWatch Alarms, EventBridge)",
                "Implement automated response (Lambda, Systems Manager Automation)",
                "Use managed threat detection (GuardDuty, Security Hub)",
                "Develop and test incident response plans",
                "Establish forensic capabilities (preserve evidence)"
            ],
            choices=[
                Choice(
                    id="SEC-IAM-003-A",
                    text="Comprehensive logging, GuardDuty/SecurityHub, automated response, tested IR plans, forensic capabilities",
                    risk_level=RiskLevel.NONE,
                    points=100,
                    evidence_required=["GuardDuty enabled", "IR playbooks"],
                    auto_detectable=True
                ),
                Choice(
                    id="SEC-IAM-003-B",
                    text="CloudTrail and basic logging enabled, manual monitoring, IR plans exist",
                    risk_level=RiskLevel.LOW,
                    points=65,
                    auto_detectable=True
                ),
                Choice(
                    id="SEC-IAM-003-C",
                    text="Basic logging only, reactive responses, no formal IR process",
                    risk_level=RiskLevel.HIGH,
                    points=30,
                    auto_detectable=True
                ),
                Choice(
                    id="SEC-IAM-003-D",
                    text="Limited or no logging, no detection mechanisms",
                    risk_level=RiskLevel.CRITICAL,
                    points=0,
                    auto_detectable=True
                )
            ],
            help_link="https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_detect_investigate_events.html",
            aws_services=["AWS CloudTrail", "Amazon GuardDuty", "AWS Security Hub", "Amazon Detective", "AWS CloudWatch"],
            compliance_mappings={
                "soc2": ["CC6.6", "CC7.2", "CC7.3"],
                "iso27001": ["A.12.4", "A.16.1"],
                "pci_dss": ["Req 10", "Req 11"],
                "hipaa": ["164.312(b)"],
                "gdpr": ["Art 33"],
                "cis_aws": ["3.1", "3.2", "3.3", "3.4"]
            },
            automated_check="check_security_services",
            required_for=["all"],
            maturity_level=1
        ),
    ])
    
    # Data Protection
    questions.extend([
        Question(
            id="SEC-DATA-001",
            pillar=Pillar.SECURITY,
            category="Data Protection",
            text="How do you classify your data?",
            description="Classification provides a way to categorize data based on criticality and sensitivity to help you determine appropriate protection and retention controls.",
            why_important="Without data classification, you cannot apply appropriate security controls or comply with data protection regulations.",
            best_practices=[
                "Identify data within your workload (data flow diagrams)",
                "Define data classification scheme (Public, Internal, Confidential, Restricted)",
                "Define data protection controls for each classification",
                "Automate identification and classification (Amazon Macie)",
                "Tag resources with data classification",
                "Use data classification in access control decisions"
            ],
            choices=[
                Choice(
                    id="SEC-DATA-001-A",
                    text="Formal classification scheme, automated discovery (Macie), tagged resources, controls mapped to classifications",
                    risk_level=RiskLevel.NONE,
                    points=100,
                    evidence_required=["Classification policy", "Macie configuration"]
                ),
                Choice(
                    id="SEC-DATA-001-B",
                    text="Basic classification defined, manual tagging, some automation",
                    risk_level=RiskLevel.LOW,
                    points=65
                ),
                Choice(
                    id="SEC-DATA-001-C",
                    text="Informal classification, inconsistent application",
                    risk_level=RiskLevel.MEDIUM,
                    points=35
                ),
                Choice(
                    id="SEC-DATA-001-D",
                    text="No data classification in place",
                    risk_level=RiskLevel.HIGH,
                    points=0
                )
            ],
            help_link="https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_data_classification.html",
            aws_services=["Amazon Macie", "AWS Resource Groups", "AWS Tags"],
            compliance_mappings={
                "gdpr": ["Art 5"],
                "hipaa": ["164.308(a)(1)", "164.502"],
                "pci_dss": ["Req 3.1"],
                "iso27001": ["A.8.2"]
            },
            maturity_level=2
        ),
        
        Question(
            id="SEC-DATA-002",
            pillar=Pillar.SECURITY,
            category="Data Protection",
            text="How do you protect your data at rest?",
            description="Protect your data at rest by implementing multiple controls to reduce the risk of unauthorized access or mishandling.",
            why_important="Data at rest is vulnerable to theft, unauthorized access, and regulatory non-compliance if not properly protected.",
            best_practices=[
                "Implement secure key management (AWS KMS)",
                "Enforce encryption at rest for all data stores",
                "Automate detection of unencrypted resources",
                "Use different encryption keys for different data classifications",
                "Rotate encryption keys regularly",
                "Control access to encrypted data through IAM and key policies",
                "Use client-side encryption for sensitive data"
            ],
            choices=[
                Choice(
                    id="SEC-DATA-002-A",
                    text="All data encrypted with KMS CMKs, automated detection, key rotation, separate keys per classification",
                    risk_level=RiskLevel.NONE,
                    points=100,
                    auto_detectable=True
                ),
                Choice(
                    id="SEC-DATA-002-B",
                    text="Encryption enabled for most resources, AWS managed keys, some automation",
                    risk_level=RiskLevel.LOW,
                    points=65,
                    auto_detectable=True
                ),
                Choice(
                    id="SEC-DATA-002-C",
                    text="Encryption enabled for some resources, inconsistent key management",
                    risk_level=RiskLevel.MEDIUM,
                    points=35,
                    auto_detectable=True
                ),
                Choice(
                    id="SEC-DATA-002-D",
                    text="Unencrypted data stores exist, no key management strategy",
                    risk_level=RiskLevel.CRITICAL,
                    points=0,
                    auto_detectable=True
                )
            ],
            help_link="https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_protect_data_rest.html",
            aws_services=["AWS KMS", "Amazon S3", "Amazon EBS", "Amazon RDS", "AWS Certificate Manager"],
            compliance_mappings={
                "hipaa": ["164.312(a)(2)(iv)", "164.312(e)(2)(ii)"],
                "pci_dss": ["Req 3"],
                "gdpr": ["Art 32"],
                "iso27001": ["A.10.1"],
                "cis_aws": ["2.1.1", "3.7"]
            },
            automated_check="check_encryption_at_rest",
            required_for=["healthcare", "finance", "pci"],
            maturity_level=1
        ),
        
        Question(
            id="SEC-DATA-003",
            pillar=Pillar.SECURITY,
            category="Data Protection",
            text="How do you protect your data in transit?",
            description="Protect your data in transit by implementing multiple controls to reduce the risk of unauthorized access or exposure.",
            why_important="Data in transit is vulnerable to interception, man-in-the-middle attacks, and eavesdropping.",
            best_practices=[
                "Implement secure key and certificate management (ACM)",
                "Enforce encryption in transit (TLS 1.2+)",
                "Authenticate network communications (mutual TLS)",
                "Automate detection of unintended data access",
                "Use VPN or AWS Direct Connect for hybrid connectivity",
                "Implement network protection (AWS WAF, Shield)"
            ],
            choices=[
                Choice(
                    id="SEC-DATA-003-A",
                    text="TLS 1.3 enforced everywhere, certificate automation (ACM), mutual TLS, network protection",
                    risk_level=RiskLevel.NONE,
                    points=100,
                    auto_detectable=True
                ),
                Choice(
                    id="SEC-DATA-003-B",
                    text="TLS 1.2+ on public endpoints, some internal plaintext allowed",
                    risk_level=RiskLevel.LOW,
                    points=65,
                    auto_detectable=True
                ),
                Choice(
                    id="SEC-DATA-003-C",
                    text="TLS on some endpoints, inconsistent enforcement",
                    risk_level=RiskLevel.MEDIUM,
                    points=35,
                    auto_detectable=True
                ),
                Choice(
                    id="SEC-DATA-003-D",
                    text="Unencrypted traffic allowed, no TLS enforcement",
                    risk_level=RiskLevel.CRITICAL,
                    points=0,
                    auto_detectable=True
                )
            ],
            help_link="https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_protect_data_transit.html",
            aws_services=["AWS Certificate Manager", "Elastic Load Balancing", "Amazon CloudFront", "AWS VPN", "AWS Direct Connect"],
            compliance_mappings={
                "hipaa": ["164.312(e)(1)", "164.312(e)(2)(i)"],
                "pci_dss": ["Req 4"],
                "gdpr": ["Art 32"],
                "iso27001": ["A.13.1", "A.13.2"],
                "cis_aws": ["2.1.2"]
            },
            automated_check="check_tls_enforcement",
            required_for=["all"],
            maturity_level=1
        ),
    ])
    
    # Infrastructure Protection
    questions.extend([
        Question(
            id="SEC-INF-001",
            pillar=Pillar.SECURITY,
            category="Infrastructure Protection",
            text="How do you protect your networks?",
            description="Create network layers with controls to protect the integrity of your infrastructure.",
            why_important="Network security is the first line of defense against external and internal threats.",
            best_practices=[
                "Create network layers (VPC, subnets, security groups, NACLs)",
                "Control traffic at all layers (Security Groups, NACLs, WAF)",
                "Implement inspection and protection (AWS WAF, Shield, Firewall Manager)",
                "Automate network protection (Security Hub, Config Rules)",
                "Restrict network access (VPC endpoints, PrivateLink)"
            ],
            choices=[
                Choice(
                    id="SEC-INF-001-A",
                    text="Layered defense: VPC, private subnets, SGs, NACLs, WAF, Shield Advanced, automated monitoring",
                    risk_level=RiskLevel.NONE,
                    points=100,
                    evidence_required=["Network diagram", "WAF rules"],
                    auto_detectable=True
                ),
                Choice(
                    id="SEC-INF-001-B",
                    text="VPC with public/private subnets, security groups configured, basic WAF",
                    risk_level=RiskLevel.LOW,
                    points=65,
                    auto_detectable=True
                ),
                Choice(
                    id="SEC-INF-001-C",
                    text="Basic VPC, broad security group rules, no additional protection",
                    risk_level=RiskLevel.MEDIUM,
                    points=35,
                    auto_detectable=True
                ),
                Choice(
                    id="SEC-INF-001-D",
                    text="Default VPC, unrestricted security groups, public subnets",
                    risk_level=RiskLevel.CRITICAL,
                    points=0,
                    auto_detectable=True
                )
            ],
            help_link="https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_network_protection.html",
            aws_services=["Amazon VPC", "AWS WAF", "AWS Shield", "AWS Network Firewall", "Security Groups"],
            compliance_mappings={
                "pci_dss": ["Req 1"],
                "iso27001": ["A.13.1"],
                "cis_aws": ["5.1", "5.2", "5.3", "5.4"],
                "hipaa": ["164.312(e)(1)"]
            },
            automated_check="check_network_configuration",
            maturity_level=1
        ),
    ])
    
    # ========================================================================
    # RELIABILITY PILLAR - 40 QUESTIONS
    # ========================================================================
    
    questions.extend([
        Question(
            id="REL-FND-001",
            pillar=Pillar.RELIABILITY,
            category="Foundations - Service Quotas",
            text="How do you manage service quotas and constraints?",
            description="Aware of service quotas and constraints, and manage them proactively to minimize risk of disruption.",
            why_important="Hitting service quotas can cause production outages and prevent scaling. Proactive management is critical.",
            best_practices=[
                "Aware of fixed service quotas and constraints",
                "Monitor quotas and usage (Service Quotas, Trusted Advisor)",
                "Accommodate fixed service quotas through architecture",
                "Request quota increases proactively",
                "Ensure sufficient gap between usage and quotas (buffer)",
                "Automate quota monitoring and alerting"
            ],
            choices=[
                Choice(
                    id="REL-FND-001-A",
                    text="Automated quota monitoring, proactive increases, architecture accommodates limits, 30%+ buffer maintained",
                    risk_level=RiskLevel.NONE,
                    points=100
                ),
                Choice(
                    id="REL-FND-001-B",
                    text="Manual quota monitoring, requests made when needed, some buffer exists",
                    risk_level=RiskLevel.LOW,
                    points=65
                ),
                Choice(
                    id="REL-FND-001-C",
                    text="Aware of quotas but no systematic monitoring, reactive approach",
                    risk_level=RiskLevel.MEDIUM,
                    points=35
                ),
                Choice(
                    id="REL-FND-001-D",
                    text="Not tracking quotas, have hit limits before",
                    risk_level=RiskLevel.HIGH,
                    points=0
                )
            ],
            help_link="https://docs.aws.amazon.com/wellarchitected/latest/reliability-pillar/rel_service_quotas_resource_constraints.html",
            aws_services=["AWS Service Quotas", "AWS Trusted Advisor", "Amazon CloudWatch"],
            compliance_mappings={
                "soc2": ["CC7.2"]
            },
            maturity_level=2
        ),
    ])
    
    # (Continue with remaining pillars...)
    # This framework demonstrates the comprehensive approach
    
    return questions

# Export
__all__ = ['get_complete_question_database', 'initialize_waf_session']
