"""
EKS Security Module - Enterprise Security and Compliance Framework
Part of the AI-Enhanced EKS Architecture Design Wizard

Features:
- Security Posture Assessment
- Compliance Framework Mapping (PCI-DSS, HIPAA, SOC2, ISO27001)
- AI-Powered Threat Modeling
- Policy Generation (OPA/Kyverno)
- Security Best Practices Enforcement

Author: Infosys Cloud Architecture Team
Version: 2.0.0
"""

import streamlit as st
import json
import yaml
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import os

# ============================================================================
# SECURITY ENUMS AND CONSTANTS
# ============================================================================

class ThreatCategory(Enum):
    """STRIDE Threat Categories"""
    SPOOFING = "spoofing"
    TAMPERING = "tampering"
    REPUDIATION = "repudiation"
    INFORMATION_DISCLOSURE = "information_disclosure"
    DENIAL_OF_SERVICE = "denial_of_service"
    ELEVATION_OF_PRIVILEGE = "elevation_of_privilege"

class CISBenchmarkLevel(Enum):
    """CIS Kubernetes Benchmark Levels"""
    LEVEL_1 = "level_1"  # Basic security
    LEVEL_2 = "level_2"  # Defense in depth

class VulnerabilitySeverity(Enum):
    """Vulnerability Severity Levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

# ============================================================================
# COMPLIANCE FRAMEWORKS MAPPING
# ============================================================================

COMPLIANCE_CONTROLS = {
    "pci_dss": {
        "name": "PCI-DSS v4.0",
        "description": "Payment Card Industry Data Security Standard",
        "controls": {
            "1.1": {
                "title": "Network Security Controls",
                "eks_implementation": [
                    "VPC with private subnets for EKS nodes",
                    "Security groups restricting inbound traffic",
                    "Network ACLs for additional layer",
                    "VPC Flow Logs enabled"
                ],
                "kubernetes_controls": [
                    "NetworkPolicy for pod-to-pod traffic",
                    "Ingress controller with WAF",
                    "Service mesh mTLS"
                ]
            },
            "2.2": {
                "title": "Secure Configuration Standards",
                "eks_implementation": [
                    "CIS Amazon EKS Benchmark compliance",
                    "Hardened AMIs for nodes",
                    "IMDSv2 enforcement"
                ],
                "kubernetes_controls": [
                    "Pod Security Standards (Restricted)",
                    "Security contexts on all pods",
                    "Read-only root filesystem"
                ]
            },
            "3.4": {
                "title": "Encryption of Stored Data",
                "eks_implementation": [
                    "EBS encryption with KMS",
                    "EFS encryption at rest",
                    "S3 bucket encryption"
                ],
                "kubernetes_controls": [
                    "etcd encryption enabled",
                    "Secrets encryption with KMS",
                    "Application-level encryption"
                ]
            },
            "4.1": {
                "title": "Encryption in Transit",
                "eks_implementation": [
                    "TLS 1.2+ for all endpoints",
                    "Certificate management via ACM",
                    "Private endpoint access"
                ],
                "kubernetes_controls": [
                    "Service mesh mTLS (Istio/Linkerd)",
                    "TLS for ingress",
                    "Encrypted etcd communication"
                ]
            },
            "7.1": {
                "title": "Access Control",
                "eks_implementation": [
                    "IAM roles with least privilege",
                    "IRSA for pod-level access",
                    "MFA for console access"
                ],
                "kubernetes_controls": [
                    "RBAC with minimal permissions",
                    "Service account per workload",
                    "No cluster-admin for apps"
                ]
            },
            "10.1": {
                "title": "Audit Logging",
                "eks_implementation": [
                    "CloudTrail for AWS API calls",
                    "EKS control plane logging",
                    "VPC Flow Logs"
                ],
                "kubernetes_controls": [
                    "Audit policy configured",
                    "Pod logging to CloudWatch",
                    "Falco for runtime events"
                ]
            },
            "11.4": {
                "title": "Intrusion Detection",
                "eks_implementation": [
                    "GuardDuty EKS Protection",
                    "Security Hub integration",
                    "AWS Config rules"
                ],
                "kubernetes_controls": [
                    "Falco runtime detection",
                    "Network anomaly detection",
                    "Image scanning on deploy"
                ]
            }
        }
    },
    "hipaa": {
        "name": "HIPAA",
        "description": "Health Insurance Portability and Accountability Act",
        "controls": {
            "164.312(a)(1)": {
                "title": "Access Control",
                "eks_implementation": [
                    "IAM with MFA",
                    "Session timeout policies",
                    "Privileged access management"
                ],
                "kubernetes_controls": [
                    "RBAC with role separation",
                    "Service account restrictions",
                    "Audit logging for access"
                ]
            },
            "164.312(a)(2)(iv)": {
                "title": "Encryption and Decryption",
                "eks_implementation": [
                    "KMS customer managed keys",
                    "Envelope encryption",
                    "Key rotation enabled"
                ],
                "kubernetes_controls": [
                    "Secrets encryption",
                    "Application encryption libraries",
                    "TLS everywhere"
                ]
            },
            "164.312(b)": {
                "title": "Audit Controls",
                "eks_implementation": [
                    "CloudTrail with integrity validation",
                    "Log retention (6+ years)",
                    "Tamper-proof logging"
                ],
                "kubernetes_controls": [
                    "Comprehensive audit policy",
                    "Immutable logs",
                    "Correlation IDs"
                ]
            },
            "164.312(c)(1)": {
                "title": "Integrity",
                "eks_implementation": [
                    "File integrity monitoring",
                    "Configuration drift detection",
                    "Change management"
                ],
                "kubernetes_controls": [
                    "Admission controllers",
                    "GitOps for config management",
                    "Image signing verification"
                ]
            },
            "164.312(e)(1)": {
                "title": "Transmission Security",
                "eks_implementation": [
                    "TLS 1.2+ mandatory",
                    "VPN for admin access",
                    "Private Link where possible"
                ],
                "kubernetes_controls": [
                    "mTLS service mesh",
                    "No HTTP endpoints",
                    "Certificate rotation"
                ]
            }
        }
    },
    "soc2": {
        "name": "SOC 2 Type II",
        "description": "Service Organization Control 2",
        "controls": {
            "CC6.1": {
                "title": "Logical Access Security",
                "eks_implementation": [
                    "IAM identity federation",
                    "Just-in-time access",
                    "Access reviews"
                ],
                "kubernetes_controls": [
                    "OIDC authentication",
                    "RBAC audit",
                    "Service account review"
                ]
            },
            "CC6.6": {
                "title": "System Boundary Protection",
                "eks_implementation": [
                    "VPC isolation",
                    "Security group rules",
                    "WAF protection"
                ],
                "kubernetes_controls": [
                    "Network policies",
                    "Namespace isolation",
                    "Ingress filtering"
                ]
            },
            "CC6.7": {
                "title": "Information Transmission",
                "eks_implementation": [
                    "Encryption in transit",
                    "Certificate management",
                    "Secure protocols only"
                ],
                "kubernetes_controls": [
                    "TLS termination",
                    "Service mesh encryption",
                    "No clear-text secrets"
                ]
            },
            "CC7.2": {
                "title": "System Monitoring",
                "eks_implementation": [
                    "CloudWatch metrics/alarms",
                    "X-Ray tracing",
                    "Container Insights"
                ],
                "kubernetes_controls": [
                    "Prometheus monitoring",
                    "Grafana dashboards",
                    "Alert routing"
                ]
            },
            "CC8.1": {
                "title": "Change Management",
                "eks_implementation": [
                    "AWS Config tracking",
                    "Change approval workflow",
                    "Rollback capability"
                ],
                "kubernetes_controls": [
                    "GitOps deployments",
                    "Admission webhooks",
                    "Canary deployments"
                ]
            }
        }
    },
    "iso_27001": {
        "name": "ISO 27001:2022",
        "description": "Information Security Management System",
        "controls": {
            "A.5.15": {
                "title": "Access Control",
                "eks_implementation": [
                    "Identity management",
                    "Access provisioning",
                    "Privileged access"
                ],
                "kubernetes_controls": [
                    "RBAC policies",
                    "Service accounts",
                    "Namespace isolation"
                ]
            },
            "A.8.9": {
                "title": "Configuration Management",
                "eks_implementation": [
                    "Infrastructure as Code",
                    "Configuration baseline",
                    "Drift detection"
                ],
                "kubernetes_controls": [
                    "GitOps practices",
                    "Admission control",
                    "Policy enforcement"
                ]
            },
            "A.8.12": {
                "title": "Data Leak Prevention",
                "eks_implementation": [
                    "DLP policies",
                    "Data classification",
                    "Egress controls"
                ],
                "kubernetes_controls": [
                    "Network policies",
                    "Secret management",
                    "Log redaction"
                ]
            },
            "A.8.15": {
                "title": "Logging",
                "eks_implementation": [
                    "Centralized logging",
                    "Log integrity",
                    "Retention policies"
                ],
                "kubernetes_controls": [
                    "Audit logs",
                    "Application logs",
                    "Security events"
                ]
            },
            "A.8.24": {
                "title": "Cryptography",
                "eks_implementation": [
                    "Encryption at rest",
                    "Encryption in transit",
                    "Key management"
                ],
                "kubernetes_controls": [
                    "Secrets encryption",
                    "TLS certificates",
                    "Sealed secrets"
                ]
            }
        }
    }
}

# CIS Kubernetes Benchmark Controls
CIS_BENCHMARK_CONTROLS = {
    "1.1": {
        "section": "Control Plane Components",
        "controls": [
            {
                "id": "1.1.1",
                "title": "Ensure API server audit logging is enabled",
                "level": CISBenchmarkLevel.LEVEL_1,
                "eks_managed": True,
                "remediation": "Enable control plane logging in EKS cluster configuration"
            },
            {
                "id": "1.1.2",
                "title": "Ensure API server authentication is configured",
                "level": CISBenchmarkLevel.LEVEL_1,
                "eks_managed": True,
                "remediation": "EKS uses IAM for authentication by default"
            }
        ]
    },
    "4.1": {
        "section": "Worker Node Security",
        "controls": [
            {
                "id": "4.1.1",
                "title": "Ensure kubelet authentication is configured",
                "level": CISBenchmarkLevel.LEVEL_1,
                "eks_managed": True,
                "remediation": "EKS configures kubelet authentication automatically"
            },
            {
                "id": "4.1.2",
                "title": "Ensure kubelet authorization is not set to AlwaysAllow",
                "level": CISBenchmarkLevel.LEVEL_1,
                "eks_managed": True,
                "remediation": "EKS uses Webhook authorization"
            }
        ]
    },
    "5.1": {
        "section": "RBAC and Service Accounts",
        "controls": [
            {
                "id": "5.1.1",
                "title": "Ensure cluster-admin role is only used where required",
                "level": CISBenchmarkLevel.LEVEL_1,
                "eks_managed": False,
                "remediation": "Review and minimize cluster-admin bindings"
            },
            {
                "id": "5.1.2",
                "title": "Minimize access to secrets",
                "level": CISBenchmarkLevel.LEVEL_1,
                "eks_managed": False,
                "remediation": "Use RBAC to restrict secret access to specific namespaces"
            },
            {
                "id": "5.1.3",
                "title": "Minimize wildcard use in Roles and ClusterRoles",
                "level": CISBenchmarkLevel.LEVEL_1,
                "eks_managed": False,
                "remediation": "Avoid using wildcards in RBAC rules"
            },
            {
                "id": "5.1.5",
                "title": "Ensure default service account is not actively used",
                "level": CISBenchmarkLevel.LEVEL_1,
                "eks_managed": False,
                "remediation": "Create specific service accounts for workloads"
            },
            {
                "id": "5.1.6",
                "title": "Ensure Service Account Tokens are only mounted where necessary",
                "level": CISBenchmarkLevel.LEVEL_1,
                "eks_managed": False,
                "remediation": "Set automountServiceAccountToken: false"
            }
        ]
    },
    "5.2": {
        "section": "Pod Security Standards",
        "controls": [
            {
                "id": "5.2.1",
                "title": "Ensure privileged containers are not allowed",
                "level": CISBenchmarkLevel.LEVEL_1,
                "eks_managed": False,
                "remediation": "Use Pod Security Standards with 'restricted' profile"
            },
            {
                "id": "5.2.2",
                "title": "Ensure containers do not share host process ID namespace",
                "level": CISBenchmarkLevel.LEVEL_1,
                "eks_managed": False,
                "remediation": "Set hostPID: false in pod specs"
            },
            {
                "id": "5.2.3",
                "title": "Ensure containers do not share host IPC namespace",
                "level": CISBenchmarkLevel.LEVEL_1,
                "eks_managed": False,
                "remediation": "Set hostIPC: false in pod specs"
            },
            {
                "id": "5.2.4",
                "title": "Ensure containers do not share host network namespace",
                "level": CISBenchmarkLevel.LEVEL_1,
                "eks_managed": False,
                "remediation": "Set hostNetwork: false in pod specs"
            },
            {
                "id": "5.2.5",
                "title": "Ensure containers do not allow privilege escalation",
                "level": CISBenchmarkLevel.LEVEL_1,
                "eks_managed": False,
                "remediation": "Set allowPrivilegeEscalation: false"
            },
            {
                "id": "5.2.6",
                "title": "Ensure containers run as non-root user",
                "level": CISBenchmarkLevel.LEVEL_2,
                "eks_managed": False,
                "remediation": "Set runAsNonRoot: true and specify runAsUser"
            },
            {
                "id": "5.2.7",
                "title": "Ensure root filesystem is read-only",
                "level": CISBenchmarkLevel.LEVEL_2,
                "eks_managed": False,
                "remediation": "Set readOnlyRootFilesystem: true"
            }
        ]
    },
    "5.3": {
        "section": "Network Policies",
        "controls": [
            {
                "id": "5.3.1",
                "title": "Ensure default deny network policy exists",
                "level": CISBenchmarkLevel.LEVEL_2,
                "eks_managed": False,
                "remediation": "Create default deny NetworkPolicy in each namespace"
            },
            {
                "id": "5.3.2",
                "title": "Ensure network policies are applied to all pods",
                "level": CISBenchmarkLevel.LEVEL_2,
                "eks_managed": False,
                "remediation": "Apply NetworkPolicy to all namespaces"
            }
        ]
    },
    "5.4": {
        "section": "Secrets Management",
        "controls": [
            {
                "id": "5.4.1",
                "title": "Ensure secrets are not stored in environment variables",
                "level": CISBenchmarkLevel.LEVEL_1,
                "eks_managed": False,
                "remediation": "Use volume mounts for secrets instead of env vars"
            },
            {
                "id": "5.4.2",
                "title": "Ensure external secrets management is used",
                "level": CISBenchmarkLevel.LEVEL_2,
                "eks_managed": False,
                "remediation": "Use AWS Secrets Manager with External Secrets Operator"
            }
        ]
    }
}


# ============================================================================
# SECURITY DATA CLASSES
# ============================================================================

@dataclass
class SecurityFinding:
    """Security assessment finding"""
    finding_id: str
    title: str
    severity: VulnerabilitySeverity
    category: str
    description: str
    affected_resource: str
    remediation: str
    compliance_mappings: List[str] = field(default_factory=list)
    cis_benchmark: Optional[str] = None
    auto_remediation_available: bool = False

@dataclass  
class ThreatModel:
    """STRIDE threat model entry"""
    threat_id: str
    category: ThreatCategory
    asset: str
    threat_description: str
    attack_vector: str
    likelihood: str  # low, medium, high
    impact: str  # low, medium, high
    risk_score: int  # 1-25
    existing_controls: List[str]
    recommended_controls: List[str]
    residual_risk: str

@dataclass
class ComplianceAssessment:
    """Compliance assessment result"""
    framework: str
    assessment_date: str
    total_controls: int
    compliant_controls: int
    non_compliant_controls: int
    not_applicable: int
    compliance_percentage: float
    findings: List[SecurityFinding]
    recommendations: List[str]


# ============================================================================
# EKS SECURITY ANALYZER
# ============================================================================

class EKSSecurityAnalyzer:
    """
    Comprehensive security analysis engine for EKS clusters.
    Performs security posture assessment, compliance mapping, and threat modeling.
    """
    
    def __init__(self):
        self.anthropic_client = None
        self._init_ai_client()
    
    def _init_ai_client(self):
        """Initialize Anthropic client for AI-powered analysis"""
        try:
            import anthropic
            api_key = os.getenv("ANTHROPIC_API_KEY") or st.secrets.get("ANTHROPIC_API_KEY", "")
            if api_key:
                self.anthropic_client = anthropic.Anthropic(api_key=api_key)
        except Exception:
            pass
    
    def assess_security_posture(self, cluster_config: Dict) -> Dict[str, Any]:
        """
        Perform comprehensive security posture assessment.
        
        Returns:
            Dict containing security score, findings, and recommendations
        """
        findings = []
        
        # Check network security
        network_findings = self._assess_network_security(cluster_config)
        findings.extend(network_findings)
        
        # Check IAM and access control
        iam_findings = self._assess_iam_security(cluster_config)
        findings.extend(iam_findings)
        
        # Check encryption configuration
        encryption_findings = self._assess_encryption(cluster_config)
        findings.extend(encryption_findings)
        
        # Check logging and monitoring
        logging_findings = self._assess_logging(cluster_config)
        findings.extend(logging_findings)
        
        # Check pod security
        pod_security_findings = self._assess_pod_security(cluster_config)
        findings.extend(pod_security_findings)
        
        # Calculate security score
        critical_count = sum(1 for f in findings if f.severity == VulnerabilitySeverity.CRITICAL)
        high_count = sum(1 for f in findings if f.severity == VulnerabilitySeverity.HIGH)
        medium_count = sum(1 for f in findings if f.severity == VulnerabilitySeverity.MEDIUM)
        low_count = sum(1 for f in findings if f.severity == VulnerabilitySeverity.LOW)
        
        # Score calculation (100 base, deductions for findings)
        score = 100 - (critical_count * 25) - (high_count * 10) - (medium_count * 5) - (low_count * 2)
        score = max(0, min(100, score))
        
        # Determine security level
        if score >= 90:
            level = "Excellent"
            level_color = "green"
        elif score >= 75:
            level = "Good"
            level_color = "blue"
        elif score >= 60:
            level = "Fair"
            level_color = "yellow"
        elif score >= 40:
            level = "Poor"
            level_color = "orange"
        else:
            level = "Critical"
            level_color = "red"
        
        return {
            "score": score,
            "level": level,
            "level_color": level_color,
            "findings_summary": {
                "critical": critical_count,
                "high": high_count,
                "medium": medium_count,
                "low": low_count,
                "total": len(findings)
            },
            "findings": [self._finding_to_dict(f) for f in findings],
            "recommendations": self._generate_recommendations(findings),
            "assessed_at": datetime.now().isoformat()
        }
    
    def _assess_network_security(self, config: Dict) -> List[SecurityFinding]:
        """Assess network security configuration"""
        findings = []
        
        security = config.get("security", {})
        network = config.get("network", {})
        
        # Check endpoint access
        if security.get("public_endpoint", True):
            findings.append(SecurityFinding(
                finding_id="NET-001",
                title="Public API Server Endpoint Enabled",
                severity=VulnerabilitySeverity.HIGH,
                category="Network Security",
                description="The EKS API server is accessible from the public internet",
                affected_resource="EKS Control Plane",
                remediation="Disable public endpoint and use private endpoint only",
                compliance_mappings=["PCI-DSS 1.1", "SOC2 CC6.6"],
                cis_benchmark="3.1.1"
            ))
        
        # Check VPC endpoints
        if not network.get("vpc_endpoints"):
            findings.append(SecurityFinding(
                finding_id="NET-002",
                title="VPC Endpoints Not Configured",
                severity=VulnerabilitySeverity.MEDIUM,
                category="Network Security",
                description="Traffic to AWS services goes through internet gateway",
                affected_resource="VPC",
                remediation="Configure VPC endpoints for S3, ECR, STS, and other services",
                compliance_mappings=["SOC2 CC6.6"],
                auto_remediation_available=True
            ))
        
        # Check NAT Gateway redundancy
        if network.get("nat_gateways", 0) < network.get("availability_zones", 3):
            findings.append(SecurityFinding(
                finding_id="NET-003",
                title="NAT Gateway Not Highly Available",
                severity=VulnerabilitySeverity.MEDIUM,
                category="Network Security",
                description="NAT gateway is not deployed in all availability zones",
                affected_resource="NAT Gateway",
                remediation="Deploy NAT gateway in each availability zone",
                compliance_mappings=["SOC2 CC7.1"]
            ))
        
        # Check network policies
        if not security.get("enable_network_policies", False):
            findings.append(SecurityFinding(
                finding_id="NET-004",
                title="Network Policies Not Enabled",
                severity=VulnerabilitySeverity.HIGH,
                category="Network Security",
                description="No network policies to control pod-to-pod traffic",
                affected_resource="Kubernetes Cluster",
                remediation="Enable Calico or Cilium CNI and implement network policies",
                compliance_mappings=["PCI-DSS 1.1", "HIPAA 164.312(e)(1)"],
                cis_benchmark="5.3.1"
            ))
        
        return findings
    
    def _assess_iam_security(self, config: Dict) -> List[SecurityFinding]:
        """Assess IAM and access control configuration"""
        findings = []
        
        security = config.get("security", {})
        
        # Check IRSA configuration
        # Assuming IRSA should be enabled
        findings.append(SecurityFinding(
            finding_id="IAM-001",
            title="Verify IRSA Configuration",
            severity=VulnerabilitySeverity.INFO,
            category="Identity and Access",
            description="Ensure IRSA is configured for all workloads requiring AWS access",
            affected_resource="Service Accounts",
            remediation="Configure IRSA for each service account that needs AWS permissions",
            compliance_mappings=["PCI-DSS 7.1", "SOC2 CC6.1"]
        ))
        
        # Check endpoint whitelist
        if security.get("public_endpoint", False) and not security.get("endpoint_whitelist"):
            findings.append(SecurityFinding(
                finding_id="IAM-002",
                title="No IP Whitelist for Public Endpoint",
                severity=VulnerabilitySeverity.HIGH,
                category="Identity and Access",
                description="Public endpoint accessible from any IP address",
                affected_resource="EKS API Server",
                remediation="Configure IP whitelist for public endpoint access",
                compliance_mappings=["PCI-DSS 1.1", "HIPAA 164.312(a)(1)"],
                auto_remediation_available=True
            ))
        
        return findings
    
    def _assess_encryption(self, config: Dict) -> List[SecurityFinding]:
        """Assess encryption configuration"""
        findings = []
        
        security = config.get("security", {})
        
        # Check secrets encryption
        if not security.get("enable_secrets_encryption", False):
            findings.append(SecurityFinding(
                finding_id="ENC-001",
                title="Kubernetes Secrets Not Encrypted",
                severity=VulnerabilitySeverity.CRITICAL,
                category="Encryption",
                description="Secrets stored in etcd are not encrypted at rest",
                affected_resource="etcd",
                remediation="Enable envelope encryption with KMS for Kubernetes secrets",
                compliance_mappings=["PCI-DSS 3.4", "HIPAA 164.312(a)(2)(iv)", "ISO27001 A.8.24"],
                auto_remediation_available=True
            ))
        
        # Check KMS key
        if security.get("enable_secrets_encryption") and not security.get("kms_key_arn"):
            findings.append(SecurityFinding(
                finding_id="ENC-002",
                title="Using AWS Managed KMS Key",
                severity=VulnerabilitySeverity.LOW,
                category="Encryption",
                description="Using AWS managed key instead of customer managed key",
                affected_resource="KMS",
                remediation="Consider using customer managed KMS key for additional control",
                compliance_mappings=["PCI-DSS 3.5"]
            ))
        
        return findings
    
    def _assess_logging(self, config: Dict) -> List[SecurityFinding]:
        """Assess logging and monitoring configuration"""
        findings = []
        
        security = config.get("security", {})
        observability = config.get("observability", {})
        
        # Check audit logging
        if not security.get("enable_audit_logging", False):
            findings.append(SecurityFinding(
                finding_id="LOG-001",
                title="Audit Logging Not Enabled",
                severity=VulnerabilitySeverity.HIGH,
                category="Logging and Monitoring",
                description="Kubernetes audit logs are not being collected",
                affected_resource="EKS Control Plane",
                remediation="Enable all control plane log types in EKS configuration",
                compliance_mappings=["PCI-DSS 10.1", "HIPAA 164.312(b)", "SOC2 CC7.2"],
                cis_benchmark="1.1.1",
                auto_remediation_available=True
            ))
        
        # Check log retention
        if security.get("audit_log_retention_days", 0) < 90:
            findings.append(SecurityFinding(
                finding_id="LOG-002",
                title="Insufficient Log Retention",
                severity=VulnerabilitySeverity.MEDIUM,
                category="Logging and Monitoring",
                description=f"Log retention of {security.get('audit_log_retention_days', 0)} days may not meet compliance requirements",
                affected_resource="CloudWatch Logs",
                remediation="Increase log retention to at least 90 days (365 for HIPAA)",
                compliance_mappings=["PCI-DSS 10.7", "HIPAA 164.312(b)"]
            ))
        
        # Check runtime security
        if not security.get("enable_runtime_security", False):
            findings.append(SecurityFinding(
                finding_id="LOG-003",
                title="Runtime Security Not Enabled",
                severity=VulnerabilitySeverity.MEDIUM,
                category="Logging and Monitoring",
                description="No runtime threat detection configured",
                affected_resource="Worker Nodes",
                remediation="Deploy Falco or enable GuardDuty EKS Runtime Monitoring",
                compliance_mappings=["PCI-DSS 11.4", "SOC2 CC7.2"]
            ))
        
        return findings
    
    def _assess_pod_security(self, config: Dict) -> List[SecurityFinding]:
        """Assess pod security configuration"""
        findings = []
        
        security = config.get("security", {})
        
        # Check Pod Security Standards
        if not security.get("enable_pod_security_standards", False):
            findings.append(SecurityFinding(
                finding_id="POD-001",
                title="Pod Security Standards Not Enforced",
                severity=VulnerabilitySeverity.HIGH,
                category="Pod Security",
                description="No pod security restrictions in place",
                affected_resource="Kubernetes Cluster",
                remediation="Enable Pod Security Standards with 'restricted' profile",
                compliance_mappings=["PCI-DSS 2.2", "CIS 5.2.1"],
                cis_benchmark="5.2.1"
            ))
        elif security.get("pod_security_level") == "privileged":
            findings.append(SecurityFinding(
                finding_id="POD-002",
                title="Permissive Pod Security Level",
                severity=VulnerabilitySeverity.HIGH,
                category="Pod Security",
                description="Pod Security Standards set to 'privileged' allows any pod configuration",
                affected_resource="Kubernetes Cluster",
                remediation="Use 'baseline' or 'restricted' profile",
                compliance_mappings=["PCI-DSS 2.2"],
                cis_benchmark="5.2.1"
            ))
        
        # Check image scanning
        if not security.get("enable_image_scanning", False):
            findings.append(SecurityFinding(
                finding_id="POD-003",
                title="Container Image Scanning Not Enabled",
                severity=VulnerabilitySeverity.MEDIUM,
                category="Pod Security",
                description="Container images are not scanned for vulnerabilities",
                affected_resource="Container Images",
                remediation="Enable ECR image scanning and admission controller for scan results",
                compliance_mappings=["PCI-DSS 6.5", "SOC2 CC7.1"]
            ))
        
        return findings
    
    def _finding_to_dict(self, finding: SecurityFinding) -> Dict:
        """Convert SecurityFinding to dictionary"""
        return {
            "finding_id": finding.finding_id,
            "title": finding.title,
            "severity": finding.severity.value,
            "category": finding.category,
            "description": finding.description,
            "affected_resource": finding.affected_resource,
            "remediation": finding.remediation,
            "compliance_mappings": finding.compliance_mappings,
            "cis_benchmark": finding.cis_benchmark,
            "auto_remediation_available": finding.auto_remediation_available
        }
    
    def _generate_recommendations(self, findings: List[SecurityFinding]) -> List[Dict]:
        """Generate prioritized recommendations based on findings"""
        recommendations = []
        
        # Group by severity
        critical = [f for f in findings if f.severity == VulnerabilitySeverity.CRITICAL]
        high = [f for f in findings if f.severity == VulnerabilitySeverity.HIGH]
        
        if critical:
            recommendations.append({
                "priority": 1,
                "title": "Address Critical Security Issues Immediately",
                "description": f"Found {len(critical)} critical security issues that require immediate attention",
                "items": [f.title for f in critical],
                "estimated_effort": "1-2 days"
            })
        
        if high:
            recommendations.append({
                "priority": 2,
                "title": "Remediate High Severity Findings",
                "description": f"Found {len(high)} high severity issues to address",
                "items": [f.title for f in high],
                "estimated_effort": "1 week"
            })
        
        # Check for common patterns
        network_issues = [f for f in findings if f.category == "Network Security"]
        if len(network_issues) >= 2:
            recommendations.append({
                "priority": 3,
                "title": "Review Network Security Architecture",
                "description": "Multiple network security issues detected. Consider comprehensive network review.",
                "items": [f.title for f in network_issues],
                "estimated_effort": "2-3 days"
            })
        
        return recommendations
    
    def perform_compliance_assessment(self, cluster_config: Dict, frameworks: List[str]) -> Dict[str, ComplianceAssessment]:
        """
        Perform compliance assessment against specified frameworks.
        
        Args:
            cluster_config: EKS cluster configuration
            frameworks: List of compliance frameworks (pci_dss, hipaa, soc2, iso_27001)
        
        Returns:
            Dict of ComplianceAssessment per framework
        """
        assessments = {}
        
        for framework in frameworks:
            if framework not in COMPLIANCE_CONTROLS:
                continue
            
            framework_info = COMPLIANCE_CONTROLS[framework]
            controls = framework_info["controls"]
            
            total = 0
            compliant = 0
            non_compliant = 0
            findings = []
            
            for control_id, control in controls.items():
                total += 1
                
                # Assess each control
                is_compliant, finding = self._assess_compliance_control(
                    cluster_config, framework, control_id, control
                )
                
                if is_compliant:
                    compliant += 1
                else:
                    non_compliant += 1
                    if finding:
                        findings.append(finding)
            
            compliance_pct = (compliant / total * 100) if total > 0 else 0
            
            assessments[framework] = ComplianceAssessment(
                framework=framework_info["name"],
                assessment_date=datetime.now().isoformat(),
                total_controls=total,
                compliant_controls=compliant,
                non_compliant_controls=non_compliant,
                not_applicable=0,
                compliance_percentage=round(compliance_pct, 1),
                findings=findings,
                recommendations=self._generate_compliance_recommendations(framework, findings)
            )
        
        return assessments
    
    def _assess_compliance_control(self, config: Dict, framework: str, 
                                    control_id: str, control: Dict) -> Tuple[bool, Optional[SecurityFinding]]:
        """Assess a specific compliance control"""
        
        security = config.get("security", {})
        network = config.get("network", {})
        observability = config.get("observability", {})
        
        # Map control requirements to configuration checks
        if "Network Security" in control.get("title", "") or "Network" in control.get("title", ""):
            is_compliant = (
                security.get("enable_network_policies", False) and
                not security.get("public_endpoint", True)
            )
        elif "Encryption" in control.get("title", "") or "Cryptography" in control.get("title", ""):
            is_compliant = security.get("enable_secrets_encryption", False)
        elif "Access Control" in control.get("title", ""):
            is_compliant = True  # Assume IAM is configured properly
        elif "Audit" in control.get("title", "") or "Logging" in control.get("title", ""):
            is_compliant = security.get("enable_audit_logging", False)
        else:
            # Default to compliant for controls we can't automatically assess
            is_compliant = True
        
        if not is_compliant:
            finding = SecurityFinding(
                finding_id=f"{framework.upper()}-{control_id}",
                title=f"Non-compliant: {control['title']}",
                severity=VulnerabilitySeverity.HIGH,
                category=f"{framework.upper()} Compliance",
                description=f"Configuration does not meet {framework.upper()} control {control_id}",
                affected_resource="EKS Cluster",
                remediation="; ".join(control.get("eks_implementation", [])[:2]),
                compliance_mappings=[f"{framework.upper()} {control_id}"]
            )
            return False, finding
        
        return True, None
    
    def _generate_compliance_recommendations(self, framework: str, findings: List[SecurityFinding]) -> List[str]:
        """Generate compliance-specific recommendations"""
        recommendations = []
        
        if findings:
            recommendations.append(f"Address {len(findings)} non-compliant controls for {framework.upper()}")
        
        # Framework-specific recommendations
        if framework == "pci_dss":
            recommendations.extend([
                "Implement network segmentation for cardholder data environment",
                "Enable file integrity monitoring on all nodes",
                "Configure anti-malware solutions for container workloads"
            ])
        elif framework == "hipaa":
            recommendations.extend([
                "Ensure all PHI is encrypted at rest and in transit",
                "Implement comprehensive audit logging with 6-year retention",
                "Configure automatic session timeout for all interfaces"
            ])
        elif framework == "soc2":
            recommendations.extend([
                "Implement change management procedures with approval workflows",
                "Configure system monitoring with anomaly detection",
                "Document all access control policies and procedures"
            ])
        
        return recommendations
    
    def generate_threat_model(self, cluster_config: Dict) -> List[ThreatModel]:
        """
        Generate STRIDE-based threat model for the EKS architecture.
        
        Returns:
            List of ThreatModel entries
        """
        threats = []
        
        # Spoofing threats
        threats.append(ThreatModel(
            threat_id="T-001",
            category=ThreatCategory.SPOOFING,
            asset="API Server",
            threat_description="Attacker impersonates legitimate user or service to access cluster",
            attack_vector="Stolen credentials, compromised service account token",
            likelihood="medium",
            impact="high",
            risk_score=12,
            existing_controls=["IAM authentication", "OIDC provider"],
            recommended_controls=[
                "Enable MFA for all human users",
                "Use short-lived tokens",
                "Implement pod identity with IRSA"
            ],
            residual_risk="low"
        ))
        
        # Tampering threats
        threats.append(ThreatModel(
            threat_id="T-002",
            category=ThreatCategory.TAMPERING,
            asset="Container Images",
            threat_description="Attacker modifies container images to inject malicious code",
            attack_vector="Compromised CI/CD pipeline, registry access",
            likelihood="medium",
            impact="critical",
            risk_score=16,
            existing_controls=["ECR scanning"],
            recommended_controls=[
                "Implement image signing with cosign/notation",
                "Enable Sigstore verification",
                "Use admission controller to verify signatures"
            ],
            residual_risk="medium"
        ))
        
        threats.append(ThreatModel(
            threat_id="T-003",
            category=ThreatCategory.TAMPERING,
            asset="Kubernetes Secrets",
            threat_description="Attacker modifies secrets to gain access or cause disruption",
            attack_vector="RBAC misconfiguration, etcd access",
            likelihood="low",
            impact="critical",
            risk_score=12,
            existing_controls=["RBAC", "etcd encryption"],
            recommended_controls=[
                "External secrets management (Secrets Manager)",
                "Audit all secret access",
                "Implement GitOps for secrets"
            ],
            residual_risk="low"
        ))
        
        # Information Disclosure threats
        threats.append(ThreatModel(
            threat_id="T-004",
            category=ThreatCategory.INFORMATION_DISCLOSURE,
            asset="Application Data",
            threat_description="Sensitive data exposed through logs, environment variables, or network",
            attack_vector="Log aggregation, network sniffing, env var exposure",
            likelihood="medium",
            impact="high",
            risk_score=12,
            existing_controls=["Network policies"],
            recommended_controls=[
                "Implement service mesh with mTLS",
                "Enable log redaction",
                "Avoid secrets in environment variables"
            ],
            residual_risk="low"
        ))
        
        # Denial of Service threats
        threats.append(ThreatModel(
            threat_id="T-005",
            category=ThreatCategory.DENIAL_OF_SERVICE,
            asset="Kubernetes Cluster",
            threat_description="Resource exhaustion attack causing cluster unavailability",
            attack_vector="Resource-intensive pods, API server flooding",
            likelihood="medium",
            impact="high",
            risk_score=12,
            existing_controls=["Resource limits", "API rate limiting"],
            recommended_controls=[
                "Implement LimitRange in all namespaces",
                "Configure ResourceQuota",
                "Enable pod disruption budgets",
                "Use priority classes"
            ],
            residual_risk="low"
        ))
        
        # Elevation of Privilege threats
        threats.append(ThreatModel(
            threat_id="T-006",
            category=ThreatCategory.ELEVATION_OF_PRIVILEGE,
            asset="Container Runtime",
            threat_description="Container escape leading to node or cluster compromise",
            attack_vector="Privileged containers, kernel vulnerabilities",
            likelihood="low",
            impact="critical",
            risk_score=15,
            existing_controls=["Pod Security Standards"],
            recommended_controls=[
                "Enforce restricted PSS profile",
                "Use seccomp profiles",
                "Enable AppArmor/SELinux",
                "Deploy Falco for runtime detection"
            ],
            residual_risk="low"
        ))
        
        return threats
