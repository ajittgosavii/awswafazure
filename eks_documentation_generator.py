"""
EKS Documentation Generator Module
Part of the AI-Enhanced EKS Architecture Design Wizard

Features:
- Architecture Decision Records (ADRs)
- Runbook Generation
- Architecture Documentation
- Implementation Guides
- Operational Playbooks

Author: Infosys Cloud Architecture Team
Version: 2.0.0
"""

import streamlit as st
import json
import yaml
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
import os
import re

# ============================================================================
# DOCUMENTATION TEMPLATES
# ============================================================================

ADR_TEMPLATE = """# ADR {adr_number}: {title}

## Status
{status}

## Context
{context}

## Decision
{decision}

## Consequences

### Positive
{positive_consequences}

### Negative
{negative_consequences}

### Neutral
{neutral_consequences}

## Compliance
{compliance_notes}

## References
{references}

---
*Date: {date}*
*Author: {author}*
*Supersedes: {supersedes}*
"""

RUNBOOK_TEMPLATE = """# Runbook: {title}

## Overview
{overview}

## Prerequisites
{prerequisites}

## Procedure

{procedure_steps}

## Rollback Procedure
{rollback_steps}

## Verification
{verification_steps}

## Troubleshooting
{troubleshooting}

## Contacts
{contacts}

## Related Documentation
{related_docs}

---
*Last Updated: {date}*
*Owner: {owner}*
*Review Cycle: {review_cycle}*
"""

ARCHITECTURE_DOC_TEMPLATE = """# {cluster_name} - Architecture Documentation

## Executive Summary
{executive_summary}

## Architecture Overview

### Cluster Configuration
{cluster_config}

### Network Architecture
{network_architecture}

### Security Architecture
{security_architecture}

### Node Configuration
{node_configuration}

## Component Details

### EKS Cluster
{eks_details}

### Networking
{networking_details}

### Storage
{storage_details}

### Observability
{observability_details}

### Security Controls
{security_controls}

## Operational Procedures

### Scaling
{scaling_procedures}

### Backup & Recovery
{backup_procedures}

### Incident Response
{incident_response}

## Cost Management
{cost_management}

## Compliance & Governance
{compliance_governance}

## Appendices

### A. Configuration Files
{config_files}

### B. IAM Policies
{iam_policies}

### C. Network Diagrams
{network_diagrams}

---
*Document Version: {version}*
*Last Updated: {date}*
*Classification: {classification}*
"""


# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class ADR:
    """Architecture Decision Record"""
    adr_number: int
    title: str
    status: str  # Proposed, Accepted, Deprecated, Superseded
    context: str
    decision: str
    positive_consequences: List[str]
    negative_consequences: List[str]
    neutral_consequences: List[str] = field(default_factory=list)
    compliance_notes: str = ""
    references: List[str] = field(default_factory=list)
    date: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d"))
    author: str = "EKS Architecture Team"
    supersedes: str = "N/A"

@dataclass
class Runbook:
    """Operational Runbook"""
    title: str
    overview: str
    prerequisites: List[str]
    procedure_steps: List[Dict[str, str]]
    rollback_steps: List[Dict[str, str]]
    verification_steps: List[str]
    troubleshooting: List[Dict[str, str]]
    contacts: Dict[str, str]
    related_docs: List[str] = field(default_factory=list)
    owner: str = "Platform Team"
    review_cycle: str = "Quarterly"


# ============================================================================
# ADR GENERATOR
# ============================================================================

class ADRGenerator:
    """
    Generates Architecture Decision Records based on cluster configuration.
    """
    
    def __init__(self, cluster_config: Dict):
        self.config = cluster_config
        self.adr_counter = 0
    
    def generate_all_adrs(self) -> List[str]:
        """Generate all relevant ADRs based on configuration"""
        adrs = []
        
        # Core architecture ADRs
        adrs.append(self._generate_eks_version_adr())
        adrs.append(self._generate_network_architecture_adr())
        adrs.append(self._generate_node_group_strategy_adr())
        
        # Security ADRs
        security = self.config.get("security", {})
        if security.get("private_endpoint"):
            adrs.append(self._generate_private_endpoint_adr())
        if security.get("enable_secrets_encryption"):
            adrs.append(self._generate_secrets_encryption_adr())
        
        # Cost optimization ADRs
        cost = self.config.get("cost", {})
        if cost.get("enable_karpenter") or any(
            ng.get("capacity_type") == "SPOT" 
            for ng in self.config.get("node_groups", [])
        ):
            adrs.append(self._generate_cost_optimization_adr())
        
        # Observability ADRs
        adrs.append(self._generate_observability_adr())
        
        return adrs
    
    def _next_adr_number(self) -> int:
        self.adr_counter += 1
        return self.adr_counter
    
    def _format_adr(self, adr: ADR) -> str:
        """Format ADR to markdown"""
        return ADR_TEMPLATE.format(
            adr_number=str(adr.adr_number).zfill(4),
            title=adr.title,
            status=adr.status,
            context=adr.context,
            decision=adr.decision,
            positive_consequences="\n".join(f"- {c}" for c in adr.positive_consequences),
            negative_consequences="\n".join(f"- {c}" for c in adr.negative_consequences),
            neutral_consequences="\n".join(f"- {c}" for c in adr.neutral_consequences) or "None identified",
            compliance_notes=adr.compliance_notes or "N/A",
            references="\n".join(f"- {r}" for r in adr.references) or "None",
            date=adr.date,
            author=adr.author,
            supersedes=adr.supersedes
        )
    
    def _generate_eks_version_adr(self) -> str:
        """Generate ADR for EKS version selection"""
        version = self.config.get("kubernetes_version", "1.29")
        
        adr = ADR(
            adr_number=self._next_adr_number(),
            title=f"Use Amazon EKS Version {version}",
            status="Accepted",
            context=f"""
The organization requires a managed Kubernetes platform for container orchestration.
Multiple Kubernetes versions are available, each with different features, support timelines,
and compatibility considerations. The cluster needs to balance stability with access to
new features.

Current requirements:
- Production workloads requiring enterprise support
- Integration with AWS services
- Long-term support and security patches
- Compatibility with existing tooling
""",
            decision=f"""
We will use Amazon EKS version {version} for the following reasons:

1. **Extended Support**: EKS {version} has extended support until at least 14 months from release
2. **Feature Set**: Includes latest stable Kubernetes features
3. **Security**: Receives regular security patches from AWS
4. **Compatibility**: Verified compatibility with our add-ons and tooling
5. **AWS Integration**: Full support for latest EKS features including Pod Identity

The cluster will follow a version upgrade strategy of N-1, upgrading within 3 months of
new version availability after internal testing.
""",
            positive_consequences=[
                "Access to latest Kubernetes features and improvements",
                "AWS managed security patches and updates",
                "Extended support timeline reduces upgrade urgency",
                "Better resource efficiency with updated scheduler",
                "Improved observability with enhanced metrics"
            ],
            negative_consequences=[
                "May require testing of existing workloads for compatibility",
                "Some third-party tools may lag in version support",
                "Team needs to stay current with version changes"
            ],
            neutral_consequences=[
                "Requires establishing upgrade runbooks and testing procedures",
                "Documentation needs to reference specific version features"
            ],
            references=[
                "https://docs.aws.amazon.com/eks/latest/userguide/kubernetes-versions.html",
                "https://kubernetes.io/releases/",
                "https://aws.amazon.com/eks/eks-anywhere/"
            ]
        )
        
        return self._format_adr(adr)
    
    def _generate_network_architecture_adr(self) -> str:
        """Generate ADR for network architecture decisions"""
        network = self.config.get("network", {})
        vpc_cidr = network.get("vpc_cidr", "10.0.0.0/16")
        azs = network.get("availability_zones", 3)
        
        adr = ADR(
            adr_number=self._next_adr_number(),
            title="VPC Network Architecture for EKS",
            status="Accepted",
            context=f"""
The EKS cluster requires network infrastructure that supports:
- High availability across multiple availability zones
- Network isolation between workloads
- Secure access to AWS services
- Scalability for pod networking
- Compliance with security requirements

The network must support both the EKS control plane and worker node communication
while providing appropriate isolation for different workload types.
""",
            decision=f"""
We will implement the following network architecture:

**VPC Configuration:**
- CIDR Block: {vpc_cidr}
- Availability Zones: {azs}
- Subnet Strategy: Public + Private + Intra subnets per AZ

**Subnet Design:**
- Public Subnets: For NAT Gateways and public-facing load balancers
- Private Subnets: For EKS nodes and internal workloads
- Intra Subnets: For EKS control plane ENIs (no internet access)

**VPC Endpoints:**
- S3 Gateway Endpoint (cost-effective, no data transfer charges)
- ECR API/DKR Interface Endpoints (container image pulls)
- STS Interface Endpoint (IAM authentication)
- CloudWatch Logs Endpoint (logging)
- SSM Endpoints (node management)

**NAT Gateway Strategy:**
- One NAT Gateway per AZ for production (high availability)
- Single NAT Gateway for non-production (cost optimization)

**Pod Networking:**
- VPC CNI with prefix delegation enabled
- Custom networking for pod IP isolation
- Security Groups for Pods enabled
""",
            positive_consequences=[
                f"High availability across {azs} availability zones",
                "Reduced data transfer costs via VPC endpoints",
                "Network isolation between workload types",
                "Scalable pod IP addressing with prefix delegation",
                "Defense in depth with multiple network layers"
            ],
            negative_consequences=[
                "Increased infrastructure costs (NAT Gateways, VPC Endpoints)",
                "More complex network troubleshooting",
                "Requires careful CIDR planning for growth"
            ],
            compliance_notes="""
This network architecture supports:
- PCI-DSS: Network segmentation (Requirement 1)
- HIPAA: Network isolation for PHI
- SOC 2: Logical access controls
""",
            references=[
                "https://docs.aws.amazon.com/eks/latest/userguide/network_reqs.html",
                "https://aws.github.io/aws-eks-best-practices/networking/vpc-cni/",
                "https://docs.aws.amazon.com/vpc/latest/privatelink/vpc-endpoints.html"
            ]
        )
        
        return self._format_adr(adr)
    
    def _generate_node_group_strategy_adr(self) -> str:
        """Generate ADR for node group strategy"""
        node_groups = self.config.get("node_groups", [])
        
        ng_summary = "\n".join([
            f"- **{ng.get('name', 'default')}**: {ng.get('instance_types', ['m6i.xlarge'])[0]}, "
            f"{ng.get('capacity_type', 'ON_DEMAND')}, {ng.get('min_size', 1)}-{ng.get('max_size', 10)} nodes"
            for ng in node_groups
        ])
        
        adr = ADR(
            adr_number=self._next_adr_number(),
            title="EKS Node Group Strategy",
            status="Accepted",
            context="""
The EKS cluster requires compute capacity that:
- Supports diverse workload types (system, application, GPU)
- Optimizes cost while maintaining availability
- Provides appropriate isolation for critical workloads
- Scales efficiently based on demand
- Meets security and compliance requirements
""",
            decision=f"""
We will implement the following node group strategy:

**Node Groups:**
{ng_summary}

**Design Principles:**

1. **Separation of Concerns**
   - System node group: Critical cluster components (CoreDNS, monitoring)
   - Application node groups: Business workloads
   - Specialized groups: GPU, high-memory as needed

2. **Capacity Type Strategy**
   - ON_DEMAND: System components, stateful workloads
   - SPOT: Stateless, fault-tolerant workloads
   - Target: 70% Spot for cost optimization

3. **Instance Selection**
   - Diversified instance types for Spot availability
   - Graviton (ARM) where compatible for cost savings
   - Right-sized based on workload profiling

4. **Scaling Strategy**
   - Karpenter for just-in-time provisioning
   - Aggressive scale-down for cost optimization
   - Pod Disruption Budgets for availability
""",
            positive_consequences=[
                "Workload isolation improves stability",
                "Cost optimization through Spot instances",
                "Flexible scaling with Karpenter",
                "Clear operational boundaries"
            ],
            negative_consequences=[
                "Multiple node groups increase complexity",
                "Spot interruptions require application resilience",
                "More IAM roles and policies to manage"
            ],
            references=[
                "https://docs.aws.amazon.com/eks/latest/userguide/managed-node-groups.html",
                "https://karpenter.sh/docs/",
                "https://aws.amazon.com/ec2/spot/"
            ]
        )
        
        return self._format_adr(adr)
    
    def _generate_private_endpoint_adr(self) -> str:
        """Generate ADR for private endpoint decision"""
        adr = ADR(
            adr_number=self._next_adr_number(),
            title="Private-Only EKS API Endpoint",
            status="Accepted",
            context="""
The EKS API server endpoint accessibility must be configured to balance:
- Security requirements and attack surface reduction
- Operational access for cluster management
- CI/CD pipeline integration
- Compliance mandates for network isolation

Public endpoint access exposes the API server to potential attacks,
while private-only access requires additional infrastructure for management.
""",
            decision="""
We will configure the EKS cluster with **private endpoint only**:

**Configuration:**
- Public Endpoint: Disabled
- Private Endpoint: Enabled
- Endpoint Access CIDR: VPC CIDR only

**Access Methods:**
1. **VPN/Direct Connect**: Primary access for administrators
2. **Bastion Host**: Jump server in private subnet with SSM
3. **CI/CD**: Runners deployed within VPC
4. **AWS Console**: Via VPC endpoint for STS

**Additional Security:**
- IP whitelisting for private endpoint
- IAM authentication required
- Kubernetes RBAC for authorization
- Audit logging enabled
""",
            positive_consequences=[
                "Eliminates public attack surface",
                "Meets compliance requirements for network isolation",
                "Forces proper access control implementation",
                "Reduces risk of credential exposure"
            ],
            negative_consequences=[
                "Requires VPN/Direct Connect for management",
                "CI/CD pipelines need VPC access",
                "More complex initial setup",
                "Debugging may be more difficult"
            ],
            compliance_notes="""
Required for:
- PCI-DSS: Restricts access to cardholder data environment
- HIPAA: Controls access to systems with PHI
- SOC 2: Logical access security controls
""",
            references=[
                "https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html",
                "https://aws.github.io/aws-eks-best-practices/security/docs/iam/"
            ]
        )
        
        return self._format_adr(adr)
    
    def _generate_secrets_encryption_adr(self) -> str:
        """Generate ADR for secrets encryption"""
        adr = ADR(
            adr_number=self._next_adr_number(),
            title="Kubernetes Secrets Encryption with KMS",
            status="Accepted",
            context="""
Kubernetes Secrets store sensitive data including:
- Database credentials
- API keys
- TLS certificates
- OAuth tokens

By default, Secrets are stored base64-encoded in etcd without encryption,
making them vulnerable if etcd is compromised. Encryption at rest is
required for compliance and security best practices.
""",
            decision="""
We will enable envelope encryption for Kubernetes Secrets using AWS KMS:

**Configuration:**
- KMS Key: Customer Managed Key (CMK)
- Key Rotation: Enabled (annual automatic rotation)
- Key Policy: Restricted to EKS service and administrators
- Encryption Provider: AWS Encryption Provider

**Additional Secret Management:**
1. **External Secrets Operator**: Sync secrets from AWS Secrets Manager
2. **Sealed Secrets**: GitOps-friendly encrypted secrets
3. **Secret Rotation**: Automated rotation via Secrets Manager

**Operational Practices:**
- Never commit secrets to Git (even encrypted)
- Use IRSA for AWS credential access
- Regular secret rotation schedule
- Audit logging for secret access
""",
            positive_consequences=[
                "Secrets encrypted at rest in etcd",
                "Customer-controlled encryption keys",
                "Automatic key rotation",
                "Audit trail for key usage",
                "Compliance with encryption requirements"
            ],
            negative_consequences=[
                "Slight increase in API latency for secret operations",
                "KMS costs for cryptographic operations",
                "Key management overhead",
                "Dependency on KMS availability"
            ],
            compliance_notes="""
Required for:
- PCI-DSS 3.4: Encryption of stored cardholder data
- HIPAA 164.312(a)(2)(iv): Encryption of PHI
- SOC 2 CC6.7: Encryption requirements
- ISO 27001 A.10.1: Cryptographic controls
""",
            references=[
                "https://docs.aws.amazon.com/eks/latest/userguide/enable-kms.html",
                "https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/",
                "https://external-secrets.io/"
            ]
        )
        
        return self._format_adr(adr)
    
    def _generate_cost_optimization_adr(self) -> str:
        """Generate ADR for cost optimization strategy"""
        adr = ADR(
            adr_number=self._next_adr_number(),
            title="EKS Cost Optimization Strategy",
            status="Accepted",
            context="""
Cloud infrastructure costs can grow significantly without proper optimization.
The EKS cluster must balance:
- Performance and availability requirements
- Cost efficiency
- Operational complexity
- Risk tolerance for interruptions

Multiple cost optimization strategies are available, each with different
trade-offs between savings and operational impact.
""",
            decision="""
We will implement a multi-layered cost optimization strategy:

**1. Spot Instances (30-70% savings)**
- Use for stateless, fault-tolerant workloads
- Diversify across instance types and AZs
- Implement graceful termination handling
- Target: 70% Spot for application workloads

**2. Karpenter Autoscaling**
- Just-in-time node provisioning
- Automatic instance type selection
- Consolidation of underutilized nodes
- Bin-packing for efficient resource usage

**3. Graviton Instances (20% savings)**
- Use ARM-based instances where compatible
- Requires multi-arch container images
- Prioritize for new workloads

**4. Right-Sizing**
- Regular resource utilization review
- VPA recommendations for resource requests
- Kubecost for visibility

**5. Compute Savings Plans**
- 1-year commitment for baseline usage
- Covers On-Demand portion of workloads
- 30% savings on committed spend
""",
            positive_consequences=[
                "40-60% cost reduction achievable",
                "Automatic optimization with Karpenter",
                "Flexibility to adjust strategy over time",
                "Improved resource efficiency"
            ],
            negative_consequences=[
                "Spot interruptions require application resilience",
                "Graviton requires image rebuilds",
                "Savings Plans require commitment",
                "More complex capacity planning"
            ],
            neutral_consequences=[
                "Need to monitor Spot availability",
                "Regular review of optimization effectiveness",
                "Balance between cost and reliability"
            ],
            references=[
                "https://aws.amazon.com/ec2/spot/",
                "https://karpenter.sh/",
                "https://aws.amazon.com/savingsplans/",
                "https://www.kubecost.com/"
            ]
        )
        
        return self._format_adr(adr)
    
    def _generate_observability_adr(self) -> str:
        """Generate ADR for observability stack"""
        adr = ADR(
            adr_number=self._next_adr_number(),
            title="EKS Observability Stack Architecture",
            status="Accepted",
            context="""
Effective observability is critical for:
- Operational visibility and troubleshooting
- Performance monitoring and optimization
- Security monitoring and incident response
- SLO/SLI tracking and reporting
- Cost attribution and analysis

The observability stack must handle metrics, logs, and traces at scale
while integrating with existing tools and processes.
""",
            decision="""
We will implement a comprehensive observability stack:

**Metrics (Prometheus Stack)**
- Prometheus Operator for metrics collection
- Thanos for long-term storage and multi-cluster
- Grafana for visualization
- Alertmanager for alert routing

**Logging (Fluent Bit → CloudWatch/OpenSearch)**
- Fluent Bit DaemonSet for log collection
- Structured JSON logging format
- CloudWatch Logs for retention
- OpenSearch for analysis (optional)

**Tracing (AWS X-Ray / OpenTelemetry)**
- OpenTelemetry Collector for trace collection
- AWS X-Ray for distributed tracing
- Service map visualization
- Trace-based debugging

**Alerting Strategy**
- PagerDuty integration for critical alerts
- Slack for warnings and notifications
- Runbook links in alert annotations
- SLO-based alerting for services
""",
            positive_consequences=[
                "Full visibility into cluster and application health",
                "Proactive issue detection through alerting",
                "Faster incident resolution with traces",
                "Data-driven capacity planning",
                "Cost attribution by team/service"
            ],
            negative_consequences=[
                "Additional infrastructure to manage",
                "Storage costs for metrics and logs",
                "Learning curve for teams",
                "Potential for alert fatigue"
            ],
            references=[
                "https://prometheus.io/",
                "https://grafana.com/",
                "https://aws.amazon.com/xray/",
                "https://opentelemetry.io/"
            ]
        )
        
        return self._format_adr(adr)


# ============================================================================
# RUNBOOK GENERATOR
# ============================================================================

class RunbookGenerator:
    """
    Generates operational runbooks for EKS cluster management.
    """
    
    def __init__(self, cluster_config: Dict):
        self.config = cluster_config
        self.cluster_name = cluster_config.get("cluster_name", "eks-cluster")
    
    def generate_all_runbooks(self) -> Dict[str, str]:
        """Generate all operational runbooks"""
        runbooks = {}
        
        runbooks["node-scaling.md"] = self._generate_node_scaling_runbook()
        runbooks["cluster-upgrade.md"] = self._generate_cluster_upgrade_runbook()
        runbooks["incident-response.md"] = self._generate_incident_response_runbook()
        runbooks["disaster-recovery.md"] = self._generate_disaster_recovery_runbook()
        runbooks["certificate-rotation.md"] = self._generate_cert_rotation_runbook()
        runbooks["troubleshooting.md"] = self._generate_troubleshooting_runbook()
        
        return runbooks
    
    def _format_runbook(self, runbook: Runbook) -> str:
        """Format runbook to markdown"""
        
        procedure_steps = "\n\n".join([
            f"### Step {i+1}: {step['title']}\n\n{step['description']}\n\n```bash\n{step.get('command', '# No command')}\n```"
            for i, step in enumerate(runbook.procedure_steps)
        ])
        
        rollback_steps = "\n\n".join([
            f"### Step {i+1}: {step['title']}\n\n{step['description']}\n\n```bash\n{step.get('command', '# No command')}\n```"
            for i, step in enumerate(runbook.rollback_steps)
        ])
        
        verification = "\n".join([f"- [ ] {v}" for v in runbook.verification_steps])
        
        troubleshooting = "\n\n".join([
            f"### {t['issue']}\n\n**Cause:** {t['cause']}\n\n**Resolution:** {t['resolution']}"
            for t in runbook.troubleshooting
        ])
        
        contacts = "\n".join([f"- **{k}**: {v}" for k, v in runbook.contacts.items()])
        
        related = "\n".join([f"- {d}" for d in runbook.related_docs])
        
        return RUNBOOK_TEMPLATE.format(
            title=runbook.title,
            overview=runbook.overview,
            prerequisites="\n".join([f"- {p}" for p in runbook.prerequisites]),
            procedure_steps=procedure_steps,
            rollback_steps=rollback_steps,
            verification_steps=verification,
            troubleshooting=troubleshooting,
            contacts=contacts,
            related_docs=related or "None",
            date=datetime.now().strftime("%Y-%m-%d"),
            owner=runbook.owner,
            review_cycle=runbook.review_cycle
        )
    
    def _generate_node_scaling_runbook(self) -> str:
        """Generate node scaling runbook"""
        
        runbook = Runbook(
            title=f"Node Scaling - {self.cluster_name}",
            overview=f"""
This runbook covers procedures for scaling EKS node groups in the {self.cluster_name} cluster.
It includes both manual scaling operations and troubleshooting Karpenter autoscaling.
""",
            prerequisites=[
                "kubectl configured for the cluster",
                "AWS CLI with appropriate IAM permissions",
                "Access to AWS Console (optional)",
                "Understanding of current workload requirements"
            ],
            procedure_steps=[
                {
                    "title": "Check Current Node Status",
                    "description": "Verify current node count and utilization before scaling.",
                    "command": f"""kubectl get nodes -o wide
kubectl top nodes
kubectl describe nodes | grep -A 5 "Allocated resources"
"""
                },
                {
                    "title": "Scale Node Group (Manual)",
                    "description": "Scale the managed node group to desired size.",
                    "command": f"""# Using AWS CLI
aws eks update-nodegroup-config \\
  --cluster-name {self.cluster_name} \\
  --nodegroup-name <nodegroup-name> \\
  --scaling-config desiredSize=<desired>,minSize=<min>,maxSize=<max>

# Verify scaling
aws eks describe-nodegroup \\
  --cluster-name {self.cluster_name} \\
  --nodegroup-name <nodegroup-name> \\
  --query 'nodegroup.scalingConfig'
"""
                },
                {
                    "title": "Verify Karpenter Provisioning",
                    "description": "If using Karpenter, verify provisioner status.",
                    "command": """# Check Karpenter logs
kubectl logs -n karpenter -l app.kubernetes.io/name=karpenter -c controller --tail=100

# Check NodePool status
kubectl get nodepools
kubectl describe nodepool default

# Check pending pods
kubectl get pods --all-namespaces --field-selector=status.phase=Pending
"""
                },
                {
                    "title": "Verify Node Health",
                    "description": "Ensure new nodes are healthy and ready.",
                    "command": """# Wait for nodes to be ready
kubectl wait --for=condition=Ready nodes --all --timeout=300s

# Check node conditions
kubectl get nodes -o custom-columns=NAME:.metadata.name,STATUS:.status.conditions[-1].type,READY:.status.conditions[-1].status
"""
                }
            ],
            rollback_steps=[
                {
                    "title": "Scale Down if Needed",
                    "description": "Reduce node count if scaling caused issues.",
                    "command": f"""aws eks update-nodegroup-config \\
  --cluster-name {self.cluster_name} \\
  --nodegroup-name <nodegroup-name> \\
  --scaling-config desiredSize=<previous-size>
"""
                },
                {
                    "title": "Drain Problematic Nodes",
                    "description": "Safely drain nodes before removal.",
                    "command": """kubectl drain <node-name> --ignore-daemonsets --delete-emptydir-data
kubectl delete node <node-name>
"""
                }
            ],
            verification_steps=[
                "All nodes showing Ready status",
                "Pod scheduling working correctly",
                "No pending pods due to resource constraints",
                "Monitoring showing expected resource utilization",
                "No errors in Karpenter logs"
            ],
            troubleshooting=[
                {
                    "issue": "Nodes stuck in NotReady state",
                    "cause": "Node failing health checks or unable to join cluster",
                    "resolution": "Check node logs via SSM, verify security groups, check VPC CNI"
                },
                {
                    "issue": "Karpenter not provisioning nodes",
                    "cause": "NodePool constraints, IAM permissions, or capacity issues",
                    "resolution": "Check Karpenter logs, verify NodePool requirements match pod requests"
                },
                {
                    "issue": "Pods not scheduling on new nodes",
                    "cause": "Taints, node selectors, or affinity rules",
                    "resolution": "Check pod spec for node requirements, verify node labels"
                }
            ],
            contacts={
                "Platform Team": "#platform-support",
                "On-Call": "Check PagerDuty",
                "AWS Support": "Open support case if needed"
            },
            related_docs=[
                "cluster-upgrade.md",
                "troubleshooting.md"
            ]
        )
        
        return self._format_runbook(runbook)
    
    def _generate_cluster_upgrade_runbook(self) -> str:
        """Generate cluster upgrade runbook"""
        
        runbook = Runbook(
            title=f"EKS Cluster Upgrade - {self.cluster_name}",
            overview=f"""
This runbook covers the procedure for upgrading the {self.cluster_name} EKS cluster
to a new Kubernetes version. This includes control plane upgrade, add-on updates,
and node group upgrades.
""",
            prerequisites=[
                "Review Kubernetes changelog for breaking changes",
                "Test upgrade in non-production environment",
                "Verify add-on compatibility with target version",
                "Schedule maintenance window",
                "Notify stakeholders",
                "Ensure rollback plan is ready"
            ],
            procedure_steps=[
                {
                    "title": "Pre-Upgrade Checks",
                    "description": "Verify cluster health and compatibility before upgrade.",
                    "command": f"""# Check current versions
kubectl version --short
aws eks describe-cluster --name {self.cluster_name} --query 'cluster.version'

# Check deprecation warnings
kubectl get --raw /metrics | grep apiserver_requested_deprecated_apis

# Verify all nodes are healthy
kubectl get nodes
kubectl get pods --all-namespaces | grep -v Running | grep -v Completed
"""
                },
                {
                    "title": "Backup Critical Resources",
                    "description": "Create backups of critical cluster resources.",
                    "command": """# Backup all resources
kubectl get all --all-namespaces -o yaml > cluster-backup.yaml

# Backup specific CRDs
kubectl get crd -o yaml > crd-backup.yaml

# Backup RBAC
kubectl get clusterroles,clusterrolebindings -o yaml > rbac-backup.yaml
"""
                },
                {
                    "title": "Upgrade Control Plane",
                    "description": "Upgrade the EKS control plane to target version.",
                    "command": f"""# Start control plane upgrade
aws eks update-cluster-version \\
  --name {self.cluster_name} \\
  --kubernetes-version <target-version>

# Monitor upgrade progress (takes 20-40 minutes)
aws eks describe-update \\
  --name {self.cluster_name} \\
  --update-id <update-id>

# Or watch status
watch -n 30 "aws eks describe-cluster --name {self.cluster_name} --query 'cluster.[version,status]'"
"""
                },
                {
                    "title": "Update Add-ons",
                    "description": "Update EKS managed add-ons to compatible versions.",
                    "command": f"""# List current add-on versions
aws eks describe-addon --cluster-name {self.cluster_name} --addon-name vpc-cni
aws eks describe-addon --cluster-name {self.cluster_name} --addon-name coredns
aws eks describe-addon --cluster-name {self.cluster_name} --addon-name kube-proxy

# Update each add-on
aws eks update-addon \\
  --cluster-name {self.cluster_name} \\
  --addon-name vpc-cni \\
  --resolve-conflicts OVERWRITE

aws eks update-addon \\
  --cluster-name {self.cluster_name} \\
  --addon-name coredns \\
  --resolve-conflicts OVERWRITE

aws eks update-addon \\
  --cluster-name {self.cluster_name} \\
  --addon-name kube-proxy \\
  --resolve-conflicts OVERWRITE
"""
                },
                {
                    "title": "Upgrade Node Groups",
                    "description": "Upgrade managed node groups to match control plane version.",
                    "command": f"""# Update node group
aws eks update-nodegroup-version \\
  --cluster-name {self.cluster_name} \\
  --nodegroup-name <nodegroup-name>

# Monitor progress
aws eks describe-nodegroup \\
  --cluster-name {self.cluster_name} \\
  --nodegroup-name <nodegroup-name> \\
  --query 'nodegroup.updateConfig'
"""
                },
                {
                    "title": "Post-Upgrade Verification",
                    "description": "Verify cluster health after upgrade.",
                    "command": """# Verify versions
kubectl version --short

# Check all components
kubectl get nodes
kubectl get pods --all-namespaces
kubectl get componentstatuses

# Run smoke tests
kubectl run test-pod --image=nginx --restart=Never
kubectl delete pod test-pod
"""
                }
            ],
            rollback_steps=[
                {
                    "title": "Node Group Rollback",
                    "description": "Note: Control plane cannot be rolled back. For node issues, create new node group with previous AMI.",
                    "command": """# Create new node group with previous version AMI
# Then drain and delete problematic nodes
kubectl drain <node-name> --ignore-daemonsets
kubectl delete node <node-name>
"""
                }
            ],
            verification_steps=[
                "Control plane version matches target",
                "All add-ons updated and healthy",
                "All nodes running target version",
                "No deprecated API usage warnings",
                "Workloads running normally",
                "Monitoring and alerting functional"
            ],
            troubleshooting=[
                {
                    "issue": "Control plane upgrade stuck",
                    "cause": "AWS service issues or configuration problems",
                    "resolution": "Check AWS service health, review CloudTrail for errors"
                },
                {
                    "issue": "Node upgrade failing",
                    "cause": "PDB blocking node drain or AMI issues",
                    "resolution": "Check PDBs, verify AMI availability, check node group IAM role"
                },
                {
                    "issue": "Pods failing after upgrade",
                    "cause": "API deprecation or compatibility issues",
                    "resolution": "Check pod logs, verify API versions in manifests"
                }
            ],
            contacts={
                "Platform Team": "#platform-support",
                "On-Call": "Check PagerDuty",
                "AWS Support": "Open support case for upgrade issues"
            }
        )
        
        return self._format_runbook(runbook)
    
    def _generate_incident_response_runbook(self) -> str:
        """Generate incident response runbook"""
        
        runbook = Runbook(
            title=f"Incident Response - {self.cluster_name}",
            overview=f"""
This runbook provides guidance for responding to incidents affecting the {self.cluster_name}
EKS cluster. It covers initial triage, communication, and resolution procedures.
""",
            prerequisites=[
                "Access to cluster via kubectl",
                "Access to monitoring dashboards",
                "Incident management tool access",
                "Communication channel access"
            ],
            procedure_steps=[
                {
                    "title": "Initial Assessment",
                    "description": "Quickly assess the scope and impact of the incident.",
                    "command": f"""# Check cluster health
kubectl get nodes
kubectl get pods --all-namespaces | grep -v Running | grep -v Completed

# Check recent events
kubectl get events --all-namespaces --sort-by='.lastTimestamp' | tail -50

# Check system pods
kubectl get pods -n kube-system

# Check resource usage
kubectl top nodes
kubectl top pods --all-namespaces --sort-by=memory | head -20
"""
                },
                {
                    "title": "Declare Incident",
                    "description": "Formally declare the incident and begin communication.",
                    "command": """# No command - manual steps:
# 1. Create incident in PagerDuty/ServiceNow
# 2. Open dedicated Slack channel: #incident-YYYYMMDD-brief-description
# 3. Post initial status update
# 4. Assign Incident Commander if severity warrants
"""
                },
                {
                    "title": "Gather Diagnostics",
                    "description": "Collect detailed diagnostic information.",
                    "command": """# Collect logs from affected pods
kubectl logs <pod-name> -n <namespace> --tail=500

# Get pod details
kubectl describe pod <pod-name> -n <namespace>

# Check node conditions
kubectl describe node <node-name>

# Export cluster state
kubectl cluster-info dump --output-directory=./incident-dump
"""
                },
                {
                    "title": "Implement Mitigation",
                    "description": "Take action to reduce impact while investigating root cause.",
                    "command": """# Scale up if capacity issue
kubectl scale deployment <deployment> --replicas=<count> -n <namespace>

# Restart problematic pods
kubectl rollout restart deployment <deployment> -n <namespace>

# Cordon problematic node
kubectl cordon <node-name>

# Enable emergency access if needed
# (Follow break-glass procedures)
"""
                },
                {
                    "title": "Resolution and Recovery",
                    "description": "Implement fix and verify recovery.",
                    "command": """# Apply fix (depends on issue)
kubectl apply -f fix.yaml

# Verify recovery
kubectl get pods -n <namespace>
kubectl logs <pod-name> -n <namespace> --tail=50

# Uncordon nodes if applicable
kubectl uncordon <node-name>
"""
                },
                {
                    "title": "Post-Incident",
                    "description": "Document and learn from the incident.",
                    "command": """# No command - manual steps:
# 1. Update incident ticket with resolution
# 2. Send final status to stakeholders
# 3. Schedule post-mortem within 48 hours
# 4. Document timeline and actions taken
# 5. Identify action items to prevent recurrence
"""
                }
            ],
            rollback_steps=[
                {
                    "title": "Revert Recent Changes",
                    "description": "Roll back recent deployments if they caused the issue.",
                    "command": """kubectl rollout undo deployment <deployment> -n <namespace>
kubectl rollout status deployment <deployment> -n <namespace>
"""
                }
            ],
            verification_steps=[
                "All affected services restored",
                "Error rates returned to baseline",
                "No pending alerts",
                "Stakeholders notified of resolution",
                "Incident ticket updated"
            ],
            troubleshooting=[
                {
                    "issue": "Cannot access cluster",
                    "cause": "API server issues, network problems, or credential issues",
                    "resolution": "Check AWS EKS console, verify VPN/network, refresh credentials"
                },
                {
                    "issue": "Pods in CrashLoopBackOff",
                    "cause": "Application error, resource issues, or dependency failure",
                    "resolution": "Check pod logs, describe pod for events, verify configmaps/secrets"
                },
                {
                    "issue": "Nodes NotReady",
                    "cause": "Node health issues, network problems, or resource exhaustion",
                    "resolution": "Check node conditions, review kubelet logs via SSM"
                }
            ],
            contacts={
                "Incident Commander": "Assigned per incident",
                "Platform Team": "#platform-support",
                "On-Call": "Check PagerDuty rotation",
                "Security Team": "#security-incidents (if security-related)",
                "Management": "Escalate P1/P2 to management"
            }
        )
        
        return self._format_runbook(runbook)
    
    def _generate_disaster_recovery_runbook(self) -> str:
        """Generate disaster recovery runbook"""
        
        runbook = Runbook(
            title=f"Disaster Recovery - {self.cluster_name}",
            overview=f"""
This runbook covers disaster recovery procedures for the {self.cluster_name} EKS cluster.
It includes procedures for various disaster scenarios and recovery steps.
""",
            prerequisites=[
                "Backup infrastructure in secondary region",
                "Latest cluster configuration backups",
                "Access to Terraform/IaC repository",
                "DNS management access",
                "Database backup access"
            ],
            procedure_steps=[
                {
                    "title": "Assess Disaster Scope",
                    "description": "Determine the extent of the disaster and recovery needs.",
                    "command": """# Check primary region status
aws eks describe-cluster --name cluster-name --region primary-region

# Check AWS service health
# https://health.aws.amazon.com/

# Verify backup status
aws s3 ls s3://backup-bucket/eks-backups/
"""
                },
                {
                    "title": "Activate DR Plan",
                    "description": "Formally activate disaster recovery procedures.",
                    "command": """# No command - manual steps:
# 1. Convene DR team
# 2. Declare DR activation
# 3. Notify stakeholders
# 4. Begin recovery procedures
"""
                },
                {
                    "title": "Deploy Infrastructure in DR Region",
                    "description": "Provision EKS cluster in DR region using IaC.",
                    "command": """# Navigate to IaC repository
cd terraform/dr-region

# Initialize and apply
terraform init
terraform plan -var-file=dr.tfvars
terraform apply -var-file=dr.tfvars -auto-approve

# Configure kubectl
aws eks update-kubeconfig --name dr-cluster --region dr-region
"""
                },
                {
                    "title": "Restore Applications",
                    "description": "Deploy applications to DR cluster.",
                    "command": """# Using GitOps (ArgoCD)
kubectl apply -f argocd-apps/dr-config.yaml

# Or manual deployment
kubectl apply -k environments/dr/

# Verify deployments
kubectl get pods --all-namespaces
"""
                },
                {
                    "title": "Restore Data",
                    "description": "Restore databases and persistent data from backups.",
                    "command": """# Restore RDS from snapshot
aws rds restore-db-instance-from-db-snapshot \\
  --db-instance-identifier dr-database \\
  --db-snapshot-identifier latest-snapshot

# Restore persistent volumes
# (Depends on storage solution - EBS snapshots, etc.)
"""
                },
                {
                    "title": "Update DNS/Traffic",
                    "description": "Route traffic to DR environment.",
                    "command": """# Update Route53 records
aws route53 change-resource-record-sets \\
  --hosted-zone-id ZONE_ID \\
  --change-batch file://dr-dns-changes.json

# Verify DNS propagation
dig +short app.example.com
"""
                }
            ],
            rollback_steps=[
                {
                    "title": "Failback to Primary",
                    "description": "Return to primary region when recovered.",
                    "command": """# Verify primary region is healthy
# Sync any data changes from DR
# Gradually shift traffic back
# Update DNS to primary
# Decommission DR resources (if temporary)
"""
                }
            ],
            verification_steps=[
                "DR cluster is operational",
                "All critical applications running",
                "Data restored and consistent",
                "DNS routing to DR environment",
                "Monitoring and alerting functional",
                "Stakeholders notified of DR status"
            ],
            troubleshooting=[
                {
                    "issue": "DR cluster creation failing",
                    "cause": "Resource limits, IAM issues, or region capacity",
                    "resolution": "Check AWS limits, verify IAM roles, try alternative instance types"
                },
                {
                    "issue": "Data inconsistency after restore",
                    "cause": "Backup timing or replication lag",
                    "resolution": "Verify backup timestamps, check replication status, consider point-in-time recovery"
                }
            ],
            contacts={
                "DR Coordinator": "Assigned during DR activation",
                "Platform Team": "#platform-support",
                "Database Team": "#database-support",
                "Management": "Executive escalation"
            }
        )
        
        return self._format_runbook(runbook)
    
    def _generate_cert_rotation_runbook(self) -> str:
        """Generate certificate rotation runbook"""
        
        runbook = Runbook(
            title=f"Certificate Rotation - {self.cluster_name}",
            overview=f"""
This runbook covers procedures for rotating certificates in the {self.cluster_name} cluster,
including TLS certificates managed by cert-manager and cluster certificates.
""",
            prerequisites=[
                "cert-manager installed and configured",
                "Access to DNS for validation",
                "Understanding of certificate dependencies"
            ],
            procedure_steps=[
                {
                    "title": "Check Certificate Status",
                    "description": "Review current certificate status and expiration.",
                    "command": """# List all certificates
kubectl get certificates --all-namespaces

# Check certificate details
kubectl describe certificate <cert-name> -n <namespace>

# Check secrets
kubectl get secrets --all-namespaces | grep tls
"""
                },
                {
                    "title": "Trigger Certificate Renewal",
                    "description": "Force renewal of certificates if needed.",
                    "command": """# Delete certificate secret to trigger renewal
kubectl delete secret <tls-secret-name> -n <namespace>

# cert-manager will automatically recreate

# Or use cmctl
cmctl renew <certificate-name> -n <namespace>
"""
                },
                {
                    "title": "Verify New Certificates",
                    "description": "Confirm certificates have been renewed.",
                    "command": """# Check certificate status
kubectl get certificate <cert-name> -n <namespace>

# Verify secret updated
kubectl get secret <tls-secret-name> -n <namespace> -o yaml

# Check expiration
kubectl get secret <tls-secret-name> -n <namespace> -o jsonpath='{.data.tls\\.crt}' | base64 -d | openssl x509 -noout -dates
"""
                }
            ],
            rollback_steps=[
                {
                    "title": "Restore Previous Certificate",
                    "description": "Restore from backup if new certificate causes issues.",
                    "command": """# Apply backed up secret
kubectl apply -f tls-secret-backup.yaml
"""
                }
            ],
            verification_steps=[
                "New certificate is valid",
                "Certificate not expired",
                "Applications using new certificate",
                "No TLS errors in logs"
            ],
            troubleshooting=[
                {
                    "issue": "Certificate not renewing",
                    "cause": "DNS challenge failing or issuer misconfigured",
                    "resolution": "Check cert-manager logs, verify DNS configuration, check issuer status"
                }
            ],
            contacts={
                "Platform Team": "#platform-support",
                "Security Team": "#security"
            }
        )
        
        return self._format_runbook(runbook)
    
    def _generate_troubleshooting_runbook(self) -> str:
        """Generate general troubleshooting runbook"""
        
        return f"""# Troubleshooting Guide - {self.cluster_name}

## Quick Diagnostics

### Cluster Health Check
```bash
# Overall cluster status
kubectl cluster-info
kubectl get nodes -o wide
kubectl get pods --all-namespaces | grep -v Running | grep -v Completed

# Component status
kubectl get componentstatuses
kubectl get pods -n kube-system
```

### Node Troubleshooting
```bash
# Node status
kubectl describe node <node-name>

# Node resource usage
kubectl top nodes

# Node events
kubectl get events --field-selector involvedObject.kind=Node

# Access node via SSM
aws ssm start-session --target <instance-id>
```

### Pod Troubleshooting
```bash
# Pod status
kubectl describe pod <pod-name> -n <namespace>

# Pod logs
kubectl logs <pod-name> -n <namespace> --tail=100
kubectl logs <pod-name> -n <namespace> --previous  # Previous container

# Execute into pod
kubectl exec -it <pod-name> -n <namespace> -- /bin/sh

# Pod resource usage
kubectl top pods -n <namespace>
```

### Networking Troubleshooting
```bash
# DNS resolution
kubectl run test-dns --image=busybox --restart=Never -- nslookup kubernetes.default
kubectl logs test-dns
kubectl delete pod test-dns

# Network connectivity
kubectl run test-net --image=nicolaka/netshoot --restart=Never -it -- bash
# Inside container: curl, ping, dig, traceroute

# Service endpoints
kubectl get endpoints <service-name> -n <namespace>
```

### Storage Troubleshooting
```bash
# PVC status
kubectl get pvc --all-namespaces

# PV status
kubectl get pv

# Storage class
kubectl get storageclass
```

## Common Issues

### Issue: Pods Stuck in Pending
**Symptoms:** Pods not scheduling

**Diagnosis:**
```bash
kubectl describe pod <pod-name> -n <namespace> | grep -A 10 Events
```

**Common Causes:**
- Insufficient resources → Scale nodes or adjust requests
- Node selectors not matching → Check node labels
- Taints preventing scheduling → Check tolerations
- PVC not bound → Check storage class and PV availability

### Issue: Pods in CrashLoopBackOff
**Symptoms:** Container continuously restarting

**Diagnosis:**
```bash
kubectl logs <pod-name> -n <namespace> --previous
kubectl describe pod <pod-name> -n <namespace>
```

**Common Causes:**
- Application error → Check logs for stack traces
- Missing configuration → Verify ConfigMaps/Secrets exist
- Resource limits too low → Increase limits
- Liveness probe failing → Adjust probe settings

### Issue: Service Not Accessible
**Symptoms:** Cannot reach service

**Diagnosis:**
```bash
kubectl get svc <service-name> -n <namespace>
kubectl get endpoints <service-name> -n <namespace>
kubectl describe ingress <ingress-name> -n <namespace>
```

**Common Causes:**
- No endpoints → Check pod labels match service selector
- Ingress misconfigured → Verify ALB/NLB settings
- Security group blocking → Check node security groups
- Network policy blocking → Review NetworkPolicy rules

### Issue: High Memory/CPU Usage
**Symptoms:** Node or pod resource exhaustion

**Diagnosis:**
```bash
kubectl top nodes
kubectl top pods --all-namespaces --sort-by=memory
kubectl describe node <node-name> | grep -A 5 "Allocated resources"
```

**Resolution:**
- Identify resource-heavy pods
- Adjust resource limits
- Scale horizontally
- Add nodes to cluster

## Emergency Procedures

### Cordon Node (Stop Scheduling)
```bash
kubectl cordon <node-name>
```

### Drain Node (Evacuate Pods)
```bash
kubectl drain <node-name> --ignore-daemonsets --delete-emptydir-data
```

### Force Delete Pod
```bash
kubectl delete pod <pod-name> -n <namespace> --force --grace-period=0
```

### Scale to Zero (Emergency Stop)
```bash
kubectl scale deployment <deployment> --replicas=0 -n <namespace>
```

---
*Last Updated: {datetime.now().strftime("%Y-%m-%d")}*
"""


# ============================================================================
# ARCHITECTURE DOCUMENTATION GENERATOR
# ============================================================================

class ArchitectureDocGenerator:
    """
    Generates comprehensive architecture documentation.
    """
    
    def __init__(self, cluster_config: Dict):
        self.config = cluster_config
        self.cluster_name = cluster_config.get("cluster_name", "eks-cluster")
    
    def generate_architecture_document(self) -> str:
        """Generate complete architecture document"""
        
        return ARCHITECTURE_DOC_TEMPLATE.format(
            cluster_name=self.cluster_name,
            executive_summary=self._generate_executive_summary(),
            cluster_config=self._generate_cluster_config_section(),
            network_architecture=self._generate_network_section(),
            security_architecture=self._generate_security_section(),
            node_configuration=self._generate_node_section(),
            eks_details=self._generate_eks_details(),
            networking_details=self._generate_networking_details(),
            storage_details=self._generate_storage_details(),
            observability_details=self._generate_observability_details(),
            security_controls=self._generate_security_controls(),
            scaling_procedures=self._generate_scaling_procedures(),
            backup_procedures=self._generate_backup_procedures(),
            incident_response=self._generate_incident_response(),
            cost_management=self._generate_cost_management(),
            compliance_governance=self._generate_compliance_governance(),
            config_files="See attached configuration files",
            iam_policies="See IAM policy documentation",
            network_diagrams="See network diagram attachments",
            version="1.0",
            date=datetime.now().strftime("%Y-%m-%d"),
            classification="Internal"
        )
    
    def _generate_executive_summary(self) -> str:
        """Generate executive summary"""
        
        region = self.config.get("region", "us-east-1")
        k8s_version = self.config.get("kubernetes_version", "1.29")
        node_groups = self.config.get("node_groups", [])
        
        return f"""
This document describes the architecture of the **{self.cluster_name}** Amazon EKS cluster
deployed in the **{region}** region running Kubernetes version **{k8s_version}**.

**Key Highlights:**
- Managed Kubernetes control plane with high availability
- {len(node_groups)} node group(s) for workload isolation
- Private networking with VPC endpoints
- Comprehensive observability stack
- GitOps-based deployment workflow
- Enterprise security controls
"""
    
    def _generate_cluster_config_section(self) -> str:
        """Generate cluster configuration section"""
        
        return f"""
| Parameter | Value |
|-----------|-------|
| Cluster Name | {self.cluster_name} |
| Kubernetes Version | {self.config.get('kubernetes_version', '1.29')} |
| Region | {self.config.get('region', 'us-east-1')} |
| Environment | {self.config.get('environment', 'production')} |
"""
    
    def _generate_network_section(self) -> str:
        """Generate network architecture section"""
        
        network = self.config.get("network", {})
        
        return f"""
The cluster uses a dedicated VPC with the following configuration:

- **VPC CIDR**: {network.get('vpc_cidr', '10.0.0.0/16')}
- **Availability Zones**: {network.get('availability_zones', 3)}
- **Subnet Types**: Public, Private, Intra
- **NAT Gateways**: One per AZ (production) or single (non-prod)
- **VPC Endpoints**: S3, ECR, STS, CloudWatch Logs, SSM
"""
    
    def _generate_security_section(self) -> str:
        """Generate security architecture section"""
        
        security = self.config.get("security", {})
        
        return f"""
Security is implemented at multiple layers:

- **API Endpoint**: {'Private only' if security.get('private_endpoint') else 'Public and Private'}
- **Secrets Encryption**: {'Enabled with KMS' if security.get('enable_secrets_encryption') else 'Disabled'}
- **Pod Security Standards**: {security.get('pod_security_level', 'baseline')}
- **Network Policies**: {'Enabled' if security.get('enable_network_policies') else 'Disabled'}
- **Audit Logging**: {'Enabled' if security.get('enable_audit_logging') else 'Disabled'}
"""
    
    def _generate_node_section(self) -> str:
        """Generate node configuration section"""
        
        node_groups = self.config.get("node_groups", [])
        
        rows = []
        for ng in node_groups:
            rows.append(
                f"| {ng.get('name', 'default')} | "
                f"{ng.get('instance_types', ['m6i.xlarge'])[0]} | "
                f"{ng.get('capacity_type', 'ON_DEMAND')} | "
                f"{ng.get('min_size', 1)}-{ng.get('max_size', 10)} |"
            )
        
        return f"""
| Node Group | Instance Type | Capacity | Size Range |
|------------|---------------|----------|------------|
{chr(10).join(rows)}
"""
    
    def _generate_eks_details(self) -> str:
        return "See EKS Cluster Configuration section above."
    
    def _generate_networking_details(self) -> str:
        return "See Network Architecture section above."
    
    def _generate_storage_details(self) -> str:
        return """
**Storage Classes:**
- gp3 (default): General purpose SSD
- gp3-encrypted: Encrypted general purpose SSD
- io2: High performance SSD for databases

**CSI Drivers:**
- EBS CSI Driver: For block storage
- EFS CSI Driver: For shared file storage (if enabled)
"""
    
    def _generate_observability_details(self) -> str:
        obs = self.config.get("observability", {})
        
        return f"""
**Metrics:**
- Prometheus: {'Enabled' if obs.get('enable_prometheus') else 'Disabled'}
- Grafana: {'Enabled' if obs.get('enable_grafana') else 'Disabled'}
- Container Insights: {'Enabled' if obs.get('enable_container_insights') else 'Disabled'}

**Logging:**
- Collection: {obs.get('logging_solution', 'fluent-bit')}
- Destination: {obs.get('log_destination', 'cloudwatch')}

**Tracing:**
- Solution: {obs.get('tracing_solution', 'xray')}
"""
    
    def _generate_security_controls(self) -> str:
        return """
**Network Security:**
- VPC isolation with private subnets
- Security groups for node and pod traffic
- Network policies for pod-to-pod traffic

**Identity & Access:**
- IAM roles for service accounts (IRSA)
- Kubernetes RBAC for authorization
- OIDC provider for federated authentication

**Data Protection:**
- EBS encryption at rest
- Secrets encryption with KMS
- TLS for all network traffic
"""
    
    def _generate_scaling_procedures(self) -> str:
        return """
**Horizontal Pod Autoscaling (HPA):**
- CPU-based scaling at 70% utilization
- Memory-based scaling at 80% utilization

**Node Autoscaling:**
- Karpenter for just-in-time provisioning
- Automatic instance type selection
- Consolidation of underutilized nodes

See `runbooks/node-scaling.md` for detailed procedures.
"""
    
    def _generate_backup_procedures(self) -> str:
        return """
**Cluster State:**
- etcd backups managed by EKS
- Configuration stored in Git (GitOps)

**Application Data:**
- EBS snapshots for persistent volumes
- Database backups per application requirements

**Disaster Recovery:**
- Infrastructure as Code for cluster recreation
- Cross-region backup replication
- DR runbook: `runbooks/disaster-recovery.md`
"""
    
    def _generate_incident_response(self) -> str:
        return """
**Incident Classification:**
- P1: Complete service outage
- P2: Partial service degradation
- P3: Minor issues, no user impact
- P4: Informational/low priority

**Response Procedures:**
See `runbooks/incident-response.md` for detailed procedures.

**Escalation:**
- P1/P2: Immediate escalation to on-call
- P3: Next business day
- P4: Standard ticket queue
"""
    
    def _generate_cost_management(self) -> str:
        return """
**Cost Optimization Strategies:**
- Spot instances for fault-tolerant workloads
- Karpenter for efficient bin-packing
- Reserved capacity for baseline usage

**Cost Allocation:**
- Kubecost for visibility
- Tags: Environment, Team, Project, CostCenter

**Monthly Review:**
- Cost trend analysis
- Optimization recommendations
- Budget vs. actual tracking
"""
    
    def _generate_compliance_governance(self) -> str:
        compliance = self.config.get("security", {}).get("compliance_frameworks", [])
        
        return f"""
**Compliance Frameworks:**
{chr(10).join(f'- {c.upper().replace("_", "-")}' for c in compliance) if compliance else '- None specified'}

**Governance Controls:**
- Policy as Code (Kyverno/OPA)
- Automated compliance scanning
- Change management via GitOps
- Audit logging and retention
"""
