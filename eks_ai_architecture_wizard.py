"""
EKS AI-Enhanced Architecture Design Wizard v2.0
Enterprise-grade Kubernetes architecture design with AI-powered recommendations

This module provides:
- Natural Language Requirements Gathering (Claude AI)
- Intelligent Workload Analysis and Sizing
- Enterprise Architecture Patterns
- Security and Compliance Framework
- GitOps Configuration Generator
- FinOps Cost Optimization
- Migration Planning
- Documentation Generation

Author: Infosys Cloud Architecture Team
Version: 2.0.0
"""

import streamlit as st
import json
import yaml
import os
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum
import hashlib
import re

# ============================================================================
# ENUMS AND CONSTANTS
# ============================================================================

class ClusterTopology(Enum):
    """EKS Cluster Topology Patterns"""
    SINGLE_CLUSTER = "single_cluster"
    HUB_SPOKE = "hub_spoke"
    FEDERATED = "federated"
    CLUSTER_PER_TEAM = "cluster_per_team"
    CLUSTER_PER_ENV = "cluster_per_environment"

class WorkloadType(Enum):
    """Workload Classification"""
    MICROSERVICES = "microservices"
    MONOLITH = "monolith"
    BATCH_PROCESSING = "batch_processing"
    ML_INFERENCE = "ml_inference"
    ML_TRAINING = "ml_training"
    STREAMING = "streaming"
    STATEFUL = "stateful"
    SERVERLESS_HYBRID = "serverless_hybrid"

class ComplianceFramework(Enum):
    """Supported Compliance Frameworks"""
    PCI_DSS = "pci_dss"
    HIPAA = "hipaa"
    SOC2 = "soc2"
    ISO_27001 = "iso_27001"
    GDPR = "gdpr"
    FEDRAMP = "fedramp"
    NIST = "nist"

class SecurityLevel(Enum):
    """Security Posture Levels"""
    BASIC = "basic"
    STANDARD = "standard"
    ENHANCED = "enhanced"
    MAXIMUM = "maximum"

class AvailabilityTier(Enum):
    """Availability Requirements"""
    DEVELOPMENT = "99.0%"
    STANDARD = "99.9%"
    HIGH = "99.95%"
    CRITICAL = "99.99%"
    MISSION_CRITICAL = "99.999%"

# Instance type categories for different workloads
INSTANCE_CATEGORIES = {
    "general_purpose": ["m6i", "m6a", "m7i", "m7a", "m5", "m5a"],
    "compute_optimized": ["c6i", "c6a", "c7i", "c7a", "c5", "c5a"],
    "memory_optimized": ["r6i", "r6a", "r7i", "r7a", "r5", "r5a"],
    "storage_optimized": ["i3", "i3en", "d2", "d3", "i4i"],
    "gpu": ["p4d", "p4de", "p3", "g5", "g4dn", "inf1", "inf2"],
    "arm_based": ["m6g", "m7g", "c6g", "c7g", "r6g", "r7g", "t4g"],
}

# Kubernetes add-ons and their categories
EKS_ADDONS = {
    "core": {
        "vpc-cni": {"description": "Amazon VPC CNI for pod networking", "required": True},
        "coredns": {"description": "DNS service discovery", "required": True},
        "kube-proxy": {"description": "Network proxy", "required": True},
    },
    "security": {
        "aws-guardduty-agent": {"description": "Runtime threat detection", "required": False},
        "amazon-cloudwatch-observability": {"description": "Container insights", "required": False},
    },
    "storage": {
        "aws-ebs-csi-driver": {"description": "EBS persistent volumes", "required": False},
        "aws-efs-csi-driver": {"description": "EFS shared storage", "required": False},
        "aws-fsx-csi-driver": {"description": "FSx for Lustre/Windows", "required": False},
    },
    "networking": {
        "aws-load-balancer-controller": {"description": "ALB/NLB integration", "required": False},
    },
}

# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class WorkloadRequirement:
    """Individual workload specification"""
    name: str
    workload_type: WorkloadType
    replicas: int
    cpu_request: str
    memory_request: str
    cpu_limit: str
    memory_limit: str
    gpu_required: bool = False
    gpu_count: int = 0
    storage_required: bool = False
    storage_size_gb: int = 0
    storage_type: str = "gp3"
    stateful: bool = False
    spot_tolerant: bool = True
    priority: str = "medium"  # low, medium, high, critical
    scaling_min: int = 1
    scaling_max: int = 10
    hpa_cpu_threshold: int = 70
    hpa_memory_threshold: int = 80

@dataclass
class NetworkRequirement:
    """Network architecture requirements"""
    vpc_cidr: str = "10.0.0.0/16"
    pod_cidr: str = "10.244.0.0/16"
    service_cidr: str = "172.20.0.0/16"
    availability_zones: int = 3
    private_subnets: bool = True
    public_subnets: bool = True
    nat_gateways: int = 3
    vpc_endpoints: List[str] = field(default_factory=lambda: [
        "s3", "ecr.api", "ecr.dkr", "sts", "logs", "ec2", "autoscaling"
    ])
    enable_flow_logs: bool = True
    enable_dns_hostnames: bool = True
    enable_dns_support: bool = True

@dataclass
class SecurityRequirement:
    """Security configuration requirements"""
    security_level: SecurityLevel = SecurityLevel.STANDARD
    compliance_frameworks: List[ComplianceFramework] = field(default_factory=list)
    private_endpoint: bool = True
    public_endpoint: bool = False
    endpoint_whitelist: List[str] = field(default_factory=list)
    enable_secrets_encryption: bool = True
    kms_key_arn: str = ""
    enable_pod_security_standards: bool = True
    pod_security_level: str = "restricted"  # privileged, baseline, restricted
    enable_network_policies: bool = True
    network_policy_engine: str = "calico"  # calico, cilium
    enable_service_mesh: bool = False
    service_mesh_type: str = "istio"  # istio, linkerd, app-mesh
    enable_runtime_security: bool = True
    runtime_security_tool: str = "falco"  # falco, sysdig
    enable_image_scanning: bool = True
    enable_audit_logging: bool = True
    audit_log_retention_days: int = 90

@dataclass
class ObservabilityRequirement:
    """Observability stack requirements"""
    enable_container_insights: bool = True
    enable_prometheus: bool = True
    prometheus_retention_days: int = 15
    enable_grafana: bool = True
    enable_alertmanager: bool = True
    enable_logging: bool = True
    logging_solution: str = "fluent-bit"  # fluent-bit, fluentd
    log_destination: str = "cloudwatch"  # cloudwatch, opensearch, s3
    log_retention_days: int = 30
    enable_tracing: bool = True
    tracing_solution: str = "xray"  # xray, jaeger, tempo
    enable_service_mesh_observability: bool = False

@dataclass
class GitOpsRequirement:
    """GitOps configuration requirements"""
    enable_gitops: bool = True
    gitops_tool: str = "argocd"  # argocd, flux
    repository_type: str = "github"  # github, gitlab, codecommit
    branch_strategy: str = "gitflow"  # gitflow, trunk-based
    enable_progressive_delivery: bool = True
    progressive_delivery_tool: str = "argo-rollouts"  # argo-rollouts, flagger
    enable_image_automation: bool = True
    enable_policy_as_code: bool = True
    policy_engine: str = "kyverno"  # kyverno, opa-gatekeeper

@dataclass
class CostRequirement:
    """Cost optimization requirements"""
    budget_monthly_usd: float = 0
    enable_spot_instances: bool = True
    spot_percentage: int = 70
    enable_savings_plans: bool = True
    enable_reserved_instances: bool = False
    enable_karpenter: bool = True
    enable_cluster_autoscaler: bool = False
    consolidation_policy: str = "WhenUnderutilized"
    enable_kubecost: bool = True
    cost_allocation_tags: List[str] = field(default_factory=lambda: [
        "Environment", "Team", "Project", "CostCenter"
    ])

@dataclass
class EKSClusterConfig:
    """Complete EKS cluster configuration"""
    cluster_name: str
    kubernetes_version: str = "1.29"
    region: str = "us-east-1"
    topology: ClusterTopology = ClusterTopology.SINGLE_CLUSTER
    environment: str = "production"
    availability_tier: AvailabilityTier = AvailabilityTier.HIGH
    
    workloads: List[WorkloadRequirement] = field(default_factory=list)
    network: NetworkRequirement = field(default_factory=NetworkRequirement)
    security: SecurityRequirement = field(default_factory=SecurityRequirement)
    observability: ObservabilityRequirement = field(default_factory=ObservabilityRequirement)
    gitops: GitOpsRequirement = field(default_factory=GitOpsRequirement)
    cost: CostRequirement = field(default_factory=CostRequirement)
    
    node_groups: List[Dict] = field(default_factory=list)
    addons: List[str] = field(default_factory=list)
    
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    created_by: str = "EKS AI Wizard"
    version: str = "2.0"

# ============================================================================
# AI REQUIREMENTS ENGINE
# ============================================================================

class EKSAIRequirementsEngine:
    """
    AI-powered requirements gathering and analysis engine.
    Uses Claude AI to parse natural language requirements and generate
    comprehensive EKS configurations.
    """
    
    def __init__(self):
        self.anthropic_client = None
        self._init_ai_client()
        
    def _init_ai_client(self):
        """Initialize Anthropic client if API key available"""
        try:
            import anthropic
            api_key = os.getenv("ANTHROPIC_API_KEY") or st.secrets.get("ANTHROPIC_API_KEY", "")
            if api_key:
                self.anthropic_client = anthropic.Anthropic(api_key=api_key)
        except Exception as e:
            st.warning(f"AI features limited: {str(e)}")
    
    def parse_natural_language_requirements(self, user_input: str) -> Dict[str, Any]:
        """
        Parse natural language requirements into structured configuration.
        
        Example input:
        "I need to migrate 50 Java microservices to EKS. They handle 10,000 RPS
        with 99.99% uptime requirement. We're PCI-DSS compliant and need 
        multi-region DR. Budget is $50K/month."
        """
        
        if not self.anthropic_client:
            return self._fallback_parsing(user_input)
        
        system_prompt = """You are an expert AWS Solutions Architect specializing in EKS and Kubernetes.
        
Your task is to analyze natural language requirements and extract structured EKS configuration parameters.

Return a JSON object with the following structure:
{
    "cluster_name": "suggested-name",
    "workload_summary": {
        "type": "microservices|monolith|batch|ml",
        "count": number,
        "language_frameworks": ["java", "python", etc],
        "estimated_replicas": number
    },
    "performance": {
        "requests_per_second": number,
        "latency_requirement_ms": number,
        "availability_target": "99.9%|99.95%|99.99%|99.999%"
    },
    "compliance": ["pci_dss", "hipaa", "soc2", "iso_27001", "gdpr"],
    "architecture": {
        "multi_region": boolean,
        "disaster_recovery": boolean,
        "topology": "single_cluster|hub_spoke|federated"
    },
    "budget": {
        "monthly_usd": number,
        "optimize_for_cost": boolean
    },
    "special_requirements": ["gpu", "spot_instances", "arm_processors", etc],
    "recommended_instance_types": ["m6i.xlarge", etc],
    "recommended_node_count": {
        "minimum": number,
        "maximum": number
    },
    "ai_recommendations": [
        "recommendation 1",
        "recommendation 2"
    ]
}

Be specific and practical. If information is not provided, make reasonable enterprise assumptions."""

        try:
            response = self.anthropic_client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=4096,
                system=system_prompt,
                messages=[
                    {"role": "user", "content": f"Parse these EKS requirements:\n\n{user_input}"}
                ]
            )
            
            # Extract JSON from response
            response_text = response.content[0].text
            json_match = re.search(r'\{[\s\S]*\}', response_text)
            if json_match:
                return json.loads(json_match.group())
            
        except Exception as e:
            st.error(f"AI parsing error: {str(e)}")
        
        return self._fallback_parsing(user_input)
    
    def _fallback_parsing(self, user_input: str) -> Dict[str, Any]:
        """Fallback parsing when AI is unavailable"""
        parsed = {
            "cluster_name": "eks-cluster",
            "workload_summary": {"type": "microservices", "count": 10},
            "performance": {"availability_target": "99.9%"},
            "compliance": [],
            "architecture": {"multi_region": False, "topology": "single_cluster"},
            "budget": {"monthly_usd": 10000},
            "ai_recommendations": ["Enable AI features for intelligent recommendations"]
        }
        
        # Simple keyword extraction
        user_lower = user_input.lower()
        
        if "pci" in user_lower:
            parsed["compliance"].append("pci_dss")
        if "hipaa" in user_lower:
            parsed["compliance"].append("hipaa")
        if "soc" in user_lower:
            parsed["compliance"].append("soc2")
        if "99.99" in user_lower:
            parsed["performance"]["availability_target"] = "99.99%"
        if "multi-region" in user_lower or "multi region" in user_lower:
            parsed["architecture"]["multi_region"] = True
            parsed["architecture"]["topology"] = "federated"
        if "gpu" in user_lower or "ml" in user_lower:
            parsed["special_requirements"] = ["gpu"]
        
        # Extract numbers for workload count
        numbers = re.findall(r'\b(\d+)\s*(?:microservices?|services?|apps?|applications?)\b', user_lower)
        if numbers:
            parsed["workload_summary"]["count"] = int(numbers[0])
        
        # Extract budget
        budget_match = re.search(r'\$\s*([\d,]+)\s*(?:k|K)?\s*(?:/\s*month|monthly)?', user_input)
        if budget_match:
            budget = budget_match.group(1).replace(',', '')
            if 'k' in user_input.lower()[budget_match.start():budget_match.end()+5]:
                parsed["budget"]["monthly_usd"] = int(budget) * 1000
            else:
                parsed["budget"]["monthly_usd"] = int(budget)
        
        return parsed
    
    def generate_architecture_recommendation(self, parsed_requirements: Dict) -> Dict[str, Any]:
        """Generate detailed architecture recommendations based on parsed requirements"""
        
        recommendations = {
            "cluster_config": {},
            "node_groups": [],
            "addons": [],
            "security_config": {},
            "networking_config": {},
            "observability_config": {},
            "cost_optimization": {},
            "risk_assessment": [],
            "implementation_phases": []
        }
        
        workload = parsed_requirements.get("workload_summary", {})
        performance = parsed_requirements.get("performance", {})
        compliance = parsed_requirements.get("compliance", [])
        architecture = parsed_requirements.get("architecture", {})
        budget = parsed_requirements.get("budget", {})
        
        # Determine cluster configuration
        availability = performance.get("availability_target", "99.9%")
        recommendations["cluster_config"] = {
            "kubernetes_version": "1.29",
            "availability_zones": 3 if availability in ["99.99%", "99.999%"] else 2,
            "control_plane_logging": ["api", "audit", "authenticator", "controllerManager", "scheduler"],
            "encryption_config": True,
            "private_endpoint": True,
            "public_endpoint": len(compliance) == 0,  # Disable public for compliance
        }
        
        # Generate node groups based on workload
        workload_count = workload.get("count", 10)
        workload_type = workload.get("type", "microservices")
        
        # System node group (always needed)
        recommendations["node_groups"].append({
            "name": "system",
            "instance_types": ["m6i.large"],
            "capacity_type": "ON_DEMAND",
            "min_size": 2,
            "max_size": 4,
            "desired_size": 2,
            "labels": {"node-type": "system"},
            "taints": [{"key": "CriticalAddonsOnly", "value": "true", "effect": "NoSchedule"}]
        })
        
        # Application node groups
        if workload_type == "microservices":
            # Calculate nodes needed (assume ~10 pods per node for microservices)
            min_nodes = max(3, workload_count // 10)
            max_nodes = min_nodes * 3
            
            recommendations["node_groups"].append({
                "name": "application",
                "instance_types": ["m6i.xlarge", "m6i.2xlarge"],
                "capacity_type": "SPOT" if budget.get("optimize_for_cost", True) else "ON_DEMAND",
                "min_size": min_nodes,
                "max_size": max_nodes,
                "desired_size": min_nodes,
                "labels": {"node-type": "application", "workload": "microservices"},
                "taints": []
            })
        
        # GPU node group if needed
        special_reqs = parsed_requirements.get("special_requirements", [])
        if "gpu" in special_reqs:
            recommendations["node_groups"].append({
                "name": "gpu",
                "instance_types": ["g5.xlarge", "g5.2xlarge"],
                "capacity_type": "ON_DEMAND",
                "min_size": 0,
                "max_size": 10,
                "desired_size": 1,
                "labels": {"node-type": "gpu", "nvidia.com/gpu": "true"},
                "taints": [{"key": "nvidia.com/gpu", "value": "true", "effect": "NoSchedule"}]
            })
        
        # Recommended addons
        recommendations["addons"] = [
            "vpc-cni",
            "coredns", 
            "kube-proxy",
            "aws-ebs-csi-driver",
            "aws-load-balancer-controller"
        ]
        
        if compliance:
            recommendations["addons"].extend([
                "aws-guardduty-agent",
                "amazon-cloudwatch-observability"
            ])
        
        # Security configuration based on compliance
        recommendations["security_config"] = {
            "pod_security_standard": "restricted" if compliance else "baseline",
            "network_policies": True,
            "secrets_encryption": True,
            "audit_logging": True,
            "runtime_security": "falco" if compliance else None,
            "image_scanning": True,
            "compliance_frameworks": compliance
        }
        
        # Networking configuration
        recommendations["networking_config"] = {
            "vpc_cni_custom_networking": True,
            "prefix_delegation": workload_count > 50,
            "security_groups_for_pods": True,
            "network_policy_engine": "calico",
            "service_mesh": "istio" if workload_count > 30 else None,
            "ingress_controller": "aws-load-balancer-controller"
        }
        
        # Observability
        recommendations["observability_config"] = {
            "container_insights": True,
            "prometheus": True,
            "grafana": True,
            "logging": "fluent-bit",
            "log_destination": "cloudwatch",
            "tracing": "xray",
            "alerting": "alertmanager"
        }
        
        # Cost optimization
        monthly_budget = budget.get("monthly_usd", 10000)
        recommendations["cost_optimization"] = {
            "use_spot_instances": monthly_budget < 50000,
            "spot_percentage": 70 if monthly_budget < 30000 else 50,
            "use_karpenter": True,
            "use_savings_plans": monthly_budget > 20000,
            "estimated_monthly_cost": self._estimate_monthly_cost(recommendations["node_groups"]),
            "potential_savings": "30-45% with Spot and Karpenter"
        }
        
        # Risk assessment
        if availability == "99.999%":
            recommendations["risk_assessment"].append({
                "level": "high",
                "area": "Availability",
                "description": "99.999% availability requires multi-region active-active setup",
                "mitigation": "Implement Route53 health checks and cross-region failover"
            })
        
        if workload_count > 100:
            recommendations["risk_assessment"].append({
                "level": "medium",
                "area": "Scalability",
                "description": "Large workload count may require cluster sharding",
                "mitigation": "Consider hub-spoke topology or cluster-per-team approach"
            })
        
        # Implementation phases
        recommendations["implementation_phases"] = [
            {"phase": 1, "name": "Foundation", "duration": "2 weeks", 
             "tasks": ["VPC setup", "EKS cluster creation", "Node groups", "Core addons"]},
            {"phase": 2, "name": "Security", "duration": "1 week",
             "tasks": ["Network policies", "Pod security", "Secrets management", "IAM roles"]},
            {"phase": 3, "name": "Observability", "duration": "1 week",
             "tasks": ["Prometheus/Grafana", "Logging stack", "Alerting", "Dashboards"]},
            {"phase": 4, "name": "GitOps", "duration": "1 week",
             "tasks": ["ArgoCD setup", "Repository structure", "CI/CD pipelines"]},
            {"phase": 5, "name": "Migration", "duration": "4-8 weeks",
             "tasks": ["Workload containerization", "Phased migration", "Testing", "Cutover"]}
        ]
        
        return recommendations
    
    def _estimate_monthly_cost(self, node_groups: List[Dict]) -> float:
        """Estimate monthly cost based on node groups"""
        # Simplified cost estimation (actual would use AWS Pricing API)
        instance_costs = {
            "m6i.large": 70,
            "m6i.xlarge": 140,
            "m6i.2xlarge": 280,
            "c6i.xlarge": 120,
            "c6i.2xlarge": 240,
            "r6i.xlarge": 180,
            "g5.xlarge": 800,
            "g5.2xlarge": 1200,
        }
        
        total = 0
        for ng in node_groups:
            instance_type = ng.get("instance_types", ["m6i.xlarge"])[0]
            desired = ng.get("desired_size", 1)
            capacity = ng.get("capacity_type", "ON_DEMAND")
            
            base_cost = instance_costs.get(instance_type, 150)
            if capacity == "SPOT":
                base_cost *= 0.4  # 60% discount for Spot
            
            total += base_cost * desired * 730  # hours per month
        
        # Add EKS control plane cost
        total += 73  # $0.10/hour
        
        return round(total, 2)


# ============================================================================
# WORKLOAD ANALYZER
# ============================================================================

class EKSWorkloadAnalyzer:
    """
    Analyzes workload characteristics and provides sizing recommendations.
    """
    
    def __init__(self):
        self.ai_engine = EKSAIRequirementsEngine()
    
    def analyze_workload_profile(self, workloads: List[WorkloadRequirement]) -> Dict[str, Any]:
        """Analyze workload profiles and provide insights"""
        
        analysis = {
            "total_workloads": len(workloads),
            "resource_summary": {
                "total_cpu_requests": 0,
                "total_memory_requests_gb": 0,
                "total_replicas": 0,
                "gpu_workloads": 0,
                "stateful_workloads": 0,
                "spot_eligible": 0
            },
            "workload_distribution": {},
            "scaling_requirements": {
                "min_replicas": 0,
                "max_replicas": 0,
                "average_hpa_cpu": 0
            },
            "node_recommendations": [],
            "optimization_opportunities": []
        }
        
        cpu_total = 0
        memory_total = 0
        
        for w in workloads:
            # Parse CPU (e.g., "500m" or "2")
            cpu_val = self._parse_cpu(w.cpu_request)
            cpu_total += cpu_val * w.replicas
            
            # Parse memory (e.g., "512Mi" or "2Gi")
            mem_val = self._parse_memory(w.memory_request)
            memory_total += mem_val * w.replicas
            
            analysis["resource_summary"]["total_replicas"] += w.replicas
            
            if w.gpu_required:
                analysis["resource_summary"]["gpu_workloads"] += 1
            if w.stateful:
                analysis["resource_summary"]["stateful_workloads"] += 1
            if w.spot_tolerant:
                analysis["resource_summary"]["spot_eligible"] += 1
            
            # Track workload type distribution
            wtype = w.workload_type.value
            analysis["workload_distribution"][wtype] = analysis["workload_distribution"].get(wtype, 0) + 1
            
            # Scaling
            analysis["scaling_requirements"]["min_replicas"] += w.scaling_min
            analysis["scaling_requirements"]["max_replicas"] += w.scaling_max
        
        analysis["resource_summary"]["total_cpu_requests"] = round(cpu_total, 2)
        analysis["resource_summary"]["total_memory_requests_gb"] = round(memory_total, 2)
        
        # Generate node recommendations
        analysis["node_recommendations"] = self._recommend_nodes(analysis["resource_summary"])
        
        # Identify optimization opportunities
        if analysis["resource_summary"]["spot_eligible"] > len(workloads) * 0.5:
            analysis["optimization_opportunities"].append({
                "type": "cost",
                "title": "High Spot Instance Eligibility",
                "description": f"{analysis['resource_summary']['spot_eligible']} of {len(workloads)} workloads are Spot-tolerant",
                "potential_savings": "40-60%",
                "recommendation": "Use Karpenter with Spot provisioner for eligible workloads"
            })
        
        if analysis["resource_summary"]["gpu_workloads"] > 0:
            analysis["optimization_opportunities"].append({
                "type": "performance",
                "title": "GPU Workload Optimization",
                "description": "GPU workloads detected",
                "recommendation": "Consider GPU time-slicing or MIG for better utilization"
            })
        
        return analysis
    
    def _parse_cpu(self, cpu_str: str) -> float:
        """Parse CPU string to cores"""
        if cpu_str.endswith('m'):
            return float(cpu_str[:-1]) / 1000
        return float(cpu_str)
    
    def _parse_memory(self, mem_str: str) -> float:
        """Parse memory string to GB"""
        if mem_str.endswith('Gi'):
            return float(mem_str[:-2])
        if mem_str.endswith('Mi'):
            return float(mem_str[:-2]) / 1024
        if mem_str.endswith('Ki'):
            return float(mem_str[:-2]) / 1024 / 1024
        return float(mem_str)
    
    def _recommend_nodes(self, resource_summary: Dict) -> List[Dict]:
        """Recommend node configuration based on resources"""
        
        total_cpu = resource_summary["total_cpu_requests"]
        total_memory = resource_summary["total_memory_requests_gb"]
        gpu_workloads = resource_summary["gpu_workloads"]
        
        recommendations = []
        
        # System nodes (always needed)
        recommendations.append({
            "name": "system",
            "purpose": "Kubernetes system components and critical addons",
            "instance_type": "m6i.large",
            "vcpu": 2,
            "memory_gb": 8,
            "count": 2,
            "capacity_type": "ON_DEMAND",
            "rationale": "Dedicated nodes for system workloads ensure stability"
        })
        
        # Calculate application nodes needed
        # Assume 70% utilization target and some overhead
        effective_cpu_per_node = 3.5  # m6i.xlarge has 4 vCPU, leave some headroom
        effective_memory_per_node = 14  # m6i.xlarge has 16GB, leave headroom
        
        nodes_for_cpu = max(1, int(total_cpu / effective_cpu_per_node) + 1)
        nodes_for_memory = max(1, int(total_memory / effective_memory_per_node) + 1)
        
        app_nodes = max(nodes_for_cpu, nodes_for_memory)
        
        # Determine best instance type based on CPU/memory ratio
        ratio = total_memory / total_cpu if total_cpu > 0 else 4
        
        if ratio > 6:  # Memory intensive
            instance_type = "r6i.xlarge"
            vcpu, memory = 4, 32
        elif ratio < 2:  # Compute intensive
            instance_type = "c6i.xlarge"
            vcpu, memory = 4, 8
        else:  # Balanced
            instance_type = "m6i.xlarge"
            vcpu, memory = 4, 16
        
        recommendations.append({
            "name": "application",
            "purpose": "Application workloads",
            "instance_type": instance_type,
            "vcpu": vcpu,
            "memory_gb": memory,
            "count": app_nodes,
            "min_count": max(2, app_nodes - 2),
            "max_count": app_nodes * 3,
            "capacity_type": "SPOT" if resource_summary["spot_eligible"] > 0 else "ON_DEMAND",
            "rationale": f"Based on {total_cpu} vCPU and {total_memory}GB memory requirements"
        })
        
        # GPU nodes if needed
        if gpu_workloads > 0:
            recommendations.append({
                "name": "gpu",
                "purpose": "GPU-accelerated workloads",
                "instance_type": "g5.xlarge",
                "vcpu": 4,
                "memory_gb": 16,
                "gpu": 1,
                "count": gpu_workloads,
                "capacity_type": "ON_DEMAND",
                "rationale": f"{gpu_workloads} GPU workloads detected"
            })
        
        return recommendations
    
    def recommend_instance_types(self, workload: WorkloadRequirement) -> List[Dict]:
        """Recommend specific instance types for a workload"""
        
        cpu = self._parse_cpu(workload.cpu_request)
        memory = self._parse_memory(workload.memory_request)
        
        recommendations = []
        
        if workload.gpu_required:
            recommendations.extend([
                {"type": "g5.xlarge", "vcpu": 4, "memory": 16, "gpu": 1, "cost_tier": "high"},
                {"type": "g5.2xlarge", "vcpu": 8, "memory": 32, "gpu": 1, "cost_tier": "high"},
                {"type": "g4dn.xlarge", "vcpu": 4, "memory": 16, "gpu": 1, "cost_tier": "medium"},
            ])
        elif workload.workload_type == WorkloadType.ML_INFERENCE:
            recommendations.extend([
                {"type": "inf2.xlarge", "vcpu": 4, "memory": 16, "inferentia": 1, "cost_tier": "medium"},
                {"type": "g5.xlarge", "vcpu": 4, "memory": 16, "gpu": 1, "cost_tier": "high"},
            ])
        elif memory / cpu > 6:  # Memory intensive
            recommendations.extend([
                {"type": "r6i.xlarge", "vcpu": 4, "memory": 32, "cost_tier": "medium"},
                {"type": "r6i.2xlarge", "vcpu": 8, "memory": 64, "cost_tier": "high"},
                {"type": "r6a.xlarge", "vcpu": 4, "memory": 32, "cost_tier": "low"},
            ])
        elif memory / cpu < 2:  # Compute intensive
            recommendations.extend([
                {"type": "c6i.xlarge", "vcpu": 4, "memory": 8, "cost_tier": "medium"},
                {"type": "c6i.2xlarge", "vcpu": 8, "memory": 16, "cost_tier": "high"},
                {"type": "c6a.xlarge", "vcpu": 4, "memory": 8, "cost_tier": "low"},
            ])
        else:  # General purpose
            recommendations.extend([
                {"type": "m6i.xlarge", "vcpu": 4, "memory": 16, "cost_tier": "medium"},
                {"type": "m6i.2xlarge", "vcpu": 8, "memory": 32, "cost_tier": "high"},
                {"type": "m6a.xlarge", "vcpu": 4, "memory": 16, "cost_tier": "low"},
            ])
        
        # Add ARM options for cost optimization
        if workload.spot_tolerant and not workload.gpu_required:
            recommendations.append({
                "type": "m6g.xlarge", "vcpu": 4, "memory": 16, 
                "cost_tier": "lowest", "note": "ARM-based, 20% cheaper"
            })
        
        return recommendations
