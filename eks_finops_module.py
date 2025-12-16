"""
EKS FinOps Cost Optimization Module
Part of the AI-Enhanced EKS Architecture Design Wizard

Features:
- Cost Estimation and Forecasting
- Spot Instance Recommendations
- Reserved Capacity Planning
- Karpenter Configuration
- Kubecost Integration
- Cost Allocation Tags
- Optimization Recommendations

Author: Infosys Cloud Architecture Team
Version: 2.0.0
"""

import streamlit as st
import json
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
import os

# ============================================================================
# FINOPS CONSTANTS AND PRICING DATA
# ============================================================================

# AWS EC2 Pricing (On-Demand, us-east-1, hourly rates)
# Prices are approximate and should be updated or fetched from AWS Pricing API
EC2_PRICING = {
    # General Purpose - Intel
    "m6i.large": {"vcpu": 2, "memory": 8, "price": 0.096, "category": "general"},
    "m6i.xlarge": {"vcpu": 4, "memory": 16, "price": 0.192, "category": "general"},
    "m6i.2xlarge": {"vcpu": 8, "memory": 32, "price": 0.384, "category": "general"},
    "m6i.4xlarge": {"vcpu": 16, "memory": 64, "price": 0.768, "category": "general"},
    "m6i.8xlarge": {"vcpu": 32, "memory": 128, "price": 1.536, "category": "general"},
    
    # General Purpose - AMD
    "m6a.large": {"vcpu": 2, "memory": 8, "price": 0.0864, "category": "general"},
    "m6a.xlarge": {"vcpu": 4, "memory": 16, "price": 0.1728, "category": "general"},
    "m6a.2xlarge": {"vcpu": 8, "memory": 32, "price": 0.3456, "category": "general"},
    
    # General Purpose - Graviton
    "m6g.large": {"vcpu": 2, "memory": 8, "price": 0.077, "category": "general"},
    "m6g.xlarge": {"vcpu": 4, "memory": 16, "price": 0.154, "category": "general"},
    "m6g.2xlarge": {"vcpu": 8, "memory": 32, "price": 0.308, "category": "general"},
    "m7g.large": {"vcpu": 2, "memory": 8, "price": 0.0816, "category": "general"},
    "m7g.xlarge": {"vcpu": 4, "memory": 16, "price": 0.1632, "category": "general"},
    
    # Compute Optimized - Intel
    "c6i.large": {"vcpu": 2, "memory": 4, "price": 0.085, "category": "compute"},
    "c6i.xlarge": {"vcpu": 4, "memory": 8, "price": 0.17, "category": "compute"},
    "c6i.2xlarge": {"vcpu": 8, "memory": 16, "price": 0.34, "category": "compute"},
    "c6i.4xlarge": {"vcpu": 16, "memory": 32, "price": 0.68, "category": "compute"},
    
    # Compute Optimized - Graviton
    "c6g.large": {"vcpu": 2, "memory": 4, "price": 0.068, "category": "compute"},
    "c6g.xlarge": {"vcpu": 4, "memory": 8, "price": 0.136, "category": "compute"},
    "c7g.large": {"vcpu": 2, "memory": 4, "price": 0.0725, "category": "compute"},
    "c7g.xlarge": {"vcpu": 4, "memory": 8, "price": 0.145, "category": "compute"},
    
    # Memory Optimized
    "r6i.large": {"vcpu": 2, "memory": 16, "price": 0.126, "category": "memory"},
    "r6i.xlarge": {"vcpu": 4, "memory": 32, "price": 0.252, "category": "memory"},
    "r6i.2xlarge": {"vcpu": 8, "memory": 64, "price": 0.504, "category": "memory"},
    "r6g.large": {"vcpu": 2, "memory": 16, "price": 0.1008, "category": "memory"},
    "r6g.xlarge": {"vcpu": 4, "memory": 32, "price": 0.2016, "category": "memory"},
    
    # GPU Instances
    "g5.xlarge": {"vcpu": 4, "memory": 16, "gpu": 1, "price": 1.006, "category": "gpu"},
    "g5.2xlarge": {"vcpu": 8, "memory": 32, "gpu": 1, "price": 1.212, "category": "gpu"},
    "g5.4xlarge": {"vcpu": 16, "memory": 64, "gpu": 1, "price": 1.624, "category": "gpu"},
    "g4dn.xlarge": {"vcpu": 4, "memory": 16, "gpu": 1, "price": 0.526, "category": "gpu"},
    "g4dn.2xlarge": {"vcpu": 8, "memory": 32, "gpu": 1, "price": 0.752, "category": "gpu"},
    "p4d.24xlarge": {"vcpu": 96, "memory": 1152, "gpu": 8, "price": 32.77, "category": "gpu"},
    
    # Inference
    "inf2.xlarge": {"vcpu": 4, "memory": 16, "inferentia": 1, "price": 0.758, "category": "inference"},
    "inf2.8xlarge": {"vcpu": 32, "memory": 128, "inferentia": 1, "price": 1.968, "category": "inference"},
}

# Spot pricing discount (percentage of on-demand)
SPOT_DISCOUNT = {
    "general": 0.35,    # 65% discount
    "compute": 0.40,    # 60% discount
    "memory": 0.35,     # 65% discount
    "gpu": 0.50,        # 50% discount
    "inference": 0.45,  # 55% discount
}

# EKS Pricing
EKS_CONTROL_PLANE_HOURLY = 0.10  # $0.10 per hour per cluster

# AWS Services Pricing (monthly estimates)
AWS_SERVICES_PRICING = {
    "nat_gateway": 32.40,  # per NAT Gateway per month (base)
    "nat_gateway_per_gb": 0.045,  # per GB processed
    "vpc_endpoint": 7.30,  # per endpoint per month
    "alb": 16.20,  # Application Load Balancer base
    "alb_lcu": 0.008,  # per LCU-hour
    "ebs_gp3_gb": 0.08,  # per GB-month
    "ebs_iops": 0.005,  # per provisioned IOPS
    "ecr_storage_gb": 0.10,  # per GB-month
    "cloudwatch_logs_ingestion_gb": 0.50,  # per GB
    "cloudwatch_logs_storage_gb": 0.03,  # per GB-month
}


# ============================================================================
# FINOPS DATA CLASSES
# ============================================================================

@dataclass
class NodeGroupCostEstimate:
    """Cost estimate for a node group"""
    name: str
    instance_type: str
    instance_count: int
    capacity_type: str  # ON_DEMAND, SPOT
    vcpu_total: int
    memory_total_gb: int
    hourly_cost: float
    monthly_cost: float
    annual_cost: float
    cost_per_vcpu_hour: float
    cost_per_gb_memory_hour: float
    potential_savings: float = 0
    savings_recommendations: List[str] = field(default_factory=list)

@dataclass
class ClusterCostEstimate:
    """Total cost estimate for EKS cluster"""
    cluster_name: str
    region: str
    
    # Compute costs
    node_groups: List[NodeGroupCostEstimate] = field(default_factory=list)
    total_nodes: int = 0
    total_vcpu: int = 0
    total_memory_gb: int = 0
    
    # EKS control plane
    control_plane_monthly: float = 0
    
    # Networking costs
    nat_gateway_monthly: float = 0
    vpc_endpoints_monthly: float = 0
    load_balancer_monthly: float = 0
    data_transfer_monthly: float = 0
    
    # Storage costs
    ebs_storage_monthly: float = 0
    
    # Observability costs
    cloudwatch_monthly: float = 0
    
    # Total costs
    monthly_total: float = 0
    annual_total: float = 0
    
    # Optimization
    potential_monthly_savings: float = 0
    cost_optimization_recommendations: List[Dict] = field(default_factory=list)
    
    # Metadata
    estimated_at: str = field(default_factory=lambda: datetime.now().isoformat())

@dataclass
class SpotRecommendation:
    """Spot instance recommendation"""
    current_instance_type: str
    recommended_spot_types: List[str]
    spot_availability_score: float  # 0-100
    interruption_frequency: str  # low, medium, high
    estimated_savings_percent: float
    diversification_strategy: str


# ============================================================================
# COST CALCULATOR ENGINE
# ============================================================================

class EKSCostCalculator:
    """
    Comprehensive cost calculation engine for EKS clusters.
    Provides detailed cost breakdown and optimization recommendations.
    """
    
    def __init__(self, region: str = "us-east-1"):
        self.region = region
        self.hours_per_month = 730
        self.hours_per_year = 8760
    
    def calculate_cluster_cost(self, cluster_config: Dict) -> ClusterCostEstimate:
        """
        Calculate comprehensive cost estimate for an EKS cluster.
        
        Args:
            cluster_config: Cluster configuration dictionary
            
        Returns:
            ClusterCostEstimate with detailed breakdown
        """
        estimate = ClusterCostEstimate(
            cluster_name=cluster_config.get("cluster_name", "eks-cluster"),
            region=cluster_config.get("region", self.region)
        )
        
        # Calculate node group costs
        node_groups = cluster_config.get("node_groups", [])
        for ng in node_groups:
            ng_estimate = self._calculate_node_group_cost(ng)
            estimate.node_groups.append(ng_estimate)
            estimate.total_nodes += ng_estimate.instance_count
            estimate.total_vcpu += ng_estimate.vcpu_total
            estimate.total_memory_gb += ng_estimate.memory_total_gb
        
        # EKS control plane cost
        estimate.control_plane_monthly = EKS_CONTROL_PLANE_HOURLY * self.hours_per_month
        
        # Networking costs
        network = cluster_config.get("network", {})
        estimate.nat_gateway_monthly = self._calculate_nat_gateway_cost(network)
        estimate.vpc_endpoints_monthly = self._calculate_vpc_endpoint_cost(network)
        estimate.load_balancer_monthly = self._calculate_load_balancer_cost(cluster_config)
        estimate.data_transfer_monthly = self._estimate_data_transfer_cost(cluster_config)
        
        # Storage costs
        estimate.ebs_storage_monthly = self._calculate_storage_cost(cluster_config)
        
        # Observability costs
        observability = cluster_config.get("observability", {})
        estimate.cloudwatch_monthly = self._calculate_observability_cost(observability)
        
        # Calculate totals
        compute_monthly = sum(ng.monthly_cost for ng in estimate.node_groups)
        estimate.monthly_total = (
            compute_monthly +
            estimate.control_plane_monthly +
            estimate.nat_gateway_monthly +
            estimate.vpc_endpoints_monthly +
            estimate.load_balancer_monthly +
            estimate.data_transfer_monthly +
            estimate.ebs_storage_monthly +
            estimate.cloudwatch_monthly
        )
        estimate.annual_total = estimate.monthly_total * 12
        
        # Calculate potential savings
        estimate.potential_monthly_savings = sum(ng.potential_savings for ng in estimate.node_groups)
        
        # Generate optimization recommendations
        estimate.cost_optimization_recommendations = self._generate_cost_recommendations(
            estimate, cluster_config
        )
        
        return estimate
    
    def _calculate_node_group_cost(self, node_group: Dict) -> NodeGroupCostEstimate:
        """Calculate cost for a single node group"""
        
        instance_type = node_group.get("instance_types", ["m6i.xlarge"])[0]
        instance_count = node_group.get("desired_size", 1)
        capacity_type = node_group.get("capacity_type", "ON_DEMAND")
        
        # Get instance pricing
        instance_info = EC2_PRICING.get(instance_type, {
            "vcpu": 4, "memory": 16, "price": 0.192, "category": "general"
        })
        
        # Calculate hourly cost
        hourly_price = instance_info["price"]
        if capacity_type == "SPOT":
            discount = SPOT_DISCOUNT.get(instance_info["category"], 0.40)
            hourly_price *= discount
        
        total_hourly = hourly_price * instance_count
        monthly_cost = total_hourly * self.hours_per_month
        annual_cost = total_hourly * self.hours_per_year
        
        # Calculate metrics
        vcpu_total = instance_info["vcpu"] * instance_count
        memory_total = instance_info["memory"] * instance_count
        
        estimate = NodeGroupCostEstimate(
            name=node_group.get("name", "default"),
            instance_type=instance_type,
            instance_count=instance_count,
            capacity_type=capacity_type,
            vcpu_total=vcpu_total,
            memory_total_gb=memory_total,
            hourly_cost=total_hourly,
            monthly_cost=monthly_cost,
            annual_cost=annual_cost,
            cost_per_vcpu_hour=total_hourly / vcpu_total if vcpu_total > 0 else 0,
            cost_per_gb_memory_hour=total_hourly / memory_total if memory_total > 0 else 0
        )
        
        # Calculate potential savings and recommendations
        if capacity_type == "ON_DEMAND":
            # Spot savings potential
            spot_price = instance_info["price"] * SPOT_DISCOUNT.get(instance_info["category"], 0.40)
            spot_monthly = spot_price * instance_count * self.hours_per_month
            estimate.potential_savings = monthly_cost - spot_monthly
            
            estimate.savings_recommendations.append(
                f"Switch to Spot instances for ~{((monthly_cost - spot_monthly) / monthly_cost * 100):.0f}% savings"
            )
        
        # Graviton recommendation
        if instance_type.startswith(("m6i", "c6i", "r6i")):
            graviton_type = instance_type.replace("6i", "6g")
            if graviton_type in EC2_PRICING:
                graviton_price = EC2_PRICING[graviton_type]["price"]
                savings_pct = (instance_info["price"] - graviton_price) / instance_info["price"] * 100
                estimate.savings_recommendations.append(
                    f"Consider Graviton ({graviton_type}) for ~{savings_pct:.0f}% savings"
                )
        
        return estimate
    
    def _calculate_nat_gateway_cost(self, network: Dict) -> float:
        """Calculate NAT Gateway costs"""
        nat_count = network.get("nat_gateways", 3)
        estimated_data_gb = 500  # Assume 500 GB/month data processing
        
        base_cost = nat_count * AWS_SERVICES_PRICING["nat_gateway"]
        data_cost = estimated_data_gb * AWS_SERVICES_PRICING["nat_gateway_per_gb"]
        
        return base_cost + data_cost
    
    def _calculate_vpc_endpoint_cost(self, network: Dict) -> float:
        """Calculate VPC Endpoint costs"""
        endpoints = network.get("vpc_endpoints", [])
        return len(endpoints) * AWS_SERVICES_PRICING["vpc_endpoint"]
    
    def _calculate_load_balancer_cost(self, config: Dict) -> float:
        """Calculate Load Balancer costs"""
        # Assume 1 ALB with moderate traffic
        alb_base = AWS_SERVICES_PRICING["alb"]
        estimated_lcu_hours = 100 * self.hours_per_month  # 100 LCUs average
        lcu_cost = estimated_lcu_hours * AWS_SERVICES_PRICING["alb_lcu"]
        
        return alb_base + lcu_cost
    
    def _estimate_data_transfer_cost(self, config: Dict) -> float:
        """Estimate data transfer costs"""
        # This is highly variable, estimate based on cluster size
        node_count = sum(ng.get("desired_size", 1) for ng in config.get("node_groups", []))
        estimated_gb = node_count * 100  # 100 GB per node per month
        
        # Inter-AZ transfer at $0.01/GB
        return estimated_gb * 0.01
    
    def _calculate_storage_cost(self, config: Dict) -> float:
        """Calculate EBS storage costs"""
        workloads = config.get("workloads", [])
        
        total_storage_gb = 0
        for w in workloads:
            if w.get("storage_required", False):
                total_storage_gb += w.get("storage_size_gb", 20)
        
        # Minimum 20 GB per node for container runtime
        node_count = sum(ng.get("desired_size", 1) for ng in config.get("node_groups", []))
        total_storage_gb += node_count * 50  # 50 GB per node
        
        return total_storage_gb * AWS_SERVICES_PRICING["ebs_gp3_gb"]
    
    def _calculate_observability_cost(self, observability: Dict) -> float:
        """Calculate CloudWatch and observability costs"""
        cost = 0
        
        if observability.get("enable_container_insights", True):
            # Container Insights costs
            cost += 50  # Base estimate
        
        if observability.get("enable_logging", True):
            # Log ingestion and storage
            estimated_logs_gb = 100  # 100 GB/month
            cost += estimated_logs_gb * AWS_SERVICES_PRICING["cloudwatch_logs_ingestion_gb"]
            cost += estimated_logs_gb * AWS_SERVICES_PRICING["cloudwatch_logs_storage_gb"]
        
        return cost
    
    def _generate_cost_recommendations(self, estimate: ClusterCostEstimate, 
                                        config: Dict) -> List[Dict]:
        """Generate cost optimization recommendations"""
        recommendations = []
        
        # Check for Spot opportunity
        on_demand_groups = [ng for ng in estimate.node_groups if ng.capacity_type == "ON_DEMAND"]
        if on_demand_groups:
            total_on_demand = sum(ng.monthly_cost for ng in on_demand_groups)
            spot_savings = sum(ng.potential_savings for ng in on_demand_groups)
            
            if spot_savings > 100:  # More than $100 savings
                recommendations.append({
                    "category": "Compute",
                    "title": "Use Spot Instances for Non-Critical Workloads",
                    "description": f"Converting eligible workloads to Spot can save ~${spot_savings:.0f}/month",
                    "potential_savings": spot_savings,
                    "effort": "Medium",
                    "risk": "Low (with proper interruption handling)",
                    "implementation": [
                        "Identify stateless workloads suitable for Spot",
                        "Configure Spot termination handling",
                        "Use instance diversification",
                        "Implement pod disruption budgets"
                    ]
                })
        
        # Check for Graviton opportunity
        intel_costs = sum(ng.monthly_cost for ng in estimate.node_groups 
                         if ng.instance_type.startswith(("m6i", "c6i", "r6i", "m5", "c5")))
        if intel_costs > 500:
            graviton_savings = intel_costs * 0.20  # ~20% savings with Graviton
            recommendations.append({
                "category": "Compute",
                "title": "Migrate to Graviton (ARM) Instances",
                "description": f"Graviton instances offer ~20% better price-performance, saving ~${graviton_savings:.0f}/month",
                "potential_savings": graviton_savings,
                "effort": "Medium",
                "risk": "Low (requires ARM-compatible images)",
                "implementation": [
                    "Build multi-arch container images",
                    "Test workloads on Graviton instances",
                    "Gradually migrate node groups",
                    "Update deployment manifests"
                ]
            })
        
        # Karpenter recommendation
        if not config.get("cost", {}).get("enable_karpenter", False):
            estimated_savings = estimate.monthly_total * 0.15  # 15% typical savings
            recommendations.append({
                "category": "Autoscaling",
                "title": "Implement Karpenter for Intelligent Scaling",
                "description": f"Karpenter can reduce costs by ~15% through better bin-packing and instance selection",
                "potential_savings": estimated_savings,
                "effort": "Medium",
                "risk": "Low",
                "implementation": [
                    "Install Karpenter controller",
                    "Define NodePool configurations",
                    "Configure instance type flexibility",
                    "Set consolidation policies"
                ]
            })
        
        # Reserved Instances / Savings Plans
        if estimate.monthly_total > 5000:
            ri_savings = estimate.monthly_total * 0.30  # 30% with 1-year commitment
            recommendations.append({
                "category": "Commitments",
                "title": "Purchase Compute Savings Plans",
                "description": f"1-year Compute Savings Plan can save ~30% (${ri_savings:.0f}/month) on committed usage",
                "potential_savings": ri_savings,
                "effort": "Low",
                "risk": "Medium (commitment required)",
                "implementation": [
                    "Analyze usage patterns with Cost Explorer",
                    "Calculate baseline compute usage",
                    "Purchase Compute Savings Plan for baseline",
                    "Use Spot/On-Demand for variable workloads"
                ]
            })
        
        # NAT Gateway optimization
        if estimate.nat_gateway_monthly > 200:
            recommendations.append({
                "category": "Networking",
                "title": "Optimize NAT Gateway Usage",
                "description": "High NAT Gateway costs detected. Consider VPC endpoints for AWS services.",
                "potential_savings": estimate.nat_gateway_monthly * 0.30,
                "effort": "Low",
                "risk": "Low",
                "implementation": [
                    "Add VPC endpoints for S3, ECR, STS",
                    "Review egress traffic patterns",
                    "Consider NAT Gateway consolidation if multi-AZ not required for dev"
                ]
            })
        
        # Right-sizing recommendation
        recommendations.append({
            "category": "Right-Sizing",
            "title": "Implement Continuous Right-Sizing",
            "description": "Regular analysis of resource utilization can identify over-provisioned resources",
            "potential_savings": estimate.monthly_total * 0.10,  # 10% typical
            "effort": "Medium",
            "risk": "Low",
            "implementation": [
                "Deploy Kubecost for visibility",
                "Set up utilization monitoring",
                "Review requests vs actual usage",
                "Implement VPA for automatic adjustment"
            ]
        })
        
        return recommendations
    
    def calculate_tco_comparison(self, cluster_config: Dict, years: int = 3) -> Dict[str, Any]:
        """
        Calculate Total Cost of Ownership comparison for different scenarios.
        
        Args:
            cluster_config: Cluster configuration
            years: Number of years for TCO calculation
            
        Returns:
            Dict with TCO comparison for different scenarios
        """
        base_estimate = self.calculate_cluster_cost(cluster_config)
        
        scenarios = {}
        
        # Scenario 1: Current (Baseline)
        scenarios["baseline"] = {
            "name": "Current Configuration",
            "monthly_cost": base_estimate.monthly_total,
            "annual_cost": base_estimate.annual_total,
            "tco": base_estimate.annual_total * years,
            "description": "Current configuration without optimization"
        }
        
        # Scenario 2: Spot Optimized
        spot_config = cluster_config.copy()
        for ng in spot_config.get("node_groups", []):
            if ng.get("name") != "system":
                ng["capacity_type"] = "SPOT"
        spot_estimate = self.calculate_cluster_cost(spot_config)
        
        scenarios["spot_optimized"] = {
            "name": "Spot Instance Optimization",
            "monthly_cost": spot_estimate.monthly_total,
            "annual_cost": spot_estimate.annual_total,
            "tco": spot_estimate.annual_total * years,
            "savings_vs_baseline": (base_estimate.annual_total - spot_estimate.annual_total) * years,
            "description": "Non-critical workloads on Spot instances"
        }
        
        # Scenario 3: Graviton + Spot
        graviton_monthly = base_estimate.monthly_total * 0.65  # 35% savings
        scenarios["graviton_spot"] = {
            "name": "Graviton + Spot",
            "monthly_cost": graviton_monthly,
            "annual_cost": graviton_monthly * 12,
            "tco": graviton_monthly * 12 * years,
            "savings_vs_baseline": (base_estimate.annual_total - graviton_monthly * 12) * years,
            "description": "Graviton instances with Spot for eligible workloads"
        }
        
        # Scenario 4: With Savings Plans
        sp_monthly = base_estimate.monthly_total * 0.70  # 30% savings
        scenarios["savings_plans"] = {
            "name": "With 1-Year Savings Plans",
            "monthly_cost": sp_monthly,
            "annual_cost": sp_monthly * 12,
            "tco": sp_monthly * 12 * years,
            "savings_vs_baseline": (base_estimate.annual_total - sp_monthly * 12) * years,
            "description": "Compute Savings Plans for baseline usage"
        }
        
        # Scenario 5: Fully Optimized
        optimized_monthly = base_estimate.monthly_total * 0.50  # 50% savings
        scenarios["fully_optimized"] = {
            "name": "Fully Optimized",
            "monthly_cost": optimized_monthly,
            "annual_cost": optimized_monthly * 12,
            "tco": optimized_monthly * 12 * years,
            "savings_vs_baseline": (base_estimate.annual_total - optimized_monthly * 12) * years,
            "description": "Graviton + Spot + Savings Plans + Right-sizing"
        }
        
        return {
            "base_estimate": base_estimate,
            "scenarios": scenarios,
            "years": years,
            "recommendation": "fully_optimized",
            "max_savings": scenarios["fully_optimized"]["savings_vs_baseline"]
        }


# ============================================================================
# KARPENTER CONFIGURATION GENERATOR
# ============================================================================

class KarpenterConfigGenerator:
    """
    Generates optimized Karpenter configurations for cost efficiency.
    """
    
    def generate_nodepool_config(self, requirements: Dict) -> Dict[str, Any]:
        """
        Generate Karpenter NodePool configuration.
        
        Args:
            requirements: Cluster and workload requirements
            
        Returns:
            Dict containing Karpenter NodePool manifests
        """
        configs = {}
        
        # Default NodePool for general workloads
        configs["default-nodepool.yaml"] = self._generate_nodepool(
            name="default",
            requirements=requirements,
            instance_categories=["m", "c", "r"],
            architectures=["amd64", "arm64"],
            capacity_types=["spot", "on-demand"],
            spot_preference=True
        )
        
        # System NodePool (On-Demand only)
        configs["system-nodepool.yaml"] = self._generate_nodepool(
            name="system",
            requirements=requirements,
            instance_categories=["m"],
            architectures=["amd64"],
            capacity_types=["on-demand"],
            spot_preference=False,
            taints=[{"key": "CriticalAddonsOnly", "value": "true", "effect": "NoSchedule"}]
        )
        
        # GPU NodePool if needed
        if requirements.get("gpu_required", False):
            configs["gpu-nodepool.yaml"] = self._generate_nodepool(
                name="gpu",
                requirements=requirements,
                instance_categories=["g", "p"],
                architectures=["amd64"],
                capacity_types=["on-demand"],
                spot_preference=False,
                taints=[{"key": "nvidia.com/gpu", "value": "true", "effect": "NoSchedule"}]
            )
        
        # EC2NodeClass
        configs["ec2nodeclass.yaml"] = self._generate_ec2nodeclass(requirements)
        
        return configs
    
    def _generate_nodepool(self, name: str, requirements: Dict, 
                           instance_categories: List[str],
                           architectures: List[str],
                           capacity_types: List[str],
                           spot_preference: bool,
                           taints: List[Dict] = None) -> str:
        """Generate individual NodePool manifest"""
        
        import yaml
        
        nodepool = {
            "apiVersion": "karpenter.sh/v1",
            "kind": "NodePool",
            "metadata": {
                "name": name
            },
            "spec": {
                "template": {
                    "metadata": {
                        "labels": {
                            "nodepool": name,
                            "capacity-type": "flexible"
                        }
                    },
                    "spec": {
                        "nodeClassRef": {
                            "group": "karpenter.k8s.aws",
                            "kind": "EC2NodeClass",
                            "name": "default"
                        },
                        "requirements": [
                            {
                                "key": "kubernetes.io/arch",
                                "operator": "In",
                                "values": architectures
                            },
                            {
                                "key": "karpenter.sh/capacity-type",
                                "operator": "In",
                                "values": capacity_types
                            },
                            {
                                "key": "karpenter.k8s.aws/instance-category",
                                "operator": "In",
                                "values": instance_categories
                            },
                            {
                                "key": "karpenter.k8s.aws/instance-generation",
                                "operator": "Gt",
                                "values": ["5"]
                            }
                        ],
                        "expireAfter": "720h"  # 30 days
                    }
                },
                "limits": {
                    "cpu": requirements.get("max_vcpu", 1000),
                    "memory": f"{requirements.get('max_memory_gb', 2000)}Gi"
                },
                "disruption": {
                    "consolidationPolicy": "WhenEmptyOrUnderutilized",
                    "consolidateAfter": "1m"
                },
                "weight": 10 if spot_preference else 1
            }
        }
        
        if taints:
            nodepool["spec"]["template"]["spec"]["taints"] = taints
        
        return yaml.dump(nodepool)
    
    def _generate_ec2nodeclass(self, requirements: Dict) -> str:
        """Generate EC2NodeClass manifest"""
        
        import yaml
        
        ec2nodeclass = {
            "apiVersion": "karpenter.k8s.aws/v1",
            "kind": "EC2NodeClass",
            "metadata": {
                "name": "default"
            },
            "spec": {
                "role": requirements.get("node_role", "KarpenterNodeRole-${CLUSTER_NAME}"),
                "subnetSelectorTerms": [
                    {"tags": {"karpenter.sh/discovery": "${CLUSTER_NAME}"}}
                ],
                "securityGroupSelectorTerms": [
                    {"tags": {"karpenter.sh/discovery": "${CLUSTER_NAME}"}}
                ],
                "amiSelectorTerms": [
                    {"alias": "al2023@latest"}
                ],
                "blockDeviceMappings": [
                    {
                        "deviceName": "/dev/xvda",
                        "ebs": {
                            "volumeSize": "100Gi",
                            "volumeType": "gp3",
                            "iops": 3000,
                            "throughput": 125,
                            "encrypted": True,
                            "deleteOnTermination": True
                        }
                    }
                ],
                "metadataOptions": {
                    "httpEndpoint": "enabled",
                    "httpProtocolIPv6": "disabled",
                    "httpPutResponseHopLimit": 1,
                    "httpTokens": "required"  # IMDSv2
                },
                "tags": {
                    "Environment": requirements.get("environment", "production"),
                    "ManagedBy": "karpenter",
                    "Project": requirements.get("project", "eks-cluster")
                }
            }
        }
        
        return yaml.dump(ec2nodeclass)


# ============================================================================
# KUBECOST INTEGRATION
# ============================================================================

class KubecostIntegration:
    """
    Generates Kubecost deployment and configuration for cost visibility.
    """
    
    def generate_kubecost_config(self, cluster_config: Dict) -> Dict[str, str]:
        """Generate Kubecost installation configuration"""
        
        import yaml
        
        configs = {}
        
        # Kubecost Helm values
        configs["kubecost-values.yaml"] = yaml.dump({
            "global": {
                "prometheus": {
                    "enabled": True,
                    "fqdn": "http://prometheus-server.monitoring.svc:80"
                },
                "grafana": {
                    "enabled": False,
                    "proxy": False
                }
            },
            "kubecostToken": "",  # Optional token for enterprise features
            "prometheus": {
                "server": {
                    "global": {
                        "external_labels": {
                            "cluster_id": cluster_config.get("cluster_name", "eks-cluster")
                        }
                    }
                }
            },
            "costAnalyzer": {
                "enabled": True
            },
            "networkCosts": {
                "enabled": True,
                "config": {
                    "services": {
                        "amazon-web-services": True
                    }
                }
            },
            "clusterController": {
                "enabled": True
            },
            "serviceAccount": {
                "create": True,
                "annotations": {
                    "eks.amazonaws.com/role-arn": "arn:aws:iam::${AWS_ACCOUNT_ID}:role/KubecostRole"
                }
            }
        })
        
        # Cost allocation labels
        configs["cost-allocation-configmap.yaml"] = yaml.dump({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": "allocation-labels",
                "namespace": "kubecost"
            },
            "data": {
                "labels": json.dumps({
                    "team": "The team responsible for the workload",
                    "environment": "Production, Staging, or Development",
                    "project": "Project or product name",
                    "cost-center": "Finance cost center code"
                })
            }
        })
        
        # IAM Policy for Kubecost
        configs["kubecost-iam-policy.json"] = json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "ce:GetCostAndUsage",
                        "ce:GetCostForecast",
                        "ce:GetReservationUtilization",
                        "ce:GetSavingsPlansPurchaseRecommendation",
                        "ce:GetSavingsPlansUtilization",
                        "pricing:GetProducts",
                        "ec2:DescribeInstances",
                        "ec2:DescribeSpotPriceHistory"
                    ],
                    "Resource": "*"
                }
            ]
        }, indent=2)
        
        # Installation script
        configs["install-kubecost.sh"] = """#!/bin/bash
set -e

# Add Kubecost Helm repo
helm repo add kubecost https://kubecost.github.io/cost-analyzer/
helm repo update

# Create namespace
kubectl create namespace kubecost --dry-run=client -o yaml | kubectl apply -f -

# Install Kubecost
helm upgrade --install kubecost kubecost/cost-analyzer \\
  --namespace kubecost \\
  -f kubecost-values.yaml \\
  --wait

echo "Kubecost installed successfully!"
echo "Access the dashboard:"
echo "kubectl port-forward -n kubecost svc/kubecost-cost-analyzer 9090:9090"
"""
        
        return configs
    
    def generate_cost_allocation_policies(self) -> Dict[str, str]:
        """Generate cost allocation policies and labels"""
        
        import yaml
        
        policies = {}
        
        # Kyverno policy to enforce cost labels
        policies["enforce-cost-labels.yaml"] = yaml.dump({
            "apiVersion": "kyverno.io/v1",
            "kind": "ClusterPolicy",
            "metadata": {
                "name": "require-cost-labels"
            },
            "spec": {
                "validationFailureAction": "Audit",
                "background": True,
                "rules": [
                    {
                        "name": "require-cost-allocation-labels",
                        "match": {
                            "any": [
                                {
                                    "resources": {
                                        "kinds": ["Deployment", "StatefulSet", "DaemonSet"]
                                    }
                                }
                            ]
                        },
                        "validate": {
                            "message": "Cost allocation labels (team, project, cost-center) are required",
                            "pattern": {
                                "metadata": {
                                    "labels": {
                                        "team": "?*",
                                        "project": "?*",
                                        "cost-center": "?*"
                                    }
                                }
                            }
                        }
                    }
                ]
            }
        })
        
        # Mutating policy to add default labels
        policies["add-default-cost-labels.yaml"] = yaml.dump({
            "apiVersion": "kyverno.io/v1",
            "kind": "ClusterPolicy",
            "metadata": {
                "name": "add-default-cost-labels"
            },
            "spec": {
                "background": False,
                "rules": [
                    {
                        "name": "add-cost-labels",
                        "match": {
                            "any": [
                                {
                                    "resources": {
                                        "kinds": ["Pod"]
                                    }
                                }
                            ]
                        },
                        "mutate": {
                            "patchStrategicMerge": {
                                "metadata": {
                                    "labels": {
                                        "+(cost-center)": "unassigned",
                                        "+(team)": "{{request.namespace}}"
                                    }
                                }
                            }
                        }
                    }
                ]
            }
        })
        
        return policies
