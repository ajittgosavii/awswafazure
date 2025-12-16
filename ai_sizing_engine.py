"""
AI-Powered AWS Sizing Recommendation Engine
Analyzes architecture requirements and provides intelligent sizing recommendations
Integrates with workflow engine and cost calculator
"""

import streamlit as st
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict, field
from datetime import datetime
import json

# ============================================================================
# SIZING RECOMMENDATION DATA MODELS
# ============================================================================

@dataclass
class SizingRecommendation:
    """Single sizing recommendation"""
    tier: str  # "cost-optimized", "balanced", "performance-optimized", "enterprise"
    tier_name: str  # Display name
    
    # EC2 Configuration
    ec2_instance_type: str
    ec2_count: int
    ec2_justification: str
    
    # RDS Configuration
    rds_instance_type: str
    rds_multi_az: bool
    rds_storage_gb: int
    rds_justification: str
    
    # Additional services
    additional_config: Dict[str, Any] = field(default_factory=dict)
    
    # Cost summary
    monthly_cost: float = 0.0
    yearly_cost: float = 0.0
    three_year_cost: float = 0.0
    
    # Performance characteristics
    vcpus: int = 0
    memory_gb: float = 0.0
    network_performance: str = ""
    
    # AI reasoning
    ai_reasoning: str = ""
    pros: List[str] = field(default_factory=list)
    cons: List[str] = field(default_factory=list)
    best_for: List[str] = field(default_factory=list)
    
    # Confidence score
    confidence_score: int = 0  # 0-100
    
    def to_dict(self):
        return asdict(self)

@dataclass
class SizingAnalysis:
    """Complete sizing analysis with multiple recommendations"""
    architecture_name: str
    environment: str
    
    # Workload characteristics (from AI analysis)
    workload_type: str  # "web", "api", "batch", "ml", "data-analytics", "mixed"
    traffic_pattern: str  # "steady", "variable", "spiky", "predictable"
    data_intensity: str  # "low", "medium", "high"
    compute_intensity: str  # "low", "medium", "high"
    availability_requirement: str  # "standard", "high", "critical"
    
    # Sizing recommendations (4 tiers)
    recommendations: List[SizingRecommendation] = field(default_factory=list)
    
    # Recommended tier
    recommended_tier: str = "balanced"
    
    # AI insights
    workload_analysis: str = ""
    scaling_recommendations: str = ""
    cost_optimization_tips: List[str] = field(default_factory=list)
    
    # Metadata
    analyzed_at: str = ""
    analyzed_by: str = "AI Sizing Engine"
    
    def to_dict(self):
        data = asdict(self)
        data['recommendations'] = [r.to_dict() for r in self.recommendations]
        return data
    
    @staticmethod
    def from_dict(data):
        if 'recommendations' in data:
            data['recommendations'] = [SizingRecommendation(**r) for r in data['recommendations']]
        return SizingAnalysis(**data)


# ============================================================================
# AI SIZING ANALYZER
# ============================================================================

class AISizingAnalyzer:
    """AI-powered sizing recommendation engine"""
    
    # Instance type database with characteristics
    EC2_INSTANCES = {
        # T3 - Burstable (Cost-optimized)
        't3.micro': {'vcpus': 2, 'memory': 1, 'network': 'Low to Moderate', 'cost_tier': 'ultra-low'},
        't3.small': {'vcpus': 2, 'memory': 2, 'network': 'Low to Moderate', 'cost_tier': 'low'},
        't3.medium': {'vcpus': 2, 'memory': 4, 'network': 'Low to Moderate', 'cost_tier': 'low'},
        't3.large': {'vcpus': 2, 'memory': 8, 'network': 'Moderate', 'cost_tier': 'low'},
        't3.xlarge': {'vcpus': 4, 'memory': 16, 'network': 'Moderate', 'cost_tier': 'medium'},
        't3.2xlarge': {'vcpus': 8, 'memory': 32, 'network': 'Moderate', 'cost_tier': 'medium'},
        
        # M5 - General Purpose (Balanced)
        'm5.large': {'vcpus': 2, 'memory': 8, 'network': 'Up to 10 Gbps', 'cost_tier': 'medium'},
        'm5.xlarge': {'vcpus': 4, 'memory': 16, 'network': 'Up to 10 Gbps', 'cost_tier': 'medium'},
        'm5.2xlarge': {'vcpus': 8, 'memory': 32, 'network': 'Up to 10 Gbps', 'cost_tier': 'medium-high'},
        'm5.4xlarge': {'vcpus': 16, 'memory': 64, 'network': '10 Gbps', 'cost_tier': 'high'},
        'm5.8xlarge': {'vcpus': 32, 'memory': 128, 'network': '10 Gbps', 'cost_tier': 'high'},
        
        # C5 - Compute Optimized (Performance)
        'c5.large': {'vcpus': 2, 'memory': 4, 'network': 'Up to 10 Gbps', 'cost_tier': 'medium'},
        'c5.xlarge': {'vcpus': 4, 'memory': 8, 'network': 'Up to 10 Gbps', 'cost_tier': 'medium'},
        'c5.2xlarge': {'vcpus': 8, 'memory': 16, 'network': 'Up to 10 Gbps', 'cost_tier': 'medium-high'},
        'c5.4xlarge': {'vcpus': 16, 'memory': 32, 'network': '10 Gbps', 'cost_tier': 'high'},
        
        # R5 - Memory Optimized
        'r5.large': {'vcpus': 2, 'memory': 16, 'network': 'Up to 10 Gbps', 'cost_tier': 'medium-high'},
        'r5.xlarge': {'vcpus': 4, 'memory': 32, 'network': 'Up to 10 Gbps', 'cost_tier': 'high'},
        'r5.2xlarge': {'vcpus': 8, 'memory': 64, 'network': 'Up to 10 Gbps', 'cost_tier': 'high'},
        'r5.4xlarge': {'vcpus': 16, 'memory': 128, 'network': '10 Gbps', 'cost_tier': 'very-high'},
    }
    
    RDS_INSTANCES = {
        # T3 - Development/Testing
        'db.t3.micro': {'vcpus': 2, 'memory': 1, 'cost_tier': 'ultra-low'},
        'db.t3.small': {'vcpus': 2, 'memory': 2, 'cost_tier': 'low'},
        'db.t3.medium': {'vcpus': 2, 'memory': 4, 'cost_tier': 'low'},
        'db.t3.large': {'vcpus': 2, 'memory': 8, 'cost_tier': 'medium'},
        
        # M5 - General Purpose
        'db.m5.large': {'vcpus': 2, 'memory': 8, 'cost_tier': 'medium'},
        'db.m5.xlarge': {'vcpus': 4, 'memory': 16, 'cost_tier': 'medium-high'},
        'db.m5.2xlarge': {'vcpus': 8, 'memory': 32, 'cost_tier': 'high'},
        'db.m5.4xlarge': {'vcpus': 16, 'memory': 64, 'cost_tier': 'high'},
        
        # R5 - Memory Optimized
        'db.r5.large': {'vcpus': 2, 'memory': 16, 'cost_tier': 'medium-high'},
        'db.r5.xlarge': {'vcpus': 4, 'memory': 32, 'cost_tier': 'high'},
        'db.r5.2xlarge': {'vcpus': 8, 'memory': 64, 'cost_tier': 'very-high'},
    }
    
    def __init__(self):
        """Initialize AI sizing analyzer"""
        pass
    
    def analyze_architecture(self, design_data: Dict[str, Any]) -> SizingAnalysis:
        """Analyze architecture and provide sizing recommendations"""
        
        # Extract key information
        services = design_data.get('services', [])
        description = design_data.get('description', '')
        business_requirements = design_data.get('business_requirements', '')
        environment = design_data.get('environment', 'Production')
        ha_required = design_data.get('ha_required', True)
        compliance = design_data.get('compliance_requirements', [])
        
        # Analyze workload characteristics
        workload_analysis = self._analyze_workload(
            description, business_requirements, services, environment
        )
        
        # Generate 4 tier recommendations
        recommendations = []
        
        # Tier 1: Cost-Optimized
        recommendations.append(self._generate_cost_optimized_sizing(
            workload_analysis, services, environment, ha_required
        ))
        
        # Tier 2: Balanced (Recommended)
        recommendations.append(self._generate_balanced_sizing(
            workload_analysis, services, environment, ha_required
        ))
        
        # Tier 3: Performance-Optimized
        recommendations.append(self._generate_performance_sizing(
            workload_analysis, services, environment, ha_required
        ))
        
        # Tier 4: Enterprise-Grade
        recommendations.append(self._generate_enterprise_sizing(
            workload_analysis, services, environment, ha_required
        ))
        
        # Calculate costs for each recommendation (will be done by cost calculator)
        
        # Determine recommended tier based on environment and requirements
        recommended_tier = self._determine_recommended_tier(
            environment, ha_required, workload_analysis, compliance
        )
        
        # Generate scaling and cost optimization recommendations
        scaling_recs = self._generate_scaling_recommendations(workload_analysis)
        cost_tips = self._generate_cost_optimization_tips(
            workload_analysis, services, environment
        )
        
        return SizingAnalysis(
            architecture_name=design_data.get('name', 'Architecture'),
            environment=environment,
            workload_type=workload_analysis['type'],
            traffic_pattern=workload_analysis['traffic_pattern'],
            data_intensity=workload_analysis['data_intensity'],
            compute_intensity=workload_analysis['compute_intensity'],
            availability_requirement=workload_analysis['availability'],
            recommendations=recommendations,
            recommended_tier=recommended_tier,
            workload_analysis=workload_analysis['summary'],
            scaling_recommendations=scaling_recs,
            cost_optimization_tips=cost_tips,
            analyzed_at=datetime.now().isoformat()
        )
    
    def _analyze_workload(
        self, 
        description: str, 
        business_req: str, 
        services: List[str],
        environment: str
    ) -> Dict[str, Any]:
        """Analyze workload characteristics using AI heuristics"""
        
        desc_lower = description.lower() + " " + business_req.lower()
        
        # Determine workload type
        workload_type = "mixed"
        if any(x in desc_lower for x in ['web', 'website', 'portal', 'frontend']):
            workload_type = "web"
        elif any(x in desc_lower for x in ['api', 'rest', 'graphql', 'microservice']):
            workload_type = "api"
        elif any(x in desc_lower for x in ['batch', 'etl', 'processing', 'pipeline']):
            workload_type = "batch"
        elif any(x in desc_lower for x in ['ml', 'machine learning', 'ai', 'training']):
            workload_type = "ml"
        elif any(x in desc_lower for x in ['analytics', 'data warehouse', 'bi']):
            workload_type = "data-analytics"
        
        # Determine traffic pattern
        traffic_pattern = "variable"
        if any(x in desc_lower for x in ['steady', 'constant', 'continuous']):
            traffic_pattern = "steady"
        elif any(x in desc_lower for x in ['spike', 'burst', 'peak', 'seasonal']):
            traffic_pattern = "spiky"
        elif any(x in desc_lower for x in ['predictable', 'scheduled', 'regular']):
            traffic_pattern = "predictable"
        
        # Determine data intensity
        data_intensity = "medium"
        if any(x in desc_lower for x in ['large data', 'big data', 'terabyte', 'petabyte', 'data lake']):
            data_intensity = "high"
        elif any(x in desc_lower for x in ['small data', 'minimal data', 'lightweight']):
            data_intensity = "low"
        elif 'RDS' in services or 'DynamoDB' in services or 'S3' in services:
            data_intensity = "medium"
        
        # Determine compute intensity
        compute_intensity = "medium"
        if any(x in desc_lower for x in ['compute intensive', 'cpu intensive', 'processing']):
            compute_intensity = "high"
        elif any(x in desc_lower for x in ['lightweight', 'simple', 'basic']):
            compute_intensity = "low"
        elif workload_type in ['ml', 'data-analytics', 'batch']:
            compute_intensity = "high"
        
        # Determine availability requirement
        availability = "high"
        if environment.lower() in ['production', 'prod']:
            availability = "critical"
        elif environment.lower() in ['staging', 'uat']:
            availability = "high"
        elif environment.lower() in ['dev', 'development', 'test']:
            availability = "standard"
        
        # Generate summary
        summary = f"""Workload Analysis:
• Type: {workload_type.upper()} workload
• Traffic Pattern: {traffic_pattern.capitalize()} traffic expected
• Data Intensity: {data_intensity.capitalize()} data processing requirements
• Compute Requirements: {compute_intensity.capitalize()} compute intensity
• Availability Needs: {availability.capitalize()} availability required for {environment}

This analysis suggests a {'mission-critical' if availability == 'critical' else 'standard'} deployment 
with {'high-performance' if compute_intensity == 'high' else 'balanced'} compute resources."""
        
        return {
            'type': workload_type,
            'traffic_pattern': traffic_pattern,
            'data_intensity': data_intensity,
            'compute_intensity': compute_intensity,
            'availability': availability,
            'summary': summary
        }
    
    def _generate_cost_optimized_sizing(
        self,
        workload: Dict[str, Any],
        services: List[str],
        environment: str,
        ha_required: bool
    ) -> SizingRecommendation:
        """Generate cost-optimized sizing recommendation"""
        
        # Use T3 instances for cost optimization
        ec2_type = "t3.small"
        ec2_count = 2 if ha_required else 1
        
        if workload['compute_intensity'] == 'medium':
            ec2_type = "t3.medium"
        elif workload['compute_intensity'] == 'high':
            ec2_type = "t3.large"
        
        # RDS sizing
        rds_type = "db.t3.small"
        if 'RDS' in services:
            if workload['data_intensity'] == 'high':
                rds_type = "db.t3.medium"
        
        ec2_info = self.EC2_INSTANCES[ec2_type]
        rds_info = self.RDS_INSTANCES.get(rds_type, {'vcpus': 2, 'memory': 2})
        
        return SizingRecommendation(
            tier="cost-optimized",
            tier_name="💰 Cost-Optimized",
            ec2_instance_type=ec2_type,
            ec2_count=ec2_count,
            ec2_justification=f"T3 burstable instances provide cost-effective compute with baseline CPU performance and ability to burst when needed.",
            rds_instance_type=rds_type,
            rds_multi_az=ha_required,
            rds_storage_gb=100,
            rds_justification=f"T3 database instance suitable for development and low-traffic workloads.",
            additional_config={
                's3': {'storage_gb': 500},
                'cloudwatch': {'detailed_monitoring': False}
            },
            vcpus=ec2_info['vcpus'] * ec2_count,
            memory_gb=ec2_info['memory'] * ec2_count,
            network_performance=ec2_info['network'],
            ai_reasoning=f"Selected T3 instances to minimize costs while meeting {workload['type']} workload requirements. Suitable for variable workloads with burst capability.",
            pros=[
                "Lowest operational cost",
                "Burstable performance for variable loads",
                "Ideal for development and testing",
                "Easy to scale up if needed"
            ],
            cons=[
                "Limited baseline CPU performance",
                "May not handle sustained high loads",
                "Network performance constraints",
                "Not suitable for production critical workloads"
            ],
            best_for=[
                "Development environments",
                "Low-traffic applications",
                "Cost-conscious deployments",
                "Variable workloads"
            ],
            confidence_score=85
        )
    
    def _generate_balanced_sizing(
        self,
        workload: Dict[str, Any],
        services: List[str],
        environment: str,
        ha_required: bool
    ) -> SizingRecommendation:
        """Generate balanced sizing recommendation (RECOMMENDED)"""
        
        # Use M5 instances for balanced performance
        ec2_type = "m5.large"
        ec2_count = 2 if ha_required else 1
        
        if workload['compute_intensity'] == 'high':
            ec2_type = "m5.xlarge"
            ec2_count = 3 if ha_required else 2
        elif workload['data_intensity'] == 'high':
            ec2_type = "m5.xlarge"
        
        # RDS sizing
        rds_type = "db.m5.large"
        if 'RDS' in services:
            if workload['data_intensity'] == 'high':
                rds_type = "db.m5.xlarge"
        
        ec2_info = self.EC2_INSTANCES[ec2_type]
        rds_info = self.RDS_INSTANCES.get(rds_type, {'vcpus': 2, 'memory': 8})
        
        return SizingRecommendation(
            tier="balanced",
            tier_name="⚖️ Balanced (Recommended)",
            ec2_instance_type=ec2_type,
            ec2_count=ec2_count,
            ec2_justification=f"M5 general-purpose instances provide excellent balance of compute, memory, and network performance for production workloads.",
            rds_instance_type=rds_type,
            rds_multi_az=ha_required,
            rds_storage_gb=500,
            rds_justification=f"M5 database instance with consistent performance for production databases.",
            additional_config={
                's3': {'storage_gb': 2000},
                'cloudwatch': {'detailed_monitoring': True},
                'auto_scaling': {
                    'min_instances': ec2_count,
                    'max_instances': ec2_count * 2
                }
            },
            vcpus=ec2_info['vcpus'] * ec2_count,
            memory_gb=ec2_info['memory'] * ec2_count,
            network_performance=ec2_info['network'],
            ai_reasoning=f"M5 instances provide optimal balance for {workload['type']} workloads in {environment}. Right-sized for consistent performance without over-provisioning.",
            pros=[
                "Excellent price-performance ratio",
                "Consistent baseline performance",
                "Suitable for production workloads",
                "Good network throughput",
                "Predictable costs with Reserved Instances"
            ],
            cons=[
                "Higher cost than T3 instances",
                "May be over-provisioned for low traffic",
                "Not optimized for specific workload types"
            ],
            best_for=[
                "Production environments",
                "General-purpose applications",
                "Steady-state workloads",
                "Cost-conscious production deployments"
            ],
            confidence_score=95
        )
    
    def _generate_performance_sizing(
        self,
        workload: Dict[str, Any],
        services: List[str],
        environment: str,
        ha_required: bool
    ) -> SizingRecommendation:
        """Generate performance-optimized sizing recommendation"""
        
        # Use C5 for compute-intensive or M5 larger instances
        if workload['compute_intensity'] == 'high':
            ec2_type = "c5.2xlarge"
            ec2_count = 3 if ha_required else 2
        else:
            ec2_type = "m5.2xlarge"
            ec2_count = 3 if ha_required else 2
        
        # RDS sizing - use larger or R5 for memory-intensive
        rds_type = "db.m5.2xlarge"
        if workload['data_intensity'] == 'high':
            rds_type = "db.r5.xlarge"
        
        ec2_info = self.EC2_INSTANCES[ec2_type]
        rds_info = self.RDS_INSTANCES.get(rds_type, {'vcpus': 8, 'memory': 32})
        
        return SizingRecommendation(
            tier="performance-optimized",
            tier_name="🚀 Performance-Optimized",
            ec2_instance_type=ec2_type,
            ec2_count=ec2_count,
            ec2_justification=f"{'C5 compute-optimized' if 'c5' in ec2_type else 'M5 large'} instances for maximum performance and low latency.",
            rds_instance_type=rds_type,
            rds_multi_az=True,
            rds_storage_gb=1000,
            rds_justification=f"High-performance database instance with {'memory optimization' if 'r5' in rds_type else 'balanced resources'}.",
            additional_config={
                's3': {'storage_gb': 5000},
                'cloudwatch': {'detailed_monitoring': True},
                'auto_scaling': {
                    'min_instances': ec2_count,
                    'max_instances': ec2_count * 3,
                    'scale_up_threshold': 60,
                    'scale_down_threshold': 30
                },
                'enhanced_networking': True,
                'placement_group': 'cluster'
            },
            vcpus=ec2_info['vcpus'] * ec2_count,
            memory_gb=ec2_info['memory'] * ec2_count,
            network_performance=ec2_info['network'],
            ai_reasoning=f"High-performance configuration for demanding {workload['type']} workloads. Optimized for low latency and high throughput.",
            pros=[
                "Maximum performance and throughput",
                "Low latency response times",
                "Excellent for compute-intensive tasks",
                "High network bandwidth",
                "Can handle traffic spikes easily"
            ],
            cons=[
                "Higher operational costs",
                "May be over-provisioned for average loads",
                "Requires careful cost monitoring"
            ],
            best_for=[
                "High-traffic production applications",
                "Compute-intensive workloads",
                "Low-latency requirements",
                "Mission-critical applications"
            ],
            confidence_score=90
        )
    
    def _generate_enterprise_sizing(
        self,
        workload: Dict[str, Any],
        services: List[str],
        environment: str,
        ha_required: bool
    ) -> SizingRecommendation:
        """Generate enterprise-grade sizing recommendation"""
        
        # Use larger M5 or C5 instances with more redundancy
        if workload['compute_intensity'] == 'high':
            ec2_type = "c5.4xlarge"
            ec2_count = 4  # Always multiple instances
        else:
            ec2_type = "m5.4xlarge"
            ec2_count = 4
        
        # RDS sizing - always R5 for enterprise
        rds_type = "db.r5.2xlarge"
        
        ec2_info = self.EC2_INSTANCES[ec2_type]
        rds_info = self.RDS_INSTANCES.get(rds_type, {'vcpus': 8, 'memory': 64})
        
        return SizingRecommendation(
            tier="enterprise",
            tier_name="🏢 Enterprise-Grade",
            ec2_instance_type=ec2_type,
            ec2_count=ec2_count,
            ec2_justification=f"Enterprise-grade {ec2_type} instances with maximum redundancy and performance across multiple AZs.",
            rds_instance_type=rds_type,
            rds_multi_az=True,
            rds_storage_gb=2000,
            rds_justification=f"Memory-optimized R5 database with Multi-AZ for maximum availability and performance.",
            additional_config={
                's3': {'storage_gb': 10000, 'intelligent_tiering': True},
                'cloudwatch': {
                    'detailed_monitoring': True,
                    'custom_metrics': True,
                    'log_retention_days': 90
                },
                'auto_scaling': {
                    'min_instances': ec2_count,
                    'max_instances': ec2_count * 4,
                    'scale_up_threshold': 50,
                    'scale_down_threshold': 20,
                    'predictive_scaling': True
                },
                'enhanced_networking': True,
                'placement_group': 'spread',
                'backup': {
                    'automated_backups': True,
                    'backup_retention_days': 35,
                    'cross_region_backup': True
                },
                'monitoring': {
                    'apm': True,
                    'distributed_tracing': True
                }
            },
            vcpus=ec2_info['vcpus'] * ec2_count,
            memory_gb=ec2_info['memory'] * ec2_count,
            network_performance=ec2_info['network'],
            ai_reasoning=f"Enterprise-grade architecture with maximum redundancy, performance, and observability for mission-critical {workload['type']} workloads.",
            pros=[
                "Maximum availability and redundancy",
                "Enterprise-grade performance",
                "Comprehensive monitoring and backup",
                "Can handle massive scale",
                "Fault-tolerant across availability zones",
                "Advanced auto-scaling capabilities"
            ],
            cons=[
                "Highest operational costs",
                "Complex management overhead",
                "May be over-engineered for simple workloads",
                "Requires skilled operations team"
            ],
            best_for=[
                "Mission-critical applications",
                "Financial services and healthcare",
                "Compliance-heavy industries",
                "Global-scale applications",
                "24/7 high-availability requirements"
            ],
            confidence_score=98
        )
    
    def _determine_recommended_tier(
        self,
        environment: str,
        ha_required: bool,
        workload: Dict[str, Any],
        compliance: List[str]
    ) -> str:
        """Determine which tier to recommend"""
        
        env_lower = environment.lower()
        
        # Enterprise for compliance-heavy or critical requirements
        if compliance or workload['availability'] == 'critical':
            return "enterprise"
        
        # Cost-optimized for dev/test
        if env_lower in ['dev', 'development', 'test']:
            return "cost-optimized"
        
        # Performance for high-compute or high-data
        if workload['compute_intensity'] == 'high' and workload['data_intensity'] == 'high':
            return "performance-optimized"
        
        # Balanced for most production workloads
        return "balanced"
    
    def _generate_scaling_recommendations(self, workload: Dict[str, Any]) -> str:
        """Generate scaling recommendations based on workload"""
        
        traffic = workload['traffic_pattern']
        
        if traffic == 'spiky':
            return """Auto-Scaling Recommendations:
• Enable aggressive auto-scaling with predictive scaling
• Set scale-up threshold at 60% CPU to handle spikes
• Configure scale-down cooldown of 10 minutes
• Use target tracking scaling for consistent performance
• Consider Spot instances for burst capacity"""
        
        elif traffic == 'predictable':
            return """Auto-Scaling Recommendations:
• Use scheduled scaling for known traffic patterns
• Set conservative thresholds (70% CPU) for scale-up
• Implement gradual scale-down during off-peak
• Consider Reserved Instances for baseline capacity
• Use Savings Plans for predictable spend"""
        
        elif traffic == 'steady':
            return """Auto-Scaling Recommendations:
• Minimal auto-scaling needed for steady workloads
• Set safety buffer with 2x capacity for failures
• Use Reserved Instances for cost optimization
• Monitor and right-size instances quarterly
• Consider fixed capacity with manual scaling"""
        
        else:  # variable
            return """Auto-Scaling Recommendations:
• Balanced auto-scaling with moderate thresholds
• Scale up at 65% CPU, scale down at 35%
• Use mix of Reserved Instances + On-Demand
• Enable CloudWatch alarms for anomaly detection
• Review scaling patterns monthly for optimization"""
    
    def _generate_cost_optimization_tips(
        self,
        workload: Dict[str, Any],
        services: List[str],
        environment: str
    ) -> List[str]:
        """Generate cost optimization tips"""
        
        tips = []
        
        # Environment-specific
        if environment.lower() in ['dev', 'development', 'test']:
            tips.append("💡 Use EC2 Instance Scheduler to stop instances during nights/weekends (save 70%)")
            tips.append("💡 Consider Spot Instances for non-critical dev/test workloads (save 90%)")
        
        # Traffic pattern
        if workload['traffic_pattern'] == 'spiky':
            tips.append("💡 Use Auto Scaling with Spot Instances for burst capacity (save 60-70%)")
        
        # Data services
        if 'S3' in services:
            tips.append("💡 Enable S3 Intelligent-Tiering for automatic cost optimization")
            tips.append("💡 Set S3 Lifecycle policies to move old data to Glacier (save 90%)")
        
        if 'RDS' in services:
            tips.append("💡 Purchase 1-year or 3-year RDS Reserved Instances (save 30-60%)")
            tips.append("💡 Enable automated backups only in production environments")
        
        # Compute
        if workload['compute_intensity'] != 'high':
            tips.append("💡 Consider Lambda for infrequent or variable compute workloads")
        
        # General
        tips.append("💡 Purchase Compute Savings Plans for flexible 1-3 year commitments (save 20-40%)")
        tips.append("💡 Use AWS Cost Explorer to identify unused resources")
        tips.append("💡 Enable AWS Budgets with alerts to prevent cost overruns")
        
        return tips[:8]  # Return top 8 tips


# ============================================================================
# SINGLETON INSTANCE
# ============================================================================

_ai_sizing_analyzer = None

def get_ai_sizing_analyzer() -> AISizingAnalyzer:
    """Get singleton AI sizing analyzer instance"""
    global _ai_sizing_analyzer
    if _ai_sizing_analyzer is None:
        _ai_sizing_analyzer = AISizingAnalyzer()
    return _ai_sizing_analyzer


# Export
__all__ = [
    'AISizingAnalyzer',
    'SizingAnalysis',
    'SizingRecommendation',
    'get_ai_sizing_analyzer'
]