"""
Architecture Workflow Engine - Streamlit Cloud Compatible with AWS Cost Analysis
Includes AWS Pricing API integration for 3-year cost projections, ROI, and TCO

Enhanced workflow: Draft → WAF Review → Stakeholder Review → Approval → 
                   Cost Analysis → CI/CD Integration → Deployed
"""

import streamlit as st
import json
import boto3
from datetime import datetime
from typing import Dict, List, Optional, Any
from enum import Enum
from dataclasses import dataclass, asdict, field
import uuid

# ============================================================================
# ENUMS & CONSTANTS
# ============================================================================

class WorkflowPhase(Enum):
    """Architecture workflow phases"""
    DRAFT = "draft"
    WAF_REVIEW = "waf_review"
    STAKEHOLDER_REVIEW = "stakeholder_review"
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    COST_ANALYSIS = "cost_analysis"  # NEW: AWS Pricing & TCO
    CICD_INTEGRATION = "cicd_integration"
    DEPLOYED = "deployed"
    REJECTED = "rejected"
    ARCHIVED = "archived"

class ApprovalStatus(Enum):
    """Approval status"""
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    CHANGES_REQUESTED = "changes_requested"

class ReviewerType(Enum):
    """Reviewer types"""
    SECURITY = "security"
    PLATFORM = "platform"
    COMPLIANCE = "compliance"
    ARCHITECTURE = "architecture"
    MANAGEMENT = "management"

# ============================================================================
# DATA MODELS
# ============================================================================

@dataclass
class WAFAnalysis:
    """WAF analysis results"""
    overall_score: int
    operational_excellence: int
    security: int
    reliability: int
    performance_efficiency: int
    cost_optimization: int
    sustainability: int
    recommendations: List[str]
    risks: List[str]
    cost_optimization_opportunities: List[str]
    analyzed_at: str
    analyzed_by: str = "AI"
    
    def to_dict(self):
        return asdict(self)
    
    @staticmethod
    def from_dict(data):
        return WAFAnalysis(**data)

@dataclass
class ServiceCost:
    """Individual service cost breakdown"""
    service_name: str
    instance_type: str = ""
    quantity: int = 1
    unit_price_monthly: float = 0.0
    total_monthly: float = 0.0
    year1_cost: float = 0.0
    year2_cost: float = 0.0
    year3_cost: float = 0.0
    pricing_details: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self):
        return asdict(self)
    
    @staticmethod
    def from_dict(data):
        return ServiceCost(**data)

@dataclass
class CostAnalysis:
    """Complete cost analysis and projections"""
    # Monthly costs
    monthly_cost: float = 0.0
    
    # Yearly projections
    year1_cost: float = 0.0
    year2_cost: float = 0.0
    year3_cost: float = 0.0
    total_3year_cost: float = 0.0
    
    # Service breakdown
    service_costs: List[ServiceCost] = field(default_factory=list)
    
    # Savings opportunities
    reserved_instance_savings: float = 0.0
    savings_plan_savings: float = 0.0
    spot_instance_savings: float = 0.0
    
    # TCO (Total Cost of Ownership)
    infrastructure_cost: float = 0.0
    operational_cost: float = 0.0
    licensing_cost: float = 0.0
    support_cost: float = 0.0
    total_tco: float = 0.0
    
    # ROI (Return on Investment)
    current_cost_baseline: float = 0.0  # Current on-prem or legacy cost
    cost_savings_3year: float = 0.0
    efficiency_gains: float = 0.0
    revenue_impact: float = 0.0
    total_roi: float = 0.0
    roi_percentage: float = 0.0
    payback_months: int = 0
    
    # Metadata
    analyzed_at: str = ""
    analyzed_by: str = "AWS Pricing API"
    region: str = "us-east-1"
    currency: str = "USD"
    
    # Recommendations
    cost_optimization_recommendations: List[str] = field(default_factory=list)
    
    def to_dict(self):
        data = asdict(self)
        data['service_costs'] = [s.to_dict() for s in self.service_costs]
        return data
    
    @staticmethod
    def from_dict(data):
        if 'service_costs' in data:
            data['service_costs'] = [ServiceCost.from_dict(s) for s in data['service_costs']]
        return CostAnalysis(**data)

@dataclass
class Review:
    """Stakeholder review"""
    reviewer_id: str
    reviewer_name: str
    reviewer_type: ReviewerType
    status: ApprovalStatus
    comments: str
    reviewed_at: str
    changes_requested: List[str] = field(default_factory=list)
    
    def to_dict(self):
        data = asdict(self)
        data['reviewer_type'] = self.reviewer_type.value
        data['status'] = self.status.value
        return data
    
    @staticmethod
    def from_dict(data):
        data['reviewer_type'] = ReviewerType(data['reviewer_type'])
        data['status'] = ApprovalStatus(data['status'])
        return Review(**data)

@dataclass
class Approval:
    """Management approval"""
    approver_id: str
    approver_name: str
    approver_role: str
    status: ApprovalStatus
    comments: str
    approved_at: Optional[str] = None
    
    def to_dict(self):
        data = asdict(self)
        data['status'] = self.status.value
        return data
    
    @staticmethod
    def from_dict(data):
        data['status'] = ApprovalStatus(data['status'])
        return Approval(**data)

@dataclass
class CICDDeployment:
    """CI/CD deployment information"""
    pipeline_id: str
    pipeline_name: str
    environment: str
    iac_generated: bool
    git_commit_sha: Optional[str] = None
    repository_url: Optional[str] = None
    triggered_at: Optional[str] = None
    completed_at: Optional[str] = None
    status: str = "pending"
    deployment_url: Optional[str] = None
    
    def to_dict(self):
        return asdict(self)
    
    @staticmethod
    def from_dict(data):
        return CICDDeployment(**data)

@dataclass
class ArchitectureDesign:
    """Complete architecture design"""
    # Identification
    id: str
    name: str
    version: str = "1.0.0"
    
    # Basic info
    category: str = ""
    environment: str = ""
    owner: str = ""
    cost_center: str = ""
    target_go_live: Optional[str] = None
    
    # Architecture details
    description: str = ""
    business_requirements: str = ""
    services: List[str] = field(default_factory=list)
    compliance_requirements: List[str] = field(default_factory=list)
    
    # Sizing information (for cost calculation)
    sizing_details: Dict[str, Any] = field(default_factory=dict)
    
    # WAF considerations
    ha_required: bool = True
    multi_az: bool = True
    encryption_at_rest: bool = True
    disaster_recovery: bool = False
    auto_scaling: bool = True
    advanced_monitoring: bool = True
    
    # IaC
    iac_type: str = "Terraform"
    iac_template: str = ""
    iac_generated: bool = False
    
    # Workflow state
    phase: WorkflowPhase = WorkflowPhase.DRAFT
    created_at: str = ""
    updated_at: str = ""
    created_by: str = ""
    
    # WAF Review
    waf_analysis: Optional[WAFAnalysis] = None
    
    # Stakeholder Review
    reviews: List[Review] = field(default_factory=list)
    required_reviewers: List[str] = field(default_factory=list)
    
    # Approval
    approvals: List[Approval] = field(default_factory=list)
    required_approvers: List[str] = field(default_factory=list)
    
    # Cost Analysis (NEW)
    cost_analysis: Optional[CostAnalysis] = None
    
    # CI/CD
    cicd_deployment: Optional[CICDDeployment] = None
    
    # Audit trail
    history: List[Dict[str, Any]] = field(default_factory=list)
    
    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now().isoformat()
        if not self.updated_at:
            self.updated_at = datetime.now().isoformat()
    
    def to_dict(self):
        data = asdict(self)
        data['phase'] = self.phase.value
        if self.waf_analysis:
            data['waf_analysis'] = self.waf_analysis.to_dict()
        if self.cost_analysis:
            data['cost_analysis'] = self.cost_analysis.to_dict()
        data['reviews'] = [r.to_dict() for r in self.reviews]
        data['approvals'] = [a.to_dict() for a in self.approvals]
        if self.cicd_deployment:
            data['cicd_deployment'] = self.cicd_deployment.to_dict()
        return data
    
    @staticmethod
    def from_dict(data):
        data['phase'] = WorkflowPhase(data['phase'])
        if data.get('waf_analysis'):
            data['waf_analysis'] = WAFAnalysis.from_dict(data['waf_analysis'])
        if data.get('cost_analysis'):
            data['cost_analysis'] = CostAnalysis.from_dict(data['cost_analysis'])
        data['reviews'] = [Review.from_dict(r) for r in data.get('reviews', [])]
        data['approvals'] = [Approval.from_dict(a) for a in data.get('approvals', [])]
        if data.get('cicd_deployment'):
            data['cicd_deployment'] = CICDDeployment.from_dict(data['cicd_deployment'])
        return ArchitectureDesign(**data)
    
    def add_history_entry(self, action: str, details: str, user: str):
        """Add entry to audit trail"""
        entry = {
            'timestamp': datetime.now().isoformat(),
            'action': action,
            'details': details,
            'user': user,
            'phase': self.phase.value
        }
        self.history.append(entry)
        self.updated_at = datetime.now().isoformat()

# ============================================================================
# AWS PRICING CALCULATOR
# ============================================================================

class AWSPricingCalculator:
    """Calculate AWS costs using Pricing API"""
    
    # Default pricing (when API unavailable - approximate USD/month)
    DEFAULT_PRICING = {
        'EC2': {
            't3.micro': 7.59,
            't3.small': 15.18,
            't3.medium': 30.37,
            't3.large': 60.74,
            't3.xlarge': 121.47,
            't3.2xlarge': 242.94,
            'm5.large': 70.08,
            'm5.xlarge': 140.16,
            'm5.2xlarge': 280.32,
            'c5.large': 62.05,
            'c5.xlarge': 124.10,
            'r5.large': 91.98,
            'r5.xlarge': 183.96
        },
        'RDS': {
            'db.t3.micro': 12.41,
            'db.t3.small': 24.82,
            'db.t3.medium': 49.64,
            'db.t3.large': 99.28,
            'db.m5.large': 124.10,
            'db.m5.xlarge': 248.20,
            'db.m5.2xlarge': 496.40
        },
        'EKS': {'cluster': 73.00},  # Per cluster
        'ALB': {'alb': 16.20},  # Per ALB
        'NLB': {'nlb': 16.20},  # Per NLB
        'NAT Gateway': {'nat': 32.40},  # Per NAT Gateway
        'VPC': {'vpc': 0.00},  # Free
        'S3': {'standard': 0.023},  # Per GB/month
        'Lambda': {'invocations': 0.20},  # Per 1M requests
        'DynamoDB': {'wcu': 0.47, 'rcu': 0.09},  # Per unit/month
        'CloudFront': {'data_transfer': 0.085},  # Per GB
        'API Gateway': {'requests': 3.50},  # Per 1M requests
        'CloudWatch': {'metrics': 0.30},  # Per custom metric
        'CloudTrail': {'trail': 2.00},  # Per trail
        'GuardDuty': {'events': 4.80},  # Per 1M events
        'WAF': {'waf': 5.00}  # Per web ACL
    }
    
    def __init__(self, region: str = 'us-east-1'):
        """Initialize pricing calculator"""
        self.region = region
        self.pricing_client = None
        
        # Try to initialize boto3 pricing client
        try:
            self.pricing_client = boto3.client('pricing', region_name='us-east-1')
        except Exception as e:
            st.warning(f"AWS Pricing API unavailable, using default pricing: {str(e)}")
    
    def get_ec2_price(self, instance_type: str, quantity: int = 1) -> ServiceCost:
        """Get EC2 instance pricing"""
        monthly_price = self.DEFAULT_PRICING['EC2'].get(instance_type, 100.0)
        
        # Try AWS Pricing API
        if self.pricing_client:
            try:
                response = self.pricing_client.get_products(
                    ServiceCode='AmazonEC2',
                    Filters=[
                        {'Type': 'TERM_MATCH', 'Field': 'instanceType', 'Value': instance_type},
                        {'Type': 'TERM_MATCH', 'Field': 'location', 'Value': 'US East (N. Virginia)'},
                        {'Type': 'TERM_MATCH', 'Field': 'operatingSystem', 'Value': 'Linux'},
                        {'Type': 'TERM_MATCH', 'Field': 'tenancy', 'Value': 'Shared'},
                        {'Type': 'TERM_MATCH', 'Field': 'preInstalledSw', 'Value': 'NA'}
                    ],
                    MaxResults=1
                )
                
                if response['PriceList']:
                    price_data = json.loads(response['PriceList'][0])
                    on_demand = price_data['terms']['OnDemand']
                    price_dimensions = list(on_demand.values())[0]['priceDimensions']
                    hourly_price = float(list(price_dimensions.values())[0]['pricePerUnit']['USD'])
                    monthly_price = hourly_price * 730  # 730 hours/month average
            except Exception as e:
                pass  # Fall back to default pricing
        
        total_monthly = monthly_price * quantity
        
        return ServiceCost(
            service_name='EC2',
            instance_type=instance_type,
            quantity=quantity,
            unit_price_monthly=monthly_price,
            total_monthly=total_monthly,
            year1_cost=total_monthly * 12,
            year2_cost=total_monthly * 12 * 0.95,  # 5% savings with 1-year RI
            year3_cost=total_monthly * 12 * 0.90,  # 10% savings with commitment
            pricing_details={'region': self.region}
        )
    
    def get_rds_price(self, instance_type: str, multi_az: bool = False, quantity: int = 1) -> ServiceCost:
        """Get RDS instance pricing"""
        monthly_price = self.DEFAULT_PRICING['RDS'].get(instance_type, 150.0)
        
        if multi_az:
            monthly_price *= 2  # Multi-AZ doubles the cost
        
        total_monthly = monthly_price * quantity
        
        return ServiceCost(
            service_name='RDS',
            instance_type=f"{instance_type} {'Multi-AZ' if multi_az else 'Single-AZ'}",
            quantity=quantity,
            unit_price_monthly=monthly_price,
            total_monthly=total_monthly,
            year1_cost=total_monthly * 12,
            year2_cost=total_monthly * 12 * 0.93,  # 7% savings with 1-year RI
            year3_cost=total_monthly * 12 * 0.87,  # 13% savings with 3-year RI
            pricing_details={'multi_az': multi_az, 'region': self.region}
        )
    
    def get_service_price(self, service: str, config: Dict[str, Any] = None) -> ServiceCost:
        """Get pricing for other AWS services"""
        config = config or {}
        
        if service == 'EKS':
            monthly_price = self.DEFAULT_PRICING['EKS']['cluster']
            return ServiceCost(
                service_name='EKS',
                instance_type='Cluster',
                quantity=config.get('clusters', 1),
                unit_price_monthly=monthly_price,
                total_monthly=monthly_price * config.get('clusters', 1),
                year1_cost=monthly_price * 12 * config.get('clusters', 1),
                year2_cost=monthly_price * 12 * config.get('clusters', 1),
                year3_cost=monthly_price * 12 * config.get('clusters', 1)
            )
        
        elif service == 'ALB' or service == 'Application Load Balancer':
            monthly_price = self.DEFAULT_PRICING['ALB']['alb']
            quantity = config.get('count', 1)
            return ServiceCost(
                service_name='ALB',
                instance_type='Application Load Balancer',
                quantity=quantity,
                unit_price_monthly=monthly_price,
                total_monthly=monthly_price * quantity,
                year1_cost=monthly_price * 12 * quantity,
                year2_cost=monthly_price * 12 * quantity,
                year3_cost=monthly_price * 12 * quantity
            )
        
        elif service == 'S3':
            storage_gb = config.get('storage_gb', 1000)
            monthly_price = storage_gb * self.DEFAULT_PRICING['S3']['standard']
            return ServiceCost(
                service_name='S3',
                instance_type=f'{storage_gb} GB',
                quantity=1,
                unit_price_monthly=monthly_price,
                total_monthly=monthly_price,
                year1_cost=monthly_price * 12,
                year2_cost=monthly_price * 12 * 0.95,  # Intelligent-Tiering savings
                year3_cost=monthly_price * 12 * 0.90
            )
        
        elif service == 'Lambda':
            monthly_price = config.get('estimated_cost', 20.0)
            return ServiceCost(
                service_name='Lambda',
                instance_type='Serverless',
                quantity=1,
                unit_price_monthly=monthly_price,
                total_monthly=monthly_price,
                year1_cost=monthly_price * 12,
                year2_cost=monthly_price * 12,
                year3_cost=monthly_price * 12
            )
        
        elif service == 'DynamoDB':
            monthly_price = config.get('estimated_cost', 25.0)
            return ServiceCost(
                service_name='DynamoDB',
                instance_type='On-Demand',
                quantity=1,
                unit_price_monthly=monthly_price,
                total_monthly=monthly_price,
                year1_cost=monthly_price * 12,
                year2_cost=monthly_price * 12,
                year3_cost=monthly_price * 12
            )
        
        elif service == 'CloudFront':
            monthly_price = config.get('estimated_cost', 50.0)
            return ServiceCost(
                service_name='CloudFront',
                instance_type='CDN',
                quantity=1,
                unit_price_monthly=monthly_price,
                total_monthly=monthly_price,
                year1_cost=monthly_price * 12,
                year2_cost=monthly_price * 12,
                year3_cost=monthly_price * 12
            )
        
        elif service == 'VPC':
            return ServiceCost(
                service_name='VPC',
                instance_type='Virtual Private Cloud',
                quantity=1,
                unit_price_monthly=0.0,
                total_monthly=0.0,
                year1_cost=0.0,
                year2_cost=0.0,
                year3_cost=0.0
            )
        
        else:
            # Generic service - estimate $50/month
            monthly_price = 50.0
            return ServiceCost(
                service_name=service,
                instance_type='Standard',
                quantity=1,
                unit_price_monthly=monthly_price,
                total_monthly=monthly_price,
                year1_cost=monthly_price * 12,
                year2_cost=monthly_price * 12,
                year3_cost=monthly_price * 12
            )
    
    def calculate_architecture_cost(self, design: ArchitectureDesign) -> CostAnalysis:
        """Calculate complete cost analysis for architecture"""
        service_costs = []
        
        # Get sizing details or use defaults
        sizing = design.sizing_details or {}
        
        # Calculate costs for each service
        for service in design.services:
            if service == 'EC2':
                instance_type = sizing.get('ec2_instance_type', 't3.medium')
                quantity = sizing.get('ec2_count', 2)
                service_costs.append(self.get_ec2_price(instance_type, quantity))
            
            elif service == 'RDS':
                instance_type = sizing.get('rds_instance_type', 'db.t3.medium')
                multi_az = design.multi_az
                service_costs.append(self.get_rds_price(instance_type, multi_az, 1))
            
            else:
                config = sizing.get(service.lower(), {})
                service_costs.append(self.get_service_price(service, config))
        
        # Calculate totals
        monthly_cost = sum(s.total_monthly for s in service_costs)
        year1_cost = sum(s.year1_cost for s in service_costs)
        year2_cost = sum(s.year2_cost for s in service_costs)
        year3_cost = sum(s.year3_cost for s in service_costs)
        total_3year = year1_cost + year2_cost + year3_cost
        
        # Calculate savings opportunities
        ri_savings = year1_cost * 0.30  # 30% savings with Reserved Instances
        sp_savings = year1_cost * 0.25  # 25% savings with Savings Plans
        spot_savings = year1_cost * 0.15  # 15% potential with Spot instances
        
        # Calculate TCO
        infrastructure_cost = total_3year
        operational_cost = total_3year * 0.20  # 20% for operations
        licensing_cost = total_3year * 0.10  # 10% for licenses
        support_cost = total_3year * 0.10  # 10% for AWS support
        total_tco = infrastructure_cost + operational_cost + licensing_cost + support_cost
        
        # Calculate ROI (assuming migration from on-prem)
        current_baseline = sizing.get('current_cost_baseline', total_3year * 1.5)  # Assume on-prem 50% more expensive
        cost_savings = current_baseline - total_tco
        efficiency_gains = total_3year * 0.30  # 30% efficiency improvement
        revenue_impact = total_3year * 0.20  # 20% revenue impact from faster time to market
        total_roi = cost_savings + efficiency_gains + revenue_impact
        roi_percentage = (total_roi / total_tco) * 100 if total_tco > 0 else 0
        payback_months = int((total_tco / (total_roi / 36)) if total_roi > 0 else 36)
        
        # Generate recommendations
        recommendations = []
        if ri_savings > monthly_cost * 2:
            recommendations.append(f"Consider Reserved Instances: Save up to ${ri_savings:,.0f} over 3 years")
        if design.auto_scaling:
            recommendations.append("Auto-scaling enabled: Right-size instances during low usage")
        if 'S3' in design.services:
            recommendations.append("Implement S3 Intelligent-Tiering for automatic cost optimization")
        if 'Lambda' in design.services or 'DynamoDB' in design.services:
            recommendations.append("Serverless services detected: Pay only for what you use")
        
        return CostAnalysis(
            monthly_cost=monthly_cost,
            year1_cost=year1_cost,
            year2_cost=year2_cost,
            year3_cost=year3_cost,
            total_3year_cost=total_3year,
            service_costs=service_costs,
            reserved_instance_savings=ri_savings,
            savings_plan_savings=sp_savings,
            spot_instance_savings=spot_savings,
            infrastructure_cost=infrastructure_cost,
            operational_cost=operational_cost,
            licensing_cost=licensing_cost,
            support_cost=support_cost,
            total_tco=total_tco,
            current_cost_baseline=current_baseline,
            cost_savings_3year=cost_savings,
            efficiency_gains=efficiency_gains,
            revenue_impact=revenue_impact,
            total_roi=total_roi,
            roi_percentage=roi_percentage,
            payback_months=payback_months,
            analyzed_at=datetime.now().isoformat(),
            region=self.region,
            cost_optimization_recommendations=recommendations
        )

# ============================================================================
# WORKFLOW ENGINE - STREAMLIT CLOUD COMPATIBLE
# ============================================================================

class WorkflowEngine:
    """Streamlit Cloud compatible workflow engine with AWS Cost Analysis"""
    
    def __init__(self):
        """Initialize workflow engine"""
        if 'workflow_designs' not in st.session_state:
            st.session_state.workflow_designs = {}
        
        if 'workflow_initialized' not in st.session_state:
            st.session_state.workflow_initialized = True
    
    # ========================================================================
    # PERSISTENCE
    # ========================================================================
    
    def _save_design(self, design: ArchitectureDesign):
        """Save design to session state"""
        st.session_state.workflow_designs[design.id] = design
        return True
    
    def _load_design(self, design_id: str) -> Optional[ArchitectureDesign]:
        """Load design from session state"""
        return st.session_state.workflow_designs.get(design_id)
    
    # ========================================================================
    # DESIGN MANAGEMENT
    # ========================================================================
    
    def create_design(self, design_data: Dict[str, Any], created_by: str) -> ArchitectureDesign:
        """Create new architecture design"""
        design_id = str(uuid.uuid4())
        
        design = ArchitectureDesign(
            id=design_id,
            name=design_data.get('name', 'Untitled'),
            category=design_data.get('category', ''),
            environment=design_data.get('environment', ''),
            owner=design_data.get('owner', ''),
            cost_center=design_data.get('cost_center', ''),
            target_go_live=design_data.get('target_go_live'),
            description=design_data.get('description', ''),
            business_requirements=design_data.get('business_requirements', ''),
            services=design_data.get('services', []),
            compliance_requirements=design_data.get('compliance_requirements', []),
            sizing_details=design_data.get('sizing_details', {}),
            ha_required=design_data.get('ha_required', True),
            multi_az=design_data.get('multi_az', True),
            encryption_at_rest=design_data.get('encryption_at_rest', True),
            disaster_recovery=design_data.get('disaster_recovery', False),
            auto_scaling=design_data.get('auto_scaling', True),
            advanced_monitoring=design_data.get('advanced_monitoring', True),
            iac_type=design_data.get('iac_type', 'Terraform'),
            iac_template=design_data.get('iac_template', ''),
            created_by=created_by,
            phase=WorkflowPhase.DRAFT
        )
        
        design.add_history_entry(
            action="CREATED",
            details=f"Architecture design '{design.name}' created",
            user=created_by
        )
        
        self._save_design(design)
        return design
    
    def get_design(self, design_id: str) -> Optional[ArchitectureDesign]:
        """Get design by ID"""
        return self._load_design(design_id)
    
    def list_designs(self, phase: Optional[WorkflowPhase] = None) -> List[ArchitectureDesign]:
        """List all designs, optionally filtered by phase"""
        designs = list(st.session_state.workflow_designs.values())
        
        if phase:
            designs = [d for d in designs if d.phase == phase]
        
        designs.sort(key=lambda d: d.updated_at, reverse=True)
        return designs
    
    def update_design(self, design_id: str, updates: Dict[str, Any], updated_by: str) -> bool:
        """Update design fields"""
        design = self.get_design(design_id)
        if not design:
            return False
        
        if design.phase != WorkflowPhase.DRAFT:
            st.error("Design can only be updated in DRAFT phase")
            return False
        
        for key, value in updates.items():
            if hasattr(design, key):
                setattr(design, key, value)
        
        design.add_history_entry(
            action="UPDATED",
            details="Design updated",
            user=updated_by
        )
        
        return self._save_design(design)
    
    def delete_design(self, design_id: str) -> bool:
        """Delete a design"""
        if design_id in st.session_state.workflow_designs:
            del st.session_state.workflow_designs[design_id]
            return True
        return False
    
    # ========================================================================
    # PHASE TRANSITIONS
    # ========================================================================
    
    def transition_to_waf_review(self, design_id: str, user: str) -> bool:
        """Transition design to WAF Review phase"""
        design = self.get_design(design_id)
        if not design:
            return False
        
        if design.phase != WorkflowPhase.DRAFT:
            st.error("Design must be in DRAFT phase")
            return False
        
        if not design.name or not design.description or not design.services:
            st.error("Please fill in all required fields (name, description, services)")
            return False
        
        design.phase = WorkflowPhase.WAF_REVIEW
        design.add_history_entry(
            action="PHASE_TRANSITION",
            details="Submitted for WAF Review",
            user=user
        )
        
        return self._save_design(design)
    
    def complete_waf_review(self, design_id: str, waf_analysis: WAFAnalysis, user: str) -> bool:
        """Complete WAF review and move to Stakeholder Review"""
        design = self.get_design(design_id)
        if not design:
            return False
        
        if design.phase != WorkflowPhase.WAF_REVIEW:
            st.error("Design must be in WAF_REVIEW phase")
            return False
        
        design.waf_analysis = waf_analysis
        design.phase = WorkflowPhase.STAKEHOLDER_REVIEW
        
        if not design.required_reviewers:
            design.required_reviewers = ['security-team', 'platform-team']
        
        design.add_history_entry(
            action="WAF_REVIEW_COMPLETE",
            details=f"WAF Analysis complete. Score: {waf_analysis.overall_score}/100",
            user=user
        )
        
        return self._save_design(design)
    
    def add_stakeholder_review(self, design_id: str, review: Review) -> bool:
        """Add stakeholder review"""
        design = self.get_design(design_id)
        if not design:
            return False
        
        if design.phase != WorkflowPhase.STAKEHOLDER_REVIEW:
            st.error("Design must be in STAKEHOLDER_REVIEW phase")
            return False
        
        existing = [r for r in design.reviews if r.reviewer_id == review.reviewer_id]
        if existing:
            design.reviews = [r for r in design.reviews if r.reviewer_id != review.reviewer_id]
        
        design.reviews.append(review)
        
        design.add_history_entry(
            action="REVIEW_ADDED",
            details=f"Review from {review.reviewer_name}: {review.status.value}",
            user=review.reviewer_id
        )
        
        if self._all_reviewers_approved(design):
            design.phase = WorkflowPhase.PENDING_APPROVAL
            
            if not design.required_approvers:
                design.required_approvers = ['engineering-director', 'vp-engineering']
            
            design.add_history_entry(
                action="PHASE_TRANSITION",
                details="All stakeholders approved. Moved to Pending Approval",
                user="system"
            )
        
        return self._save_design(design)
    
    def _all_reviewers_approved(self, design: ArchitectureDesign) -> bool:
        """Check if all required reviewers approved"""
        approved_reviewers = {r.reviewer_id for r in design.reviews if r.status == ApprovalStatus.APPROVED}
        required = set(design.required_reviewers)
        return required.issubset(approved_reviewers)
    
    def add_approval(self, design_id: str, approval: Approval) -> bool:
        """Add management approval"""
        design = self.get_design(design_id)
        if not design:
            return False
        
        if design.phase != WorkflowPhase.PENDING_APPROVAL:
            st.error("Design must be in PENDING_APPROVAL phase")
            return False
        
        existing = [a for a in design.approvals if a.approver_id == approval.approver_id]
        if existing:
            design.approvals = [a for a in design.approvals if a.approver_id != approval.approver_id]
        
        design.approvals.append(approval)
        
        design.add_history_entry(
            action="APPROVAL_ADDED",
            details=f"Approval from {approval.approver_name}: {approval.status.value}",
            user=approval.approver_id
        )
        
        if self._all_approvers_approved(design):
            design.phase = WorkflowPhase.APPROVED
            design.add_history_entry(
                action="PHASE_TRANSITION",
                details="All approvals received. Design APPROVED - Ready for Cost Analysis",
                user="system"
            )
        elif self._any_approver_rejected(design):
            design.phase = WorkflowPhase.REJECTED
            design.add_history_entry(
                action="PHASE_TRANSITION",
                details="Design REJECTED by management",
                user="system"
            )
        
        return self._save_design(design)
    
    def _all_approvers_approved(self, design: ArchitectureDesign) -> bool:
        """Check if all required approvers approved"""
        approved = {a.approver_id for a in design.approvals if a.status == ApprovalStatus.APPROVED}
        required = set(design.required_approvers)
        return required.issubset(approved)
    
    def _any_approver_rejected(self, design: ArchitectureDesign) -> bool:
        """Check if any approver rejected"""
        return any(a.status == ApprovalStatus.REJECTED for a in design.approvals)
    
    # ========================================================================
    # COST ANALYSIS (NEW)
    # ========================================================================
    
    def start_cost_analysis(self, design_id: str, region: str = 'us-east-1') -> bool:
        """Start AWS cost analysis"""
        design = self.get_design(design_id)
        if not design:
            return False
        
        if design.phase != WorkflowPhase.APPROVED:
            st.error("Design must be APPROVED before cost analysis")
            return False
        
        design.phase = WorkflowPhase.COST_ANALYSIS
        design.add_history_entry(
            action="COST_ANALYSIS_START",
            details="Starting AWS cost analysis and 3-year projection",
            user="system"
        )
        
        return self._save_design(design)
    
    def complete_cost_analysis(self, design_id: str, cost_analysis: CostAnalysis) -> bool:
        """Complete cost analysis"""
        design = self.get_design(design_id)
        if not design:
            return False
        
        if design.phase != WorkflowPhase.COST_ANALYSIS:
            st.error("Design must be in COST_ANALYSIS phase")
            return False
        
        design.cost_analysis = cost_analysis
        
        design.add_history_entry(
            action="COST_ANALYSIS_COMPLETE",
            details=f"Cost Analysis complete. 3-year TCO: ${cost_analysis.total_tco:,.0f}, ROI: {cost_analysis.roi_percentage:.1f}%",
            user="AWS Pricing API"
        )
        
        # Don't auto-transition - wait for user confirmation
        return self._save_design(design)
    
    def approve_cost_analysis(self, design_id: str, user: str) -> bool:
        """Approve cost analysis and proceed to CI/CD"""
        design = self.get_design(design_id)
        if not design:
            return False
        
        if design.phase != WorkflowPhase.COST_ANALYSIS:
            st.error("Design must be in COST_ANALYSIS phase")
            return False
        
        if not design.cost_analysis:
            st.error("Cost analysis must be completed first")
            return False
        
        design.add_history_entry(
            action="COST_APPROVED",
            details=f"Cost analysis approved. Ready for CI/CD deployment.",
            user=user
        )
        
        # Note: Don't transition to CICD yet - user will trigger that separately
        return self._save_design(design)
    
    # ========================================================================
    # CI/CD INTEGRATION
    # ========================================================================
    
    def start_cicd_integration(self, design_id: str, iac_code: str, user: str) -> bool:
        """Start CI/CD integration"""
        design = self.get_design(design_id)
        if not design:
            return False
        
        # Must have completed cost analysis
        if design.phase != WorkflowPhase.COST_ANALYSIS:
            st.error("Must complete cost analysis before CI/CD deployment")
            return False
        
        if not design.cost_analysis:
            st.error("Cost analysis required before deployment")
            return False
        
        design.iac_template = iac_code
        design.iac_generated = True
        
        design.cicd_deployment = CICDDeployment(
            pipeline_id=f"pipe-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            pipeline_name=f"deploy-{design.environment}-{design.name}",
            environment=design.environment,
            iac_generated=True,
            triggered_at=datetime.now().isoformat(),
            status="triggered"
        )
        
        design.phase = WorkflowPhase.CICD_INTEGRATION
        design.add_history_entry(
            action="CICD_INTEGRATION_START",
            details=f"CI/CD pipeline triggered: {design.cicd_deployment.pipeline_id}",
            user=user
        )
        
        return self._save_design(design)
    
    def update_cicd_status(self, design_id: str, status: str, details: Dict[str, Any]) -> bool:
        """Update CI/CD deployment status"""
        design = self.get_design(design_id)
        if not design or not design.cicd_deployment:
            return False
        
        design.cicd_deployment.status = status
        
        if details.get('git_commit_sha'):
            design.cicd_deployment.git_commit_sha = details['git_commit_sha']
        if details.get('repository_url'):
            design.cicd_deployment.repository_url = details['repository_url']
        if details.get('deployment_url'):
            design.cicd_deployment.deployment_url = details['deployment_url']
        
        if status == "deployed":
            design.cicd_deployment.completed_at = datetime.now().isoformat()
            design.phase = WorkflowPhase.DEPLOYED
            design.add_history_entry(
                action="DEPLOYED",
                details="Architecture successfully deployed to production",
                user="cicd-system"
            )
        elif status == "failed":
            design.add_history_entry(
                action="DEPLOYMENT_FAILED",
                details=f"Deployment failed: {details.get('error', 'Unknown error')}",
                user="cicd-system"
            )
        
        return self._save_design(design)
    
    def return_to_draft(self, design_id: str, reason: str, user: str) -> bool:
        """Return design to DRAFT phase for changes"""
        design = self.get_design(design_id)
        if not design:
            return False
        
        design.phase = WorkflowPhase.DRAFT
        design.add_history_entry(
            action="RETURNED_TO_DRAFT",
            details=f"Returned to draft. Reason: {reason}",
            user=user
        )
        
        return self._save_design(design)
    
    # ========================================================================
    # UTILITIES
    # ========================================================================
    
    def get_phase_statistics(self) -> Dict[WorkflowPhase, int]:
        """Get count of designs in each phase"""
        stats = {phase: 0 for phase in WorkflowPhase}
        
        for design in st.session_state.workflow_designs.values():
            stats[design.phase] += 1
        
        return stats
    
    def get_designs_requiring_action(self, user_id: str, user_role: str) -> List[ArchitectureDesign]:
        """Get designs requiring action from this user"""
        designs = []
        
        for design in st.session_state.workflow_designs.values():
            if design.phase == WorkflowPhase.STAKEHOLDER_REVIEW:
                if user_id in design.required_reviewers:
                    if not any(r.reviewer_id == user_id for r in design.reviews):
                        designs.append(design)
            
            elif design.phase == WorkflowPhase.PENDING_APPROVAL:
                if user_id in design.required_approvers:
                    if not any(a.approver_id == user_id for a in design.approvals):
                        designs.append(design)
        
        return designs
    
    def search_designs(self, query: str) -> List[ArchitectureDesign]:
        """Search designs by name, description, or services"""
        results = []
        query_lower = query.lower()
        
        for design in st.session_state.workflow_designs.values():
            if (query_lower in design.name.lower() or
                query_lower in design.description.lower() or
                any(query_lower in s.lower() for s in design.services)):
                results.append(design)
        
        return results
    
    def export_all_designs(self) -> str:
        """Export all designs as JSON for backup"""
        export_data = {
            'version': '2.0.0',
            'exported_at': datetime.now().isoformat(),
            'designs': {
                design_id: design.to_dict()
                for design_id, design in st.session_state.workflow_designs.items()
            }
        }
        return json.dumps(export_data, indent=2)
    
    def import_designs(self, json_data: str) -> int:
        """Import designs from JSON backup"""
        try:
            import_data = json.loads(json_data)
            designs_data = import_data.get('designs', import_data)  # Handle both old and new format
            count = 0
            
            for design_id, design_dict in designs_data.items():
                design = ArchitectureDesign.from_dict(design_dict)
                st.session_state.workflow_designs[design_id] = design
                count += 1
            
            return count
        except Exception as e:
            st.error(f"Import error: {str(e)}")
            return 0


# ============================================================================
# SINGLETON INSTANCE
# ============================================================================

_workflow_engine = None

def get_workflow_engine() -> WorkflowEngine:
    """Get singleton workflow engine instance"""
    global _workflow_engine
    if _workflow_engine is None:
        _workflow_engine = WorkflowEngine()
    return _workflow_engine


# Export
__all__ = [
    'WorkflowEngine',
    'WorkflowPhase',
    'ApprovalStatus',
    'ReviewerType',
    'ArchitectureDesign',
    'WAFAnalysis',
    'Review',
    'Approval',
    'CICDDeployment',
    'CostAnalysis',
    'ServiceCost',
    'AWSPricingCalculator',
    'get_workflow_engine'
]