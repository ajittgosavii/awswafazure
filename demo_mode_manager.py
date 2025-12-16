"""
Demo Mode Manager for AWS WAF Scanner Enterprise
=================================================
Provides comprehensive demo/simulation capabilities for:
- Sales demonstrations
- Training and onboarding
- Testing without AWS credentials
- Offline development

Version: 4.0.0
"""

import streamlit as st
import random
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
import json

# ============================================================================
# DEMO MODE CONFIGURATION
# ============================================================================

@dataclass
class DemoConfig:
    """Configuration for demo mode behavior"""
    # Simulated account info
    account_id: str = "123456789012"
    account_name: str = "Demo-Production"
    region: str = "us-east-1"
    organization_id: str = "o-abc123demo"
    
    # Simulation settings
    resource_count_multiplier: float = 1.0  # Adjust for larger/smaller demos
    issue_severity_distribution: Dict[str, float] = field(default_factory=lambda: {
        "critical": 0.05,
        "high": 0.15,
        "medium": 0.35,
        "low": 0.45
    })
    waf_score_range: tuple = (65, 92)
    
    # Demo personas
    available_personas: List[str] = field(default_factory=lambda: [
        "enterprise_finance",
        "healthcare_hipaa",
        "startup_saas",
        "retail_pci",
        "government_fedramp"
    ])

# ============================================================================
# DEMO MODE MANAGER
# ============================================================================

class DemoModeManager:
    """
    Centralized manager for demo mode functionality.
    Controls all simulated data generation and mode switching.
    """
    
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self.config = DemoConfig()
        self._demo_cache = {}
    
    @property
    def is_demo_mode(self) -> bool:
        """Check if demo mode is active"""
        return st.session_state.get('demo_mode', True)
    
    @is_demo_mode.setter
    def is_demo_mode(self, value: bool):
        """Set demo mode state"""
        st.session_state.demo_mode = value
        if value:
            self._initialize_demo_session()
    
    def _initialize_demo_session(self):
        """Initialize demo session with consistent data"""
        if 'demo_seed' not in st.session_state:
            st.session_state.demo_seed = random.randint(1000, 9999)
        random.seed(st.session_state.demo_seed)
    
    def get_mode_label(self) -> str:
        """Get current mode label for display"""
        return "🎭 DEMO MODE" if self.is_demo_mode else "🔴 LIVE MODE"
    
    def get_mode_color(self) -> str:
        """Get color for mode indicator"""
        return "#FF6B6B" if self.is_demo_mode else "#4CAF50"
    
    # ========================================================================
    # DEMO AWS IDENTITY
    # ========================================================================
    
    def get_demo_identity(self) -> Dict[str, Any]:
        """Get simulated AWS caller identity"""
        return {
            "Account": self.config.account_id,
            "Arn": f"arn:aws:iam::{self.config.account_id}:user/demo-admin",
            "UserId": "AIDADEMO123456789ABCD"
        }
    
    def get_demo_accounts(self) -> List[Dict[str, Any]]:
        """Get simulated multi-account list"""
        return [
            {
                "account_id": "123456789012",
                "name": "Production",
                "email": "prod@demo-company.com",
                "status": "ACTIVE",
                "ou": "Production OU",
                "tags": {"Environment": "Production", "CostCenter": "IT-001"}
            },
            {
                "account_id": "234567890123",
                "name": "Development",
                "email": "dev@demo-company.com",
                "status": "ACTIVE",
                "ou": "Development OU",
                "tags": {"Environment": "Development", "CostCenter": "IT-002"}
            },
            {
                "account_id": "345678901234",
                "name": "Staging",
                "email": "staging@demo-company.com",
                "status": "ACTIVE",
                "ou": "Staging OU",
                "tags": {"Environment": "Staging", "CostCenter": "IT-001"}
            },
            {
                "account_id": "456789012345",
                "name": "Security",
                "email": "security@demo-company.com",
                "status": "ACTIVE",
                "ou": "Security OU",
                "tags": {"Environment": "Security", "CostCenter": "SEC-001"}
            },
            {
                "account_id": "567890123456",
                "name": "Shared Services",
                "email": "shared@demo-company.com",
                "status": "ACTIVE",
                "ou": "Infrastructure OU",
                "tags": {"Environment": "Shared", "CostCenter": "IT-003"}
            }
        ]
    
    # ========================================================================
    # DEMO RESOURCES
    # ========================================================================
    
    def get_demo_resources(self) -> Dict[str, Any]:
        """Get simulated AWS resource inventory"""
        multiplier = self.config.resource_count_multiplier
        
        return {
            "ec2_instances": int(47 * multiplier),
            "rds_databases": int(12 * multiplier),
            "s3_buckets": int(34 * multiplier),
            "lambda_functions": int(89 * multiplier),
            "eks_clusters": int(3 * multiplier),
            "ecs_clusters": int(2 * multiplier),
            "vpc_count": int(8 * multiplier),
            "security_groups": int(156 * multiplier),
            "iam_users": int(45 * multiplier),
            "iam_roles": int(127 * multiplier),
            "cloudfront_distributions": int(5 * multiplier),
            "api_gateways": int(8 * multiplier),
            "dynamodb_tables": int(23 * multiplier),
            "sns_topics": int(34 * multiplier),
            "sqs_queues": int(28 * multiplier),
            "secrets_manager": int(15 * multiplier),
            "kms_keys": int(12 * multiplier),
            "elastic_ips": int(18 * multiplier),
            "nat_gateways": int(4 * multiplier),
            "load_balancers": int(9 * multiplier),
            "target_groups": int(15 * multiplier),
            "auto_scaling_groups": int(11 * multiplier),
            "cloudwatch_alarms": int(67 * multiplier),
            "config_rules": int(42 * multiplier),
            "guardduty_findings": int(8 * multiplier),
        }
    
    def get_demo_resource_details(self, resource_type: str) -> List[Dict[str, Any]]:
        """Get detailed list of simulated resources"""
        resources = {
            "ec2": self._generate_ec2_instances(),
            "rds": self._generate_rds_instances(),
            "s3": self._generate_s3_buckets(),
            "lambda": self._generate_lambda_functions(),
            "eks": self._generate_eks_clusters(),
            "security_groups": self._generate_security_groups(),
        }
        return resources.get(resource_type, [])
    
    def _generate_ec2_instances(self) -> List[Dict[str, Any]]:
        """Generate demo EC2 instances"""
        instance_types = ["t3.micro", "t3.small", "t3.medium", "m5.large", "m5.xlarge", "c5.xlarge", "r5.large"]
        states = ["running", "running", "running", "stopped", "running"]
        
        instances = []
        for i in range(int(47 * self.config.resource_count_multiplier)):
            instances.append({
                "instance_id": f"i-{random.randint(10000000, 99999999):08x}",
                "name": f"demo-server-{i+1:03d}",
                "instance_type": random.choice(instance_types),
                "state": random.choice(states),
                "az": f"{self.config.region}{random.choice(['a', 'b', 'c'])}",
                "private_ip": f"10.0.{random.randint(1, 254)}.{random.randint(1, 254)}",
                "public_ip": f"52.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}" if random.random() > 0.6 else None,
                "launch_time": (datetime.now() - timedelta(days=random.randint(1, 365))).isoformat(),
                "tags": {"Environment": random.choice(["Production", "Development", "Staging"])}
            })
        return instances
    
    def _generate_rds_instances(self) -> List[Dict[str, Any]]:
        """Generate demo RDS instances"""
        engines = ["mysql", "postgres", "aurora-mysql", "aurora-postgresql", "mariadb"]
        classes = ["db.t3.micro", "db.t3.small", "db.r5.large", "db.r5.xlarge"]
        
        instances = []
        for i in range(int(12 * self.config.resource_count_multiplier)):
            instances.append({
                "db_instance_id": f"demo-db-{i+1:02d}",
                "engine": random.choice(engines),
                "instance_class": random.choice(classes),
                "status": "available",
                "multi_az": random.random() > 0.4,
                "storage_encrypted": random.random() > 0.2,
                "backup_retention": random.randint(0, 35),
                "publicly_accessible": random.random() > 0.8,
            })
        return instances
    
    def _generate_s3_buckets(self) -> List[Dict[str, Any]]:
        """Generate demo S3 buckets"""
        buckets = []
        purposes = ["logs", "data", "backup", "static", "uploads", "archive", "reports"]
        
        for i in range(int(34 * self.config.resource_count_multiplier)):
            buckets.append({
                "name": f"demo-company-{random.choice(purposes)}-{i+1:03d}",
                "region": self.config.region,
                "creation_date": (datetime.now() - timedelta(days=random.randint(30, 730))).isoformat(),
                "versioning": random.choice(["Enabled", "Suspended", "Disabled"]),
                "encryption": random.choice(["AES256", "aws:kms", None]),
                "public_access_blocked": random.random() > 0.15,
                "logging_enabled": random.random() > 0.5,
            })
        return buckets
    
    def _generate_lambda_functions(self) -> List[Dict[str, Any]]:
        """Generate demo Lambda functions"""
        runtimes = ["python3.11", "python3.10", "nodejs18.x", "nodejs16.x", "java17", "go1.x"]
        
        functions = []
        for i in range(int(89 * self.config.resource_count_multiplier)):
            functions.append({
                "function_name": f"demo-function-{i+1:03d}",
                "runtime": random.choice(runtimes),
                "memory": random.choice([128, 256, 512, 1024, 2048]),
                "timeout": random.randint(3, 900),
                "last_modified": (datetime.now() - timedelta(days=random.randint(1, 180))).isoformat(),
                "code_size": random.randint(1000, 50000000),
            })
        return functions
    
    def _generate_eks_clusters(self) -> List[Dict[str, Any]]:
        """Generate demo EKS clusters"""
        return [
            {
                "name": "demo-prod-cluster",
                "version": "1.28",
                "status": "ACTIVE",
                "node_groups": 3,
                "total_nodes": 12,
                "endpoint": "https://ABC123.gr7.us-east-1.eks.amazonaws.com",
            },
            {
                "name": "demo-staging-cluster",
                "version": "1.28",
                "status": "ACTIVE",
                "node_groups": 2,
                "total_nodes": 6,
                "endpoint": "https://DEF456.gr7.us-east-1.eks.amazonaws.com",
            },
            {
                "name": "demo-dev-cluster",
                "version": "1.27",
                "status": "ACTIVE",
                "node_groups": 1,
                "total_nodes": 3,
                "endpoint": "https://GHI789.gr7.us-east-1.eks.amazonaws.com",
            },
        ]
    
    def _generate_security_groups(self) -> List[Dict[str, Any]]:
        """Generate demo security groups"""
        sgs = []
        for i in range(int(156 * self.config.resource_count_multiplier)):
            has_open_ingress = random.random() > 0.85
            sgs.append({
                "group_id": f"sg-{random.randint(10000000, 99999999):08x}",
                "group_name": f"demo-sg-{i+1:03d}",
                "vpc_id": f"vpc-{random.randint(10000000, 99999999):08x}",
                "description": f"Security group for demo resources {i+1}",
                "inbound_rules": random.randint(1, 15),
                "outbound_rules": random.randint(1, 5),
                "open_to_world": has_open_ingress,
            })
        return sgs
    
    # ========================================================================
    # DEMO WAF FINDINGS
    # ========================================================================
    
    def get_demo_waf_findings(self) -> Dict[str, Any]:
        """Get simulated WAF assessment findings"""
        
        findings = {
            "security": self._generate_pillar_findings("Security", [
                ("S3 buckets without encryption", "high", 3),
                ("EC2 instances with public IPs in production", "high", 5),
                ("Security groups with 0.0.0.0/0 ingress", "critical", 2),
                ("IAM users without MFA enabled", "critical", 4),
                ("RDS instances publicly accessible", "high", 1),
                ("KMS keys without rotation", "medium", 6),
                ("Secrets not using Secrets Manager", "medium", 8),
                ("CloudTrail not enabled in all regions", "high", 1),
            ]),
            "reliability": self._generate_pillar_findings("Reliability", [
                ("RDS without Multi-AZ deployment", "high", 4),
                ("No backup configured for critical databases", "critical", 2),
                ("Single AZ deployment for production workloads", "high", 3),
                ("Auto-scaling not configured", "medium", 7),
                ("No disaster recovery plan documented", "medium", 1),
                ("Health checks not configured for load balancers", "medium", 5),
            ]),
            "performance": self._generate_pillar_findings("Performance Efficiency", [
                ("Oversized EC2 instances detected", "low", 12),
                ("CloudFront not used for static content", "medium", 3),
                ("Database queries without indexes", "medium", 8),
                ("Lambda functions with excessive memory", "low", 15),
                ("No caching layer implemented", "medium", 2),
            ]),
            "cost": self._generate_pillar_findings("Cost Optimization", [
                ("Unattached EBS volumes", "medium", 8),
                ("Idle EC2 instances (low CPU utilization)", "medium", 6),
                ("No Reserved Instance coverage", "low", 1),
                ("Unused Elastic IPs", "low", 4),
                ("Old generation instance types", "low", 9),
                ("S3 buckets without lifecycle policies", "medium", 12),
            ]),
            "operational": self._generate_pillar_findings("Operational Excellence", [
                ("Resources without proper tagging", "medium", 34),
                ("No runbooks documented", "medium", 1),
                ("CloudWatch alarms not configured", "high", 5),
                ("No automated patching enabled", "medium", 8),
                ("Infrastructure not defined as code", "medium", 3),
            ]),
            "sustainability": self._generate_pillar_findings("Sustainability", [
                ("Workloads not optimized for Graviton", "low", 15),
                ("No data lifecycle management", "low", 8),
                ("Oversized storage allocations", "low", 6),
            ]),
        }
        
        # Calculate summary
        total_findings = sum(
            len(pillar["findings"]) 
            for pillar in findings.values()
        )
        
        critical_count = sum(
            sum(1 for f in pillar["findings"] if f["severity"] == "critical")
            for pillar in findings.values()
        )
        
        high_count = sum(
            sum(1 for f in pillar["findings"] if f["severity"] == "high")
            for pillar in findings.values()
        )
        
        # Calculate WAF score
        base_score = random.randint(*self.config.waf_score_range)
        waf_score = max(0, base_score - (critical_count * 5) - (high_count * 2))
        
        return {
            "findings": findings,
            "summary": {
                "total_findings": total_findings,
                "critical_count": critical_count,
                "high_count": high_count,
                "medium_count": sum(
                    sum(1 for f in pillar["findings"] if f["severity"] == "medium")
                    for pillar in findings.values()
                ),
                "low_count": sum(
                    sum(1 for f in pillar["findings"] if f["severity"] == "low")
                    for pillar in findings.values()
                ),
                "waf_score": waf_score,
                "scan_time": datetime.now().isoformat(),
                "account_id": self.config.account_id,
                "region": self.config.region,
            },
            "pillar_scores": {
                "security": random.randint(60, 85),
                "reliability": random.randint(65, 90),
                "performance": random.randint(70, 95),
                "cost": random.randint(55, 80),
                "operational": random.randint(60, 85),
                "sustainability": random.randint(70, 95),
            }
        }
    
    def _generate_pillar_findings(
        self, 
        pillar: str, 
        finding_templates: List[tuple]
    ) -> Dict[str, Any]:
        """Generate findings for a specific WAF pillar"""
        findings = []
        
        for title, severity, count in finding_templates:
            for i in range(count):
                findings.append({
                    "id": f"WAF-{pillar[:3].upper()}-{len(findings)+1:04d}",
                    "title": title,
                    "severity": severity,
                    "pillar": pillar,
                    "resource_type": self._infer_resource_type(title),
                    "resource_id": f"demo-resource-{random.randint(1000, 9999)}",
                    "description": f"Demo finding: {title}",
                    "recommendation": f"Recommended action for: {title}",
                    "compliance_frameworks": self._get_compliance_frameworks(severity),
                    "detected_at": (datetime.now() - timedelta(hours=random.randint(1, 72))).isoformat(),
                })
        
        return {
            "pillar": pillar,
            "findings": findings,
            "finding_count": len(findings),
        }
    
    def _infer_resource_type(self, title: str) -> str:
        """Infer resource type from finding title"""
        mappings = {
            "S3": "AWS::S3::Bucket",
            "EC2": "AWS::EC2::Instance",
            "RDS": "AWS::RDS::DBInstance",
            "IAM": "AWS::IAM::User",
            "Security group": "AWS::EC2::SecurityGroup",
            "Lambda": "AWS::Lambda::Function",
            "KMS": "AWS::KMS::Key",
            "EBS": "AWS::EC2::Volume",
            "CloudWatch": "AWS::CloudWatch::Alarm",
            "CloudTrail": "AWS::CloudTrail::Trail",
        }
        for key, resource_type in mappings.items():
            if key.lower() in title.lower():
                return resource_type
        return "AWS::Unknown::Resource"
    
    def _get_compliance_frameworks(self, severity: str) -> List[str]:
        """Get applicable compliance frameworks based on severity"""
        frameworks = ["CIS AWS Benchmark", "AWS Well-Architected"]
        if severity in ["critical", "high"]:
            frameworks.extend(["PCI-DSS", "SOC 2"])
        if severity == "critical":
            frameworks.append("HIPAA")
        return frameworks
    
    # ========================================================================
    # DEMO COMPLIANCE DATA
    # ========================================================================
    
    def get_demo_compliance_status(self) -> Dict[str, Any]:
        """Get simulated compliance status"""
        return {
            "cis_aws": {
                "name": "CIS AWS Foundations Benchmark",
                "version": "1.5.0",
                "total_controls": 58,
                "passed": 42,
                "failed": 12,
                "not_applicable": 4,
                "score": 77.8,
            },
            "pci_dss": {
                "name": "PCI DSS v4.0",
                "total_controls": 264,
                "passed": 198,
                "failed": 45,
                "not_applicable": 21,
                "score": 81.5,
            },
            "hipaa": {
                "name": "HIPAA Security Rule",
                "total_controls": 45,
                "passed": 35,
                "failed": 8,
                "not_applicable": 2,
                "score": 81.4,
            },
            "soc2": {
                "name": "SOC 2 Type II",
                "total_controls": 64,
                "passed": 51,
                "failed": 10,
                "not_applicable": 3,
                "score": 83.6,
            },
            "nist_csf": {
                "name": "NIST Cybersecurity Framework",
                "total_controls": 108,
                "passed": 82,
                "failed": 19,
                "not_applicable": 7,
                "score": 81.2,
            },
        }
    
    # ========================================================================
    # DEMO COST DATA
    # ========================================================================
    
    def get_demo_cost_data(self) -> Dict[str, Any]:
        """Get simulated cost and savings data"""
        return {
            "current_monthly_cost": 45678.90,
            "projected_monthly_cost": 48234.56,
            "potential_savings": 8934.23,
            "savings_percentage": 19.5,
            "cost_by_service": {
                "EC2": 18234.56,
                "RDS": 8945.23,
                "S3": 2345.67,
                "Lambda": 1234.56,
                "EKS": 5678.90,
                "Data Transfer": 3456.78,
                "CloudWatch": 1234.56,
                "Other": 4548.64,
            },
            "optimization_opportunities": [
                {
                    "category": "Right-sizing",
                    "description": "Downsize 12 over-provisioned EC2 instances",
                    "monthly_savings": 3456.78,
                    "effort": "Low",
                },
                {
                    "category": "Reserved Instances",
                    "description": "Purchase 1-year RIs for stable workloads",
                    "monthly_savings": 2345.67,
                    "effort": "Medium",
                },
                {
                    "category": "Unused Resources",
                    "description": "Delete 8 unattached EBS volumes",
                    "monthly_savings": 456.78,
                    "effort": "Low",
                },
                {
                    "category": "Storage Optimization",
                    "description": "Implement S3 lifecycle policies",
                    "monthly_savings": 1234.56,
                    "effort": "Medium",
                },
                {
                    "category": "Compute Savings Plans",
                    "description": "Purchase Compute Savings Plans",
                    "monthly_savings": 1440.44,
                    "effort": "Low",
                },
            ],
            "trend_data": self._generate_cost_trend(),
        }
    
    def _generate_cost_trend(self) -> List[Dict[str, Any]]:
        """Generate cost trend data for the last 12 months"""
        trend = []
        base_cost = 42000
        
        for i in range(12):
            month_date = datetime.now() - timedelta(days=30 * (11 - i))
            variation = random.uniform(-0.05, 0.08)
            cost = base_cost * (1 + variation) * (1 + i * 0.02)
            
            trend.append({
                "month": month_date.strftime("%Y-%m"),
                "cost": round(cost, 2),
                "forecast": round(cost * 1.05, 2) if i >= 10 else None,
            })
        
        return trend
    
    # ========================================================================
    # DEMO SCAN SIMULATION
    # ========================================================================
    
    def simulate_scan_progress(self) -> Dict[str, Any]:
        """Simulate a scan in progress for demo purposes"""
        services = [
            "EC2", "RDS", "S3", "Lambda", "IAM", "VPC", 
            "EKS", "CloudWatch", "KMS", "Secrets Manager"
        ]
        
        progress = []
        for i, service in enumerate(services):
            progress.append({
                "service": service,
                "status": "completed",
                "resources_scanned": random.randint(5, 50),
                "findings": random.randint(0, 8),
            })
        
        return {
            "status": "completed",
            "progress_percentage": 100,
            "services_scanned": services,
            "service_progress": progress,
            "total_resources": sum(p["resources_scanned"] for p in progress),
            "total_findings": sum(p["findings"] for p in progress),
        }


# ============================================================================
# SINGLETON INSTANCE
# ============================================================================

def get_demo_manager() -> DemoModeManager:
    """Get the singleton demo mode manager instance"""
    return DemoModeManager()


# ============================================================================
# UI COMPONENTS
# ============================================================================

def render_mode_toggle():
    """Render the demo/live mode toggle in sidebar"""
    demo_mgr = get_demo_manager()
    
    st.sidebar.markdown("---")
    st.sidebar.markdown("### 🎮 Mode Selection")
    
    # Mode toggle
    col1, col2 = st.sidebar.columns([1, 1])
    
    with col1:
        if st.button(
            "🎭 Demo",
            type="primary" if demo_mgr.is_demo_mode else "secondary",
            use_container_width=True,
            help="Use simulated data for demonstrations"
        ):
            demo_mgr.is_demo_mode = True
            st.rerun()
    
    with col2:
        if st.button(
            "🔴 Live",
            type="primary" if not demo_mgr.is_demo_mode else "secondary",
            use_container_width=True,
            help="Connect to real AWS accounts"
        ):
            demo_mgr.is_demo_mode = False
            st.rerun()
    
    # Mode indicator
    if demo_mgr.is_demo_mode:
        st.sidebar.info("""
        **Demo Mode Active**
        
        Using simulated data. No AWS credentials required.
        
        Perfect for:
        - 🎯 Sales demos
        - 📚 Training
        - 🧪 Testing
        """)
    else:
        st.sidebar.success("""
        **Live Mode Active**
        
        Connecting to real AWS accounts.
        
        Ensure credentials are configured.
        """)
    
    return demo_mgr.is_demo_mode


def render_mode_banner():
    """Render a banner indicating current mode"""
    demo_mgr = get_demo_manager()
    
    if demo_mgr.is_demo_mode:
        st.markdown("""
            <div style="background: linear-gradient(90deg, #FF6B6B 0%, #FF8E8E 100%); 
                        padding: 0.5rem 1rem; 
                        border-radius: 5px; 
                        margin-bottom: 1rem;
                        text-align: center;">
                <span style="color: white; font-weight: bold;">
                    🎭 DEMO MODE - Using Simulated Data | 
                    <span style="font-weight: normal;">Switch to Live Mode for real AWS scanning</span>
                </span>
            </div>
        """, unsafe_allow_html=True)


def render_demo_account_info():
    """Render demo account information panel"""
    demo_mgr = get_demo_manager()
    
    if demo_mgr.is_demo_mode:
        identity = demo_mgr.get_demo_identity()
        
        st.success("✅ Connected to Demo Account")
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Account ID", identity["Account"])
        with col2:
            st.metric("Region", demo_mgr.config.region)
        with col3:
            st.metric("Mode", "Demo")
        
        return True, identity
    
    return False, None
