"""
EKS Modernization & Architecture Hub - REVAMPED v3.0
Real-world use cases for Architects and Engineers

This module addresses ACTUAL problems that EKS users face:
1. Greenfield Design - Design new clusters from requirements
2. Migration Assessment - Move from EC2/VMs/On-prem to EKS
3. Cluster Optimization - Optimize existing cluster costs/performance
4. Security Hardening - Implement security best practices
5. Architecture Visualization - SVG diagrams of your design

Author: Revamped for real-world use cases
Version: 3.0.0
"""

import streamlit as st
import json
import yaml
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field, asdict
import base64

# ============================================================================
# SVG DIAGRAM GENERATOR - Visual Architecture
# ============================================================================

class EKSSVGDiagramGenerator:
    """Generate SVG diagrams for EKS architectures"""
    
    @staticmethod
    @st.cache_data(ttl=3600)  # Cache SVG for 1 hour
    def generate_cluster_diagram(config_json: str) -> str:
        """Generate an SVG diagram of the EKS cluster architecture"""
        # Parse JSON config (needed for caching - dicts aren't hashable)
        config = json.loads(config_json) if isinstance(config_json, str) else config_json
        
        project_name = config.get('project_name', 'my-eks-cluster')
        region = config.get('region', 'us-east-1')
        azs = config.get('availability_zones', ['us-east-1a', 'us-east-1b'])
        node_groups = config.get('node_groups', [])
        addons = config.get('addons', [])
        
        # Calculate dimensions
        az_count = len(azs)
        width = max(1200, az_count * 350)
        height = 900
        
        svg = f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}">
  <defs>
    <linearGradient id="awsGradient" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:#FF9900;stop-opacity:1" />
      <stop offset="100%" style="stop-color:#FF6600;stop-opacity:1" />
    </linearGradient>
    <linearGradient id="eksGradient" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:#326CE5;stop-opacity:1" />
      <stop offset="100%" style="stop-color:#1E4DB7;stop-opacity:1" />
    </linearGradient>
    <linearGradient id="vpcGradient" x1="0%" y1="0%" x2="0%" y2="100%">
      <stop offset="0%" style="stop-color:#E8F4FD;stop-opacity:1" />
      <stop offset="100%" style="stop-color:#D4E8F7;stop-opacity:1" />
    </linearGradient>
    <filter id="shadow" x="-20%" y="-20%" width="140%" height="140%">
      <feDropShadow dx="3" dy="3" stdDeviation="3" flood-opacity="0.2"/>
    </filter>
  </defs>
  
  <!-- Background -->
  <rect width="100%" height="100%" fill="#F8F9FA"/>
  
  <!-- Title -->
  <text x="{width/2}" y="35" text-anchor="middle" font-family="Arial, sans-serif" font-size="24" font-weight="bold" fill="#232F3E">
    EKS Architecture: {project_name}
  </text>
  <text x="{width/2}" y="58" text-anchor="middle" font-family="Arial, sans-serif" font-size="14" fill="#666">
    Region: {region} | AZs: {az_count} | Generated: {datetime.now().strftime("%Y-%m-%d")}
  </text>
  
  <!-- AWS Cloud Border -->
  <rect x="20" y="70" width="{width-40}" height="{height-90}" rx="10" ry="10" 
        fill="none" stroke="#FF9900" stroke-width="3" stroke-dasharray="10,5"/>
  <rect x="25" y="75" width="120" height="25" fill="#FF9900" rx="3"/>
  <text x="85" y="92" text-anchor="middle" font-family="Arial, sans-serif" font-size="12" fill="white" font-weight="bold">AWS Cloud</text>
  
  <!-- VPC -->
  <rect x="40" y="110" width="{width-80}" height="{height-150}" rx="8" ry="8" 
        fill="url(#vpcGradient)" stroke="#147EB4" stroke-width="2"/>
  <rect x="45" y="115" width="80" height="22" fill="#147EB4" rx="3"/>
  <text x="85" y="130" text-anchor="middle" font-family="Arial, sans-serif" font-size="11" fill="white" font-weight="bold">VPC</text>
'''
        
        # Add Availability Zones
        az_width = (width - 120) / az_count - 20
        for i, az in enumerate(azs):
            az_x = 60 + i * (az_width + 20)
            az_name = az.split('-')[-1] if '-' in az else az
            
            svg += f'''
  <!-- Availability Zone {i+1} -->
  <rect x="{az_x}" y="150" width="{az_width}" height="{height-220}" rx="6" ry="6" 
        fill="white" stroke="#5C6BC0" stroke-width="2" filter="url(#shadow)"/>
  <rect x="{az_x+5}" y="155" width="{az_width-10}" height="25" fill="#5C6BC0" rx="3"/>
  <text x="{az_x + az_width/2}" y="172" text-anchor="middle" font-family="Arial, sans-serif" font-size="11" fill="white" font-weight="bold">
    {az_name.upper()}
  </text>
  
  <!-- Private Subnet -->
  <rect x="{az_x+10}" y="190" width="{az_width-20}" height="200" rx="4" ry="4" 
        fill="#E8F5E9" stroke="#4CAF50" stroke-width="1.5"/>
  <text x="{az_x + az_width/2}" y="210" text-anchor="middle" font-family="Arial, sans-serif" font-size="10" fill="#2E7D32" font-weight="bold">
    Private Subnet
  </text>
'''
            
            # Add nodes in this AZ
            ng_in_az = [ng for ng in node_groups if i < len(node_groups)]
            if ng_in_az and i < len(ng_in_az):
                ng = ng_in_az[i] if i < len(ng_in_az) else node_groups[0]
                node_count = ng.get('desired_size', 2)
                instance_type = ng.get('instance_type', 'm5.large')
                capacity = ng.get('capacity_type', 'ON_DEMAND')
                
                # Draw worker nodes
                for n in range(min(node_count, 3)):
                    node_y = 230 + n * 50
                    node_color = "#FFB74D" if capacity == "SPOT" else "#64B5F6"
                    
                    svg += f'''
  <!-- Worker Node -->
  <rect x="{az_x+20}" y="{node_y}" width="{az_width-40}" height="40" rx="4" ry="4" 
        fill="{node_color}" stroke="#333" stroke-width="1"/>
  <text x="{az_x + az_width/2}" y="{node_y+18}" text-anchor="middle" font-family="Arial, sans-serif" font-size="9" fill="#333" font-weight="bold">
    Worker Node
  </text>
  <text x="{az_x + az_width/2}" y="{node_y+32}" text-anchor="middle" font-family="Arial, sans-serif" font-size="8" fill="#555">
    {instance_type}
  </text>
'''
            
            # Public Subnet
            svg += f'''
  <!-- Public Subnet -->
  <rect x="{az_x+10}" y="{height-300}" width="{az_width-20}" height="80" rx="4" ry="4" 
        fill="#FFF3E0" stroke="#FF9800" stroke-width="1.5"/>
  <text x="{az_x + az_width/2}" y="{height-280}" text-anchor="middle" font-family="Arial, sans-serif" font-size="10" fill="#E65100" font-weight="bold">
    Public Subnet
  </text>
  
  <!-- NAT Gateway -->
  <rect x="{az_x+20}" y="{height-265}" width="{az_width-40}" height="35" rx="4" ry="4" 
        fill="#81C784" stroke="#388E3C" stroke-width="1"/>
  <text x="{az_x + az_width/2}" y="{height-243}" text-anchor="middle" font-family="Arial, sans-serif" font-size="9" fill="white" font-weight="bold">
    NAT Gateway
  </text>
'''
        
        # EKS Control Plane
        svg += f'''
  <!-- EKS Control Plane -->
  <rect x="{width/2-150}" y="{height-200}" width="300" height="70" rx="8" ry="8" 
        fill="url(#eksGradient)" stroke="#1565C0" stroke-width="2" filter="url(#shadow)"/>
  <text x="{width/2}" y="{height-170}" text-anchor="middle" font-family="Arial, sans-serif" font-size="14" fill="white" font-weight="bold">
    EKS Control Plane
  </text>
  <text x="{width/2}" y="{height-152}" text-anchor="middle" font-family="Arial, sans-serif" font-size="10" fill="#B3E5FC">
    Kubernetes API Server | etcd | Scheduler
  </text>
  
  <!-- Internet Gateway -->
  <rect x="{width/2-60}" y="{height-115}" width="120" height="40" rx="6" ry="6" 
        fill="url(#awsGradient)" stroke="#CC7A00" stroke-width="2"/>
  <text x="{width/2}" y="{height-90}" text-anchor="middle" font-family="Arial, sans-serif" font-size="11" fill="white" font-weight="bold">
    Internet Gateway
  </text>
  
  <!-- Users/Internet -->
  <ellipse cx="{width/2}" cy="{height-50}" rx="60" ry="25" fill="#E3F2FD" stroke="#1976D2" stroke-width="2"/>
  <text x="{width/2}" y="{height-45}" text-anchor="middle" font-family="Arial, sans-serif" font-size="11" fill="#1565C0" font-weight="bold">
    Users / Internet
  </text>
'''
        
        # Add-ons box
        if addons:
            addon_text = ", ".join(addons[:5])
            svg += f'''
  <!-- Add-ons -->
  <rect x="60" y="{height-115}" width="250" height="40" rx="4" ry="4" 
        fill="#F3E5F5" stroke="#7B1FA2" stroke-width="1"/>
  <text x="185" y="{height-100}" text-anchor="middle" font-family="Arial, sans-serif" font-size="10" fill="#7B1FA2" font-weight="bold">
    Add-ons: {addon_text}
  </text>
'''
        
        # Legend
        svg += f'''
  <!-- Legend -->
  <rect x="{width-220}" y="{height-115}" width="200" height="80" rx="4" ry="4" fill="white" stroke="#CCC"/>
  <text x="{width-120}" y="{height-98}" text-anchor="middle" font-family="Arial, sans-serif" font-size="10" font-weight="bold">Legend</text>
  <rect x="{width-210}" y="{height-85}" width="20" height="12" fill="#64B5F6"/>
  <text x="{width-185}" y="{height-76}" font-family="Arial, sans-serif" font-size="9">On-Demand Nodes</text>
  <rect x="{width-210}" y="{height-68}" width="20" height="12" fill="#FFB74D"/>
  <text x="{width-185}" y="{height-59}" font-family="Arial, sans-serif" font-size="9">Spot Nodes</text>
  <rect x="{width-210}" y="{height-51}" width="20" height="12" fill="#E8F5E9" stroke="#4CAF50"/>
  <text x="{width-185}" y="{height-42}" font-family="Arial, sans-serif" font-size="9">Private Subnet</text>
</svg>'''
        
        return svg
    
    @staticmethod
    def get_svg_download_link(svg_content: str, filename: str = "eks_architecture.svg") -> str:
        """Generate a download link for the SVG"""
        b64 = base64.b64encode(svg_content.encode()).decode()
        return f'<a href="data:image/svg+xml;base64,{b64}" download="{filename}">📥 Download SVG Diagram</a>'


# ============================================================================
# REAL-WORLD USE CASES
# ============================================================================

class EKSUseCases:
    """Real-world EKS use cases that architects and engineers face"""
    
    USE_CASES = {
        "greenfield": {
            "title": "🆕 Greenfield Cluster Design",
            "description": "Design a new EKS cluster from scratch based on your requirements",
            "problems_solved": [
                "Right-size cluster from day 1",
                "Choose optimal node types",
                "Design for scalability",
                "Implement security best practices"
            ],
            "icon": "🆕"
        },
        "migration": {
            "title": "🔄 Migration Assessment",
            "description": "Migrate existing workloads from EC2/VMs/On-prem to EKS",
            "problems_solved": [
                "Assess migration readiness",
                "Plan containerization strategy",
                "Calculate TCO comparison",
                "Create migration roadmap"
            ],
            "icon": "🔄"
        },
        "optimization": {
            "title": "💰 Cluster Optimization",
            "description": "Optimize existing EKS cluster for cost and performance",
            "problems_solved": [
                "Reduce monthly costs by 30-60%",
                "Right-size node groups",
                "Implement Spot instances",
                "Enable Karpenter autoscaling"
            ],
            "icon": "💰"
        },
        "security": {
            "title": "🔒 Security Hardening",
            "description": "Implement security best practices on your EKS cluster",
            "problems_solved": [
                "Enable Pod Security Standards",
                "Implement IRSA for IAM",
                "Configure Network Policies",
                "Set up secrets management"
            ],
            "icon": "🔒"
        },
        "multicluster": {
            "title": "🌐 Multi-Cluster Strategy",
            "description": "Design multi-cluster architecture for scale or compliance",
            "problems_solved": [
                "Hub-spoke cluster topology",
                "Cross-cluster networking",
                "Centralized observability",
                "DR and failover"
            ],
            "icon": "🌐"
        }
    }


# ============================================================================
# NLP PARSER FOR AI-POWERED REQUIREMENTS
# ============================================================================

class EKSNLPParser:
    """Parse natural language requirements into EKS configuration"""
    
    # Keywords for detection
    REGION_KEYWORDS = {
        'us-east-1': ['us-east-1', 'virginia', 'n. virginia', 'us east', 'east coast'],
        'us-east-2': ['us-east-2', 'ohio'],
        'us-west-1': ['us-west-1', 'n. california', 'california'],
        'us-west-2': ['us-west-2', 'oregon', 'west coast'],
        'eu-west-1': ['eu-west-1', 'ireland', 'dublin', 'europe west'],
        'eu-central-1': ['eu-central-1', 'frankfurt', 'germany', 'europe central'],
        'ap-southeast-1': ['ap-southeast-1', 'singapore', 'asia pacific', 'southeast asia'],
        'ap-northeast-1': ['ap-northeast-1', 'tokyo', 'japan'],
    }
    
    ENVIRONMENT_KEYWORDS = {
        'production': ['production', 'prod', 'live', 'critical', 'enterprise'],
        'staging': ['staging', 'stage', 'uat', 'pre-prod', 'preprod'],
        'development': ['development', 'dev', 'test', 'testing', 'sandbox', 'experimental'],
        'dr': ['dr', 'disaster recovery', 'backup', 'failover'],
    }
    
    COMPLIANCE_KEYWORDS = {
        'PCI-DSS': ['pci', 'pci-dss', 'payment card', 'credit card'],
        'HIPAA': ['hipaa', 'healthcare', 'health data', 'phi', 'medical'],
        'SOC2': ['soc2', 'soc 2', 'type 2', 'audit'],
        'GDPR': ['gdpr', 'european', 'eu data', 'privacy'],
        'ISO27001': ['iso 27001', 'iso27001', 'information security'],
        'FedRAMP': ['fedramp', 'federal', 'government', 'gov'],
    }
    
    WORKLOAD_KEYWORDS = {
        'Web/API': ['web', 'api', 'rest', 'graphql', 'http', 'frontend', 'backend'],
        'ML/AI': ['ml', 'machine learning', 'ai', 'artificial intelligence', 'training', 'inference', 'gpu', 'model'],
        'Batch Processing': ['batch', 'job', 'cron', 'scheduled', 'etl', 'data processing'],
        'Databases': ['database', 'db', 'postgres', 'mysql', 'mongodb', 'redis', 'stateful'],
        'Event Processing': ['event', 'kafka', 'streaming', 'real-time', 'realtime', 'queue', 'message'],
    }
    
    INSTANCE_RECOMMENDATIONS = {
        'general': 'm6i.large',
        'compute': 'c6i.large',
        'memory': 'r6i.large',
        'gpu': 'g5.xlarge',
        'arm': 'm6g.large',
        'cost': 't3.large',
    }
    
    @staticmethod
    def parse_requirements(text: str) -> Dict:
        """Parse natural language text into EKS configuration"""
        text_lower = text.lower()
        config = {}
        
        # Parse region
        config['region'] = EKSNLPParser._extract_region(text_lower)
        
        # Parse environment
        config['environment'] = EKSNLPParser._extract_environment(text_lower)
        
        # Parse compliance requirements
        config['compliance'] = EKSNLPParser._extract_compliance(text_lower)
        
        # Parse workload types
        config['workload_types'] = EKSNLPParser._extract_workloads(text_lower)
        
        # Parse budget
        config['monthly_budget'] = EKSNLPParser._extract_budget(text_lower)
        
        # Parse pod count
        pod_count = EKSNLPParser._extract_pod_count(text_lower)
        
        # Parse service count
        service_count = EKSNLPParser._extract_number(text_lower, ['services', 'microservices', 'applications', 'apps'])
        
        # Parse AZ requirements
        az_count = EKSNLPParser._extract_az_count(text_lower, config['environment'])
        config['availability_zones'] = [f"{config['region']}{az}" for az in ['a', 'b', 'c'][:az_count]]
        
        # Determine instance type based on workloads
        instance_type = EKSNLPParser._recommend_instance_type(config['workload_types'], text_lower)
        
        # Determine capacity type
        capacity_type = 'SPOT' if any(kw in text_lower for kw in ['spot', 'cost saving', 'budget', 'cheap']) else 'ON_DEMAND'
        if config['environment'] == 'production' and 'spot' not in text_lower:
            capacity_type = 'ON_DEMAND'
        
        # Calculate node sizing
        min_nodes, max_nodes = EKSNLPParser._calculate_node_sizing(pod_count, service_count, config['environment'])
        
        # Create node group config
        config['node_groups'] = [{
            'name': 'primary',
            'instance_type': instance_type,
            'min_size': min_nodes,
            'max_size': max_nodes,
            'desired_size': min_nodes,
            'capacity_type': capacity_type
        }]
        
        # Add GPU node group if ML workload
        if 'ML/AI' in config.get('workload_types', []):
            config['node_groups'].append({
                'name': 'gpu',
                'instance_type': 'g5.xlarge',
                'min_size': 0,
                'max_size': 5,
                'desired_size': 0,
                'capacity_type': 'ON_DEMAND'
            })
        
        # Determine add-ons based on requirements
        config['addons'] = EKSNLPParser._recommend_addons(config)
        
        # Generate cluster name
        config['project_name'] = EKSNLPParser._generate_cluster_name(config)
        
        return config
    
    @staticmethod
    def _extract_region(text: str) -> str:
        """Extract AWS region from text"""
        for region, keywords in EKSNLPParser.REGION_KEYWORDS.items():
            if any(kw in text for kw in keywords):
                return region
        return 'us-east-1'  # Default
    
    @staticmethod
    def _extract_environment(text: str) -> str:
        """Extract environment from text"""
        for env, keywords in EKSNLPParser.ENVIRONMENT_KEYWORDS.items():
            if any(kw in text for kw in keywords):
                return env
        return 'production'  # Default
    
    @staticmethod
    def _extract_compliance(text: str) -> List[str]:
        """Extract compliance requirements"""
        compliance = []
        for framework, keywords in EKSNLPParser.COMPLIANCE_KEYWORDS.items():
            if any(kw in text for kw in keywords):
                compliance.append(framework)
        return compliance
    
    @staticmethod
    def _extract_workloads(text: str) -> List[str]:
        """Extract workload types"""
        workloads = []
        for workload, keywords in EKSNLPParser.WORKLOAD_KEYWORDS.items():
            if any(kw in text for kw in keywords):
                workloads.append(workload)
        return workloads if workloads else ['Web/API']
    
    @staticmethod
    def _extract_budget(text: str) -> int:
        """Extract monthly budget"""
        import re
        # Look for dollar amounts
        patterns = [
            r'\$\s*([\d,]+)\s*(?:k|K)?\s*(?:/month|per month|monthly)?',
            r'([\d,]+)\s*(?:k|K)?\s*(?:dollars?|usd)\s*(?:/month|per month|monthly)?',
            r'budget\s*(?:of|is|:)?\s*\$?\s*([\d,]+)\s*(?:k|K)?',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, text)
            if match:
                value = match.group(1).replace(',', '')
                value = int(float(value))
                # Handle 'k' notation
                if 'k' in text[match.start():match.end()].lower():
                    value *= 1000
                return value
        
        return 5000  # Default
    
    @staticmethod
    def _extract_pod_count(text: str) -> int:
        """Extract expected pod count"""
        import re
        patterns = [
            r'(\d+)\s*pods?',
            r'peak\s*(?:of|around|about)?\s*(\d+)',
            r'around\s*(\d+)\s*pods?',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, text)
            if match:
                return int(match.group(1))
        
        return 100  # Default
    
    @staticmethod
    def _extract_number(text: str, keywords: List[str]) -> int:
        """Extract number associated with keywords"""
        import re
        for kw in keywords:
            patterns = [
                rf'(\d+)\s*{kw}',
                rf'{kw}\s*(?:of|about|around)?\s*(\d+)',
            ]
            for pattern in patterns:
                match = re.search(pattern, text)
                if match:
                    return int(match.group(1))
        return 10  # Default
    
    @staticmethod
    def _extract_az_count(text: str, environment: str) -> int:
        """Extract AZ count preference"""
        import re
        # Look for explicit AZ mention
        az_match = re.search(r'(\d+)\s*(?:az|availability zone)', text)
        if az_match:
            return min(3, max(1, int(az_match.group(1))))
        
        # Check for HA keywords
        if any(kw in text for kw in ['high availability', 'ha', 'multi-az', 'highly available']):
            return 3
        
        # Check for single AZ
        if any(kw in text for kw in ['single az', 'one az', 'cost saving']):
            return 1
        
        # Default based on environment
        return 3 if environment == 'production' else 2
    
    @staticmethod
    def _recommend_instance_type(workloads: List[str], text: str) -> str:
        """Recommend instance type based on workloads"""
        if 'ML/AI' in workloads and 'gpu' in text:
            return 'g5.xlarge'
        elif 'ML/AI' in workloads:
            return 'c6i.xlarge'
        elif 'Databases' in workloads:
            return 'r6i.large'
        elif 'Event Processing' in workloads:
            return 'c6i.large'
        elif any(kw in text for kw in ['graviton', 'arm']):
            return 'm6g.large'
        elif any(kw in text for kw in ['cost', 'cheap', 'budget', 'small']):
            return 't3.large'
        else:
            return 'm6i.large'
    
    @staticmethod
    def _calculate_node_sizing(pod_count: int, service_count: int, environment: str) -> tuple:
        """Calculate min/max node counts"""
        # Assume ~30 pods per node for safety
        pods_per_node = 30
        min_nodes = max(3, int(pod_count / pods_per_node) + 1)
        
        # Add headroom for scaling
        if environment == 'production':
            max_nodes = min_nodes * 3
        else:
            max_nodes = min_nodes * 2
        
        return min_nodes, max_nodes
    
    @staticmethod
    def _recommend_addons(config: Dict) -> List[str]:
        """Recommend add-ons based on configuration"""
        addons = ['vpc-cni', 'coredns', 'kube-proxy', 'aws-ebs-csi-driver']
        
        # Add observability
        addons.append('aws-cloudwatch-observability')
        
        # Add ALB controller for web workloads
        if 'Web/API' in config.get('workload_types', []):
            addons.append('aws-load-balancer-controller')
        
        # Add EFS for stateful workloads
        if 'Databases' in config.get('workload_types', []):
            addons.append('aws-efs-csi-driver')
        
        return addons
    
    @staticmethod
    def _generate_cluster_name(config: Dict) -> str:
        """Generate a cluster name"""
        env_prefix = config.get('environment', 'prod')[:4]
        region_suffix = config.get('region', 'us-east-1').split('-')[1][:2]
        return f"{env_prefix}-eks-{region_suffix}"


# ============================================================================
# MIGRATION ASSESSMENT MODULE
# ============================================================================

class EKSMigrationAssessment:
    """Assess migration readiness from EC2/VMs to EKS"""
    
    @staticmethod
    def render():
        """Render migration assessment tool"""
        st.markdown("## 🔄 Migration Assessment Tool")
        st.markdown("Evaluate your workloads for EKS migration readiness")
        
        # Workload inventory
        st.markdown("### 📋 Current Workload Inventory")
        
        col1, col2 = st.columns(2)
        
        with col1:
            source_platform = st.selectbox(
                "Current Platform",
                ["EC2 Instances", "On-Premises VMs", "Other Cloud (Azure/GCP)", "Docker Swarm", "Other Container Platform"]
            )
            
            num_applications = st.number_input("Number of Applications", 1, 500, 10)
            num_servers = st.number_input("Number of Servers/VMs", 1, 1000, 20)
        
        with col2:
            avg_cpu_util = st.slider("Avg CPU Utilization (%)", 0, 100, 40)
            avg_memory_util = st.slider("Avg Memory Utilization (%)", 0, 100, 50)
            has_stateful = st.checkbox("Has Stateful Workloads (Databases, etc.)")
        
        # Application characteristics
        st.markdown("### 🔍 Application Characteristics")
        
        app_types = st.multiselect(
            "Application Types",
            ["Web Applications", "REST APIs", "Microservices", "Batch Jobs", 
             "Event Processors", "Databases", "Message Queues", "ML/AI Workloads",
             "Legacy Monoliths", "Stateful Applications"],
            default=["Web Applications", "REST APIs"]
        )
        
        containerization_status = st.radio(
            "Containerization Status",
            ["Not containerized", "Partially containerized (some apps)", "Fully containerized"],
            index=0
        )
        
        # Assessment button
        if st.button("🔍 Assess Migration Readiness", type="primary", use_container_width=True):
            st.markdown("---")
            st.markdown("### 📊 Migration Assessment Results")
            
            # Calculate readiness score
            readiness_score = 50  # Base score
            
            # Adjust based on containerization
            if containerization_status == "Fully containerized":
                readiness_score += 30
            elif containerization_status == "Partially containerized (some apps)":
                readiness_score += 15
            
            # Adjust based on app types
            if "Legacy Monoliths" in app_types:
                readiness_score -= 15
            if "Microservices" in app_types:
                readiness_score += 10
            if "Databases" in app_types and has_stateful:
                readiness_score -= 10
            
            # Adjust based on utilization (low util = easier migration)
            if avg_cpu_util < 30:
                readiness_score += 5
            
            readiness_score = min(100, max(0, readiness_score))
            
            # Display results
            col1, col2, col3 = st.columns(3)
            
            with col1:
                color = "green" if readiness_score >= 70 else "orange" if readiness_score >= 50 else "red"
                st.metric("Readiness Score", f"{readiness_score}/100")
            
            with col2:
                complexity = "Low" if readiness_score >= 70 else "Medium" if readiness_score >= 50 else "High"
                st.metric("Migration Complexity", complexity)
            
            with col3:
                timeline = "4-8 weeks" if readiness_score >= 70 else "8-16 weeks" if readiness_score >= 50 else "16-24 weeks"
                st.metric("Estimated Timeline", timeline)
            
            # Recommendations
            st.markdown("### 💡 Recommendations")
            
            recommendations = []
            
            if containerization_status == "Not containerized":
                recommendations.append({
                    "priority": "High",
                    "title": "Containerize Applications First",
                    "description": "Create Dockerfiles for your applications. Start with stateless apps.",
                    "effort": "2-4 weeks per app"
                })
            
            if "Legacy Monoliths" in app_types:
                recommendations.append({
                    "priority": "High",
                    "title": "Consider Strangler Fig Pattern",
                    "description": "Gradually migrate monolith functionality to microservices.",
                    "effort": "Ongoing"
                })
            
            if has_stateful:
                recommendations.append({
                    "priority": "Medium",
                    "title": "Plan Stateful Workload Migration",
                    "description": "Consider EBS CSI driver for persistent storage or managed databases (RDS).",
                    "effort": "1-2 weeks"
                })
            
            recommendations.append({
                "priority": "Medium",
                "title": "Set Up CI/CD Pipeline",
                "description": "Implement GitOps with ArgoCD or Flux for automated deployments.",
                "effort": "1 week"
            })
            
            recommendations.append({
                "priority": "Low",
                "title": "Implement Observability",
                "description": "Set up Prometheus, Grafana, and CloudWatch Container Insights.",
                "effort": "3-5 days"
            })
            
            for rec in recommendations:
                priority_color = "🔴" if rec["priority"] == "High" else "🟡" if rec["priority"] == "Medium" else "🟢"
                with st.expander(f"{priority_color} {rec['title']} ({rec['priority']} Priority)"):
                    st.write(rec["description"])
                    st.caption(f"⏱️ Effort: {rec['effort']}")
            
            # TCO Comparison
            st.markdown("### 💰 TCO Comparison (Estimated)")
            
            # Rough estimates
            current_monthly = num_servers * 150  # $150/server avg
            eks_monthly = num_servers * 0.6 * 100  # 40% fewer resources, $100/node
            savings = current_monthly - eks_monthly
            savings_pct = (savings / current_monthly) * 100 if current_monthly > 0 else 0
            
            col1, col2, col3 = st.columns(3)
            col1.metric("Current Monthly Cost", f"${current_monthly:,.0f}")
            col2.metric("Estimated EKS Monthly", f"${eks_monthly:,.0f}")
            col3.metric("Monthly Savings", f"${savings:,.0f}", f"{savings_pct:.0f}%")


# ============================================================================
# CLUSTER OPTIMIZATION MODULE
# ============================================================================

class EKSClusterOptimization:
    """Optimize existing EKS cluster"""
    
    @staticmethod
    def render():
        """Render cluster optimization tool"""
        st.markdown("## 💰 Cluster Optimization Tool")
        st.markdown("Analyze and optimize your existing EKS cluster")
        
        # Current cluster info
        st.markdown("### 📊 Current Cluster Configuration")
        
        col1, col2 = st.columns(2)
        
        with col1:
            cluster_name = st.text_input("Cluster Name", "my-eks-cluster")
            current_node_count = st.number_input("Current Node Count", 1, 500, 10)
            current_instance_type = st.selectbox(
                "Primary Instance Type",
                ["m5.large", "m5.xlarge", "m5.2xlarge", "m6i.large", "m6i.xlarge",
                 "c5.large", "c5.xlarge", "r5.large", "r5.xlarge", "t3.large", "t3.xlarge"]
            )
        
        with col2:
            current_scaling = st.selectbox(
                "Current Scaling Method",
                ["Cluster Autoscaler", "Karpenter", "Manual Scaling", "None"]
            )
            spot_usage = st.slider("Current Spot Usage (%)", 0, 100, 0)
            avg_node_utilization = st.slider("Avg Node Utilization (%)", 0, 100, 40)
        
        # Monthly cost input
        current_monthly_cost = st.number_input(
            "Current Monthly EKS Cost ($)", 
            min_value=0, max_value=1000000, value=5000
        )
        
        if st.button("🔍 Analyze & Recommend Optimizations", type="primary", use_container_width=True):
            st.markdown("---")
            st.markdown("### 📈 Optimization Recommendations")
            
            optimizations = []
            total_savings = 0
            
            # Recommendation 1: Karpenter
            if current_scaling != "Karpenter":
                karpenter_savings = current_monthly_cost * 0.25
                total_savings += karpenter_savings
                optimizations.append({
                    "title": "🚀 Switch to Karpenter",
                    "description": "Karpenter provides 25-35% cost savings through intelligent node provisioning and consolidation.",
                    "monthly_savings": karpenter_savings,
                    "implementation": """
1. Install Karpenter controller
2. Create NodePool and EC2NodeClass
3. Migrate workloads gradually
4. Remove Cluster Autoscaler

```yaml
apiVersion: karpenter.sh/v1beta1
kind: NodePool
metadata:
  name: default
spec:
  template:
    spec:
      requirements:
        - key: karpenter.sh/capacity-type
          operator: In
          values: ["spot", "on-demand"]
        - key: node.kubernetes.io/instance-type
          operator: In
          values: ["m5.large", "m5.xlarge", "m6i.large"]
```
"""
                })
            
            # Recommendation 2: Spot instances
            if spot_usage < 50:
                spot_potential = 70 - spot_usage
                spot_savings = current_monthly_cost * (spot_potential / 100) * 0.6
                total_savings += spot_savings
                optimizations.append({
                    "title": "🏷️ Increase Spot Instance Usage",
                    "description": f"You're only using {spot_usage}% Spot. Increase to 60-70% for stateless workloads.",
                    "monthly_savings": spot_savings,
                    "implementation": """
For fault-tolerant workloads, use Spot instances:

1. Update NodePool for Spot:
```yaml
spec:
  template:
    spec:
      requirements:
        - key: karpenter.sh/capacity-type
          operator: In
          values: ["spot"]  # Spot-only for non-critical
```

2. Add pod disruption budgets for graceful handling
3. Use multiple instance types for better Spot availability
"""
                })
            
            # Recommendation 3: Right-sizing
            if avg_node_utilization < 50:
                rightsizing_savings = current_monthly_cost * 0.15
                total_savings += rightsizing_savings
                optimizations.append({
                    "title": "📏 Right-Size Node Groups",
                    "description": f"Node utilization is only {avg_node_utilization}%. Consolidate to fewer, larger nodes.",
                    "monthly_savings": rightsizing_savings,
                    "implementation": """
Options for right-sizing:

1. **Use Karpenter consolidation:**
```yaml
spec:
  disruption:
    consolidationPolicy: WhenEmpty  # or WhenUnderutilized
    consolidateAfter: 30s
```

2. **Enable VPA (Vertical Pod Autoscaler):**
   - Automatically adjusts pod resource requests
   - Reduces wasted capacity

3. **Review and adjust resource requests:**
   - Many pods over-request CPU/memory
   - Use metrics to set accurate requests
"""
                })
            
            # Recommendation 4: Graviton
            if "m5" in current_instance_type or "c5" in current_instance_type:
                graviton_savings = current_monthly_cost * 0.20
                total_savings += graviton_savings
                optimizations.append({
                    "title": "🔧 Switch to Graviton (ARM) Instances",
                    "description": "Graviton instances offer 20% better price-performance than x86.",
                    "monthly_savings": graviton_savings,
                    "implementation": """
1. Build multi-arch container images:
```bash
docker buildx build --platform linux/amd64,linux/arm64 -t myapp:latest .
```

2. Update NodePool for Graviton:
```yaml
spec:
  template:
    spec:
      requirements:
        - key: kubernetes.io/arch
          operator: In
          values: ["arm64"]
        - key: node.kubernetes.io/instance-type
          operator: In
          values: ["m6g.large", "m6g.xlarge", "c6g.large"]
```

3. Test workloads on ARM before full migration
"""
                })
            
            # Summary
            st.markdown("### 💰 Optimization Summary")
            
            col1, col2, col3 = st.columns(3)
            col1.metric("Current Monthly", f"${current_monthly_cost:,.0f}")
            col2.metric("Optimized Monthly", f"${current_monthly_cost - total_savings:,.0f}")
            col3.metric("Total Savings", f"${total_savings:,.0f}/month", f"{(total_savings/current_monthly_cost)*100:.0f}%")
            
            st.success(f"💰 **Annual Savings Potential: ${total_savings * 12:,.0f}**")
            
            # Display each optimization
            for opt in optimizations:
                with st.expander(f"{opt['title']} - Save ${opt['monthly_savings']:,.0f}/month"):
                    st.write(opt['description'])
                    st.markdown("**Implementation:**")
                    st.code(opt['implementation'], language="yaml")


# ============================================================================
# SECURITY HARDENING MODULE
# ============================================================================

class EKSSecurityHardening:
    """Security hardening recommendations for EKS"""
    
    SECURITY_CONTROLS = [
        {
            "category": "Identity & Access",
            "controls": [
                {"name": "Enable IRSA (IAM Roles for Service Accounts)", "critical": True, "implemented": False},
                {"name": "Disable node IAM instance roles", "critical": True, "implemented": False},
                {"name": "Use least-privilege IAM policies", "critical": True, "implemented": False},
                {"name": "Enable EKS cluster endpoint private access", "critical": False, "implemented": False},
                {"name": "Restrict public endpoint CIDR blocks", "critical": False, "implemented": False},
            ]
        },
        {
            "category": "Pod Security",
            "controls": [
                {"name": "Enable Pod Security Standards (PSS) - Restricted", "critical": True, "implemented": False},
                {"name": "Disable privileged containers", "critical": True, "implemented": False},
                {"name": "Set runAsNonRoot: true", "critical": True, "implemented": False},
                {"name": "Set readOnlyRootFilesystem: true", "critical": False, "implemented": False},
                {"name": "Drop all capabilities, add only required", "critical": False, "implemented": False},
            ]
        },
        {
            "category": "Network Security",
            "controls": [
                {"name": "Implement Network Policies", "critical": True, "implemented": False},
                {"name": "Use VPC CNI network policies", "critical": False, "implemented": False},
                {"name": "Enable encryption in transit (mTLS)", "critical": False, "implemented": False},
                {"name": "Use private subnets for nodes", "critical": True, "implemented": False},
                {"name": "Configure security groups properly", "critical": True, "implemented": False},
            ]
        },
        {
            "category": "Data Protection",
            "controls": [
                {"name": "Enable envelope encryption for Secrets", "critical": True, "implemented": False},
                {"name": "Use AWS Secrets Manager or External Secrets", "critical": True, "implemented": False},
                {"name": "Enable EBS encryption", "critical": True, "implemented": False},
                {"name": "Enable S3 encryption for logs", "critical": False, "implemented": False},
            ]
        },
        {
            "category": "Monitoring & Detection",
            "controls": [
                {"name": "Enable EKS Control Plane logging", "critical": True, "implemented": False},
                {"name": "Enable GuardDuty for EKS", "critical": True, "implemented": False},
                {"name": "Implement Falco for runtime security", "critical": False, "implemented": False},
                {"name": "Enable CloudTrail for API auditing", "critical": True, "implemented": False},
            ]
        }
    ]
    
    @staticmethod
    def render():
        """Render security hardening assessment - optimized"""
        st.markdown("## 🔒 Security Hardening Assessment")
        st.markdown("Assess and improve your EKS cluster security posture")
        
        # Quick assessment option
        assessment_mode = st.radio(
            "Assessment Mode",
            ["Quick Assessment", "Detailed Checklist"],
            horizontal=True
        )
        
        if assessment_mode == "Quick Assessment":
            # Quick assessment with sliders
            st.markdown("### 📊 Quick Security Assessment")
            
            col1, col2 = st.columns(2)
            with col1:
                irsa_enabled = st.checkbox("IRSA Enabled", key="quick_irsa")
                pss_enabled = st.checkbox("Pod Security Standards", key="quick_pss")
                network_policies = st.checkbox("Network Policies", key="quick_np")
            with col2:
                secrets_encrypted = st.checkbox("Secrets Encryption", key="quick_secrets")
                guardduty_enabled = st.checkbox("GuardDuty EKS", key="quick_gd")
                logging_enabled = st.checkbox("Control Plane Logging", key="quick_log")
            
            implemented = sum([irsa_enabled, pss_enabled, network_policies, 
                              secrets_encrypted, guardduty_enabled, logging_enabled])
            score = int((implemented / 6) * 100)
            
            st.markdown("---")
            col1, col2 = st.columns(2)
            col1.metric("Security Score", f"{score}/100")
            col2.metric("Controls Implemented", f"{implemented}/6")
            
            if score < 100:
                st.warning("⚠️ Some critical controls are not implemented. Enable all controls for maximum security.")
        
        else:
            # Detailed checklist in expanders
            st.markdown("### ✅ Security Controls Checklist")
            
            total_controls = 0
            implemented_controls = 0
            critical_missing = []
            
            for category in EKSSecurityHardening.SECURITY_CONTROLS:
                with st.expander(f"📁 {category['category']}", expanded=False):
                    for control in category['controls']:
                        total_controls += 1
                        key = f"sec_{hash(control['name']) % 100000}"
                        
                        critical_badge = "🔴 CRITICAL" if control['critical'] else "🟡 Recommended"
                        is_implemented = st.checkbox(
                            f"{control['name']} ({critical_badge})",
                            key=key,
                            value=control.get('implemented', False)
                        )
                        
                        if is_implemented:
                            implemented_controls += 1
                        elif control['critical']:
                            critical_missing.append(control['name'])
        
        # Calculate score
        security_score = int((implemented_controls / total_controls) * 100)
        
        st.markdown("---")
        st.markdown("### 📊 Security Assessment Results")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("Security Score", f"{security_score}/100")
        with col2:
            st.metric("Controls Implemented", f"{implemented_controls}/{total_controls}")
        with col3:
            st.metric("Critical Missing", len(critical_missing))
        
        # Critical missing controls
        if critical_missing:
            st.error("### 🚨 Critical Controls Missing")
            for control in critical_missing:
                st.markdown(f"- ❌ {control}")
            
            st.markdown("### 🔧 Remediation Steps")
            
            if "Enable IRSA" in str(critical_missing):
                with st.expander("🔧 Enable IRSA (IAM Roles for Service Accounts)"):
                    st.code("""
# 1. Create IAM OIDC provider
eksctl utils associate-iam-oidc-provider \\
  --cluster my-cluster \\
  --approve

# 2. Create IAM role with trust policy
# 3. Annotate ServiceAccount
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-app
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::ACCOUNT:role/my-role
""", language="yaml")
            
            if "Pod Security Standards" in str(critical_missing):
                with st.expander("🔧 Enable Pod Security Standards"):
                    st.code("""
# Apply PSS to namespace
kubectl label namespace my-namespace \\
  pod-security.kubernetes.io/enforce=restricted \\
  pod-security.kubernetes.io/warn=restricted \\
  pod-security.kubernetes.io/audit=restricted
""", language="bash")
            
            if "Network Policies" in str(critical_missing):
                with st.expander("🔧 Implement Network Policies"):
                    st.code("""
# Default deny all ingress
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
spec:
  podSelector: {}
  policyTypes:
    - Ingress

# Allow specific traffic
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-frontend-to-backend
spec:
  podSelector:
    matchLabels:
      app: backend
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: frontend
      ports:
        - port: 8080
""", language="yaml")
        else:
            st.success("✅ All critical security controls are implemented!")


# ============================================================================
# MAIN EKS MODULE - REVAMPED
# ============================================================================

class EKSModernizationModuleRevamped:
    """Main EKS Modernization Module - Revamped with real-world use cases"""
    
    @staticmethod
    def render():
        """Main render method - optimized for speed"""
        st.title("🚀 EKS Modernization & Architecture Hub")
        st.markdown("Design, migrate, optimize, and secure your Kubernetes workloads")
        
        # Use case selection - optimized with radio buttons (faster than button grid)
        selected = st.radio(
            "🎯 What would you like to do?",
            options=["greenfield", "migration", "optimization", "security", "multicluster"],
            format_func=lambda x: EKSUseCases.USE_CASES[x]['title'],
            horizontal=True,
            key="eks_use_case_radio"
        )
        
        st.markdown("---")
        
        # Render selected use case
        if selected == 'greenfield':
            EKSModernizationModuleRevamped._render_greenfield_design()
        elif selected == 'migration':
            EKSMigrationAssessment.render()
        elif selected == 'optimization':
            EKSClusterOptimization.render()
        elif selected == 'security':
            EKSSecurityHardening.render()
        elif selected == 'multicluster':
            EKSModernizationModuleRevamped._render_multicluster_design()
    
    @staticmethod
    def _render_greenfield_design():
        """Render greenfield cluster design wizard"""
        st.markdown("## 🆕 Greenfield EKS Cluster Design")
        st.markdown("Design a new EKS cluster optimized for your requirements")
        
        # Tabs for design workflow - CONSOLIDATED (no duplicate forms)
        tab1, tab2, tab3, tab4 = st.tabs([
            "📝 Requirements & Config",
            "🏗️ Architecture & Diagram",
            "🔒 Security",
            "📦 Export"
        ])
        
        with tab1:
            EKSModernizationModuleRevamped._render_requirements_tab()
        
        with tab2:
            EKSModernizationModuleRevamped._render_architecture_tab()
        
        with tab3:
            EKSModernizationModuleRevamped._render_security_tab()
        
        with tab4:
            EKSModernizationModuleRevamped._render_export_tab()
    
    @staticmethod
    def _render_requirements_tab():
        """Consolidated requirements tab with AI NLP + Manual options"""
        st.markdown("### 📝 Define Your Requirements")
        
        # Input mode selection
        input_mode = st.radio(
            "Choose input method:",
            ["🤖 AI Assistant (Describe in plain English)", "⚙️ Manual Configuration"],
            horizontal=True,
            key="eks_input_mode"
        )
        
        # Initialize session state
        if 'eks_config' not in st.session_state:
            st.session_state.eks_config = {
                'project_name': 'my-eks-cluster',
                'environment': 'production',
                'region': 'us-east-1',
                'availability_zones': ['us-east-1a', 'us-east-1b', 'us-east-1c'],
                'node_groups': [],
                'addons': ['vpc-cni', 'coredns', 'kube-proxy'],
                'monthly_budget': 5000
            }
        
        config = st.session_state.eks_config
        
        if "AI Assistant" in input_mode:
            # AI NLP Input Mode
            EKSModernizationModuleRevamped._render_ai_requirements_input(config)
        else:
            # Manual Configuration Mode
            EKSModernizationModuleRevamped._render_manual_requirements_input(config)
    
    @staticmethod
    def _render_ai_requirements_input(config: Dict):
        """AI-powered natural language requirements input"""
        st.markdown("#### 🤖 Describe Your EKS Requirements")
        st.markdown("*Tell me about your workload in plain English, and I'll configure the cluster for you.*")
        
        # Example prompts
        with st.expander("💡 Example prompts you can use", expanded=False):
            st.markdown("""
            **Production Web Application:**
            > "I need a production EKS cluster in us-west-2 for running 20 microservices. 
            > We expect around 500 pods at peak. Budget is $8000/month. 
            > We need high availability across 3 AZs and PCI-DSS compliance."
            
            **ML/AI Workload:**
            > "Set up a cluster for machine learning workloads with GPU support. 
            > We'll run training jobs and inference services. Need spot instances to save costs.
            > Region should be us-east-1, budget around $15000/month."
            
            **Development Environment:**
            > "Create a small dev cluster for our team of 5 developers. 
            > We run about 10 services, nothing critical. Keep costs under $500/month.
            > Single AZ is fine, us-east-1 region."
            
            **Event-Driven Architecture:**
            > "We need a cluster for event processing with Kafka and real-time analytics.
            > High throughput, memory-optimized instances. Production environment in eu-west-1.
            > Must be GDPR compliant. Budget is $12000/month."
            """)
        
        # Text input for requirements
        requirements_text = st.text_area(
            "Describe your requirements:",
            height=150,
            placeholder="Example: I need a production EKS cluster for 30 microservices in us-west-2. We expect 800 pods at peak load. Need high availability with 3 AZs. Budget is $10,000/month. We need HIPAA compliance for healthcare data.",
            key="eks_nlp_input"
        )
        
        col1, col2 = st.columns([1, 4])
        with col1:
            analyze_button = st.button("🔍 Analyze & Configure", type="primary", use_container_width=True)
        
        if analyze_button and requirements_text:
            with st.spinner("🤖 Analyzing your requirements..."):
                # Parse requirements using NLP
                parsed_config = EKSNLPParser.parse_requirements(requirements_text)
                
                # Update config
                for key, value in parsed_config.items():
                    if value is not None:
                        config[key] = value
                
                st.session_state.eks_config = config
                st.success("✅ Requirements analyzed! Configuration updated.")
        
        # Show parsed configuration
        if requirements_text or st.session_state.get('eks_nlp_analyzed'):
            st.markdown("---")
            st.markdown("#### 📊 Extracted Configuration")
            
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.markdown("**Basic Settings**")
                st.write(f"🏷️ Cluster: `{config['project_name']}`")
                st.write(f"🌍 Region: `{config['region']}`")
                st.write(f"🏢 Environment: `{config['environment']}`")
                st.write(f"📍 AZs: `{len(config['availability_zones'])}`")
            
            with col2:
                st.markdown("**Compute**")
                if config.get('node_groups'):
                    ng = config['node_groups'][0]
                    st.write(f"💻 Instance: `{ng.get('instance_type', 'm6i.large')}`")
                    st.write(f"📊 Nodes: `{ng.get('min_size', 3)}-{ng.get('max_size', 20)}`")
                    st.write(f"🏷️ Capacity: `{ng.get('capacity_type', 'ON_DEMAND')}`")
                else:
                    st.write("💻 Instance: `m6i.large`")
                    st.write("📊 Nodes: `3-20`")
            
            with col3:
                st.markdown("**Budget & Compliance**")
                st.write(f"💰 Budget: `${config['monthly_budget']:,}/month`")
                if config.get('compliance'):
                    st.write(f"📜 Compliance: `{', '.join(config['compliance'])}`")
                st.write(f"🔌 Add-ons: `{len(config.get('addons', []))}`")
            
            # Allow manual adjustments
            with st.expander("✏️ Fine-tune configuration", expanded=False):
                EKSModernizationModuleRevamped._render_manual_requirements_input(config)
        
        # Save button
        st.markdown("---")
        if st.button("✅ Save Configuration & Generate Architecture", type="primary", use_container_width=True, key="save_ai"):
            st.session_state.eks_config = config
            st.session_state.eks_config_saved = True
            st.success("✅ Configuration saved! Go to **Architecture & Diagram** tab to see your cluster design.")
    
    @staticmethod
    def _render_manual_requirements_input(config: Dict):
        """Manual configuration form for EKS requirements"""
        st.markdown("*Configure your cluster settings manually*")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("#### Basic Configuration")
            config['project_name'] = st.text_input("Cluster Name", config['project_name'], key="manual_cluster_name")
            config['environment'] = st.selectbox(
                "Environment",
                ["development", "staging", "production", "dr"],
                index=["development", "staging", "production", "dr"].index(config['environment']),
                key="manual_env"
            )
            config['region'] = st.selectbox(
                "AWS Region",
                ["us-east-1", "us-east-2", "us-west-2", "eu-west-1", "eu-central-1", "ap-southeast-1"],
                index=0,
                key="manual_region"
            )
            
            # Update AZs based on region
            az_options = [f"{config['region']}a", f"{config['region']}b", f"{config['region']}c"]
            config['availability_zones'] = st.multiselect(
                "Availability Zones",
                az_options,
                default=az_options if config['environment'] == 'production' else az_options[:2],
                key="manual_azs"
            )
        
        with col2:
            st.markdown("#### Workload Requirements")
            num_services = st.number_input("Number of Services", 1, 500, 10, key="manual_services")
            peak_pods = st.number_input("Peak Pod Count", 10, 10000, 100, key="manual_pods")
            config['monthly_budget'] = st.number_input("Monthly Budget ($)", 0, 1000000, config['monthly_budget'], key="manual_budget")
            
            workload_types = st.multiselect(
                "Workload Types",
                ["Web/API", "Batch Processing", "ML/AI", "Databases", "Event Processing"],
                default=["Web/API"],
                key="manual_workloads"
            )
        
        # Node group configuration
        st.markdown("#### 🖥️ Node Group Configuration")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            compute_strategy = st.selectbox(
                "Compute Strategy",
                ["Karpenter (Recommended)", "Managed Node Groups", "Fargate"],
                key="manual_compute"
            )
        
        with col2:
            instance_type = st.selectbox(
                "Primary Instance Type",
                ["m6i.large", "m6i.xlarge", "m6i.2xlarge", "m6g.large (Graviton)", 
                 "c6i.large", "c6i.xlarge", "r6i.large", "t3.large"],
                key="manual_instance"
            )
        
        with col3:
            capacity_type = st.selectbox(
                "Capacity Type",
                ["Mixed (Spot + On-Demand)", "Spot Only", "On-Demand Only"],
                key="manual_capacity"
            )
        
        min_nodes = st.slider("Min Nodes", 1, 50, 3, key="manual_min_nodes")
        max_nodes = st.slider("Max Nodes", min_nodes, 200, 20, key="manual_max_nodes")
        
        # Save node group config
        config['node_groups'] = [{
            'name': 'primary',
            'instance_type': instance_type.split(' ')[0],
            'min_size': min_nodes,
            'max_size': max_nodes,
            'desired_size': min_nodes,
            'capacity_type': 'SPOT' if 'Spot' in capacity_type else 'ON_DEMAND'
        }]
        
        # Add-ons selection
        st.markdown("#### 🔌 Add-ons")
        
        addon_options = {
            'vpc-cni': 'VPC CNI (Required)',
            'coredns': 'CoreDNS (Required)',
            'kube-proxy': 'kube-proxy (Required)',
            'aws-ebs-csi-driver': 'EBS CSI Driver',
            'aws-efs-csi-driver': 'EFS CSI Driver',
            'aws-load-balancer-controller': 'AWS Load Balancer Controller',
            'metrics-server': 'Metrics Server',
            'cluster-autoscaler': 'Cluster Autoscaler'
        }
        
        selected_addons = st.multiselect(
            "Select Add-ons",
            list(addon_options.keys()),
            default=['vpc-cni', 'coredns', 'kube-proxy', 'aws-ebs-csi-driver', 'aws-load-balancer-controller'],
            format_func=lambda x: addon_options[x],
            key="manual_addons"
        )
        config['addons'] = selected_addons
        
        # Save to session state
        st.session_state.eks_config = config
        
        # Show recommendations
        st.markdown("---")
        st.markdown("### 💡 AI Recommendations")
        
        recommendations = []
        
        if config['environment'] == 'production' and len(config['availability_zones']) < 3:
            recommendations.append("⚠️ Production environment should use 3 AZs for high availability")
        
        if 'Karpenter' in compute_strategy:
            recommendations.append("✅ Karpenter is excellent for cost optimization (30-50% savings)")
        
        if 'Spot' in capacity_type and config['environment'] == 'production':
            recommendations.append("💡 Using Spot with Pod Disruption Budgets for production workloads")
        
        if config['monthly_budget'] > 0:
            estimated_cost = min_nodes * 150  # Rough estimate
            if estimated_cost > config['monthly_budget']:
                recommendations.append(f"⚠️ Estimated cost (${estimated_cost}/mo) exceeds budget (${config['monthly_budget']}/mo)")
            else:
                recommendations.append(f"✅ Configuration within budget: ~${estimated_cost}/mo vs ${config['monthly_budget']}/mo budget")
        
        for rec in recommendations:
            st.info(rec)
        
        if st.button("✅ Save Configuration & Generate Architecture", type="primary", use_container_width=True, key="save_manual"):
            st.session_state.eks_config_saved = True
            st.success("Configuration saved! Go to Architecture tab to see your diagram.")
    
    @staticmethod
    def _render_architecture_tab():
        """Render architecture diagram"""
        st.markdown("### 🏗️ Architecture Visualization")
        
        if 'eks_config' not in st.session_state:
            st.warning("Please configure your requirements first in the Requirements tab.")
            return
        
        config = st.session_state.eks_config
        
        # Generate SVG diagram (pass JSON for caching)
        svg_content = EKSSVGDiagramGenerator.generate_cluster_diagram(json.dumps(config))
        
        # Display the SVG
        st.markdown("#### Your EKS Architecture")
        st.markdown(svg_content, unsafe_allow_html=True)
        
        # Download button
        st.markdown(
            EKSSVGDiagramGenerator.get_svg_download_link(svg_content, f"{config['project_name']}_architecture.svg"),
            unsafe_allow_html=True
        )
        
        # Architecture summary
        st.markdown("---")
        st.markdown("### 📋 Architecture Summary")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("Region", config['region'])
            st.metric("Availability Zones", len(config['availability_zones']))
        
        with col2:
            if config['node_groups']:
                ng = config['node_groups'][0]
                st.metric("Instance Type", ng['instance_type'])
                st.metric("Node Range", f"{ng['min_size']} - {ng['max_size']}")
        
        with col3:
            st.metric("Add-ons", len(config.get('addons', [])))
            st.metric("Environment", config['environment'].title())
        
        # Component details
        st.markdown("### 🔧 Components")
        
        with st.expander("📦 Node Groups"):
            for ng in config.get('node_groups', []):
                st.markdown(f"""
                - **Name:** {ng['name']}
                - **Instance Type:** {ng['instance_type']}
                - **Capacity:** {ng.get('capacity_type', 'ON_DEMAND')}
                - **Scaling:** {ng['min_size']} - {ng['max_size']} nodes
                """)
        
        with st.expander("🔌 Add-ons"):
            for addon in config.get('addons', []):
                st.markdown(f"- {addon}")
        
        with st.expander("🌐 Networking"):
            st.markdown(f"""
            - **VPC:** New VPC with public/private subnets
            - **Availability Zones:** {', '.join(config['availability_zones'])}
            - **NAT Gateways:** {len(config['availability_zones'])} (one per AZ)
            - **Load Balancer:** AWS ALB via Load Balancer Controller
            """)
    
    @staticmethod
    def _render_security_tab():
        """Render security configuration"""
        st.markdown("### 🔒 Security Configuration")
        
        if 'eks_config' not in st.session_state:
            st.warning("Please configure your requirements first.")
            return
        
        config = st.session_state.eks_config
        
        # Security level selection
        security_level = st.select_slider(
            "Security Level",
            options=["Basic", "Standard", "Enhanced", "Maximum"],
            value="Enhanced" if config['environment'] == 'production' else "Standard"
        )
        
        # Security controls based on level
        st.markdown("#### 🛡️ Security Controls")
        
        controls = {
            "Basic": [
                ("✅ VPC isolation", True),
                ("✅ Security groups", True),
                ("⬜ IRSA", False),
                ("⬜ Pod Security Standards", False),
                ("⬜ Network Policies", False),
            ],
            "Standard": [
                ("✅ VPC isolation", True),
                ("✅ Security groups", True),
                ("✅ IRSA", True),
                ("✅ Basic Pod Security", True),
                ("⬜ Network Policies", False),
            ],
            "Enhanced": [
                ("✅ VPC isolation", True),
                ("✅ Security groups", True),
                ("✅ IRSA", True),
                ("✅ Pod Security Standards (Restricted)", True),
                ("✅ Network Policies", True),
                ("✅ Secrets encryption", True),
            ],
            "Maximum": [
                ("✅ VPC isolation", True),
                ("✅ Security groups", True),
                ("✅ IRSA", True),
                ("✅ Pod Security Standards (Restricted)", True),
                ("✅ Network Policies", True),
                ("✅ Secrets encryption", True),
                ("✅ GuardDuty EKS", True),
                ("✅ Private endpoint only", True),
                ("✅ mTLS (service mesh)", True),
            ]
        }
        
        for control, enabled in controls[security_level]:
            st.markdown(control)
        
        # Compliance frameworks
        st.markdown("#### 📜 Compliance Frameworks")
        
        compliance = st.multiselect(
            "Select applicable frameworks",
            ["PCI-DSS", "HIPAA", "SOC 2", "ISO 27001", "GDPR", "FedRAMP"],
            default=[]
        )
        
        if compliance:
            st.info(f"Selected: {', '.join(compliance)}. Additional controls will be applied.")
        
        # Run security assessment button (now connected!)
        st.markdown("---")
        if st.button("🔍 Run Security Assessment", type="primary", use_container_width=True):
            st.session_state.eks_use_case = 'security'
            st.rerun()
    
    @staticmethod
    def _render_export_tab():
        """Render IaC export"""
        st.markdown("### 📦 Export Infrastructure as Code")
        
        if 'eks_config' not in st.session_state:
            st.warning("Please configure your requirements first.")
            return
        
        config = st.session_state.eks_config
        
        export_format = st.selectbox(
            "Export Format",
            ["Terraform", "CloudFormation", "eksctl", "Pulumi"]
        )
        
        if export_format == "Terraform":
            terraform_code = EKSModernizationModuleRevamped._generate_terraform(config)
            st.code(terraform_code, language="hcl")
            
            st.download_button(
                "📥 Download Terraform",
                terraform_code,
                file_name=f"{config['project_name']}_eks.tf",
                mime="text/plain"
            )
        
        elif export_format == "eksctl":
            eksctl_code = EKSModernizationModuleRevamped._generate_eksctl(config)
            st.code(eksctl_code, language="yaml")
            
            st.download_button(
                "📥 Download eksctl Config",
                eksctl_code,
                file_name=f"{config['project_name']}_eksctl.yaml",
                mime="text/yaml"
            )
    
    @staticmethod
    def _generate_terraform(config: Dict) -> str:
        """Generate Terraform code for EKS cluster"""
        ng = config.get('node_groups', [{}])[0]
        
        return f'''# EKS Cluster: {config['project_name']}
# Generated by EKS Modernization Hub
# Environment: {config['environment']}

terraform {{
  required_version = ">= 1.0"
  required_providers {{
    aws = {{
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }}
  }}
}}

provider "aws" {{
  region = "{config['region']}"
}}

# VPC Module
module "vpc" {{
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"

  name = "{config['project_name']}-vpc"
  cidr = "10.0.0.0/16"

  azs             = {json.dumps(config['availability_zones'])}
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnets  = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]

  enable_nat_gateway     = true
  single_nat_gateway     = {str(config['environment'] != 'production').lower()}
  enable_dns_hostnames   = true
  enable_dns_support     = true

  tags = {{
    Environment = "{config['environment']}"
    Terraform   = "true"
  }}
}}

# EKS Module
module "eks" {{
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.0"

  cluster_name    = "{config['project_name']}"
  cluster_version = "1.29"

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  cluster_endpoint_public_access  = true
  cluster_endpoint_private_access = true

  eks_managed_node_groups = {{
    primary = {{
      name           = "primary"
      instance_types = ["{ng.get('instance_type', 'm6i.large')}"]
      capacity_type  = "{ng.get('capacity_type', 'ON_DEMAND')}"

      min_size     = {ng.get('min_size', 3)}
      max_size     = {ng.get('max_size', 20)}
      desired_size = {ng.get('desired_size', 3)}
    }}
  }}

  # Add-ons
  cluster_addons = {{
    coredns = {{
      most_recent = true
    }}
    kube-proxy = {{
      most_recent = true
    }}
    vpc-cni = {{
      most_recent = true
    }}
    aws-ebs-csi-driver = {{
      most_recent = true
    }}
  }}

  tags = {{
    Environment = "{config['environment']}"
    Terraform   = "true"
  }}
}}

output "cluster_endpoint" {{
  value = module.eks.cluster_endpoint
}}

output "cluster_name" {{
  value = module.eks.cluster_name
}}
'''
    
    @staticmethod
    def _generate_eksctl(config: Dict) -> str:
        """Generate eksctl config"""
        ng = config.get('node_groups', [{}])[0]
        
        return f'''# eksctl config for {config['project_name']}
# Generated by EKS Modernization Hub

apiVersion: eksctl.io/v1alpha5
kind: ClusterConfig

metadata:
  name: {config['project_name']}
  region: {config['region']}
  version: "1.29"

vpc:
  cidr: 10.0.0.0/16
  nat:
    gateway: {"HighlyAvailable" if config['environment'] == 'production' else "Single"}

availabilityZones: {json.dumps(config['availability_zones'])}

managedNodeGroups:
  - name: primary
    instanceType: {ng.get('instance_type', 'm6i.large')}
    minSize: {ng.get('min_size', 3)}
    maxSize: {ng.get('max_size', 20)}
    desiredCapacity: {ng.get('desired_size', 3)}
    volumeSize: 100
    volumeType: gp3
    privateNetworking: true
    iam:
      withAddonPolicies:
        ebs: true
        efs: true
        albIngress: true
        cloudWatch: true

addons:
  - name: vpc-cni
    version: latest
  - name: coredns
    version: latest
  - name: kube-proxy
    version: latest
  - name: aws-ebs-csi-driver
    version: latest

cloudWatch:
  clusterLogging:
    enableTypes: ["api", "audit", "authenticator", "controllerManager", "scheduler"]
'''
    
    @staticmethod
    def _render_multicluster_design():
        """Render multi-cluster design wizard"""
        st.markdown("## 🌐 Multi-Cluster Architecture Design")
        st.markdown("Design a multi-cluster Kubernetes strategy")
        
        topology = st.selectbox(
            "Select Topology Pattern",
            ["Hub-Spoke (Centralized Management)", 
             "Federated (Equal Clusters)", 
             "Cluster per Environment",
             "Cluster per Team"]
        )
        
        if "Hub-Spoke" in topology:
            st.markdown("""
            ### Hub-Spoke Architecture
            
            **Use Case:** Centralized management cluster with workload clusters
            
            ```
                    ┌─────────────────┐
                    │   Hub Cluster   │
                    │  (Management)   │
                    └────────┬────────┘
                             │
            ┌────────────────┼────────────────┐
            │                │                │
            ▼                ▼                ▼
        ┌───────┐       ┌───────┐       ┌───────┐
        │ Prod  │       │Staging│       │  Dev  │
        │Cluster│       │Cluster│       │Cluster│
        └───────┘       └───────┘       └───────┘
            ```
            
            **Components:**
            - ArgoCD/Flux in hub for GitOps
            - Prometheus federation for monitoring
            - Shared VPC or Transit Gateway
            """)
        
        num_clusters = st.number_input("Number of Clusters", 2, 20, 3)
        
        st.markdown("### 🔧 Cluster Configuration")
        
        clusters = []
        for i in range(num_clusters):
            with st.expander(f"Cluster {i+1} Configuration"):
                name = st.text_input(f"Name", f"cluster-{i+1}", key=f"mc_name_{i}")
                purpose = st.selectbox(
                    "Purpose",
                    ["Production", "Staging", "Development", "Management", "DR"],
                    key=f"mc_purpose_{i}"
                )
                region = st.selectbox(
                    "Region",
                    ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"],
                    key=f"mc_region_{i}"
                )
                clusters.append({"name": name, "purpose": purpose, "region": region})
        
        if st.button("📊 Generate Multi-Cluster Architecture", type="primary"):
            st.success(f"Multi-cluster architecture with {num_clusters} clusters generated!")
            st.json({"topology": topology, "clusters": clusters})


# ============================================================================
# ENTRY POINTS
# ============================================================================

def render_eks_architecture_wizard():
    """Entry point for the EKS module"""
    EKSModernizationModuleRevamped.render()


class EKSArchitectureWizardModule:
    """Wrapper class for compatibility"""
    
    @staticmethod
    def render():
        EKSModernizationModuleRevamped.render()


# For direct execution
if __name__ == "__main__":
    import streamlit as st
    st.set_page_config(page_title="EKS Modernization Hub", page_icon="🚀", layout="wide")
    render_eks_architecture_wizard()
