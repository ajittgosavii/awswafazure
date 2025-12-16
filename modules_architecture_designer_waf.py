"""
AWS Architecture Designer + Well-Architected Assessment
Complete visual architecture design with NLP, Terraform import, and conversational WAF completion

Features:
- Natural language architecture input
- Terraform import and visualization
- Visual component designer
- Real-time WAF assessment
- AI chat interface for completing assessment
- Export to Terraform/CloudFormation
"""

from __future__ import annotations

import streamlit as st
import json
import pandas as pd
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field, asdict
import uuid
import re

# Import existing WAF engine
try:
    from waf_review_module import (
        WAFAssessment,
        Question,
        Pillar,
        get_waf_questions,
        WAFAutoDetector
    )
    WAF_ENGINE_AVAILABLE = True
except:
    WAF_ENGINE_AVAILABLE = False

# Anthropic for NLP and chat
try:
    import anthropic
    import os
    ANTHROPIC_AVAILABLE = True
    
    # Initialize client
    api_key = os.getenv('ANTHROPIC_API_KEY') or st.secrets.get('ANTHROPIC_API_KEY', '')
    if api_key:
        anthropic_client = anthropic.Anthropic(api_key=api_key)
    else:
        anthropic_client = None
except:
    ANTHROPIC_AVAILABLE = False
    anthropic_client = None

# ============================================================================
# AWS ENVIRONMENT SCANNER INTEGRATION
# ============================================================================

try:
    from aws_connector import get_aws_session, test_aws_connection
    from landscape_scanner import (
        AWSLandscapeScanner,
        Finding as ScannerFinding,
        LandscapeAssessment,
        generate_demo_assessment
    )
    AWS_SCANNER_AVAILABLE = True
except ImportError:
    AWS_SCANNER_AVAILABLE = False

class AWSEnvironmentImporter:
    """Import existing AWS infrastructure into architecture designer"""
    
    @staticmethod
    def scan_and_import(region: str = 'us-east-1', account_id: str = None) -> List[AWSComponent]:
        """Scan AWS environment and import as components"""
        
        if not AWS_SCANNER_AVAILABLE:
            st.error("AWS Scanner not available. Install aws_connector and landscape_scanner modules.")
            return []
        
        components = []
        
        try:
            # Test AWS connection
            session = get_aws_session()
            if not session:
                st.error("❌ No AWS credentials configured")
                return []
            
            # Run landscape scan
            with st.spinner(f"Scanning AWS environment in {region}..."):
                scanner = AWSLandscapeScanner(session, region)
                assessment = scanner.scan_landscape()
            
            # Convert scan results to components
            components = AWSEnvironmentImporter._convert_scan_to_components(assessment, region)
            
            st.success(f"✅ Imported {len(components)} resources from AWS")
            
        except Exception as e:
            st.error(f"Error scanning AWS: {str(e)}")
        
        return components
    
    @staticmethod
    def _convert_scan_to_components(assessment: 'LandscapeAssessment', region: str) -> List[AWSComponent]:
        """Convert landscape assessment to architecture components"""
        
        components = []
        
        # Process each resource type
        if hasattr(assessment, 'compute_resources'):
            for resource in assessment.compute_resources:
                component = AWSEnvironmentImporter._convert_compute(resource, region)
                if component:
                    components.append(component)
        
        if hasattr(assessment, 'database_resources'):
            for resource in assessment.database_resources:
                component = AWSEnvironmentImporter._convert_database(resource, region)
                if component:
                    components.append(component)
        
        if hasattr(assessment, 'storage_resources'):
            for resource in assessment.storage_resources:
                component = AWSEnvironmentImporter._convert_storage(resource, region)
                if component:
                    components.append(component)
        
        if hasattr(assessment, 'network_resources'):
            for resource in assessment.network_resources:
                component = AWSEnvironmentImporter._convert_network(resource, region)
                if component:
                    components.append(component)
        
        # If assessment has generic resources dict
        if hasattr(assessment, 'resources'):
            for resource_type, resources in assessment.resources.items():
                for resource in resources:
                    component = AWSEnvironmentImporter._convert_generic(resource, resource_type, region)
                    if component:
                        components.append(component)
        
        return components
    
    @staticmethod
    def _convert_compute(resource: Dict, region: str) -> Optional[AWSComponent]:
        """Convert compute resource to component"""
        
        resource_type = resource.get('Type', '')
        
        if 'EC2' in resource_type or 'Instance' in resource_type:
            return AWSComponent(
                id=resource.get('ResourceId', str(uuid.uuid4())),
                name=resource.get('Name') or resource.get('ResourceId', 'EC2 Instance'),
                service_type='ec2',
                properties={
                    'instance_type': resource.get('InstanceType'),
                    'region': region,
                    'state': resource.get('State'),
                    'availability_zone': resource.get('AvailabilityZone'),
                    'imported': True,
                    'resource_id': resource.get('ResourceId')
                }
            )
        
        elif 'ECS' in resource_type:
            return AWSComponent(
                id=str(uuid.uuid4()),
                name=resource.get('Name', 'ECS Cluster'),
                service_type='ecs',
                properties={
                    'region': region,
                    'imported': True
                }
            )
        
        elif 'EKS' in resource_type:
            return AWSComponent(
                id=str(uuid.uuid4()),
                name=resource.get('Name', 'EKS Cluster'),
                service_type='eks',
                properties={
                    'region': region,
                    'version': resource.get('Version'),
                    'imported': True
                }
            )
        
        return None
    
    @staticmethod
    def _convert_database(resource: Dict, region: str) -> Optional[AWSComponent]:
        """Convert database resource to component"""
        
        resource_type = resource.get('Type', '')
        
        if 'RDS' in resource_type or 'DBInstance' in resource_type:
            return AWSComponent(
                id=resource.get('ResourceId', str(uuid.uuid4())),
                name=resource.get('Name') or resource.get('DBInstanceIdentifier', 'RDS Instance'),
                service_type='rds',
                properties={
                    'engine': resource.get('Engine'),
                    'instance_class': resource.get('DBInstanceClass'),
                    'encrypted': resource.get('StorageEncrypted', False),
                    'multi_az': resource.get('MultiAZ', False),
                    'backup_enabled': resource.get('BackupRetentionPeriod', 0) > 0,
                    'publicly_accessible': resource.get('PubliclyAccessible', False),
                    'region': region,
                    'imported': True,
                    'resource_id': resource.get('ResourceId')
                }
            )
        
        elif 'DynamoDB' in resource_type:
            return AWSComponent(
                id=str(uuid.uuid4()),
                name=resource.get('Name', 'DynamoDB Table'),
                service_type='dynamodb',
                properties={
                    'region': region,
                    'billing_mode': resource.get('BillingMode'),
                    'imported': True
                }
            )
        
        return None
    
    @staticmethod
    def _convert_storage(resource: Dict, region: str) -> Optional[AWSComponent]:
        """Convert storage resource to component"""
        
        resource_type = resource.get('Type', '')
        
        if 'S3' in resource_type or 'Bucket' in resource_type:
            return AWSComponent(
                id=resource.get('ResourceId', str(uuid.uuid4())),
                name=resource.get('Name') or resource.get('BucketName', 'S3 Bucket'),
                service_type='s3',
                properties={
                    'region': region,
                    'versioning': resource.get('Versioning', False),
                    'encryption': resource.get('Encryption', False),
                    'public': resource.get('PublicAccess', False),
                    'imported': True,
                    'resource_id': resource.get('ResourceId')
                }
            )
        
        return None
    
    @staticmethod
    def _convert_network(resource: Dict, region: str) -> Optional[AWSComponent]:
        """Convert network resource to component"""
        
        resource_type = resource.get('Type', '')
        
        if 'VPC' in resource_type:
            return AWSComponent(
                id=str(uuid.uuid4()),
                name=resource.get('Name', 'VPC'),
                service_type='vpc',
                properties={
                    'cidr': resource.get('CidrBlock'),
                    'region': region,
                    'imported': True
                }
            )
        
        elif 'LoadBalancer' in resource_type or 'ALB' in resource_type or 'ELB' in resource_type:
            return AWSComponent(
                id=str(uuid.uuid4()),
                name=resource.get('Name', 'Load Balancer'),
                service_type='alb',
                properties={
                    'region': region,
                    'scheme': resource.get('Scheme'),
                    'imported': True
                }
            )
        
        return None
    
    @staticmethod
    def _convert_generic(resource: Dict, resource_type: str, region: str) -> Optional[AWSComponent]:
        """Convert generic resource to component"""
        
        # Map resource types to service types
        service_type_map = {
            'ec2': 'ec2',
            'rds': 'rds',
            's3': 's3',
            'lambda': 'lambda',
            'vpc': 'vpc',
            'alb': 'alb',
            'elb': 'alb',
            'ecs': 'ecs',
            'eks': 'eks',
            'cloudfront': 'cloudfront',
            'elasticache': 'cache',
            'sqs': 'queue',
            'sns': 'sns'
        }
        
        service_type = service_type_map.get(resource_type.lower(), resource_type.lower())
        
        return AWSComponent(
            id=str(uuid.uuid4()),
            name=resource.get('Name', f"{resource_type.upper()} Resource"),
            service_type=service_type,
            properties={
                'region': region,
                'imported': True,
                'resource_data': resource
            }
        )

# ============================================================================
# DATA MODELS
# ============================================================================

@dataclass
class AWSComponent:
    """AWS Service Component"""
    id: str
    name: str
    service_type: str  # ec2, rds, s3, alb, vpc, etc.
    properties: Dict[str, Any] = field(default_factory=dict)
    connections: List[str] = field(default_factory=list)  # Connected component IDs
    waf_score: int = 0
    issues: List[str] = field(default_factory=list)

@dataclass  
class Architecture:
    """Complete Architecture"""
    id: str
    name: str
    description: str
    components: List[AWSComponent] = field(default_factory=list)
    waf_assessment: Optional[Dict] = None
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'components': [asdict(c) for c in self.components],
            'waf_assessment': self.waf_assessment,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }

# ============================================================================
# NLP ARCHITECTURE PARSER
# ============================================================================

class NLPArchitectureParser:
    """Parse natural language into architecture components"""
    
    @staticmethod
    def parse(description: str) -> List[AWSComponent]:
        """Parse NLP description into components"""
        
        if not anthropic_client:
            return NLPArchitectureParser._basic_parse(description)
        
        try:
            # Call Claude API to parse
            message = anthropic_client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=2000,
                messages=[{
                    "role": "user",
                    "content": f"""Parse this architecture description into AWS components:

{description}

Extract all mentioned AWS services and return as JSON array with this format:
[
  {{
    "name": "Component name",
    "service_type": "AWS service (ec2, rds, s3, alb, vpc, etc)",
    "properties": {{"key": "value"}}
  }}
]

Be specific about:
- Instance types
- Database engines
- Storage types
- Networking details
- Security settings"""
                }]
            )
            
            # Extract JSON from response
            response_text = message.content[0].text
            json_match = re.search(r'\[.*\]', response_text, re.DOTALL)
            
            if json_match:
                components_data = json.loads(json_match.group(0))
                components = []
                
                for comp_data in components_data:
                    component = AWSComponent(
                        id=str(uuid.uuid4()),
                        name=comp_data.get('name', 'Unknown'),
                        service_type=comp_data.get('service_type', 'unknown'),
                        properties=comp_data.get('properties', {})
                    )
                    components.append(component)
                
                return components
            
        except Exception as e:
            st.warning(f"NLP parsing error: {e}")
        
        return NLPArchitectureParser._basic_parse(description)
    
    @staticmethod
    def _basic_parse(description: str) -> List[AWSComponent]:
        """Basic keyword-based parsing"""
        components = []
        desc_lower = description.lower()
        
        # Service mapping
        service_keywords = {
            'rds': ('rds', 'database', 'postgres', 'mysql', 'aurora'),
            'ec2': ('ec2', 'instance', 'server', 'compute'),
            's3': ('s3', 'bucket', 'storage', 'static'),
            'alb': ('alb', 'load balancer', 'elb'),
            'vpc': ('vpc', 'network'),
            'cloudfront': ('cloudfront', 'cdn'),
            'lambda': ('lambda', 'serverless', 'function'),
            'ecs': ('ecs', 'fargate', 'container'),
            'eks': ('eks', 'kubernetes', 'k8s')
        }
        
        for service, keywords in service_keywords.items():
            if any(kw in desc_lower for kw in keywords):
                component = AWSComponent(
                    id=str(uuid.uuid4()),
                    name=f"{service.upper()} Component",
                    service_type=service,
                    properties={}
                )
                components.append(component)
        
        return components

# ============================================================================
# TERRAFORM PARSER
# ============================================================================

class TerraformParser:
    """Parse Terraform files into architecture"""
    
    @staticmethod
    def parse(terraform_content: str) -> List[AWSComponent]:
        """Parse Terraform HCL into components"""
        components = []
        
        # Basic regex-based parsing
        # resource "aws_instance" "web" { ... }
        resource_pattern = r'resource\s+"([^"]+)"\s+"([^"]+)"\s*{([^}]*)}'
        
        matches = re.finditer(resource_pattern, terraform_content, re.DOTALL)
        
        for match in matches:
            resource_type = match.group(1)
            resource_name = match.group(2)
            resource_body = match.group(3)
            
            # Map to our service types
            service_type = TerraformParser._map_terraform_type(resource_type)
            
            # Extract properties
            properties = TerraformParser._extract_properties(resource_body)
            
            component = AWSComponent(
                id=str(uuid.uuid4()),
                name=f"{resource_name} ({service_type})",
                service_type=service_type,
                properties=properties
            )
            components.append(component)
        
        return components
    
    @staticmethod
    def _map_terraform_type(tf_type: str) -> str:
        """Map Terraform resource type to our service type"""
        mapping = {
            'aws_instance': 'ec2',
            'aws_db_instance': 'rds',
            'aws_s3_bucket': 's3',
            'aws_lb': 'alb',
            'aws_alb': 'alb',
            'aws_vpc': 'vpc',
            'aws_cloudfront_distribution': 'cloudfront',
            'aws_lambda_function': 'lambda',
            'aws_ecs_cluster': 'ecs',
            'aws_eks_cluster': 'eks'
        }
        return mapping.get(tf_type, tf_type.replace('aws_', ''))
    
    @staticmethod
    def _extract_properties(body: str) -> Dict:
        """Extract properties from Terraform resource body"""
        properties = {}
        
        # Simple key-value extraction
        kv_pattern = r'(\w+)\s*=\s*"([^"]*)"'
        for match in re.finditer(kv_pattern, body):
            properties[match.group(1)] = match.group(2)
        
        # Boolean values
        bool_pattern = r'(\w+)\s*=\s*(true|false)'
        for match in re.finditer(bool_pattern, body):
            properties[match.group(1)] = match.group(2) == 'true'
        
        return properties

# ============================================================================
# WAF ASSESSMENT ENGINE
# ============================================================================

class ArchitectureWAFAssessor:
    """Assess architecture against WAF"""
    
    @staticmethod
    def assess(architecture: Architecture) -> Dict:
        """Run WAF assessment on architecture"""
        
        scores = {
            'operational_excellence': 75,
            'security': 70,
            'reliability': 75,
            'performance': 80,
            'cost': 85,
            'sustainability': 70
        }
        
        questions_remaining = []
        
        # Analyze components
        for component in architecture.components:
            service = component.service_type.lower()
            props = component.properties
            
            # Security scoring
            if service in ['rds', 'database']:
                if props.get('encrypted') or props.get('storage_encrypted'):
                    scores['security'] += 5
                else:
                    scores['security'] -= 10
                    component.issues.append("Database not encrypted")
                    questions_remaining.append({
                        'component': component.name,
                        'question': 'Why is encryption not enabled for this database?'
                    })
                
                if props.get('publicly_accessible') == True:
                    scores['security'] -= 15
                    component.issues.append("Database publicly accessible")
            
            # Reliability scoring
            if service in ['rds', 'ec2', 'alb']:
                if props.get('multi_az') or props.get('availability_zones'):
                    scores['reliability'] += 5
                else:
                    scores['reliability'] -= 8
                    questions_remaining.append({
                        'component': component.name,
                        'question': 'What is your strategy for high availability?'
                    })
            
            # Auto scaling
            if service in ['ec2', 'ecs']:
                if 'auto' in str(props) or 'scaling' in str(props):
                    scores['performance'] += 5
                    scores['cost'] += 3
        
        # Cap scores
        scores = {k: max(0, min(100, v)) for k, v in scores.items()}
        
        # Overall score
        overall = sum(scores.values()) // len(scores)
        
        return {
            'overall_score': overall,
            'pillar_scores': scores,
            'questions_remaining': questions_remaining,
            'issues_found': sum(len(c.issues) for c in architecture.components)
        }

# ============================================================================
# AI CHAT INTERFACE
# ============================================================================

class WAFChatAssistant:
    """Conversational AI for completing WAF assessment"""
    
    def __init__(self):
        self.conversation_history = []
    
    def chat(self, user_message: str, architecture: Architecture, 
             assessment: Dict) -> str:
        """Chat with user to complete assessment"""
        
        if not anthropic_client:
            return "AI chat not available. Please configure ANTHROPIC_API_KEY."
        
        try:
            # Build context
            context = self._build_context(architecture, assessment)
            
            # Add to history
            self.conversation_history.append({
                "role": "user",
                "content": user_message
            })
            
            # Call Claude
            message = anthropic_client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=1000,
                system=f"""You are an AWS Well-Architected Framework expert helping complete an architecture assessment.

Architecture Context:
{context}

Your role:
- Ask clarifying questions about the architecture
- Help complete the WAF assessment
- Provide recommendations
- Update assessment scores based on responses

Be conversational and helpful.""",
                messages=self.conversation_history
            )
            
            response = message.content[0].text
            
            # Add to history
            self.conversation_history.append({
                "role": "assistant",
                "content": response
            })
            
            return response
            
        except Exception as e:
            return f"Error: {str(e)}"
    
    def _build_context(self, architecture: Architecture, assessment: Dict) -> str:
        """Build context for AI"""
        context = f"Architecture: {architecture.name}\n"
        context += f"Components: {len(architecture.components)}\n\n"
        
        for comp in architecture.components:
            context += f"- {comp.name} ({comp.service_type})\n"
        
        if assessment:
            context += f"\nCurrent WAF Score: {assessment.get('overall_score', 0)}/100\n"
            context += f"Questions Remaining: {len(assessment.get('questions_remaining', []))}\n"
        
        return context

# ============================================================================
# MAIN MODULE CLASS
# ============================================================================

class ArchitectureDesignerModule:
    """Main Architecture Designer + WAF Module"""
    
    @staticmethod
    def initialize():
        """Initialize session state"""
        if 'current_architecture' not in st.session_state:
            st.session_state.current_architecture = None
        if 'architectures' not in st.session_state:
            st.session_state.architectures = {}
        if 'chat_assistant' not in st.session_state:
            st.session_state.chat_assistant = WAFChatAssistant()
        if 'chat_messages' not in st.session_state:
            st.session_state.chat_messages = []
    
    @staticmethod
    def render():
        """Main render method"""
        
        ArchitectureDesignerModule.initialize()
        
        # Header
        st.markdown("""
        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                    padding: 2rem; border-radius: 12px; margin-bottom: 2rem; color: white;">
            <h1 style="margin: 0;">🎨 Architecture Designer + WAF Assessment</h1>
            <p style="margin: 0.5rem 0 0 0; opacity: 0.9;">
                Design with NLP, visualize Terraform, assess with AI
            </p>
        </div>
        """, unsafe_allow_html=True)
        
        # Status indicators
        col1, col2, col3 = st.columns(3)
        with col1:
            st.info(f"NLP: {'✅' if ANTHROPIC_AVAILABLE else '⚠️'}")
        with col2:
            st.info(f"WAF: {'✅' if WAF_ENGINE_AVAILABLE else '⚠️'}")
        with col3:
            st.info(f"Designs: {len(st.session_state.architectures)}")
        
        # Main tabs
        tabs = st.tabs([
            "🎨 Design",
            "⚡ WAF Assessment",
            "💬 AI Discussion",
            "📤 Export"
        ])
        
        with tabs[0]:
            ArchitectureDesignerModule._render_design_tab()
        
        with tabs[1]:
            ArchitectureDesignerModule._render_waf_tab()
        
        with tabs[2]:
            ArchitectureDesignerModule._render_chat_tab()
        
        with tabs[3]:
            ArchitectureDesignerModule._render_export_tab()
    
    @staticmethod
    def _render_design_tab():
        """Render design interface"""
        
        st.subheader("🎨 Design Your Architecture")
        
        # Input methods
        st.markdown("### Choose Input Method")
        
        input_method = st.radio(
            "How would you like to design?",
            ["💬 Natural Language", "📄 Upload Terraform", "☁️ Scan AWS Environment", "🖱️ Visual Builder"],
            horizontal=True
        )
        
        if input_method == "💬 Natural Language":
            ArchitectureDesignerModule._render_nlp_input()
        
        elif input_method == "📄 Upload Terraform":
            ArchitectureDesignerModule._render_terraform_input()
        
        elif input_method == "☁️ Scan AWS Environment":
            ArchitectureDesignerModule._render_aws_scan_input()
        
        else:
            ArchitectureDesignerModule._render_visual_builder()
        
        # Show current architecture
        if st.session_state.current_architecture:
            st.markdown("---")
            ArchitectureDesignerModule._render_architecture_view()
    
    @staticmethod
    def _render_nlp_input():
        """Natural language input"""
        
        st.markdown("### Describe Your Architecture")
        
        example_text = """Example:
I need a production-ready 3-tier web application with:
- Application Load Balancer for traffic distribution
- EC2 Auto Scaling group (2-10 instances, t3.medium)
- RDS PostgreSQL database (Multi-AZ, encrypted)
- S3 bucket for static assets
- CloudFront CDN
- VPC with public and private subnets"""
        
        with st.expander("💡 See Example"):
            st.code(example_text)
        
        description = st.text_area(
            "Describe your architecture:",
            height=200,
            placeholder="I need a web application with..."
        )
        
        col1, col2 = st.columns(2)
        
        with col1:
            arch_name = st.text_input("Architecture Name", "My Architecture")
        
        with col2:
            if st.button("🚀 Generate Architecture", type="primary", use_container_width=True):
                if description:
                    with st.spinner("Parsing your description..."):
                        components = NLPArchitectureParser.parse(description)
                        
                        architecture = Architecture(
                            id=str(uuid.uuid4()),
                            name=arch_name,
                            description=description,
                            components=components
                        )
                        
                        st.session_state.current_architecture = architecture
                        st.session_state.architectures[arch_name] = architecture
                        
                        st.success(f"✅ Created architecture with {len(components)} components!")
                        st.rerun()
                else:
                    st.error("Please provide a description")
    
    @staticmethod
    def _render_terraform_input():
        """Terraform upload"""
        
        st.markdown("### Upload Terraform Files")
        
        uploaded_file = st.file_uploader(
            "Upload .tf file",
            type=['tf', 'txt'],
            help="Upload your Terraform configuration file"
        )
        
        if uploaded_file:
            terraform_content = uploaded_file.read().decode('utf-8')
            
            st.code(terraform_content, language='hcl')
            
            if st.button("📊 Parse & Visualize", type="primary"):
                with st.spinner("Parsing Terraform..."):
                    components = TerraformParser.parse(terraform_content)
                    
                    architecture = Architecture(
                        id=str(uuid.uuid4()),
                        name=uploaded_file.name.replace('.tf', ''),
                        description=f"Imported from {uploaded_file.name}",
                        components=components
                    )
                    
                    st.session_state.current_architecture = architecture
                    st.session_state.architectures[architecture.name] = architecture
                    
                    st.success(f"✅ Parsed {len(components)} resources!")
                    st.rerun()
    

    @staticmethod
    def _render_aws_scan_input():
        """AWS environment scanning"""
        
        st.markdown("### Import from AWS Environment")
        
        if not AWS_SCANNER_AVAILABLE:
            st.error("""
            ❌ **AWS Scanner Not Available**
            
            To enable AWS environment scanning, ensure:
            1. `aws_connector.py` is in your project
            2. `landscape_scanner.py` is in your project
            3. AWS credentials are configured
            
            These modules should already be part of your AWS WAF Advisor application.
            """)
            return
        
        st.info("""
        📡 **Import Your Existing AWS Infrastructure**
        
        This will scan your AWS account and automatically import:
        - EC2 instances and Auto Scaling groups
        - RDS databases
        - S3 buckets
        - Load Balancers
        - VPCs and networking
        - Lambda functions
        - ECS/EKS clusters
        - And more...
        
        All resources will be analyzed against the Well-Architected Framework!
        """)
        
        # Check AWS connection
        try:
            from aws_connector import get_aws_session
            session = get_aws_session()
            
            if not session:
                st.warning("""
                ⚠️ **No AWS Credentials Configured**
                
                Please configure AWS credentials first:
                1. Go to AWS Connector tab
                2. Enter your credentials
                3. Test connection
                4. Return here to scan
                """)
                return
            
            st.success("✅ AWS credentials configured")
            
        except Exception as e:
            st.error(f"Error checking AWS connection: {str(e)}")
            return
        
        # Scan configuration
        col1, col2 = st.columns(2)
        
        with col1:
            region = st.selectbox(
                "AWS Region",
                ["us-east-1", "us-east-2", "us-west-1", "us-west-2", 
                 "eu-west-1", "eu-central-1", "ap-southeast-1", "ap-northeast-1"]
            )
        
        with col2:
            arch_name = st.text_input("Architecture Name", f"AWS-{region}")
        
        # Scan options
        with st.expander("⚙️ Advanced Options"):
            scan_compute = st.checkbox("Scan Compute (EC2, ECS, EKS)", value=True)
            scan_database = st.checkbox("Scan Databases (RDS, DynamoDB)", value=True)
            scan_storage = st.checkbox("Scan Storage (S3)", value=True)
            scan_network = st.checkbox("Scan Network (VPC, ALB)", value=True)
        
        # Scan button
        if st.button("🔍 Scan AWS Environment", type="primary", use_container_width=True):
            
            with st.status("Scanning AWS environment...", expanded=True) as status:
                
                try:
                    # Import existing infrastructure
                    st.write("📡 Connecting to AWS...")
                    components = AWSEnvironmentImporter.scan_and_import(region)
                    
                    if components:
                        st.write(f"✅ Found {len(components)} resources")
                        
                        # Create architecture
                        architecture = Architecture(
                            id=str(uuid.uuid4()),
                            name=arch_name,
                            description=f"Imported from AWS {region} on {datetime.now().strftime('%Y-%m-%d %H:%M')}",
                            components=components
                        )
                        
                        st.session_state.current_architecture = architecture
                        st.session_state.architectures[arch_name] = architecture
                        
                        st.write("📊 Analyzing against Well-Architected Framework...")
                        
                        # Run immediate WAF assessment
                        assessment = ArchitectureWAFAssessor.assess(architecture)
                        architecture.waf_assessment = assessment
                        
                        st.write(f"⚡ WAF Score: {assessment['overall_score']}/100")
                        
                        status.update(label="✅ Import complete!", state="complete")
                        
                        # Show summary
                        st.balloons()
                        
                        col1, col2, col3 = st.columns(3)
                        with col1:
                            st.metric("Resources", len(components))
                        with col2:
                            st.metric("WAF Score", f"{assessment['overall_score']}/100")
                        with col3:
                            issues = assessment.get('issues_found', 0)
                            st.metric("Issues", issues)
                        
                        st.rerun()
                    
                    else:
                        status.update(label="No resources found", state="error")
                        st.warning("No resources found in selected region")
                
                except Exception as e:
                    status.update(label="Scan failed", state="error")
                    st.error(f"Error during scan: {str(e)}")
    
    @staticmethod
    def _render_visual_builder():
        """Visual component builder"""
        
        st.markdown("### Build Visually")
        
        # Create new or select existing
        arch_name = st.text_input("Architecture Name", "My Architecture")
        
        if st.button("➕ Create New Architecture"):
            architecture = Architecture(
                id=str(uuid.uuid4()),
                name=arch_name,
                description=""
            )
            st.session_state.current_architecture = architecture
            st.session_state.architectures[arch_name] = architecture
            st.rerun()
        
        # Add components
        if st.session_state.current_architecture:
            st.markdown("### Add Components")
            
            col1, col2 = st.columns(2)
            
            with col1:
                service_type = st.selectbox(
                    "AWS Service",
                    ["ec2", "rds", "s3", "alb", "vpc", "cloudfront", 
                     "lambda", "ecs", "eks", "dynamodb", "elasticache"]
                )
            
            with col2:
                comp_name = st.text_input("Component Name", f"{service_type.upper()} Component")
            
            # Service-specific properties
            props = {}
            
            if service_type == "rds":
                col1, col2, col3 = st.columns(3)
                with col1:
                    props['engine'] = st.selectbox("Engine", ["postgres", "mysql", "aurora"])
                with col2:
                    props['encrypted'] = st.checkbox("Encrypted", value=True)
                with col3:
                    props['multi_az'] = st.checkbox("Multi-AZ")
            
            elif service_type == "ec2":
                col1, col2 = st.columns(2)
                with col1:
                    props['instance_type'] = st.selectbox("Instance Type", 
                                                         ["t3.micro", "t3.small", "t3.medium", "t3.large"])
                with col2:
                    props['auto_scaling'] = st.checkbox("Auto Scaling")
            
            if st.button("➕ Add Component"):
                component = AWSComponent(
                    id=str(uuid.uuid4()),
                    name=comp_name,
                    service_type=service_type,
                    properties=props
                )
                
                st.session_state.current_architecture.components.append(component)
                st.success(f"✅ Added {comp_name}")
                st.rerun()
    
    @staticmethod
    def _render_architecture_view():
        """Display current architecture"""
        
        arch = st.session_state.current_architecture
        
        st.markdown("### 📐 Current Architecture")
        
        st.info(f"**{arch.name}** - {len(arch.components)} components")
        
        if arch.components:
            for i, comp in enumerate(arch.components):
                with st.container():
                    col1, col2, col3 = st.columns([2, 2, 1])
                    
                    with col1:
                        st.markdown(f"**{comp.name}**")
                        st.caption(f"Service: {comp.service_type}")
                    
                    with col2:
                        # Show key properties
                        if comp.properties:
                            props_str = ", ".join([f"{k}: {v}" for k, v in list(comp.properties.items())[:3]])
                            st.caption(props_str)
                    
                    with col3:
                        if st.button("🗑️", key=f"del_{i}"):
                            arch.components.remove(comp)
                            st.rerun()
                    
                    # Show issues if any
                    if comp.issues:
                        st.warning(f"⚠️ {len(comp.issues)} issues")
                    
                    st.markdown("---")
    
    @staticmethod
    def _render_waf_tab():
        """WAF assessment"""
        
        st.subheader("⚡ Well-Architected Assessment")
        
        arch = st.session_state.current_architecture
        
        if not arch:
            st.warning("No architecture selected. Go to Design tab to create one.")
            return
        
        if not arch.components:
            st.info("Add components to your architecture to enable assessment.")
            return
        
        # Run assessment
        if st.button("🔍 Run WAF Assessment", type="primary"):
            with st.spinner("Assessing architecture..."):
                assessment = ArchitectureWAFAssessor.assess(arch)
                arch.waf_assessment = assessment
                st.success("✅ Assessment complete!")
                st.rerun()
        
        # Show results
        if arch.waf_assessment:
            assessment = arch.waf_assessment
            
            # Overall score
            col1, col2 = st.columns([1, 3])
            
            with col1:
                score = assessment['overall_score']
                st.metric("Overall Score", f"{score}/100")
            
            with col2:
                st.progress(score / 100)
            
            st.markdown("---")
            
            # Pillar scores
            st.markdown("### WAF Pillars")
            
            cols = st.columns(3)
            pillars = list(assessment['pillar_scores'].items())
            
            for i, (pillar, score) in enumerate(pillars):
                with cols[i % 3]:
                    color = "🟢" if score >= 80 else "🟡" if score >= 60 else "🔴"
                    st.metric(
                        pillar.replace('_', ' ').title(),
                        f"{score}/100",
                        delta=None
                    )
            
            # Questions remaining
            if assessment.get('questions_remaining'):
                st.markdown("---")
                st.markdown("### ❓ Questions to Complete Assessment")
                
                for q in assessment['questions_remaining'][:5]:
                    st.info(f"**{q['component']}**: {q['question']}")
                
                st.info("💬 Go to 'AI Discussion' tab to answer these questions")
    
    @staticmethod
    def _render_chat_tab():
        """AI chat interface"""
        
        st.subheader("💬 Complete Assessment with AI")
        
        arch = st.session_state.current_architecture
        
        if not arch:
            st.warning("No architecture selected.")
            return
        
        # Display chat history
        for message in st.session_state.chat_messages:
            with st.chat_message(message["role"]):
                st.write(message["content"])
        
        # Chat input
        if prompt := st.chat_input("Ask about your architecture or answer AI questions..."):
            # Add user message
            st.session_state.chat_messages.append({
                "role": "user",
                "content": prompt
            })
            
            # Get AI response
            with st.spinner("AI thinking..."):
                assistant = st.session_state.chat_assistant
                response = assistant.chat(
                    prompt,
                    arch,
                    arch.waf_assessment or {}
                )
            
            # Add AI response
            st.session_state.chat_messages.append({
                "role": "assistant",
                "content": response
            })
            
            st.rerun()
    
    @staticmethod
    def _render_export_tab():
        """Export options"""
        
        st.subheader("📤 Export Architecture")
        
        arch = st.session_state.current_architecture
        
        if not arch:
            st.warning("No architecture to export.")
            return
        
        # Export options
        export_format = st.radio(
            "Export Format",
            ["JSON", "Terraform", "CloudFormation", "Diagram"],
            horizontal=True
        )
        
        if export_format == "JSON":
            json_output = json.dumps(arch.to_dict(), indent=2)
            st.code(json_output, language='json')
            
            st.download_button(
                "💾 Download JSON",
                json_output,
                file_name=f"{arch.name}.json",
                mime="application/json"
            )
        
        elif export_format == "Terraform":
            st.info("Terraform export coming soon!")
        
        elif export_format == "CloudFormation":
            st.info("CloudFormation export coming soon!")
        
        else:
            st.info("Diagram export coming soon!")

# Entry point
def main():
    st.set_page_config(
        page_title="Architecture Designer + WAF",
        page_icon="🎨",
        layout="wide"
    )
    
    ArchitectureDesignerModule.render()

if __name__ == "__main__":
    main()
