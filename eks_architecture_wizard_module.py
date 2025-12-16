"""
EKS AI-Enhanced Architecture Design Wizard - Integration Module
Wrapper module for integration with AWS WAF Scanner application

This module wraps all EKS wizard functionality into a single render function
that can be called from the main streamlit_app.py as a new tab.

FEATURES (v2.4):
- AI-Powered NLP Architecture Design (NEW!)
  - Natural language requirements input
  - Automatic workload type detection (web, data, ML, HA, cost-optimized)
  - Compliance requirement extraction (PCI-DSS, HIPAA, SOC2, ISO27001, GDPR)
  - Performance and budget analysis
  - AI-generated architecture with node groups, security, observability
  - Optional Claude API integration for enhanced analysis
  - WAF alignment scoring for AI-generated architectures
- Dynamic AWS API Integration
  - Real-time instance type fetching via EC2 DescribeInstanceTypes API
  - Live pricing from AWS Pricing API
  - Region-aware instance availability
  - Session-state caching (1 hour TTL) for performance
  - Graceful fallback to static catalog when API unavailable
- Architecture Upload & WAF Alignment Scoring
  - Terraform file analysis
  - CloudFormation template analysis
  - Text/markdown description analysis
  - Scoring against all 6 AWS Well-Architected Framework pillars
  - Actionable recommendations with priority ranking
  - Export reports (JSON, Markdown)
- Safe Default Handling
  - Automatic validation of multiselect defaults
  - Fallback chain for invalid instance types
  - Prevents Streamlit multiselect errors
- Natural Language Requirements Parsing (AI-powered)
- Form-based Configuration Input
- Architecture Designer with topology selection
- Security & Compliance Assessment
- FinOps Cost Optimization
- Infrastructure as Code Export (Terraform, CloudFormation)
- Summary & Export

Author: Infosys Cloud Architecture Team
Version: 2.4.0
"""

import streamlit as st
import json
import yaml
import io
import zipfile
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple

# ============================================================================
# MODULE IMPORTS WITH ERROR HANDLING
# ============================================================================

EKS_WIZARD_STATUS = {}

# Core AI Requirements Engine
try:
    from eks_ai_architecture_wizard import (
        EKSAIRequirementsEngine,
        EKSWorkloadAnalyzer,
        EKSClusterConfig,
        WorkloadType,
        ClusterTopology,
        AvailabilityTier,
        ComplianceFramework,
        SecurityLevel
    )
    EKS_WIZARD_STATUS['core'] = True
except ImportError as e:
    EKS_WIZARD_STATUS['core'] = False
    print(f"EKS Core module not available: {e}")

# Security Module
try:
    from eks_security_module_v2 import (
        EKSSecurityAnalyzer,
        COMPLIANCE_CONTROLS,
        CIS_BENCHMARK_CONTROLS
    )
    EKS_WIZARD_STATUS['security'] = True
except ImportError as e:
    EKS_WIZARD_STATUS['security'] = False
    COMPLIANCE_CONTROLS = {}
    CIS_BENCHMARK_CONTROLS = {}

# GitOps Module
try:
    from eks_gitops_generator import (
        GitOpsConfigurationGenerator,
        GitOpsConfiguration,
        GitOpsToolType,
        REPOSITORY_STRUCTURES
    )
    EKS_WIZARD_STATUS['gitops'] = True
except ImportError as e:
    EKS_WIZARD_STATUS['gitops'] = False
    REPOSITORY_STRUCTURES = {}

# FinOps Module
try:
    from eks_finops_module import (
        EKSCostCalculator,
        KarpenterConfigGenerator,
        KubecostIntegration,
        EC2_PRICING
    )
    EKS_WIZARD_STATUS['finops'] = True
except ImportError as e:
    EKS_WIZARD_STATUS['finops'] = False
    EC2_PRICING = {}

# Observability Module
try:
    from eks_observability_module import (
        PrometheusConfigGenerator,
        LoggingConfigGenerator,
        TracingConfigGenerator,
        GrafanaDashboardGenerator
    )
    EKS_WIZARD_STATUS['observability'] = True
except ImportError as e:
    EKS_WIZARD_STATUS['observability'] = False

# IaC Export Module
try:
    from eks_iac_export import (
        TerraformGenerator,
        CloudFormationGenerator
    )
    EKS_WIZARD_STATUS['iac'] = True
except ImportError as e:
    EKS_WIZARD_STATUS['iac'] = False

# Documentation Module
try:
    from eks_documentation_generator import (
        ADRGenerator,
        RunbookGenerator,
        ArchitectureDocGenerator
    )
    EKS_WIZARD_STATUS['docs'] = True
except ImportError as e:
    EKS_WIZARD_STATUS['docs'] = False

# ============================================================================
# INFOSYS STYLING
# ============================================================================

INFOSYS_BLUE = "#007CC3"
AWS_ORANGE = "#FF9900"

# ============================================================================
# AWS EC2 INSTANCE CATALOG & DYNAMIC PRICING
# ============================================================================

# Static fallback catalog (used when AWS APIs are unavailable)
EC2_INSTANCE_CATALOG_FALLBACK = {
    # General Purpose - M6i (Intel)
    'm6i.large': {'vcpu': 2, 'memory': 8, 'price_per_hour': 0.096, 'family': 'General Purpose', 'processor': 'Intel'},
    'm6i.xlarge': {'vcpu': 4, 'memory': 16, 'price_per_hour': 0.192, 'family': 'General Purpose', 'processor': 'Intel'},
    'm6i.2xlarge': {'vcpu': 8, 'memory': 32, 'price_per_hour': 0.384, 'family': 'General Purpose', 'processor': 'Intel'},
    'm6i.4xlarge': {'vcpu': 16, 'memory': 64, 'price_per_hour': 0.768, 'family': 'General Purpose', 'processor': 'Intel'},
    # General Purpose - M7g (Graviton3)
    'm7g.large': {'vcpu': 2, 'memory': 8, 'price_per_hour': 0.0816, 'family': 'General Purpose', 'processor': 'Graviton3'},
    'm7g.xlarge': {'vcpu': 4, 'memory': 16, 'price_per_hour': 0.1632, 'family': 'General Purpose', 'processor': 'Graviton3'},
    'm7g.2xlarge': {'vcpu': 8, 'memory': 32, 'price_per_hour': 0.3264, 'family': 'General Purpose', 'processor': 'Graviton3'},
    # Compute Optimized
    'c6i.large': {'vcpu': 2, 'memory': 4, 'price_per_hour': 0.085, 'family': 'Compute Optimized', 'processor': 'Intel'},
    'c6i.xlarge': {'vcpu': 4, 'memory': 8, 'price_per_hour': 0.17, 'family': 'Compute Optimized', 'processor': 'Intel'},
    'c6i.2xlarge': {'vcpu': 8, 'memory': 16, 'price_per_hour': 0.34, 'family': 'Compute Optimized', 'processor': 'Intel'},
    'c7g.xlarge': {'vcpu': 4, 'memory': 8, 'price_per_hour': 0.1445, 'family': 'Compute Optimized', 'processor': 'Graviton3'},
    # Memory Optimized
    'r6i.large': {'vcpu': 2, 'memory': 16, 'price_per_hour': 0.126, 'family': 'Memory Optimized', 'processor': 'Intel'},
    'r6i.xlarge': {'vcpu': 4, 'memory': 32, 'price_per_hour': 0.252, 'family': 'Memory Optimized', 'processor': 'Intel'},
    'r6i.2xlarge': {'vcpu': 8, 'memory': 64, 'price_per_hour': 0.504, 'family': 'Memory Optimized', 'processor': 'Intel'},
    # Burstable
    't3.medium': {'vcpu': 2, 'memory': 4, 'price_per_hour': 0.0416, 'family': 'Burstable', 'processor': 'Intel'},
    't3.large': {'vcpu': 2, 'memory': 8, 'price_per_hour': 0.0832, 'family': 'Burstable', 'processor': 'Intel'},
    't3.xlarge': {'vcpu': 4, 'memory': 16, 'price_per_hour': 0.1664, 'family': 'Burstable', 'processor': 'Intel'},
    # GPU
    'g5.xlarge': {'vcpu': 4, 'memory': 16, 'price_per_hour': 1.006, 'family': 'GPU', 'processor': 'NVIDIA A10G', 'gpu': 1},
    'g5.2xlarge': {'vcpu': 8, 'memory': 32, 'price_per_hour': 1.212, 'family': 'GPU', 'processor': 'NVIDIA A10G', 'gpu': 1},
}

# EKS-suitable instance family prefixes
EKS_INSTANCE_FAMILIES = [
    'm5', 'm5a', 'm5n', 'm6i', 'm6a', 'm6g', 'm7i', 'm7a', 'm7g',  # General Purpose
    'c5', 'c5a', 'c5n', 'c6i', 'c6a', 'c6g', 'c7i', 'c7a', 'c7g',  # Compute Optimized
    'r5', 'r5a', 'r5n', 'r6i', 'r6a', 'r6g', 'r7i', 'r7a', 'r7g',  # Memory Optimized
    't3', 't3a',  # Burstable
    'g4dn', 'g5', 'g5g', 'p4d', 'p5',  # GPU/ML
    'i3', 'i3en', 'i4i',  # Storage Optimized
    'inf1', 'inf2',  # Inference
]

# Default instance options (fallback)
DEFAULT_EKS_INSTANCE_OPTIONS = [
    'm6i.large', 'm6i.xlarge', 'm6i.2xlarge', 'm6i.4xlarge',
    'm7g.large', 'm7g.xlarge', 'm7g.2xlarge',
    'c6i.large', 'c6i.xlarge', 'c6i.2xlarge',
    'c7g.large', 'c7g.xlarge',
    'r6i.large', 'r6i.xlarge', 'r6i.2xlarge',
    't3.medium', 't3.large', 't3.xlarge',
    'g5.xlarge', 'g5.2xlarge',
]


class AWSEC2DynamicFetcher:
    """
    Dynamically fetch EC2 instance types and pricing from AWS APIs.
    Uses session state caching to avoid repeated API calls.
    """
    
    # Region to location name mapping for Pricing API
    REGION_LOCATION_MAP = {
        'us-east-1': 'US East (N. Virginia)',
        'us-east-2': 'US East (Ohio)',
        'us-west-1': 'US West (N. California)',
        'us-west-2': 'US West (Oregon)',
        'eu-west-1': 'EU (Ireland)',
        'eu-west-2': 'EU (London)',
        'eu-west-3': 'EU (Paris)',
        'eu-central-1': 'EU (Frankfurt)',
        'eu-north-1': 'EU (Stockholm)',
        'ap-southeast-1': 'Asia Pacific (Singapore)',
        'ap-southeast-2': 'Asia Pacific (Sydney)',
        'ap-northeast-1': 'Asia Pacific (Tokyo)',
        'ap-northeast-2': 'Asia Pacific (Seoul)',
        'ap-northeast-3': 'Asia Pacific (Osaka)',
        'ap-south-1': 'Asia Pacific (Mumbai)',
        'sa-east-1': 'South America (Sao Paulo)',
        'ca-central-1': 'Canada (Central)',
        'me-south-1': 'Middle East (Bahrain)',
        'af-south-1': 'Africa (Cape Town)',
    }
    
    def __init__(self, region: str = 'us-east-1'):
        self.region = region
        self._ec2_client = None
        self._pricing_client = None
    
    def _get_ec2_client(self):
        """Get or create EC2 client"""
        if self._ec2_client is None:
            try:
                import boto3
                self._ec2_client = boto3.client('ec2', region_name=self.region)
            except Exception:
                return None
        return self._ec2_client
    
    def _get_pricing_client(self):
        """Get or create Pricing client (only works in us-east-1)"""
        if self._pricing_client is None:
            try:
                import boto3
                # Pricing API is only available in us-east-1 and ap-south-1
                self._pricing_client = boto3.client('pricing', region_name='us-east-1')
            except Exception:
                return None
        return self._pricing_client
    
    def fetch_instance_types(self, use_cache: bool = True) -> Dict[str, Dict]:
        """
        Fetch available EC2 instance types from AWS API.
        
        Returns:
            Dict mapping instance type to specs (vcpu, memory, etc.)
        """
        # Check session state cache
        cache_key = f'eks_instance_types_{self.region}'
        if use_cache and cache_key in st.session_state:
            cached = st.session_state[cache_key]
            # Check if cache is still valid (1 hour)
            if cached.get('timestamp') and (datetime.now() - cached['timestamp']).seconds < 3600:
                return cached.get('data', {})
        
        ec2_client = self._get_ec2_client()
        if not ec2_client:
            return {}
        
        try:
            instances = {}
            paginator = ec2_client.get_paginator('describe_instance_types')
            
            # Filter for current generation, EKS-suitable instances
            for page in paginator.paginate(
                Filters=[
                    {'Name': 'current-generation', 'Values': ['true']},
                    {'Name': 'supported-usage-class', 'Values': ['on-demand', 'spot']},
                    {'Name': 'supported-virtualization-type', 'Values': ['hvm']},
                ]
            ):
                for instance in page.get('InstanceTypes', []):
                    instance_type = instance.get('InstanceType', '')
                    
                    # Filter for EKS-suitable instance families
                    family_prefix = instance_type.split('.')[0] if '.' in instance_type else ''
                    if not any(instance_type.startswith(f) for f in EKS_INSTANCE_FAMILIES):
                        continue
                    
                    # Extract specs
                    vcpu = instance.get('VCpuInfo', {}).get('DefaultVCpus', 0)
                    memory_mib = instance.get('MemoryInfo', {}).get('SizeInMiB', 0)
                    memory_gb = round(memory_mib / 1024, 1)
                    
                    # Processor info
                    proc_info = instance.get('ProcessorInfo', {})
                    architectures = proc_info.get('SupportedArchitectures', ['x86_64'])
                    processor = 'Graviton' if 'arm64' in architectures else 'Intel/AMD'
                    
                    # GPU info
                    gpu_info = instance.get('GpuInfo', {})
                    gpus = gpu_info.get('Gpus', [])
                    gpu_count = sum(g.get('Count', 0) for g in gpus)
                    gpu_name = gpus[0].get('Name', '') if gpus else ''
                    
                    # Determine family category
                    if family_prefix.startswith(('g', 'p', 'inf')):
                        family = 'GPU/ML'
                    elif family_prefix.startswith('c'):
                        family = 'Compute Optimized'
                    elif family_prefix.startswith('r'):
                        family = 'Memory Optimized'
                    elif family_prefix.startswith('i'):
                        family = 'Storage Optimized'
                    elif family_prefix.startswith('t'):
                        family = 'Burstable'
                    else:
                        family = 'General Purpose'
                    
                    instances[instance_type] = {
                        'vcpu': vcpu,
                        'memory': memory_gb,
                        'family': family,
                        'processor': gpu_name if gpu_name else processor,
                        'gpu': gpu_count,
                        'architecture': architectures[0] if architectures else 'x86_64',
                        'source': 'AWS API'
                    }
            
            # Cache the results
            st.session_state[cache_key] = {
                'timestamp': datetime.now(),
                'data': instances
            }
            
            return instances
            
        except Exception as e:
            st.session_state[f'{cache_key}_error'] = str(e)
            return {}
    
    def fetch_pricing(self, instance_types: List[str] = None, use_cache: bool = True) -> Dict[str, float]:
        """
        Fetch On-Demand pricing from AWS Pricing API.
        
        Returns:
            Dict mapping instance type to hourly price
        """
        # Check session state cache
        cache_key = f'eks_pricing_{self.region}'
        if use_cache and cache_key in st.session_state:
            cached = st.session_state[cache_key]
            if cached.get('timestamp') and (datetime.now() - cached['timestamp']).seconds < 3600:
                return cached.get('data', {})
        
        pricing_client = self._get_pricing_client()
        if not pricing_client:
            return {}
        
        location = self.REGION_LOCATION_MAP.get(self.region, 'US East (N. Virginia)')
        pricing = {}
        
        # Limit to specific instance types or fetch common ones
        types_to_fetch = instance_types or list(EC2_INSTANCE_CATALOG_FALLBACK.keys())
        
        try:
            for instance_type in types_to_fetch[:30]:  # Limit API calls
                try:
                    response = pricing_client.get_products(
                        ServiceCode='AmazonEC2',
                        Filters=[
                            {'Type': 'TERM_MATCH', 'Field': 'instanceType', 'Value': instance_type},
                            {'Type': 'TERM_MATCH', 'Field': 'location', 'Value': location},
                            {'Type': 'TERM_MATCH', 'Field': 'operatingSystem', 'Value': 'Linux'},
                            {'Type': 'TERM_MATCH', 'Field': 'tenancy', 'Value': 'Shared'},
                            {'Type': 'TERM_MATCH', 'Field': 'preInstalledSw', 'Value': 'NA'},
                            {'Type': 'TERM_MATCH', 'Field': 'capacitystatus', 'Value': 'Used'},
                        ],
                        MaxResults=1
                    )
                    
                    if response.get('PriceList'):
                        price_item = json.loads(response['PriceList'][0])
                        on_demand = price_item.get('terms', {}).get('OnDemand', {})
                        
                        for term_value in on_demand.values():
                            for dim_value in term_value.get('priceDimensions', {}).values():
                                price_str = dim_value.get('pricePerUnit', {}).get('USD', '0')
                                pricing[instance_type] = float(price_str)
                                break
                            break
                            
                except Exception:
                    continue  # Skip this instance type
            
            # Cache the results
            st.session_state[cache_key] = {
                'timestamp': datetime.now(),
                'data': pricing
            }
            
            return pricing
            
        except Exception as e:
            st.session_state[f'{cache_key}_error'] = str(e)
            return {}
    
    def get_eks_instance_options(self, use_cache: bool = True) -> List[str]:
        """
        Get sorted list of instance types suitable for EKS.
        Tries AWS API first, falls back to static list.
        """
        # Try to fetch from AWS API
        instances = self.fetch_instance_types(use_cache=use_cache)
        
        if instances:
            # Sort by family, then by size
            def sort_key(inst_type):
                family = instances.get(inst_type, {}).get('family', 'Z')
                vcpu = instances.get(inst_type, {}).get('vcpu', 0)
                return (family, vcpu)
            
            return sorted(instances.keys(), key=sort_key)
        
        # Fallback to static list
        return DEFAULT_EKS_INSTANCE_OPTIONS
    
    def get_instance_info(self, instance_type: str) -> Dict:
        """
        Get complete info for a specific instance type.
        Combines specs and pricing.
        """
        # Try dynamic fetch first
        instances = self.fetch_instance_types()
        pricing = self.fetch_pricing([instance_type])
        
        if instance_type in instances:
            info = instances[instance_type].copy()
            info['price_per_hour'] = pricing.get(instance_type, 0)
            info['monthly_cost'] = info['price_per_hour'] * 730
            return info
        
        # Fallback to static catalog
        if instance_type in EC2_INSTANCE_CATALOG_FALLBACK:
            info = EC2_INSTANCE_CATALOG_FALLBACK[instance_type].copy()
            info['monthly_cost'] = info.get('price_per_hour', 0) * 730
            info['source'] = 'Static Catalog'
            return info
        
        return {
            'vcpu': 'Unknown',
            'memory': 'Unknown',
            'price_per_hour': 0,
            'monthly_cost': 0,
            'family': 'Unknown',
            'processor': 'Unknown',
            'source': 'Not found'
        }


def get_dynamic_instance_options(region: str = 'us-east-1') -> Tuple[List[str], str]:
    """
    Get instance options dynamically from AWS API.
    Returns (list of instance types, source description)
    """
    fetcher = AWSEC2DynamicFetcher(region=region)
    
    # Try to fetch from AWS
    instances = fetcher.fetch_instance_types()
    
    if instances:
        # Filter and sort for EKS-suitable instances
        eks_instances = []
        for inst_type, specs in instances.items():
            # Filter out very large instances (cost control)
            if specs.get('vcpu', 0) <= 96 and specs.get('memory', 0) <= 768:
                eks_instances.append(inst_type)
        
        # Sort by family then size
        def sort_key(inst_type):
            specs = instances.get(inst_type, {})
            family_order = {
                'General Purpose': 1, 'Compute Optimized': 2, 
                'Memory Optimized': 3, 'Burstable': 4,
                'Storage Optimized': 5, 'GPU/ML': 6
            }
            return (
                family_order.get(specs.get('family', 'Z'), 99),
                specs.get('vcpu', 0),
                specs.get('memory', 0)
            )
        
        sorted_instances = sorted(eks_instances, key=sort_key)
        return sorted_instances[:50], f"AWS API ({len(sorted_instances)} types from {region})"
    
    # Fallback
    return DEFAULT_EKS_INSTANCE_OPTIONS, "Static Catalog (AWS API unavailable)"


def get_safe_instance_defaults(current_defaults: List[str], available_options: List[str]) -> List[str]:
    """
    Ensure default instance types are always a subset of available options.
    This prevents the Streamlit multiselect error.
    """
    if not current_defaults:
        return ['m6i.xlarge'] if 'm6i.xlarge' in available_options else [available_options[0]] if available_options else []
    
    # Filter defaults to only include options that exist
    safe_defaults = [d for d in current_defaults if d in available_options]
    
    # If no valid defaults remain, use a safe fallback
    if not safe_defaults:
        fallbacks = ['m6i.xlarge', 'm6i.large', 'm6a.xlarge', 'm7g.xlarge', 't3.xlarge', 't3.large']
        for fallback in fallbacks:
            if fallback in available_options:
                return [fallback]
        return [available_options[0]] if available_options else []
    
    return safe_defaults


# Legacy compatibility alias
AWSEC2PricingFetcher = AWSEC2DynamicFetcher
EC2_INSTANCE_CATALOG = EC2_INSTANCE_CATALOG_FALLBACK


# ============================================================================
# AI-POWERED NLP ARCHITECTURE DESIGNER
# ============================================================================

class AIArchitectureDesigner:
    """
    AI-powered Natural Language Processing for EKS architecture design.
    Uses Claude API to parse requirements and generate WAF-aligned architectures.
    """
    
    # Architecture patterns for different workload types
    WORKLOAD_PATTERNS = {
        'web_application': {
            'description': 'Web applications, APIs, microservices',
            'keywords': ['web', 'api', 'microservice', 'rest', 'graphql', 'frontend', 'backend', 'website'],
            'recommended': {
                'instance_types': ['m6i.xlarge', 'm6i.2xlarge'],
                'min_nodes': 3,
                'autoscaling': True,
                'spot_percentage': 50,
                'addons': ['alb-controller', 'external-dns', 'cert-manager'],
            }
        },
        'data_processing': {
            'description': 'Data pipelines, ETL, batch processing',
            'keywords': ['data', 'etl', 'batch', 'spark', 'pipeline', 'processing', 'analytics'],
            'recommended': {
                'instance_types': ['r6i.xlarge', 'r6i.2xlarge'],
                'min_nodes': 2,
                'autoscaling': True,
                'spot_percentage': 70,
                'addons': ['cluster-autoscaler', 'karpenter'],
            }
        },
        'machine_learning': {
            'description': 'ML training, inference, AI workloads',
            'keywords': ['ml', 'machine learning', 'ai', 'training', 'inference', 'model', 'gpu', 'tensorflow', 'pytorch'],
            'recommended': {
                'instance_types': ['g5.xlarge', 'g5.2xlarge', 'p4d.24xlarge'],
                'min_nodes': 1,
                'autoscaling': True,
                'spot_percentage': 30,
                'addons': ['nvidia-device-plugin', 'karpenter'],
            }
        },
        'high_availability': {
            'description': 'Mission-critical, high availability workloads',
            'keywords': ['critical', 'production', 'high availability', 'ha', '99.99', '99.9', 'mission critical', 'enterprise'],
            'recommended': {
                'instance_types': ['m6i.xlarge', 'm6i.2xlarge'],
                'min_nodes': 6,
                'autoscaling': True,
                'spot_percentage': 0,
                'multi_az': True,
                'addons': ['alb-controller', 'external-dns', 'velero'],
            }
        },
        'cost_optimized': {
            'description': 'Development, testing, cost-sensitive workloads',
            'keywords': ['dev', 'development', 'test', 'staging', 'cost', 'budget', 'cheap', 'economical'],
            'recommended': {
                'instance_types': ['t3.large', 't3.xlarge', 'm6a.large'],
                'min_nodes': 2,
                'autoscaling': True,
                'spot_percentage': 80,
                'addons': ['karpenter'],
            }
        },
    }
    
    # Compliance requirement mappings
    COMPLIANCE_KEYWORDS = {
        'pci_dss': ['pci', 'pci-dss', 'payment', 'credit card', 'cardholder'],
        'hipaa': ['hipaa', 'health', 'phi', 'medical', 'healthcare', 'patient'],
        'soc2': ['soc2', 'soc 2', 'audit', 'trust'],
        'iso_27001': ['iso', 'iso27001', 'iso 27001', 'information security'],
        'gdpr': ['gdpr', 'european', 'eu data', 'privacy'],
        'fedramp': ['fedramp', 'federal', 'government', 'gov'],
    }
    
    @staticmethod
    def parse_requirements_locally(requirements_text: str) -> Dict:
        """
        Parse natural language requirements without external AI API.
        Uses keyword matching and pattern recognition.
        """
        text_lower = requirements_text.lower()
        
        # Detect workload type
        detected_workload = 'web_application'  # Default
        max_matches = 0
        for workload_type, config in AIArchitectureDesigner.WORKLOAD_PATTERNS.items():
            matches = sum(1 for kw in config['keywords'] if kw in text_lower)
            if matches > max_matches:
                max_matches = matches
                detected_workload = workload_type
        
        # Detect compliance requirements
        detected_compliance = []
        for compliance, keywords in AIArchitectureDesigner.COMPLIANCE_KEYWORDS.items():
            if any(kw in text_lower for kw in keywords):
                detected_compliance.append(compliance)
        
        # Extract numeric values
        import re
        
        # Pod/service count
        pod_match = re.search(r'(\d+)\s*(pod|service|microservice|application|container)', text_lower)
        estimated_pods = int(pod_match.group(1)) if pod_match else 20
        
        # Request rate
        rps_match = re.search(r'(\d+[,\d]*)\s*(request|rps|req/s|qps)', text_lower)
        requests_per_second = int(rps_match.group(1).replace(',', '')) if rps_match else 1000
        
        # Availability target
        availability_match = re.search(r'(99\.?\d*)\s*%?\s*(uptime|availability|sla)', text_lower)
        availability_target = availability_match.group(1) if availability_match else '99.9'
        
        # Budget
        budget_match = re.search(r'\$?\s*(\d+[,\d]*)\s*(k|thousand|/month|monthly|budget)', text_lower)
        monthly_budget = int(budget_match.group(1).replace(',', '')) * (1000 if 'k' in (budget_match.group(2) or '') else 1) if budget_match else 10000
        
        # Region
        region = 'us-east-1'
        region_patterns = {
            'us-east-1': ['virginia', 'us-east-1', 'n. virginia'],
            'us-east-2': ['ohio', 'us-east-2'],
            'us-west-2': ['oregon', 'us-west-2'],
            'eu-west-1': ['ireland', 'eu-west-1', 'europe'],
            'ap-southeast-1': ['singapore', 'ap-southeast-1', 'asia'],
        }
        for reg, patterns in region_patterns.items():
            if any(p in text_lower for p in patterns):
                region = reg
                break
        
        # Environment
        environment = 'production'
        if any(e in text_lower for e in ['dev', 'development', 'sandbox']):
            environment = 'development'
        elif any(e in text_lower for e in ['staging', 'stage', 'uat', 'test']):
            environment = 'staging'
        
        # Get workload pattern recommendations
        pattern = AIArchitectureDesigner.WORKLOAD_PATTERNS[detected_workload]
        
        return {
            'workload_type': detected_workload,
            'workload_description': pattern['description'],
            'environment': environment,
            'region': region,
            'estimated_pods': estimated_pods,
            'requests_per_second': requests_per_second,
            'availability_target': availability_target,
            'monthly_budget': monthly_budget,
            'compliance': detected_compliance,
            'recommended_instances': pattern['recommended']['instance_types'],
            'min_nodes': pattern['recommended']['min_nodes'],
            'spot_percentage': pattern['recommended']['spot_percentage'],
            'addons': pattern['recommended'].get('addons', []),
            'original_text': requirements_text,
        }
    
    @staticmethod
    def generate_architecture_from_requirements(parsed_requirements: Dict) -> Dict:
        """Generate a complete EKS architecture configuration from parsed requirements."""
        
        workload_type = parsed_requirements.get('workload_type', 'web_application')
        environment = parsed_requirements.get('environment', 'production')
        region = parsed_requirements.get('region', 'us-east-1')
        compliance = parsed_requirements.get('compliance', [])
        estimated_pods = parsed_requirements.get('estimated_pods', 20)
        min_nodes = parsed_requirements.get('min_nodes', 3)
        spot_percentage = parsed_requirements.get('spot_percentage', 50)
        
        # Calculate node requirements
        pods_per_node = 30  # Conservative estimate
        required_nodes = max(min_nodes, (estimated_pods // pods_per_node) + 1)
        
        # Adjust for HA if production
        if environment == 'production':
            required_nodes = max(required_nodes, 3)
        
        # Calculate spot vs on-demand split
        spot_nodes = int(required_nodes * (spot_percentage / 100))
        on_demand_nodes = required_nodes - spot_nodes
        
        # Build node groups
        node_groups = []
        
        # System node group (always on-demand)
        node_groups.append({
            'name': 'system',
            'instance_types': ['m6i.large'],
            'capacity_type': 'ON_DEMAND',
            'min_size': 2,
            'max_size': 4,
            'desired_size': 2,
            'labels': {'workload-type': 'system'},
            'taints': []
        })
        
        # Application node group
        recommended_instances = parsed_requirements.get('recommended_instances', ['m6i.xlarge'])
        
        if on_demand_nodes > 0:
            node_groups.append({
                'name': 'application-ondemand',
                'instance_types': recommended_instances[:2],
                'capacity_type': 'ON_DEMAND',
                'min_size': max(1, on_demand_nodes - 1),
                'max_size': on_demand_nodes * 3,
                'desired_size': on_demand_nodes,
                'labels': {'workload-type': 'application', 'capacity': 'on-demand'},
                'taints': []
            })
        
        if spot_nodes > 0:
            node_groups.append({
                'name': 'application-spot',
                'instance_types': recommended_instances + ['m6a.xlarge', 'm5.xlarge'],  # Diversify for spot
                'capacity_type': 'SPOT',
                'min_size': 0,
                'max_size': spot_nodes * 4,
                'desired_size': spot_nodes,
                'labels': {'workload-type': 'application', 'capacity': 'spot'},
                'taints': []
            })
        
        # GPU node group if ML workload
        if workload_type == 'machine_learning':
            node_groups.append({
                'name': 'gpu-ml',
                'instance_types': ['g5.xlarge', 'g5.2xlarge'],
                'capacity_type': 'ON_DEMAND',
                'min_size': 0,
                'max_size': 4,
                'desired_size': 1,
                'labels': {'workload-type': 'ml', 'gpu': 'true'},
                'taints': [{'key': 'nvidia.com/gpu', 'value': 'true', 'effect': 'NoSchedule'}]
            })
        
        # Security configuration based on compliance
        security_config = {
            'private_endpoint': environment == 'production',
            'public_endpoint': environment != 'production',
            'enable_secrets_encryption': True,
            'enable_network_policies': len(compliance) > 0 or environment == 'production',
            'enable_audit_logging': True,
            'enable_irsa': True,
            'pod_security_standards': 'restricted' if compliance else 'baseline',
            'enable_guardduty': any(c in compliance for c in ['pci_dss', 'hipaa']),
        }
        
        # Observability configuration
        observability_config = {
            'enable_container_insights': True,
            'enable_prometheus': environment == 'production',
            'enable_grafana': environment == 'production',
            'log_retention_days': 90 if compliance else 30,
            'enable_distributed_tracing': environment == 'production',
        }
        
        # Add-ons
        addons = ['vpc-cni', 'coredns', 'kube-proxy', 'ebs-csi-driver']
        if environment == 'production':
            addons.extend(['aws-load-balancer-controller', 'external-dns', 'cert-manager'])
        if spot_percentage > 0:
            addons.append('karpenter')
        addons.extend(parsed_requirements.get('addons', []))
        addons = list(set(addons))  # Remove duplicates
        
        return {
            'cluster_name': f"eks-{environment}-{workload_type.replace('_', '-')}",
            'kubernetes_version': '1.29',
            'region': region,
            'environment': environment,
            'workload_type': workload_type,
            'node_groups': node_groups,
            'security': security_config,
            'observability': observability_config,
            'addons': addons,
            'compliance': compliance,
            'estimated_monthly_cost': AIArchitectureDesigner._estimate_cost(node_groups, region),
            'parsed_requirements': parsed_requirements,
        }
    
    @staticmethod
    def _estimate_cost(node_groups: List[Dict], region: str) -> float:
        """Estimate monthly cost for the architecture."""
        total_cost = 0
        
        # EKS control plane cost
        total_cost += 73  # $0.10/hour * 730 hours
        
        # Node costs
        for ng in node_groups:
            instance_type = ng['instance_types'][0] if ng['instance_types'] else 'm6i.xlarge'
            node_count = ng.get('desired_size', 2)
            
            # Get hourly rate from catalog
            hourly_rate = EC2_INSTANCE_CATALOG_FALLBACK.get(instance_type, {}).get('price_per_hour', 0.192)
            
            # Apply spot discount if applicable
            if ng.get('capacity_type') == 'SPOT':
                hourly_rate *= 0.35
            
            total_cost += hourly_rate * 730 * node_count
        
        return round(total_cost, 2)
    
    @staticmethod
    def analyze_with_claude_api(requirements_text: str, api_key: str = None) -> Dict:
        """
        Use Claude API to analyze requirements and generate architecture.
        Falls back to local parsing if API unavailable.
        """
        if not api_key:
            # Try to get from environment or Streamlit secrets
            import os
            api_key = os.environ.get('ANTHROPIC_API_KEY')
            if not api_key:
                try:
                    api_key = st.secrets.get('ANTHROPIC_API_KEY')
                except:
                    pass
        
        if not api_key:
            # Fall back to local parsing
            return AIArchitectureDesigner.parse_requirements_locally(requirements_text)
        
        try:
            import anthropic
            
            client = anthropic.Anthropic(api_key=api_key)
            
            prompt = f"""Analyze the following EKS architecture requirements and extract structured information.

Requirements:
{requirements_text}

Please extract and return a JSON object with the following fields:
- workload_type: one of [web_application, data_processing, machine_learning, high_availability, cost_optimized]
- environment: one of [production, staging, development]
- region: AWS region code (e.g., us-east-1)
- estimated_pods: estimated number of pods/containers
- requests_per_second: estimated requests per second
- availability_target: target availability percentage (e.g., "99.9")
- monthly_budget: estimated monthly budget in USD
- compliance: list of compliance requirements from [pci_dss, hipaa, soc2, iso_27001, gdpr, fedramp]
- recommended_instances: list of recommended EC2 instance types
- min_nodes: minimum number of nodes recommended
- spot_percentage: percentage of nodes that can use spot instances (0-100)
- key_requirements: list of key requirements extracted from the text
- risks_identified: list of potential risks or concerns

Return ONLY valid JSON, no other text."""

            response = client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=1024,
                messages=[{"role": "user", "content": prompt}]
            )
            
            # Parse the response
            response_text = response.content[0].text
            
            # Extract JSON from response
            import re
            json_match = re.search(r'\{[\s\S]*\}', response_text)
            if json_match:
                parsed = json.loads(json_match.group())
                parsed['original_text'] = requirements_text
                parsed['analysis_source'] = 'Claude AI'
                return parsed
            
        except Exception as e:
            st.warning(f"AI analysis unavailable: {str(e)}. Using local parsing.")
        
        # Fall back to local parsing
        result = AIArchitectureDesigner.parse_requirements_locally(requirements_text)
        result['analysis_source'] = 'Local Parser'
        return result
    
    @staticmethod
    def generate_waf_alignment_from_architecture(architecture: Dict) -> Dict:
        """
        Generate WAF alignment scores from a generated architecture configuration.
        """
        # Build components dict from architecture
        components = {
            'eks_cluster': True,
            'vpc': True,
            'node_groups': len(architecture.get('node_groups', [])) > 0,
            'karpenter': 'karpenter' in architecture.get('addons', []),
            'alb': 'aws-load-balancer-controller' in architecture.get('addons', []),
            'cloudwatch': architecture.get('observability', {}).get('enable_container_insights', False),
            'prometheus': architecture.get('observability', {}).get('enable_prometheus', False),
            'grafana': architecture.get('observability', {}).get('enable_grafana', False),
            'secrets_manager': architecture.get('security', {}).get('enable_secrets_encryption', False),
            'kms': architecture.get('security', {}).get('enable_secrets_encryption', False),
            'iam_roles': architecture.get('security', {}).get('enable_irsa', False),
            'security_groups': True,
            'multi_az': architecture.get('environment') == 'production',
            'encryption': architecture.get('security', {}).get('enable_secrets_encryption', False),
            'autoscaling': any(ng.get('max_size', 0) > ng.get('desired_size', 0) for ng in architecture.get('node_groups', [])),
            'argocd': 'argocd' in architecture.get('addons', []),
            'spot_instances': any(ng.get('capacity_type') == 'SPOT' for ng in architecture.get('node_groups', [])),
            'graviton': any('g' in inst for ng in architecture.get('node_groups', []) for inst in ng.get('instance_types', [])),
        }
        
        # Calculate WAF alignment using the existing analyzer
        return ArchitectureUploadAnalyzer.calculate_waf_alignment(components)


# ============================================================================
# WAF PILLARS FOR ALIGNMENT SCORING
# ============================================================================

WAF_PILLARS = {
    'operational_excellence': {
        'name': 'Operational Excellence',
        'icon': '⚙️',
        'color': '#3F8624',
        'checks': ['logging', 'monitoring', 'runbooks', 'automation', 'gitops']
    },
    'security': {
        'name': 'Security',
        'icon': '🔒',
        'color': '#D32F2F',
        'checks': ['encryption', 'irsa', 'network_policies', 'secrets_management', 'pod_security']
    },
    'reliability': {
        'name': 'Reliability',
        'icon': '🛡️',
        'color': '#1976D2',
        'checks': ['multi_az', 'auto_scaling', 'health_checks', 'dr_strategy', 'backup']
    },
    'performance_efficiency': {
        'name': 'Performance Efficiency',
        'icon': '⚡',
        'color': '#FF9800',
        'checks': ['right_sizing', 'metrics_server', 'hpa', 'caching', 'cdn']
    },
    'cost_optimization': {
        'name': 'Cost Optimization',
        'icon': '💰',
        'color': '#4CAF50',
        'checks': ['spot_instances', 'karpenter', 'savings_plans', 'rightsizing', 'cleanup']
    },
    'sustainability': {
        'name': 'Sustainability',
        'icon': '🌱',
        'color': '#00796B',
        'checks': ['graviton', 'efficient_instances', 'resource_optimization', 'serverless']
    }
}

# ============================================================================
# ARCHITECTURE UPLOAD ANALYZER
# ============================================================================

class ArchitectureUploadAnalyzer:
    """Analyze uploaded architecture documents and score against WAF pillars"""
    
    @staticmethod
    def analyze_terraform(content: str) -> Dict:
        """Analyze Terraform file and extract architecture components"""
        components = {
            'eks_cluster': 'aws_eks_cluster' in content or 'module "eks"' in content,
            'vpc': 'aws_vpc' in content or 'module "vpc"' in content,
            'node_groups': 'eks_managed_node_groups' in content or 'aws_eks_node_group' in content,
            'karpenter': 'karpenter' in content.lower(),
            'alb': 'aws_lb' in content or 'load_balancer' in content.lower(),
            'rds': 'aws_db_instance' in content or 'aws_rds_cluster' in content,
            's3': 'aws_s3_bucket' in content,
            'secrets_manager': 'aws_secretsmanager' in content,
            'kms': 'aws_kms_key' in content,
            'cloudwatch': 'aws_cloudwatch' in content,
            'iam_roles': 'aws_iam_role' in content,
            'security_groups': 'aws_security_group' in content,
            'multi_az': 'availability_zones' in content or 'azs' in content,
            'encryption': 'encrypted = true' in content.lower() or 'kms_key' in content,
            'autoscaling': 'autoscaling' in content.lower() or 'scaling_config' in content,
            'prometheus': 'prometheus' in content.lower(),
            'grafana': 'grafana' in content.lower(),
            'argocd': 'argocd' in content.lower(),
            'spot_instances': 'SPOT' in content or 'spot' in content.lower(),
            'graviton': 'graviton' in content.lower() or any(g in content for g in ['m6g', 'c6g', 'r6g', 'm7g', 'c7g']),
        }
        return components
    
    @staticmethod
    def analyze_cloudformation(content: str) -> Dict:
        """Analyze CloudFormation template and extract components"""
        components = {
            'eks_cluster': 'AWS::EKS::Cluster' in content,
            'vpc': 'AWS::EC2::VPC' in content,
            'node_groups': 'AWS::EKS::Nodegroup' in content,
            'alb': 'AWS::ElasticLoadBalancingV2' in content,
            'rds': 'AWS::RDS::DBInstance' in content or 'AWS::RDS::DBCluster' in content,
            's3': 'AWS::S3::Bucket' in content,
            'secrets_manager': 'AWS::SecretsManager' in content,
            'kms': 'AWS::KMS::Key' in content,
            'cloudwatch': 'AWS::CloudWatch' in content or 'AWS::Logs' in content,
            'iam_roles': 'AWS::IAM::Role' in content,
            'security_groups': 'AWS::EC2::SecurityGroup' in content,
            'multi_az': 'AvailabilityZone' in content,
            'encryption': 'StorageEncrypted' in content or 'KmsKeyId' in content,
            'autoscaling': 'AWS::AutoScaling' in content or 'ScalingConfig' in content,
            'karpenter': 'karpenter' in content.lower(),
            'prometheus': 'prometheus' in content.lower(),
            'grafana': 'grafana' in content.lower(),
            'argocd': 'argocd' in content.lower(),
            'spot_instances': 'SPOT' in content,
            'graviton': any(g in content for g in ['m6g', 'c6g', 'r6g', 'm7g', 'c7g']),
        }
        return components
    
    @staticmethod
    def analyze_text_description(content: str) -> Dict:
        """Analyze text/markdown description for architecture components"""
        content_lower = content.lower()
        components = {
            'eks_cluster': any(k in content_lower for k in ['eks', 'kubernetes', 'k8s']),
            'vpc': 'vpc' in content_lower,
            'node_groups': any(k in content_lower for k in ['node group', 'nodegroup', 'worker node']),
            'karpenter': 'karpenter' in content_lower,
            'alb': any(k in content_lower for k in ['alb', 'load balancer', 'nlb', 'elb']),
            'rds': any(k in content_lower for k in ['rds', 'aurora', 'database', 'mysql', 'postgres']),
            's3': 's3' in content_lower or 'object storage' in content_lower,
            'secrets_manager': any(k in content_lower for k in ['secrets manager', 'vault', 'secrets']),
            'kms': 'kms' in content_lower or 'encryption key' in content_lower,
            'cloudwatch': any(k in content_lower for k in ['cloudwatch', 'monitoring', 'logging', 'observability']),
            'iam_roles': any(k in content_lower for k in ['iam', 'irsa', 'service account', 'role']),
            'multi_az': any(k in content_lower for k in ['multi-az', 'availability zone', 'ha', 'high availability', 'multiple az']),
            'encryption': any(k in content_lower for k in ['encrypt', 'tls', 'ssl', 'kms']),
            'autoscaling': any(k in content_lower for k in ['autoscal', 'hpa', 'vpa', 'scale', 'keda']),
            'prometheus': 'prometheus' in content_lower,
            'grafana': 'grafana' in content_lower,
            'argocd': 'argocd' in content_lower or 'argo cd' in content_lower or 'gitops' in content_lower,
            'security_groups': any(k in content_lower for k in ['security group', 'firewall', 'network policy']),
            'spot_instances': any(k in content_lower for k in ['spot', 'spot instance']),
            'graviton': 'graviton' in content_lower or 'arm64' in content_lower,
        }
        return components
    
    @staticmethod
    def calculate_waf_alignment(components: Dict) -> Dict:
        """Calculate WAF alignment scores based on detected components"""
        scores = {}
        
        # Operational Excellence
        ops_checks = {
            'logging': components.get('cloudwatch', False),
            'monitoring': components.get('prometheus', False) or components.get('cloudwatch', False) or components.get('grafana', False),
            'automation': components.get('autoscaling', False),
            'gitops': components.get('argocd', False),
            'iac': True  # Assumed if analyzing IaC
        }
        ops_score = sum(ops_checks.values()) / len(ops_checks) * 100
        ops_recommendations = []
        if not ops_checks['logging']:
            ops_recommendations.append('Enable CloudWatch logging for comprehensive audit trails')
        if not ops_checks['monitoring']:
            ops_recommendations.append('Add Prometheus/Grafana for detailed cluster monitoring')
        if not ops_checks['gitops']:
            ops_recommendations.append('Implement GitOps with ArgoCD or Flux for declarative deployments')
        if not ops_checks['automation']:
            ops_recommendations.append('Enable auto-scaling for operational efficiency')
        
        scores['operational_excellence'] = {
            'score': ops_score,
            'checks': ops_checks,
            'recommendations': ops_recommendations
        }
        
        # Security
        sec_checks = {
            'encryption': components.get('encryption', False) or components.get('kms', False),
            'secrets_management': components.get('secrets_manager', False),
            'iam_roles': components.get('iam_roles', False),
            'network_security': components.get('security_groups', False),
            'private_networking': components.get('vpc', False)
        }
        sec_score = sum(sec_checks.values()) / len(sec_checks) * 100
        sec_recommendations = []
        if not sec_checks['encryption']:
            sec_recommendations.append('Enable encryption at rest with KMS for EBS, EFS, and secrets')
        if not sec_checks['secrets_management']:
            sec_recommendations.append('Use AWS Secrets Manager or External Secrets for sensitive data')
        if not sec_checks['iam_roles']:
            sec_recommendations.append('Implement IRSA (IAM Roles for Service Accounts) for least privilege')
        if not sec_checks['network_security']:
            sec_recommendations.append('Configure security groups and network policies for pod isolation')
        
        scores['security'] = {
            'score': sec_score,
            'checks': sec_checks,
            'recommendations': sec_recommendations
        }
        
        # Reliability
        rel_checks = {
            'multi_az': components.get('multi_az', False),
            'auto_scaling': components.get('autoscaling', False),
            'managed_services': components.get('rds', False) or components.get('eks_cluster', False),
            'load_balancing': components.get('alb', False),
            'backup_capable': components.get('s3', False) or components.get('rds', False)
        }
        rel_score = sum(rel_checks.values()) / len(rel_checks) * 100
        rel_recommendations = []
        if not rel_checks['multi_az']:
            rel_recommendations.append('Deploy across multiple Availability Zones (minimum 2, recommended 3)')
        if not rel_checks['auto_scaling']:
            rel_recommendations.append('Implement auto-scaling for workload resilience')
        if not rel_checks['load_balancing']:
            rel_recommendations.append('Use Application Load Balancer for traffic distribution')
        
        scores['reliability'] = {
            'score': rel_score,
            'checks': rel_checks,
            'recommendations': rel_recommendations
        }
        
        # Performance Efficiency
        perf_checks = {
            'container_orchestration': components.get('eks_cluster', False),
            'load_balancing': components.get('alb', False),
            'auto_scaling': components.get('autoscaling', False),
            'right_sizing': components.get('karpenter', False) or components.get('node_groups', False),
            'monitoring': components.get('prometheus', False) or components.get('cloudwatch', False)
        }
        perf_score = sum(perf_checks.values()) / len(perf_checks) * 100
        perf_recommendations = []
        if not perf_checks['right_sizing']:
            perf_recommendations.append('Use Karpenter for intelligent node provisioning and right-sizing')
        if not perf_checks['monitoring']:
            perf_recommendations.append('Enable metrics collection for performance optimization decisions')
        
        scores['performance_efficiency'] = {
            'score': perf_score,
            'checks': perf_checks,
            'recommendations': perf_recommendations
        }
        
        # Cost Optimization
        cost_checks = {
            'karpenter': components.get('karpenter', False),
            'spot_instances': components.get('spot_instances', False),
            'auto_scaling': components.get('autoscaling', False),
            'managed_services': components.get('eks_cluster', False),
            'monitoring': components.get('cloudwatch', False)
        }
        cost_score = sum(cost_checks.values()) / len(cost_checks) * 100
        cost_recommendations = []
        if not cost_checks['karpenter']:
            cost_recommendations.append('Implement Karpenter for 30-50% cost savings through consolidation')
        if not cost_checks['spot_instances']:
            cost_recommendations.append('Use Spot instances for fault-tolerant workloads (60-90% savings)')
        if not cost_checks['auto_scaling']:
            cost_recommendations.append('Enable auto-scaling to avoid over-provisioning')
        
        scores['cost_optimization'] = {
            'score': cost_score,
            'checks': cost_checks,
            'recommendations': cost_recommendations
        }
        
        # Sustainability
        sus_checks = {
            'graviton': components.get('graviton', False),
            'managed_services': components.get('eks_cluster', False),
            'auto_scaling': components.get('autoscaling', False),
            'efficient_storage': components.get('s3', False)
        }
        sus_score = sum(sus_checks.values()) / len(sus_checks) * 100
        sus_recommendations = []
        if not sus_checks['graviton']:
            sus_recommendations.append('Use Graviton instances for 20-40% better price-performance and lower carbon footprint')
        if not sus_checks['auto_scaling']:
            sus_recommendations.append('Use auto-scaling to reduce idle resources and energy consumption')
        
        scores['sustainability'] = {
            'score': sus_score,
            'checks': sus_checks,
            'recommendations': sus_recommendations
        }
        
        # Overall score
        total_score = sum(p['score'] for p in scores.values()) / len(scores)
        
        return {
            'overall_score': total_score,
            'pillars': scores,
            'components_detected': components
        }

# ============================================================================
# SESSION STATE INITIALIZATION
# ============================================================================

def init_eks_wizard_state():
    """Initialize EKS wizard session state"""
    if 'eks_cluster_config' not in st.session_state:
        st.session_state.eks_cluster_config = None
    if 'eks_parsed_requirements' not in st.session_state:
        st.session_state.eks_parsed_requirements = None
    if 'eks_security_assessment' not in st.session_state:
        st.session_state.eks_security_assessment = None
    if 'eks_cost_estimate' not in st.session_state:
        st.session_state.eks_cost_estimate = None
    if 'eks_generated_configs' not in st.session_state:
        st.session_state.eks_generated_configs = {}
    # Architecture Upload & WAF Alignment
    if 'eks_uploaded_architecture' not in st.session_state:
        st.session_state.eks_uploaded_architecture = None
    if 'eks_waf_alignment' not in st.session_state:
        st.session_state.eks_waf_alignment = None
    # AI Generated Architecture
    if 'eks_ai_generated_architecture' not in st.session_state:
        st.session_state.eks_ai_generated_architecture = None

# ============================================================================
# MAIN RENDER FUNCTION
# ============================================================================

class EKSArchitectureWizardModule:
    """EKS Architecture Wizard Module for integration with WAF Scanner"""
    
    @staticmethod
    def render():
        """Main render function - call this from streamlit_app.py"""
        
        init_eks_wizard_state()
        
        # Header
        st.markdown(f"""
        <div style="background: linear-gradient(135deg, {INFOSYS_BLUE} 0%, #005a8c 100%); 
                    padding: 15px 20px; border-radius: 10px; color: white; margin-bottom: 20px;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <div>
                    <h2 style="margin: 0; color: white;">🚀 EKS AI Architecture Design Wizard</h2>
                    <p style="margin: 5px 0 0 0; opacity: 0.9;">Enterprise Kubernetes architecture with AI-powered NLP design & WAF alignment</p>
                </div>
                <div style="text-align: right;">
                    <span style="font-size: 1.2rem; font-weight: bold;">v2.4</span>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        # Module status
        loaded_count = sum(1 for v in EKS_WIZARD_STATUS.values() if v)
        total_count = len(EKS_WIZARD_STATUS)
        
        if loaded_count < total_count:
            with st.expander(f"⚠️ Module Status ({loaded_count}/{total_count} loaded)", expanded=False):
                for module, status in EKS_WIZARD_STATUS.items():
                    if status:
                        st.success(f"✅ {module.title()}")
                    else:
                        st.error(f"❌ {module.title()}")
        
        # Main tabs - Now includes Architecture Upload & WAF Analysis
        tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs([
            "📤 Upload & Analyze",
            "🎯 Requirements",
            "🏗️ Architecture",
            "🔒 Security",
            "💰 FinOps",
            "📦 IaC Export",
            "📋 Summary"
        ])
        
        with tab1:
            EKSArchitectureWizardModule._render_upload_tab()
        
        with tab2:
            EKSArchitectureWizardModule._render_requirements_tab()
        
        with tab3:
            EKSArchitectureWizardModule._render_architecture_tab()
        
        with tab4:
            EKSArchitectureWizardModule._render_security_tab()
        
        with tab5:
            EKSArchitectureWizardModule._render_finops_tab()
        
        with tab6:
            EKSArchitectureWizardModule._render_iac_tab()
        
        with tab7:
            EKSArchitectureWizardModule._render_summary_tab()
    
    @staticmethod
    def _render_upload_tab():
        """Render Architecture Upload & AI Design with WAF Analysis tab"""
        
        st.markdown("### 📤 Architecture Analysis & AI Design")
        
        # Input method selection
        input_method = st.radio(
            "Choose Input Method",
            ["🤖 AI-Powered Design (NLP)", "📄 Upload Existing Architecture"],
            horizontal=True,
            help="Use AI to design from requirements, or upload existing IaC files for analysis"
        )
        
        if input_method == "🤖 AI-Powered Design (NLP)":
            EKSArchitectureWizardModule._render_nlp_design_section()
        else:
            EKSArchitectureWizardModule._render_upload_section()
        
        # Display WAF alignment results (shared by both methods)
        if st.session_state.eks_waf_alignment:
            EKSArchitectureWizardModule._render_waf_results()
    
    @staticmethod
    def _render_nlp_design_section():
        """Render the NLP-powered AI architecture design section"""
        
        st.markdown("""
        **Describe your EKS requirements in plain English**, and AI will:
        1. 🧠 Parse and understand your needs
        2. 🏗️ Generate an optimized architecture
        3. 📊 Score it against AWS Well-Architected Framework
        4. 💡 Provide recommendations for improvement
        """)
        
        # Example prompts
        with st.expander("💡 Example Prompts (click to expand)"):
            st.markdown("""
            **Web Application:**
            > "I need a production EKS cluster for 50 microservices handling 10,000 requests/second. 
            > We need 99.99% uptime, PCI-DSS compliance, and a budget of $15,000/month. 
            > Deploy in us-east-1 with GitOps and full observability."
            
            **Machine Learning:**
            > "Set up an EKS cluster for ML training workloads. We need GPU nodes for TensorFlow 
            > model training, spot instances for cost savings, and integration with SageMaker. 
            > Development environment in us-west-2."
            
            **Cost-Optimized:**
            > "Create a development EKS cluster for our dev team. We have 20 services, 
            > low traffic, and want to minimize costs. Use spot instances wherever possible.
            > Budget is $3,000/month."
            
            **High Availability:**
            > "Mission-critical production cluster for our e-commerce platform. 
            > HIPAA compliant, multi-AZ deployment, 99.99% SLA required. 
            > 100 microservices, peak traffic during Black Friday."
            """)
        
        # Requirements input
        requirements_text = st.text_area(
            "Describe your EKS architecture requirements:",
            height=180,
            placeholder="Example: I need a production EKS cluster for 30 microservices. We handle about 5,000 requests per second with 99.9% uptime requirement. Need PCI-DSS compliance, Prometheus monitoring, and GitOps deployment. Monthly budget around $10,000.",
            help="Be as specific as possible about workloads, compliance, performance, and budget requirements"
        )
        
        # Advanced options
        with st.expander("⚙️ Advanced Options"):
            col1, col2 = st.columns(2)
            with col1:
                use_ai_api = st.checkbox(
                    "Use Claude AI for enhanced analysis",
                    value=False,
                    help="Uses Anthropic Claude API for more accurate requirement parsing (requires API key)"
                )
                if use_ai_api:
                    api_key = st.text_input(
                        "Anthropic API Key (optional)",
                        type="password",
                        help="Leave blank to use environment variable or Streamlit secrets"
                    )
            with col2:
                target_region = st.selectbox(
                    "Target AWS Region",
                    ["Auto-detect", "us-east-1", "us-east-2", "us-west-2", "eu-west-1", "ap-southeast-1"],
                    help="Override region detection from requirements"
                )
        
        # Analyze button
        if st.button("🚀 Generate Architecture & Analyze WAF Alignment", type="primary", use_container_width=True):
            if not requirements_text.strip():
                st.warning("⚠️ Please enter your requirements.")
                return
            
            with st.spinner("🧠 AI is analyzing your requirements..."):
                # Parse requirements
                if use_ai_api:
                    parsed = AIArchitectureDesigner.analyze_with_claude_api(
                        requirements_text, 
                        api_key if 'api_key' in dir() and api_key else None
                    )
                else:
                    parsed = AIArchitectureDesigner.parse_requirements_locally(requirements_text)
                
                # Override region if specified
                if target_region != "Auto-detect":
                    parsed['region'] = target_region
                
                # Store parsed requirements
                st.session_state.eks_parsed_requirements = parsed
                
                # Generate architecture
                architecture = AIArchitectureDesigner.generate_architecture_from_requirements(parsed)
                st.session_state.eks_cluster_config = architecture
                st.session_state.eks_ai_generated_architecture = architecture
                
                # Calculate WAF alignment
                waf_alignment = AIArchitectureDesigner.generate_waf_alignment_from_architecture(architecture)
                st.session_state.eks_waf_alignment = waf_alignment
                
                st.success("✅ Architecture generated successfully!")
        
        # Display generated architecture
        if st.session_state.get('eks_ai_generated_architecture'):
            st.markdown("---")
            st.markdown("## 🏗️ AI-Generated Architecture")
            
            arch = st.session_state.eks_ai_generated_architecture
            parsed = st.session_state.get('eks_parsed_requirements', {})
            
            # Analysis source badge
            analysis_source = parsed.get('analysis_source', 'Local Parser')
            if analysis_source == 'Claude AI':
                st.success(f"🤖 Analyzed by: **{analysis_source}**")
            else:
                st.info(f"🔧 Analyzed by: **{analysis_source}** (Enable Claude AI for enhanced analysis)")
            
            # Key metrics
            st.markdown("### 📊 Architecture Overview")
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Cluster Name", arch.get('cluster_name', 'N/A')[:20])
            with col2:
                st.metric("Environment", arch.get('environment', 'N/A').title())
            with col3:
                st.metric("Region", arch.get('region', 'us-east-1'))
            with col4:
                st.metric("Est. Monthly Cost", f"${arch.get('estimated_monthly_cost', 0):,.0f}")
            
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("K8s Version", arch.get('kubernetes_version', '1.29'))
            with col2:
                total_nodes = sum(ng.get('desired_size', 0) for ng in arch.get('node_groups', []))
                st.metric("Total Nodes", total_nodes)
            with col3:
                st.metric("Node Groups", len(arch.get('node_groups', [])))
            with col4:
                workload = arch.get('workload_type', 'N/A').replace('_', ' ').title()
                st.metric("Workload Type", workload[:15])
            
            # Detected requirements
            st.markdown("### 🎯 Detected Requirements")
            
            col1, col2 = st.columns(2)
            with col1:
                st.markdown("**Performance:**")
                st.write(f"- Estimated Pods: {parsed.get('estimated_pods', 'N/A')}")
                st.write(f"- Requests/sec: {parsed.get('requests_per_second', 'N/A'):,}")
                st.write(f"- Availability Target: {parsed.get('availability_target', 'N/A')}%")
                st.write(f"- Monthly Budget: ${parsed.get('monthly_budget', 'N/A'):,}")
            with col2:
                st.markdown("**Compliance & Security:**")
                compliance = arch.get('compliance', [])
                if compliance:
                    for c in compliance:
                        st.write(f"- ✅ {c.upper().replace('_', '-')}")
                else:
                    st.write("- No specific compliance requirements detected")
            
            # Node Groups
            st.markdown("### 🖥️ Recommended Node Groups")
            
            for ng in arch.get('node_groups', []):
                capacity_badge = "🏷️ Spot" if ng.get('capacity_type') == 'SPOT' else "📦 On-Demand"
                with st.expander(f"{capacity_badge} **{ng.get('name', 'node-group')}** - {ng.get('desired_size', 0)} nodes"):
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.write(f"**Instance Types:** {', '.join(ng.get('instance_types', []))}")
                        st.write(f"**Capacity:** {ng.get('capacity_type', 'ON_DEMAND')}")
                    with col2:
                        st.write(f"**Min Size:** {ng.get('min_size', 0)}")
                        st.write(f"**Max Size:** {ng.get('max_size', 0)}")
                        st.write(f"**Desired:** {ng.get('desired_size', 0)}")
                    with col3:
                        labels = ng.get('labels', {})
                        if labels:
                            st.write("**Labels:**")
                            for k, v in labels.items():
                                st.write(f"  `{k}: {v}`")
            
            # Add-ons
            st.markdown("### 📦 Recommended Add-ons")
            addons = arch.get('addons', [])
            addon_cols = st.columns(4)
            for i, addon in enumerate(addons):
                with addon_cols[i % 4]:
                    st.markdown(f"✅ `{addon}`")
            
            # Security Configuration
            with st.expander("🔒 Security Configuration"):
                security = arch.get('security', {})
                col1, col2 = st.columns(2)
                with col1:
                    st.write(f"- Private Endpoint: {'✅' if security.get('private_endpoint') else '❌'}")
                    st.write(f"- Public Endpoint: {'✅' if security.get('public_endpoint') else '❌'}")
                    st.write(f"- Secrets Encryption: {'✅' if security.get('enable_secrets_encryption') else '❌'}")
                    st.write(f"- Network Policies: {'✅' if security.get('enable_network_policies') else '❌'}")
                with col2:
                    st.write(f"- Audit Logging: {'✅' if security.get('enable_audit_logging') else '❌'}")
                    st.write(f"- IRSA Enabled: {'✅' if security.get('enable_irsa') else '❌'}")
                    st.write(f"- Pod Security Standards: `{security.get('pod_security_standards', 'baseline')}`")
                    st.write(f"- GuardDuty: {'✅' if security.get('enable_guardduty') else '❌'}")
            
            # Observability Configuration
            with st.expander("📊 Observability Configuration"):
                obs = arch.get('observability', {})
                col1, col2 = st.columns(2)
                with col1:
                    st.write(f"- Container Insights: {'✅' if obs.get('enable_container_insights') else '❌'}")
                    st.write(f"- Prometheus: {'✅' if obs.get('enable_prometheus') else '❌'}")
                    st.write(f"- Grafana: {'✅' if obs.get('enable_grafana') else '❌'}")
                with col2:
                    st.write(f"- Distributed Tracing: {'✅' if obs.get('enable_distributed_tracing') else '❌'}")
                    st.write(f"- Log Retention: {obs.get('log_retention_days', 30)} days")
            
            # Export options
            st.markdown("### 📥 Export Generated Architecture")
            col1, col2, col3 = st.columns(3)
            with col1:
                arch_json = json.dumps(arch, indent=2, default=str)
                st.download_button(
                    "📄 Download Config (JSON)",
                    arch_json,
                    f"{arch.get('cluster_name', 'eks')}-config.json",
                    "application/json",
                    use_container_width=True
                )
            with col2:
                arch_yaml = yaml.dump(arch, default_flow_style=False)
                st.download_button(
                    "📄 Download Config (YAML)",
                    arch_yaml,
                    f"{arch.get('cluster_name', 'eks')}-config.yaml",
                    "text/yaml",
                    use_container_width=True
                )
            with col3:
                if st.button("➡️ Use in Architecture Tab", use_container_width=True):
                    st.success("✅ Configuration loaded! Go to the Architecture tab to customize.")
    
    @staticmethod
    def _render_upload_section():
        """Render the file upload section for existing architectures"""
        
        st.markdown("""
        Upload your existing EKS architecture documents (Terraform, CloudFormation, or text descriptions) 
        to analyze alignment with **AWS Well-Architected Framework** pillars.
        """)
        
        # Upload type selection
        upload_type = st.radio(
            "Select Upload Type",
            ["📄 Terraform (.tf)", "📄 CloudFormation (.yaml/.json)", "📝 Text/Markdown Description"],
            horizontal=True
        )
        
        # File uploader
        file_types = ['tf'] if 'Terraform' in upload_type else ['yaml', 'yml', 'json'] if 'CloudFormation' in upload_type else ['md', 'txt']
        
        uploaded_file = st.file_uploader(
            "Upload your architecture file",
            type=file_types + ['tf', 'yaml', 'yml', 'json', 'md', 'txt'],
            help="Upload Terraform, CloudFormation, or text description"
        )
        
        # Or paste content directly
        st.markdown("**— OR paste content directly —**")
        pasted_content = st.text_area(
            "Paste architecture content",
            height=200,
            placeholder="Paste your Terraform code, CloudFormation YAML, or architecture description here...",
            help="You can paste Terraform HCL, CloudFormation YAML/JSON, or plain text description"
        )
        
        # Example templates
        with st.expander("💡 Example: What to upload?"):
            st.markdown("""
            **Terraform Example:**
            ```hcl
            module "eks" {
              source  = "terraform-aws-modules/eks/aws"
              cluster_name    = "production-eks"
              cluster_version = "1.29"
              vpc_id          = module.vpc.vpc_id
              subnet_ids      = module.vpc.private_subnets
              
              eks_managed_node_groups = {
                application = {
                  instance_types = ["m6i.xlarge"]
                  capacity_type  = "SPOT"
                  min_size       = 2
                  max_size       = 10
                }
              }
            }
            ```
            
            **Text Description Example:**
            > "Our EKS cluster runs in us-east-1 across 3 AZs with Karpenter for auto-scaling. 
            > We use ALB for ingress, Prometheus/Grafana for monitoring, and ArgoCD for GitOps.
            > All data is encrypted with KMS, and we use IRSA for pod-level IAM permissions."
            """)
        
        # Analyze button
        if st.button("🔍 Analyze Architecture & Score WAF Alignment", type="primary", use_container_width=True):
            content = ""
            
            if uploaded_file:
                try:
                    content = uploaded_file.read().decode('utf-8')
                    st.session_state.eks_uploaded_architecture = content
                except Exception as e:
                    st.error(f"Error reading file: {str(e)}")
                    return
            elif pasted_content:
                content = pasted_content
                st.session_state.eks_uploaded_architecture = content
            
            if content:
                with st.spinner("🔄 Analyzing architecture against WAF pillars..."):
                    # Determine file type and analyze
                    if "Terraform" in upload_type or content.strip().startswith('terraform') or 'resource "aws' in content or 'module "' in content:
                        components = ArchitectureUploadAnalyzer.analyze_terraform(content)
                        analysis_type = "Terraform"
                    elif "CloudFormation" in upload_type or 'AWSTemplateFormatVersion' in content or 'Resources:' in content:
                        components = ArchitectureUploadAnalyzer.analyze_cloudformation(content)
                        analysis_type = "CloudFormation"
                    else:
                        components = ArchitectureUploadAnalyzer.analyze_text_description(content)
                        analysis_type = "Text Description"
                    
                    # Calculate WAF alignment
                    waf_alignment = ArchitectureUploadAnalyzer.calculate_waf_alignment(components)
                    st.session_state.eks_waf_alignment = waf_alignment
                    
                    # Clear AI-generated architecture flag
                    st.session_state.eks_ai_generated_architecture = None
                    
                    st.success(f"✅ Architecture analysis complete! (Analyzed as: {analysis_type})")
            else:
                st.warning("⚠️ Please upload a file or paste content to analyze.")
    
    @staticmethod
    def _render_waf_results():
        """Render WAF alignment results (shared by both input methods)"""
        
        st.markdown("---")
        st.markdown("## 📊 WAF Alignment Results")
        
        alignment = st.session_state.eks_waf_alignment
        overall_score = alignment.get('overall_score', 0)
        
        # Overall score gauge with color coding
        if overall_score >= 80:
            score_color = "#4CAF50"
            score_level = "Excellent"
            score_emoji = "🏆"
        elif overall_score >= 60:
            score_color = "#FF9800"
            score_level = "Good"
            score_emoji = "✅"
        elif overall_score >= 40:
            score_color = "#FF5722"
            score_level = "Needs Improvement"
            score_emoji = "⚠️"
        else:
            score_color = "#F44336"
            score_level = "Critical Gaps"
            score_emoji = "🚨"
        
        st.markdown(f"""
        <div style="text-align: center; padding: 25px; background: linear-gradient(135deg, {score_color} 0%, {score_color}dd 100%); 
                    border-radius: 15px; color: white; margin-bottom: 25px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
            <div style="font-size: 4rem; font-weight: bold; text-shadow: 2px 2px 4px rgba(0,0,0,0.2);">{overall_score:.0f}%</div>
            <div style="font-size: 1.5rem; margin-top: 5px;">{score_emoji} {score_level}</div>
            <div style="font-size: 1rem; opacity: 0.9; margin-top: 10px;">Overall WAF Alignment Score</div>
        </div>
        """, unsafe_allow_html=True)
        
        # Pillar-by-Pillar Analysis
        st.markdown("### 📈 Pillar-by-Pillar Analysis")
        
        pillars_list = list(alignment.get('pillars', {}).items())
        
        for row in range(2):
            cols = st.columns(3)
            for col_idx in range(3):
                pillar_idx = row * 3 + col_idx
                if pillar_idx < len(pillars_list):
                    pillar_key, pillar_data = pillars_list[pillar_idx]
                    pillar_info = WAF_PILLARS.get(pillar_key, {})
                    pillar_name = pillar_info.get('name', pillar_key.replace('_', ' ').title())
                    pillar_icon = pillar_info.get('icon', '📋')
                    score = pillar_data.get('score', 0)
                    
                    if score >= 80:
                        border_color = "#4CAF50"
                    elif score >= 60:
                        border_color = "#FF9800"
                    else:
                        border_color = "#F44336"
                    
                    with cols[col_idx]:
                        st.markdown(f"""
                        <div style="padding: 15px; background: #f8f9fa; border-radius: 10px; 
                                    border-left: 5px solid {border_color}; margin-bottom: 15px;
                                    box-shadow: 0 2px 4px rgba(0,0,0,0.05);">
                            <div style="font-size: 1.1rem; font-weight: bold; color: #333;">
                                {pillar_icon} {pillar_name}
                            </div>
                            <div style="font-size: 2rem; font-weight: bold; color: {border_color}; margin: 10px 0;">
                                {score:.0f}%
                            </div>
                            <div style="font-size: 0.8rem; color: #666;">
                                {sum(pillar_data.get('checks', {}).values())}/{len(pillar_data.get('checks', {}))} checks passed
                            </div>
                        </div>
                        """, unsafe_allow_html=True)
        
        # Detailed Recommendations
        st.markdown("### 💡 Recommendations for Improvement")
        
        all_recommendations = []
        for pillar_key, pillar_data in alignment.get('pillars', {}).items():
            pillar_info = WAF_PILLARS.get(pillar_key, {})
            pillar_name = pillar_info.get('name', pillar_key.replace('_', ' ').title())
            pillar_icon = pillar_info.get('icon', '📋')
            for rec in pillar_data.get('recommendations', []):
                all_recommendations.append({
                    'pillar': pillar_name,
                    'icon': pillar_icon,
                    'recommendation': rec,
                    'score': pillar_data.get('score', 0)
                })
        
        all_recommendations.sort(key=lambda x: x['score'])
        
        if all_recommendations:
            for rec in all_recommendations[:8]:  # Show top 8 recommendations
                priority = "🔴 High" if rec['score'] < 40 else "🟡 Medium" if rec['score'] < 70 else "🟢 Low"
                with st.expander(f"{priority} | {rec['icon']} {rec['pillar']}: {rec['recommendation'][:60]}..."):
                    st.markdown(f"**Pillar:** {rec['icon']} {rec['pillar']}")
                    st.markdown(f"**Current Score:** {rec['score']:.0f}%")
                    st.markdown(f"**Recommendation:** {rec['recommendation']}")
        else:
            st.success("🎉 Excellent! No critical recommendations - your architecture is well-aligned with WAF best practices!")
        
        # Detected Components Summary
        with st.expander("🔍 Detected Architecture Components"):
            components = alignment.get('components_detected', {})
            detected = [k for k, v in components.items() if v]
            not_detected = [k for k, v in components.items() if not v]
            
            col1, col2 = st.columns(2)
            with col1:
                st.markdown("**✅ Detected Components:**")
                if detected:
                    for comp in sorted(detected):
                        st.markdown(f"- {comp.replace('_', ' ').title()}")
                else:
                    st.markdown("*No components detected*")
            with col2:
                st.markdown("**❌ Not Detected (Consider Adding):**")
                if not_detected:
                    for comp in sorted(not_detected)[:10]:
                        st.markdown(f"- {comp.replace('_', ' ').title()}")
                else:
                    st.markdown("*All key components detected!*")
        
        # Export Report
        st.markdown("### 📥 Export WAF Analysis Report")
        
        col1, col2 = st.columns(2)
        with col1:
            report_json = json.dumps({
                'analysis_date': datetime.now().isoformat(),
                'overall_score': overall_score,
                'score_level': score_level,
                'pillars': {k: {'score': v['score'], 'recommendations': v['recommendations']} 
                           for k, v in alignment.get('pillars', {}).items()},
                'components_detected': alignment.get('components_detected', {})
            }, indent=2)
            st.download_button(
                "📄 Download Report (JSON)",
                report_json,
                "waf-alignment-report.json",
                "application/json",
                use_container_width=True
            )
        with col2:
            report_md = f"""# WAF Alignment Report

**Analysis Date:** {datetime.now().strftime('%Y-%m-%d %H:%M')}

## Overall Score: {overall_score:.0f}% ({score_level})

## Pillar Scores

| Pillar | Score | Status |
|--------|-------|--------|
"""
            for pillar_key, pillar_data in alignment.get('pillars', {}).items():
                pillar_info = WAF_PILLARS.get(pillar_key, {})
                pillar_name = pillar_info.get('name', pillar_key)
                score = pillar_data.get('score', 0)
                status = "✅ Good" if score >= 80 else "⚠️ Needs Work" if score >= 60 else "❌ Critical"
                report_md += f"| {pillar_name} | {score:.0f}% | {status} |\n"
            
            report_md += "\n## Recommendations\n\n"
            for rec in all_recommendations:
                report_md += f"- **{rec['pillar']}**: {rec['recommendation']}\n"
            
            st.download_button(
                "📄 Download Report (Markdown)",
                report_md,
                "waf-alignment-report.md",
                "text/markdown",
                use_container_width=True
            )
    
    @staticmethod
    def _render_requirements_tab():
        """Render requirements gathering tab"""
        
        st.markdown("### 🎯 Define Your EKS Requirements")
        
        input_method = st.radio(
            "Input Method",
            ["💬 Natural Language (AI)", "📝 Form Input"],
            horizontal=True
        )
        
        if input_method == "💬 Natural Language (AI)":
            st.markdown("""
            **Describe your EKS architecture needs in plain English.** 
            Our AI will parse your requirements and generate optimal configurations.
            """)
            
            with st.expander("💡 Example Prompts"):
                st.markdown("""
                - *"I need to migrate 50 Java microservices to EKS. They handle 10,000 requests/second with 99.99% uptime. We're PCI-DSS compliant."*
                - *"Set up a development EKS cluster for our ML team with GPU support and SageMaker integration."*
                - *"Production cluster for e-commerce, 20 services, peak traffic during Black Friday, HIPAA compliant."*
                """)
            
            user_requirements = st.text_area(
                "Enter your requirements:",
                height=120,
                placeholder="Describe your EKS architecture requirements here..."
            )
            
            if st.button("🤖 Analyze Requirements", type="primary"):
                if user_requirements and EKS_WIZARD_STATUS.get('core'):
                    with st.spinner("AI is analyzing your requirements..."):
                        try:
                            engine = EKSAIRequirementsEngine()
                            parsed = engine.parse_natural_language_requirements(user_requirements)
                            st.session_state.eks_parsed_requirements = parsed
                            
                            recommendations = engine.generate_architecture_recommendation(parsed)
                            
                            st.session_state.eks_cluster_config = {
                                "cluster_name": parsed.get("cluster_name", "eks-cluster"),
                                "kubernetes_version": "1.29",
                                "region": "us-east-1",
                                "environment": "production",
                                "node_groups": recommendations.get("node_groups", []),
                                "security": recommendations.get("security_config", {}),
                                "observability": recommendations.get("observability_config", {}),
                                "network": recommendations.get("networking_config", {}),
                                "cost": recommendations.get("cost_optimization", {})
                            }
                            
                            st.success("✅ Requirements analyzed successfully!")
                        except Exception as e:
                            st.error(f"Error analyzing requirements: {str(e)}")
                elif not EKS_WIZARD_STATUS.get('core'):
                    st.error("Core module not loaded. Cannot analyze requirements.")
                else:
                    st.warning("Please enter your requirements.")
            
            # Display parsed requirements
            if st.session_state.eks_parsed_requirements:
                st.markdown("---")
                st.markdown("### 📋 Parsed Requirements")
                parsed = st.session_state.eks_parsed_requirements
                
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Workloads", parsed.get("workload_summary", {}).get("count", "N/A"))
                with col2:
                    st.metric("Availability", parsed.get("performance", {}).get("availability_target", "99.9%"))
                with col3:
                    budget = parsed.get("budget", {}).get("monthly_usd", 0)
                    st.metric("Budget", f"${budget:,.0f}/mo")
                
                if parsed.get("compliance"):
                    st.markdown("**Compliance Requirements:**")
                    st.write(", ".join([c.upper().replace("_", "-") for c in parsed.get("compliance", [])]))
        
        else:
            # Form-based input
            EKSArchitectureWizardModule._render_form_input()
    
    @staticmethod
    def _render_form_input():
        """Render form-based input"""
        
        col1, col2 = st.columns(2)
        
        with col1:
            cluster_name = st.text_input("Cluster Name", value="eks-production")
            k8s_version = st.selectbox("Kubernetes Version", ["1.29", "1.28", "1.27"])
            region = st.selectbox("AWS Region", [
                "us-east-1", "us-east-2", "us-west-2", "eu-west-1", "ap-southeast-1"
            ])
        
        with col2:
            environment = st.selectbox("Environment", ["production", "staging", "development"])
            budget = st.number_input("Monthly Budget (USD)", min_value=0, value=10000)
        
        st.markdown("#### Compliance Requirements")
        comp_cols = st.columns(4)
        pci = comp_cols[0].checkbox("PCI-DSS")
        hipaa = comp_cols[1].checkbox("HIPAA")
        soc2 = comp_cols[2].checkbox("SOC 2")
        iso = comp_cols[3].checkbox("ISO 27001")
        
        if st.button("Generate Configuration", type="primary"):
            compliance = []
            if pci: compliance.append("pci_dss")
            if hipaa: compliance.append("hipaa")
            if soc2: compliance.append("soc2")
            if iso: compliance.append("iso_27001")
            
            st.session_state.eks_cluster_config = {
                "cluster_name": cluster_name,
                "kubernetes_version": k8s_version,
                "region": region,
                "environment": environment,
                "budget_monthly_usd": budget,
                "compliance": compliance,
                "node_groups": [
                    {
                        "name": "system",
                        "instance_types": ["m6i.large"],
                        "capacity_type": "ON_DEMAND",
                        "min_size": 2,
                        "max_size": 4,
                        "desired_size": 2
                    },
                    {
                        "name": "application",
                        "instance_types": ["m6i.xlarge"],
                        "capacity_type": "SPOT" if budget < 20000 else "ON_DEMAND",
                        "min_size": 2,
                        "max_size": 20,
                        "desired_size": 3
                    }
                ],
                "security": {
                    "private_endpoint": True,
                    "public_endpoint": environment == "development",
                    "enable_secrets_encryption": True,
                    "enable_network_policies": True,
                    "enable_audit_logging": True
                }
            }
            st.success("✅ Configuration created!")
    
    @staticmethod
    def _render_architecture_tab():
        """Render architecture designer tab"""
        
        st.markdown("### 🏗️ Architecture Designer")
        
        if not st.session_state.eks_cluster_config:
            st.info("👆 Please define requirements first in the Requirements tab.")
            return
        
        config = st.session_state.eks_cluster_config
        region = config.get('region', 'us-east-1')
        
        # Cluster topology
        st.markdown("#### Cluster Topology")
        topology = st.selectbox(
            "Select Topology Pattern",
            ["Single Cluster", "Hub-Spoke", "Federated", "Cluster-per-Team"]
        )
        
        topology_info = {
            "Single Cluster": "Best for: Small-medium teams, dev/test. Simple management, lower cost.",
            "Hub-Spoke": "Best for: Enterprise with multiple teams. Centralized management, good isolation.",
            "Federated": "Best for: Global deployments, mission critical. Multi-region, DR capable.",
            "Cluster-per-Team": "Best for: Strong isolation needs. Team autonomy, clear boundaries."
        }
        st.info(topology_info.get(topology, ""))
        
        # Dynamic Instance Type Fetching
        st.markdown("#### Instance Types")
        
        # Fetch button and status
        col_fetch1, col_fetch2 = st.columns([3, 1])
        with col_fetch1:
            fetch_from_aws = st.checkbox(
                "🔄 Fetch instance types from AWS API", 
                value=True,
                help="Dynamically fetch available instance types from your AWS account"
            )
        with col_fetch2:
            if st.button("🔄 Refresh", help="Force refresh from AWS API"):
                # Clear cache to force refresh
                for key in list(st.session_state.keys()):
                    if key.startswith('eks_instance_types_') or key.startswith('eks_pricing_'):
                        del st.session_state[key]
                st.rerun()
        
        # Get instance options (dynamic or static)
        if fetch_from_aws:
            with st.spinner("Fetching instance types from AWS..."):
                instance_options, source = get_dynamic_instance_options(region)
        else:
            instance_options = DEFAULT_EKS_INSTANCE_OPTIONS
            source = "Static Catalog (manual selection)"
        
        # Show source info
        if 'AWS API' in source:
            st.success(f"✅ {source}")
        else:
            st.warning(f"⚠️ {source}")
        
        # Show pricing info toggle
        show_pricing = st.checkbox("💰 Show instance pricing & specs", value=False)
        
        if show_pricing:
            st.markdown("##### Instance Reference (On-Demand pricing)")
            
            fetcher = AWSEC2DynamicFetcher(region=region)
            
            # Try to get pricing
            pricing_data = fetcher.fetch_pricing(instance_options[:20])
            instances_data = fetcher.fetch_instance_types()
            
            # Build display data
            display_data = []
            for inst_type in instance_options[:20]:
                if inst_type in instances_data:
                    specs = instances_data[inst_type]
                    price = pricing_data.get(inst_type, 0)
                    if price == 0 and inst_type in EC2_INSTANCE_CATALOG_FALLBACK:
                        price = EC2_INSTANCE_CATALOG_FALLBACK[inst_type].get('price_per_hour', 0)
                    
                    display_data.append({
                        'Instance': inst_type,
                        'vCPU': specs.get('vcpu', 'N/A'),
                        'Memory (GB)': specs.get('memory', 'N/A'),
                        'Family': specs.get('family', 'N/A'),
                        'Processor': specs.get('processor', 'N/A'),
                        '$/Hour': f"${price:.4f}" if price else 'N/A',
                        '$/Month': f"${price * 730:.0f}" if price else 'N/A',
                    })
                elif inst_type in EC2_INSTANCE_CATALOG_FALLBACK:
                    specs = EC2_INSTANCE_CATALOG_FALLBACK[inst_type]
                    display_data.append({
                        'Instance': inst_type,
                        'vCPU': specs.get('vcpu', 'N/A'),
                        'Memory (GB)': specs.get('memory', 'N/A'),
                        'Family': specs.get('family', 'N/A'),
                        'Processor': specs.get('processor', 'N/A'),
                        '$/Hour': f"${specs.get('price_per_hour', 0):.4f}",
                        '$/Month': f"${specs.get('price_per_hour', 0) * 730:.0f}",
                    })
            
            if display_data:
                import pandas as pd
                df = pd.DataFrame(display_data)
                st.dataframe(df, use_container_width=True, hide_index=True)
            else:
                st.info("No pricing data available. Connect to AWS for live pricing.")
        
        # Node Groups
        st.markdown("#### Node Groups")
        node_groups = config.get("node_groups", [])
        
        for i, ng in enumerate(node_groups):
            with st.expander(f"🖥️ {ng.get('name', f'group-{i}')}", expanded=i==0):
                col1, col2, col3 = st.columns(3)
                with col1:
                    # Get safe defaults that exist in options
                    current_instance_types = ng.get('instance_types', ['m6i.xlarge'])
                    safe_defaults = get_safe_instance_defaults(current_instance_types, instance_options)
                    
                    ng['instance_types'] = st.multiselect(
                        f"Instance Types##{i}",
                        options=instance_options,
                        default=safe_defaults,
                        help="Select one or more instance types for this node group"
                    )
                with col2:
                    capacity_options = ["ON_DEMAND", "SPOT"]
                    current_capacity = ng.get('capacity_type', 'ON_DEMAND')
                    capacity_index = capacity_options.index(current_capacity) if current_capacity in capacity_options else 0
                    
                    ng['capacity_type'] = st.selectbox(
                        f"Capacity##{i}",
                        capacity_options,
                        index=capacity_index,
                        help="ON_DEMAND for stable workloads, SPOT for cost savings (60-90% cheaper)"
                    )
                with col3:
                    ng['desired_size'] = st.number_input(
                        f"Nodes##{i}", 
                        value=ng.get('desired_size', 2), 
                        min_value=1,
                        max_value=100,
                        help="Number of nodes in this group"
                    )
                
                # Show estimated cost for this node group
                if ng.get('instance_types'):
                    primary_instance = ng['instance_types'][0]
                    fetcher = AWSEC2DynamicFetcher(region=region)
                    pricing_info = fetcher.get_instance_info(primary_instance)
                    hourly_rate = pricing_info.get('price_per_hour', 0)
                    
                    # Apply spot discount if applicable
                    if ng.get('capacity_type') == 'SPOT':
                        hourly_rate *= 0.35  # ~65% discount for Spot
                    
                    node_count = ng.get('desired_size', 2)
                    monthly_cost = hourly_rate * 730 * node_count
                    
                    spot_badge = "🏷️ Spot (~65% savings)" if ng.get('capacity_type') == 'SPOT' else "📦 On-Demand"
                    vcpu = pricing_info.get('vcpu', 'N/A')
                    memory = pricing_info.get('memory', 'N/A')
                    
                    st.caption(
                        f"💰 Estimated: **${monthly_cost:,.0f}/month** ({spot_badge}) | "
                        f"{node_count} × {primary_instance} ({vcpu} vCPU, {memory} GB RAM)"
                    )
        
        # Add-ons
        st.markdown("#### EKS Add-ons")
        addon_cols = st.columns(3)
        with addon_cols[0]:
            st.checkbox("VPC CNI (Required)", value=True, disabled=True)
            st.checkbox("EBS CSI Driver", value=True, key="addon_ebs")
        with addon_cols[1]:
            st.checkbox("CoreDNS (Required)", value=True, disabled=True)
            st.checkbox("AWS LB Controller", value=True, key="addon_alb")
        with addon_cols[2]:
            st.checkbox("kube-proxy (Required)", value=True, disabled=True)
            st.checkbox("Karpenter", value=True, key="addon_karpenter")
    
    @staticmethod
    def _render_security_tab():
        """Render security assessment tab"""
        
        st.markdown("### 🔒 Security & Compliance")
        
        if not st.session_state.eks_cluster_config:
            st.info("👆 Please define requirements first.")
            return
        
        config = st.session_state.eks_cluster_config
        
        if st.button("🔍 Run Security Assessment", type="primary"):
            if EKS_WIZARD_STATUS.get('security'):
                with st.spinner("Analyzing security configuration..."):
                    try:
                        analyzer = EKSSecurityAnalyzer()
                        assessment = analyzer.assess_security_posture(config)
                        st.session_state.eks_security_assessment = assessment
                        st.success("Assessment complete!")
                    except Exception as e:
                        st.error(f"Error: {str(e)}")
            else:
                st.error("Security module not loaded.")
        
        if st.session_state.eks_security_assessment:
            assessment = st.session_state.eks_security_assessment
            
            score = assessment.get('score', 0)
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                color = "green" if score >= 80 else "orange" if score >= 60 else "red"
                st.markdown(f"""
                <div style="text-align: center; padding: 15px; background: {color}; border-radius: 8px; color: white;">
                    <div style="font-size: 2rem; font-weight: bold;">{score}</div>
                    <div>Security Score</div>
                </div>
                """, unsafe_allow_html=True)
            with col2:
                st.metric("Critical", assessment.get('findings_summary', {}).get('critical', 0))
            with col3:
                st.metric("High", assessment.get('findings_summary', {}).get('high', 0))
            with col4:
                st.metric("Medium", assessment.get('findings_summary', {}).get('medium', 0))
            
            # Findings
            if assessment.get('findings'):
                st.markdown("#### Findings")
                for finding in assessment.get('findings', [])[:5]:
                    severity = finding.get('severity', 'info')
                    icon = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}.get(severity, '⚪')
                    with st.expander(f"{icon} {finding.get('title', 'Finding')}"):
                        st.markdown(f"**Category:** {finding.get('category', 'N/A')}")
                        st.markdown(f"**Remediation:** {finding.get('remediation', 'N/A')}")
    
    @staticmethod
    def _render_finops_tab():
        """Render FinOps cost optimization tab"""
        
        st.markdown("### 💰 FinOps - Cost Optimization")
        
        if not st.session_state.eks_cluster_config:
            st.info("👆 Please define requirements first.")
            return
        
        config = st.session_state.eks_cluster_config
        
        if st.button("💵 Calculate Costs", type="primary"):
            if EKS_WIZARD_STATUS.get('finops'):
                with st.spinner("Calculating costs..."):
                    try:
                        calculator = EKSCostCalculator(region=config.get("region", "us-east-1"))
                        estimate = calculator.calculate_cluster_cost(config)
                        st.session_state.eks_cost_estimate = estimate
                        st.success("Cost calculation complete!")
                    except Exception as e:
                        st.error(f"Error: {str(e)}")
            else:
                st.error("FinOps module not loaded.")
        
        if st.session_state.eks_cost_estimate:
            estimate = st.session_state.eks_cost_estimate
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Monthly Cost", f"${estimate.monthly_total:,.0f}")
            with col2:
                st.metric("Annual Cost", f"${estimate.annual_total:,.0f}")
            with col3:
                st.metric("Potential Savings", f"${estimate.potential_monthly_savings:,.0f}/mo")
            
            # Recommendations
            if estimate.cost_optimization_recommendations:
                st.markdown("#### 💡 Optimization Recommendations")
                for rec in estimate.cost_optimization_recommendations[:3]:
                    with st.expander(f"💡 {rec.get('title', 'Recommendation')} - Save ${rec.get('potential_savings', 0):,.0f}/mo"):
                        st.markdown(f"**Description:** {rec.get('description', '')}")
                        st.markdown(f"**Effort:** {rec.get('effort', 'N/A')} | **Risk:** {rec.get('risk', 'N/A')}")
    
    @staticmethod
    def _render_iac_tab():
        """Render Infrastructure as Code export tab"""
        
        st.markdown("### 📦 Infrastructure as Code Export")
        
        if not st.session_state.eks_cluster_config:
            st.info("👆 Please define requirements first.")
            return
        
        config = st.session_state.eks_cluster_config
        
        iac_type = st.radio("Select IaC Tool", ["Terraform", "CloudFormation"], horizontal=True)
        
        if st.button(f"Generate {iac_type}", type="primary"):
            if EKS_WIZARD_STATUS.get('iac'):
                with st.spinner(f"Generating {iac_type} configuration..."):
                    try:
                        if iac_type == "Terraform":
                            generator = TerraformGenerator()
                            configs = generator.generate_terraform(config)
                        else:
                            generator = CloudFormationGenerator()
                            configs = generator.generate_cloudformation(config)
                        
                        st.session_state.eks_generated_configs[iac_type.lower()] = configs
                        st.success(f"✅ {iac_type} configuration generated!")
                    except Exception as e:
                        st.error(f"Error: {str(e)}")
            else:
                st.error("IaC module not loaded.")
        
        # Display generated configs
        key = iac_type.lower()
        if st.session_state.eks_generated_configs.get(key):
            configs = st.session_state.eks_generated_configs[key]
            
            for filename, content in list(configs.items())[:5]:
                with st.expander(f"📄 {filename}"):
                    lang = "hcl" if filename.endswith('.tf') else "yaml"
                    st.code(content[:3000] + ("..." if len(content) > 3000 else ""), language=lang)
            
            # Download button
            zip_buffer = io.BytesIO()
            with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
                for filename, content in configs.items():
                    zf.writestr(f"{iac_type.lower()}/{filename}", content)
            
            st.download_button(
                label=f"📥 Download {iac_type} Package",
                data=zip_buffer.getvalue(),
                file_name=f"{config.get('cluster_name', 'eks')}-{iac_type.lower()}.zip",
                mime="application/zip"
            )
    
    @staticmethod
    def _render_summary_tab():
        """Render summary and export tab"""
        
        st.markdown("### 📋 Architecture Summary")
        
        if not st.session_state.eks_cluster_config:
            st.info("👆 Complete the wizard to see summary.")
            return
        
        config = st.session_state.eks_cluster_config
        
        # Overview
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Cluster", config.get("cluster_name", "N/A"))
        with col2:
            st.metric("K8s Version", config.get("kubernetes_version", "1.29"))
        with col3:
            st.metric("Node Groups", len(config.get("node_groups", [])))
        with col4:
            st.metric("Region", config.get("region", "us-east-1"))
        
        # Security Summary
        if st.session_state.eks_security_assessment:
            st.markdown("---")
            assessment = st.session_state.eks_security_assessment
            st.metric("Security Score", f"{assessment.get('score', 0)}/100")
        
        # Cost Summary
        if st.session_state.eks_cost_estimate:
            st.markdown("---")
            estimate = st.session_state.eks_cost_estimate
            st.metric("Estimated Monthly Cost", f"${estimate.monthly_total:,.0f}")
        
        # Export options
        st.markdown("---")
        st.markdown("### 📥 Export Configuration")
        
        col1, col2 = st.columns(2)
        with col1:
            config_json = json.dumps(config, indent=2, default=str)
            st.download_button(
                "📄 Download Config (JSON)",
                config_json,
                f"{config.get('cluster_name', 'eks')}-config.json",
                "application/json"
            )
        with col2:
            config_yaml = yaml.dump(config, default_flow_style=False)
            st.download_button(
                "📄 Download Config (YAML)",
                config_yaml,
                f"{config.get('cluster_name', 'eks')}-config.yaml",
                "text/yaml"
            )


# ============================================================================
# CONVENIENCE FUNCTION
# ============================================================================

def render_eks_architecture_wizard():
    """Convenience function to render the EKS Architecture Wizard"""
    EKSArchitectureWizardModule.render()
