"""
Architecture Designer - REVAMPED with Real-World Use Cases
==========================================================
Problem-driven architecture design tool aligned with AWS Well-Architected Framework.

Real-World Use Cases:
1. 🆕 Greenfield Architecture - Design new AWS infrastructure from requirements
2. 🔄 Migration Planning - Migrate from on-prem/other cloud to AWS
3. 💰 Cost Optimization - Optimize existing architecture costs
4. 🔒 Security Hardening - Enhance security posture
5. 🌍 Multi-Region & DR - Disaster recovery and global deployment
6. ⚡ Performance Optimization - Improve latency and throughput

Version: 5.0.0 (Revamped)
"""

import streamlit as st
import streamlit.components.v1 as components
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
import json
import re

# ============================================================================
# USE CASES - REAL-WORLD PROBLEMS
# ============================================================================

USE_CASES = {
    "greenfield": {
        "title": "🆕 Greenfield Architecture",
        "description": "Design a new AWS architecture from scratch",
        "icon": "🆕",
        "problems_solved": [
            "Start with best practices from day 1",
            "Right-size services for your workload",
            "Build in security and compliance",
            "Plan for future growth"
        ]
    },
    "migration": {
        "title": "🔄 Migration Planning",
        "description": "Migrate from on-premises or other cloud to AWS",
        "icon": "🔄",
        "problems_solved": [
            "Assess migration complexity",
            "Choose migration strategy (6 Rs)",
            "Plan cutover and rollback",
            "Minimize downtime"
        ]
    },
    "cost_optimization": {
        "title": "💰 Cost Optimization",
        "description": "Reduce costs of existing AWS architecture",
        "icon": "💰",
        "problems_solved": [
            "Identify over-provisioned resources",
            "Right-size instances and databases",
            "Implement Reserved/Spot instances",
            "Optimize data transfer costs"
        ]
    },
    "security_hardening": {
        "title": "🔒 Security Hardening",
        "description": "Enhance security posture of your architecture",
        "icon": "🔒",
        "problems_solved": [
            "Implement defense in depth",
            "Meet compliance requirements",
            "Encrypt data at rest and in transit",
            "Implement least privilege access"
        ]
    },
    "multi_region": {
        "title": "🌍 Multi-Region & DR",
        "description": "Design for disaster recovery and global deployment",
        "icon": "🌍",
        "problems_solved": [
            "Achieve target RTO/RPO",
            "Implement cross-region replication",
            "Design failover automation",
            "Optimize global latency"
        ]
    },
    "performance": {
        "title": "⚡ Performance Optimization",
        "description": "Improve application performance and scalability",
        "icon": "⚡",
        "problems_solved": [
            "Reduce latency",
            "Increase throughput",
            "Implement caching strategies",
            "Auto-scale efficiently"
        ]
    }
}

# ============================================================================
# INDUSTRY TEMPLATES
# ============================================================================

INDUSTRY_TEMPLATES = {
    "healthcare": {
        "name": "Healthcare (HIPAA)",
        "icon": "🏥",
        "compliance": ["HIPAA", "HITRUST"],
        "required_services": ["kms", "cloudtrail", "config", "guardduty", "macie"],
        "architecture_notes": [
            "PHI data must be encrypted at rest and in transit",
            "Audit logging is mandatory",
            "Access controls must follow minimum necessary standard",
            "Business Associate Agreements required"
        ]
    },
    "financial": {
        "name": "Financial Services (PCI-DSS)",
        "icon": "🏦",
        "compliance": ["PCI-DSS", "SOC2", "SOX"],
        "required_services": ["waf", "shield", "kms", "secrets_manager", "cloudtrail", "security_hub"],
        "architecture_notes": [
            "Cardholder data must be isolated",
            "Network segmentation required",
            "Vulnerability scanning mandatory",
            "Strong access controls"
        ]
    },
    "ecommerce": {
        "name": "E-Commerce / Retail",
        "icon": "🛒",
        "compliance": ["PCI-DSS", "GDPR"],
        "required_services": ["cloudfront", "waf", "elasticache", "aurora", "sqs"],
        "architecture_notes": [
            "Handle traffic spikes (Black Friday)",
            "Payment processing security",
            "Customer data privacy",
            "Global CDN for performance"
        ]
    },
    "saas": {
        "name": "SaaS / Multi-Tenant",
        "icon": "☁️",
        "compliance": ["SOC2", "ISO27001"],
        "required_services": ["cognito", "api_gateway", "dynamodb", "sqs", "cloudwatch"],
        "architecture_notes": [
            "Tenant isolation",
            "Usage metering and billing",
            "Multi-region for SLA",
            "API rate limiting"
        ]
    },
    "gaming": {
        "name": "Gaming",
        "icon": "🎮",
        "compliance": ["GDPR", "COPPA"],
        "required_services": ["gamelift", "dynamodb", "elasticache", "cloudfront", "kinesis"],
        "architecture_notes": [
            "Low latency matchmaking",
            "Real-time leaderboards",
            "Session management",
            "Anti-cheat measures"
        ]
    },
    "media": {
        "name": "Media & Streaming",
        "icon": "📺",
        "compliance": ["DRM", "Content Protection"],
        "required_services": ["mediaconvert", "cloudfront", "s3", "elemental", "dynamodb"],
        "architecture_notes": [
            "Adaptive bitrate streaming",
            "Global content delivery",
            "DRM integration",
            "Live and on-demand content"
        ]
    }
}

# ============================================================================
# NLP PARSER FOR REQUIREMENTS
# ============================================================================

class ArchitectureNLPParser:
    """Parse natural language requirements into architecture configuration"""
    
    # Workload keywords
    WORKLOAD_KEYWORDS = {
        'web_application': ['web', 'website', 'frontend', 'portal', 'dashboard'],
        'api_backend': ['api', 'rest', 'graphql', 'backend', 'microservices'],
        'data_analytics': ['analytics', 'data lake', 'bi', 'reporting', 'etl'],
        'ml_ai': ['machine learning', 'ml', 'ai', 'training', 'inference', 'model'],
        'batch_processing': ['batch', 'job', 'scheduled', 'cron', 'etl'],
        'real_time': ['real-time', 'streaming', 'event', 'kafka', 'kinesis'],
        'mobile_backend': ['mobile', 'ios', 'android', 'app backend'],
    }
    
    # Scale keywords
    SCALE_KEYWORDS = {
        'small': ['small', 'startup', 'poc', 'prototype', 'test', 'dev', 'few users'],
        'medium': ['medium', 'growing', 'hundreds', 'moderate'],
        'large': ['large', 'enterprise', 'thousands', 'high traffic', 'scale'],
        'massive': ['massive', 'millions', 'global', 'hyperscale', 'viral'],
    }
    
    # Compliance keywords
    COMPLIANCE_KEYWORDS = {
        'HIPAA': ['hipaa', 'healthcare', 'medical', 'phi', 'health data'],
        'PCI-DSS': ['pci', 'payment', 'credit card', 'cardholder'],
        'SOC2': ['soc2', 'soc 2', 'audit', 'enterprise customers'],
        'GDPR': ['gdpr', 'european', 'eu', 'privacy', 'data protection'],
        'FedRAMP': ['fedramp', 'federal', 'government', 'gov'],
    }
    
    # Performance keywords
    PERFORMANCE_KEYWORDS = {
        'low_latency': ['low latency', 'fast', 'real-time', 'millisecond', 'responsive'],
        'high_throughput': ['high throughput', 'high volume', 'transactions', 'requests per second'],
        'high_availability': ['high availability', 'ha', '99.9', 'always on', 'no downtime'],
    }
    
    @staticmethod
    def parse_requirements(text: str) -> Dict:
        """Parse natural language text into architecture requirements"""
        text_lower = text.lower()
        config = {}
        
        # Parse workload type
        config['workload_types'] = []
        for workload, keywords in ArchitectureNLPParser.WORKLOAD_KEYWORDS.items():
            if any(kw in text_lower for kw in keywords):
                config['workload_types'].append(workload)
        if not config['workload_types']:
            config['workload_types'] = ['web_application']
        
        # Parse scale
        config['scale'] = 'medium'  # default
        for scale, keywords in ArchitectureNLPParser.SCALE_KEYWORDS.items():
            if any(kw in text_lower for kw in keywords):
                config['scale'] = scale
                break
        
        # Parse compliance
        config['compliance'] = []
        for framework, keywords in ArchitectureNLPParser.COMPLIANCE_KEYWORDS.items():
            if any(kw in text_lower for kw in keywords):
                config['compliance'].append(framework)
        
        # Parse performance requirements
        config['performance'] = []
        for perf, keywords in ArchitectureNLPParser.PERFORMANCE_KEYWORDS.items():
            if any(kw in text_lower for kw in keywords):
                config['performance'].append(perf)
        
        # Parse budget
        config['monthly_budget'] = ArchitectureNLPParser._extract_budget(text_lower)
        
        # Parse user count
        config['expected_users'] = ArchitectureNLPParser._extract_users(text_lower)
        
        # Recommend services based on parsed requirements
        config['recommended_services'] = ArchitectureNLPParser._recommend_services(config)
        
        return config
    
    @staticmethod
    def _extract_budget(text: str) -> int:
        """Extract monthly budget from text"""
        patterns = [
            r'\$\s*([\d,]+)\s*(?:k|K)?\s*(?:/month|per month|monthly)?',
            r'budget\s*(?:of|is|:)?\s*\$?\s*([\d,]+)\s*(?:k|K)?',
        ]
        for pattern in patterns:
            match = re.search(pattern, text)
            if match:
                value = int(match.group(1).replace(',', ''))
                if 'k' in text[match.start():match.end()].lower():
                    value *= 1000
                return value
        return 5000  # Default
    
    @staticmethod
    def _extract_users(text: str) -> int:
        """Extract expected user count"""
        patterns = [
            r'(\d+)\s*(?:users|customers|visitors)',
            r'(?:users|customers).*?(\d+)',
        ]
        for pattern in patterns:
            match = re.search(pattern, text)
            if match:
                return int(match.group(1))
        return 1000  # Default
    
    @staticmethod
    def _recommend_services(config: Dict) -> List[str]:
        """Recommend AWS services based on requirements"""
        services = []
        
        # Base services for any architecture
        services.extend(['vpc', 'cloudwatch', 'cloudtrail', 'iam'])
        
        # Workload-specific services
        workload_services = {
            'web_application': ['route53', 'cloudfront', 'alb', 'ec2', 'rds', 's3'],
            'api_backend': ['api_gateway', 'lambda', 'dynamodb', 'cognito'],
            'data_analytics': ['s3', 'glue', 'athena', 'redshift', 'quicksight'],
            'ml_ai': ['sagemaker', 's3', 'ecr', 'lambda'],
            'batch_processing': ['batch', 's3', 'sqs', 'lambda'],
            'real_time': ['kinesis', 'lambda', 'dynamodb', 'opensearch'],
            'mobile_backend': ['amplify', 'appsync', 'cognito', 'dynamodb', 's3'],
        }
        
        for workload in config.get('workload_types', []):
            services.extend(workload_services.get(workload, []))
        
        # Scale-specific services
        if config.get('scale') in ['large', 'massive']:
            services.extend(['elasticache', 'aurora', 'eks'])
        
        # Compliance-specific services
        if config.get('compliance'):
            services.extend(['kms', 'secrets_manager', 'config', 'security_hub'])
            if 'HIPAA' in config['compliance']:
                services.extend(['macie', 'guardduty'])
            if 'PCI-DSS' in config['compliance']:
                services.extend(['waf', 'shield'])
        
        # Performance-specific services
        if 'low_latency' in config.get('performance', []):
            services.extend(['cloudfront', 'elasticache', 'global_accelerator'])
        if 'high_availability' in config.get('performance', []):
            services.extend(['route53', 'multi_az'])
        
        # Deduplicate and return
        return list(dict.fromkeys(services))


# ============================================================================
# ARCHITECTURE DIAGRAM GENERATOR
# ============================================================================

class ArchitectureDiagramGenerator:
    """Generate visual architecture diagrams"""
    
    # Service metadata for visualization
    SERVICE_INFO = {
        'route53': {'name': 'Route 53', 'icon': '🌐', 'category': 'Networking', 'color': '#8C4FFF'},
        'cloudfront': {'name': 'CloudFront', 'icon': '🌍', 'category': 'CDN', 'color': '#8C4FFF'},
        'waf': {'name': 'WAF', 'icon': '🛡️', 'category': 'Security', 'color': '#DD344C'},
        'shield': {'name': 'Shield', 'icon': '🔰', 'category': 'Security', 'color': '#DD344C'},
        'alb': {'name': 'ALB', 'icon': '⚖️', 'category': 'Load Balancing', 'color': '#8C4FFF'},
        'nlb': {'name': 'NLB', 'icon': '⚡', 'category': 'Load Balancing', 'color': '#8C4FFF'},
        'api_gateway': {'name': 'API Gateway', 'icon': '🔌', 'category': 'API', 'color': '#E7157B'},
        'ec2': {'name': 'EC2', 'icon': '💻', 'category': 'Compute', 'color': '#ED7100'},
        'lambda': {'name': 'Lambda', 'icon': '⚡', 'category': 'Compute', 'color': '#ED7100'},
        'ecs': {'name': 'ECS', 'icon': '🐳', 'category': 'Containers', 'color': '#ED7100'},
        'eks': {'name': 'EKS', 'icon': '☸️', 'category': 'Containers', 'color': '#ED7100'},
        'fargate': {'name': 'Fargate', 'icon': '🚀', 'category': 'Containers', 'color': '#ED7100'},
        'rds': {'name': 'RDS', 'icon': '🗄️', 'category': 'Database', 'color': '#3B48CC'},
        'aurora': {'name': 'Aurora', 'icon': '🌟', 'category': 'Database', 'color': '#3B48CC'},
        'dynamodb': {'name': 'DynamoDB', 'icon': '📊', 'category': 'Database', 'color': '#3B48CC'},
        'elasticache': {'name': 'ElastiCache', 'icon': '⚡', 'category': 'Cache', 'color': '#3B48CC'},
        's3': {'name': 'S3', 'icon': '📦', 'category': 'Storage', 'color': '#3F8624'},
        'efs': {'name': 'EFS', 'icon': '📁', 'category': 'Storage', 'color': '#3F8624'},
        'sqs': {'name': 'SQS', 'icon': '📨', 'category': 'Messaging', 'color': '#E7157B'},
        'sns': {'name': 'SNS', 'icon': '📢', 'category': 'Messaging', 'color': '#E7157B'},
        'eventbridge': {'name': 'EventBridge', 'icon': '🔔', 'category': 'Events', 'color': '#E7157B'},
        'kinesis': {'name': 'Kinesis', 'icon': '🌊', 'category': 'Streaming', 'color': '#8C4FFF'},
        'cognito': {'name': 'Cognito', 'icon': '👤', 'category': 'Identity', 'color': '#DD344C'},
        'kms': {'name': 'KMS', 'icon': '🔐', 'category': 'Security', 'color': '#DD344C'},
        'secrets_manager': {'name': 'Secrets Manager', 'icon': '🗝️', 'category': 'Security', 'color': '#DD344C'},
        'guardduty': {'name': 'GuardDuty', 'icon': '🛡️', 'category': 'Security', 'color': '#DD344C'},
        'security_hub': {'name': 'Security Hub', 'icon': '🔒', 'category': 'Security', 'color': '#DD344C'},
        'macie': {'name': 'Macie', 'icon': '🔍', 'category': 'Security', 'color': '#DD344C'},
        'inspector': {'name': 'Inspector', 'icon': '🔎', 'category': 'Security', 'color': '#DD344C'},
        'cloudwatch': {'name': 'CloudWatch', 'icon': '📊', 'category': 'Monitoring', 'color': '#E7157B'},
        'cloudtrail': {'name': 'CloudTrail', 'icon': '📋', 'category': 'Audit', 'color': '#E7157B'},
        'config': {'name': 'Config', 'icon': '⚙️', 'category': 'Compliance', 'color': '#E7157B'},
        'xray': {'name': 'X-Ray', 'icon': '🔬', 'category': 'Tracing', 'color': '#E7157B'},
        'sagemaker': {'name': 'SageMaker', 'icon': '🤖', 'category': 'ML', 'color': '#01A88D'},
        'glue': {'name': 'Glue', 'icon': '🔗', 'category': 'ETL', 'color': '#8C4FFF'},
        'athena': {'name': 'Athena', 'icon': '🔍', 'category': 'Analytics', 'color': '#8C4FFF'},
        'redshift': {'name': 'Redshift', 'icon': '📈', 'category': 'Data Warehouse', 'color': '#8C4FFF'},
        'vpc': {'name': 'VPC', 'icon': '🌐', 'category': 'Networking', 'color': '#8C4FFF'},
        'iam': {'name': 'IAM', 'icon': '🔑', 'category': 'Identity', 'color': '#DD344C'},
        'rds_proxy': {'name': 'RDS Proxy', 'icon': '🔀', 'category': 'Database', 'color': '#3B48CC'},
        'auto_scaling': {'name': 'Auto Scaling', 'icon': '📈', 'category': 'Compute', 'color': '#ED7100'},
        'step_functions': {'name': 'Step Functions', 'icon': '🔄', 'category': 'Orchestration', 'color': '#E7157B'},
        'mediaconvert': {'name': 'MediaConvert', 'icon': '🎬', 'category': 'Media', 'color': '#ED7100'},
        'gamelift': {'name': 'GameLift', 'icon': '🎮', 'category': 'Gaming', 'color': '#ED7100'},
        'global_accelerator': {'name': 'Global Accelerator', 'icon': '🌐', 'category': 'Networking', 'color': '#8C4FFF'},
        'direct_connect': {'name': 'Direct Connect', 'icon': '🔌', 'category': 'Networking', 'color': '#8C4FFF'},
        'backup': {'name': 'AWS Backup', 'icon': '💾', 'category': 'Storage', 'color': '#3F8624'},
        'ebs': {'name': 'EBS', 'icon': '💿', 'category': 'Storage', 'color': '#3F8624'},
    }
    
    @staticmethod
    def generate_diagram(services: List[str], title: str, config: Dict) -> str:
        """Generate HTML architecture diagram"""
        
        # Group services by category
        categories = {}
        for service in services:
            info = ArchitectureDiagramGenerator.SERVICE_INFO.get(service, {
                'name': service, 'icon': '📦', 'category': 'Other', 'color': '#666'
            })
            cat = info['category']
            if cat not in categories:
                categories[cat] = []
            categories[cat].append({**info, 'id': service})
        
        html = f'''<!DOCTYPE html>
<html>
<head>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: 'Segoe UI', -apple-system, Arial, sans-serif;
            background: #f5f7fa;
            padding: 15px;
        }}
        .diagram-container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .header {{
            text-align: center;
            padding: 15px;
            background: linear-gradient(135deg, #232F3E 0%, #37475A 100%);
            border-radius: 10px;
            color: white;
            margin-bottom: 15px;
        }}
        .header h1 {{ font-size: 18px; margin-bottom: 5px; }}
        .header .meta {{ font-size: 11px; opacity: 0.8; }}
        
        .architecture-flow {{
            display: flex;
            flex-direction: column;
            gap: 15px;
        }}
        
        .tier {{
            background: white;
            border-radius: 10px;
            padding: 12px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .tier-header {{
            font-weight: bold;
            font-size: 12px;
            padding: 5px 10px;
            border-radius: 5px;
            color: white;
            display: inline-block;
            margin-bottom: 10px;
        }}
        .tier-content {{
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            justify-content: center;
        }}
        
        .service-box {{
            background: #f8f9fa;
            border: 2px solid #dee2e6;
            border-radius: 8px;
            padding: 10px 15px;
            text-align: center;
            min-width: 100px;
            transition: transform 0.2s, box-shadow 0.2s;
        }}
        .service-box:hover {{
            transform: translateY(-3px);
            box-shadow: 0 4px 8px rgba(0,0,0,0.15);
        }}
        .service-icon {{ font-size: 24px; }}
        .service-name {{ font-size: 11px; font-weight: 600; margin-top: 5px; }}
        
        .connector {{
            text-align: center;
            color: #666;
            font-size: 20px;
            padding: 5px;
        }}
        
        .legend {{
            display: flex;
            gap: 15px;
            justify-content: center;
            flex-wrap: wrap;
            margin-top: 15px;
            padding: 10px;
            background: white;
            border-radius: 8px;
        }}
        .legend-item {{
            display: flex;
            align-items: center;
            gap: 5px;
            font-size: 10px;
        }}
        .legend-color {{
            width: 12px;
            height: 12px;
            border-radius: 3px;
        }}
        
        .waf-scores {{
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 10px;
            margin-top: 15px;
        }}
        .waf-score {{
            background: white;
            border-radius: 8px;
            padding: 10px;
            text-align: center;
        }}
        .waf-score-value {{
            font-size: 20px;
            font-weight: bold;
        }}
        .waf-score-label {{
            font-size: 10px;
            color: #666;
        }}
    </style>
</head>
<body>
    <div class="diagram-container">
        <div class="header">
            <h1>🏗️ {title}</h1>
            <div class="meta">
                Services: {len(services)} | 
                Scale: {config.get('scale', 'medium').title()} | 
                Generated: {datetime.now().strftime("%Y-%m-%d")}
            </div>
        </div>
        
        <div class="architecture-flow">
'''
        
        # Define tier order
        tier_order = [
            ('CDN', '#8C4FFF', '🌍 Edge / CDN'),
            ('Security', '#DD344C', '🛡️ Security'),
            ('Load Balancing', '#8C4FFF', '⚖️ Load Balancing'),
            ('API', '#E7157B', '🔌 API Layer'),
            ('Compute', '#ED7100', '💻 Compute'),
            ('Containers', '#ED7100', '🐳 Containers'),
            ('Cache', '#3B48CC', '⚡ Caching'),
            ('Database', '#3B48CC', '🗄️ Database'),
            ('Storage', '#3F8624', '📦 Storage'),
            ('Messaging', '#E7157B', '📨 Messaging'),
            ('Streaming', '#8C4FFF', '🌊 Streaming'),
            ('Analytics', '#8C4FFF', '📊 Analytics'),
            ('ML', '#01A88D', '🤖 ML/AI'),
            ('Monitoring', '#E7157B', '📊 Monitoring'),
            ('Identity', '#DD344C', '👤 Identity'),
        ]
        
        for category, color, label in tier_order:
            if category in categories:
                services_in_cat = categories[category]
                html += f'''
            <div class="tier">
                <div class="tier-header" style="background: {color};">{label}</div>
                <div class="tier-content">
'''
                for svc in services_in_cat:
                    html += f'''
                    <div class="service-box" style="border-color: {svc['color']};">
                        <div class="service-icon">{svc['icon']}</div>
                        <div class="service-name">{svc['name']}</div>
                    </div>
'''
                html += '''
                </div>
            </div>
            <div class="connector">↓</div>
'''
        
        # Remove last connector
        html = html.rsplit('<div class="connector">↓</div>', 1)[0]
        
        html += '''
        </div>
        
        <div class="legend">
            <div class="legend-item">
                <div class="legend-color" style="background: #ED7100;"></div>
                <span>Compute</span>
            </div>
            <div class="legend-item">
                <div class="legend-color" style="background: #3B48CC;"></div>
                <span>Database</span>
            </div>
            <div class="legend-item">
                <div class="legend-color" style="background: #DD344C;"></div>
                <span>Security</span>
            </div>
            <div class="legend-item">
                <div class="legend-color" style="background: #8C4FFF;"></div>
                <span>Networking</span>
            </div>
            <div class="legend-item">
                <div class="legend-color" style="background: #3F8624;"></div>
                <span>Storage</span>
            </div>
            <div class="legend-item">
                <div class="legend-color" style="background: #E7157B;"></div>
                <span>Integration</span>
            </div>
        </div>
    </div>
</body>
</html>'''
        
        return html
    
    @staticmethod
    def generate_hld(services: List[str], title: str, config: Dict) -> str:
        """Generate High-Level Design (HLD) diagram - simplified architecture view"""
        
        # Determine architecture tiers based on services
        has_cdn = any(s in services for s in ['cloudfront', 'route53'])
        has_security = any(s in services for s in ['waf', 'shield', 'cognito'])
        has_lb = any(s in services for s in ['alb', 'nlb', 'api_gateway'])
        has_compute = any(s in services for s in ['ec2', 'ecs', 'eks', 'lambda', 'fargate'])
        has_cache = 'elasticache' in services
        has_db = any(s in services for s in ['rds', 'aurora', 'dynamodb'])
        has_storage = any(s in services for s in ['s3', 'efs'])
        has_messaging = any(s in services for s in ['sqs', 'sns', 'eventbridge'])
        
        scale = config.get('scale', 'medium')
        compliance = config.get('compliance', [])
        industry = config.get('industry', '')
        
        html = f'''<!DOCTYPE html>
<html>
<head>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: 'Segoe UI', Arial, sans-serif;
            background: linear-gradient(135deg, #1a237e 0%, #0d47a1 100%);
            padding: 20px;
            min-height: 100vh;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        
        .header {{
            background: rgba(255,255,255,0.1);
            border-radius: 12px;
            padding: 20px;
            text-align: center;
            color: white;
            margin-bottom: 20px;
        }}
        .header h1 {{ font-size: 24px; margin-bottom: 8px; }}
        .header .meta {{ font-size: 12px; opacity: 0.8; }}
        .header .badges {{ margin-top: 10px; }}
        .header .badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 11px;
            margin: 3px;
        }}
        .badge-scale {{ background: #4CAF50; }}
        .badge-compliance {{ background: #FF9800; }}
        .badge-industry {{ background: #9C27B0; }}
        
        .architecture {{
            display: flex;
            flex-direction: column;
            gap: 15px;
        }}
        
        .tier {{
            background: white;
            border-radius: 12px;
            padding: 15px 20px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.2);
        }}
        .tier-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 2px solid #eee;
        }}
        .tier-title {{
            font-weight: bold;
            font-size: 14px;
            color: #333;
        }}
        .tier-badge {{
            background: #e3f2fd;
            color: #1976D2;
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 10px;
        }}
        
        .tier-content {{
            display: flex;
            justify-content: center;
            gap: 20px;
            flex-wrap: wrap;
        }}
        
        .component {{
            background: #f8f9fa;
            border: 2px solid #dee2e6;
            border-radius: 10px;
            padding: 15px 25px;
            text-align: center;
            min-width: 120px;
            transition: all 0.3s ease;
        }}
        .component:hover {{
            transform: translateY(-5px);
            box-shadow: 0 8px 20px rgba(0,0,0,0.15);
        }}
        .component-icon {{ font-size: 32px; margin-bottom: 8px; }}
        .component-name {{ font-size: 12px; font-weight: 600; color: #333; }}
        .component-desc {{ font-size: 10px; color: #666; margin-top: 4px; }}
        
        .component.edge {{ border-color: #8C4FFF; background: #f3e5f5; }}
        .component.security {{ border-color: #DD344C; background: #ffebee; }}
        .component.compute {{ border-color: #ED7100; background: #fff3e0; }}
        .component.data {{ border-color: #3B48CC; background: #e8eaf6; }}
        .component.storage {{ border-color: #3F8624; background: #e8f5e9; }}
        
        .flow-arrow {{
            text-align: center;
            font-size: 24px;
            color: #666;
            padding: 5px 0;
        }}
        
        .info-panel {{
            background: rgba(255,255,255,0.1);
            border-radius: 12px;
            padding: 15px;
            margin-top: 20px;
            color: white;
        }}
        .info-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 15px;
        }}
        .info-item {{
            text-align: center;
            padding: 10px;
            background: rgba(255,255,255,0.1);
            border-radius: 8px;
        }}
        .info-value {{ font-size: 20px; font-weight: bold; }}
        .info-label {{ font-size: 10px; opacity: 0.8; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📊 {title} - High-Level Design</h1>
            <div class="meta">AWS Well-Architected Framework Aligned</div>
            <div class="badges">
                <span class="badge badge-scale">Scale: {scale.title()}</span>
                {"".join(f'<span class="badge badge-compliance">{c}</span>' for c in compliance[:3])}
                {f'<span class="badge badge-industry">{industry.replace("_", " ").title()}</span>' if industry else ''}
            </div>
        </div>
        
        <div class="architecture">
'''
        
        # Users/Internet tier
        html += '''
            <div class="tier">
                <div class="tier-header">
                    <span class="tier-title">🌐 Users / Internet</span>
                    <span class="tier-badge">Public Access</span>
                </div>
                <div class="tier-content">
                    <div class="component edge">
                        <div class="component-icon">👥</div>
                        <div class="component-name">End Users</div>
                        <div class="component-desc">Web & Mobile</div>
                    </div>
                </div>
            </div>
            <div class="flow-arrow">⬇️</div>
'''
        
        # Edge/CDN tier
        if has_cdn:
            html += '''
            <div class="tier">
                <div class="tier-header">
                    <span class="tier-title">🌍 Edge / CDN Layer</span>
                    <span class="tier-badge">Global Distribution</span>
                </div>
                <div class="tier-content">
'''
            if 'route53' in services:
                html += '''
                    <div class="component edge">
                        <div class="component-icon">🌐</div>
                        <div class="component-name">Route 53</div>
                        <div class="component-desc">DNS & Routing</div>
                    </div>
'''
            if 'cloudfront' in services:
                html += '''
                    <div class="component edge">
                        <div class="component-icon">🌍</div>
                        <div class="component-name">CloudFront</div>
                        <div class="component-desc">CDN</div>
                    </div>
'''
            html += '''
                </div>
            </div>
            <div class="flow-arrow">⬇️</div>
'''
        
        # Security tier
        if has_security:
            html += '''
            <div class="tier">
                <div class="tier-header">
                    <span class="tier-title">🔒 Security Layer</span>
                    <span class="tier-badge">Protection & Identity</span>
                </div>
                <div class="tier-content">
'''
            if 'waf' in services:
                html += '''
                    <div class="component security">
                        <div class="component-icon">🛡️</div>
                        <div class="component-name">WAF</div>
                        <div class="component-desc">Web Firewall</div>
                    </div>
'''
            if 'shield' in services:
                html += '''
                    <div class="component security">
                        <div class="component-icon">🔰</div>
                        <div class="component-name">Shield</div>
                        <div class="component-desc">DDoS Protection</div>
                    </div>
'''
            if 'cognito' in services:
                html += '''
                    <div class="component security">
                        <div class="component-icon">👤</div>
                        <div class="component-name">Cognito</div>
                        <div class="component-desc">Identity</div>
                    </div>
'''
            html += '''
                </div>
            </div>
            <div class="flow-arrow">⬇️</div>
'''
        
        # Load Balancing tier
        if has_lb:
            html += '''
            <div class="tier">
                <div class="tier-header">
                    <span class="tier-title">⚖️ Load Balancing / API Layer</span>
                    <span class="tier-badge">Traffic Distribution</span>
                </div>
                <div class="tier-content">
'''
            if 'alb' in services:
                html += '''
                    <div class="component edge">
                        <div class="component-icon">⚖️</div>
                        <div class="component-name">ALB</div>
                        <div class="component-desc">Application LB</div>
                    </div>
'''
            if 'api_gateway' in services:
                html += '''
                    <div class="component edge">
                        <div class="component-icon">🔌</div>
                        <div class="component-name">API Gateway</div>
                        <div class="component-desc">REST/WebSocket</div>
                    </div>
'''
            html += '''
                </div>
            </div>
            <div class="flow-arrow">⬇️</div>
'''
        
        # Compute tier
        if has_compute:
            html += '''
            <div class="tier">
                <div class="tier-header">
                    <span class="tier-title">💻 Compute Layer</span>
                    <span class="tier-badge">Application Processing</span>
                </div>
                <div class="tier-content">
'''
            if 'ec2' in services:
                html += '''
                    <div class="component compute">
                        <div class="component-icon">💻</div>
                        <div class="component-name">EC2</div>
                        <div class="component-desc">Virtual Servers</div>
                    </div>
'''
            if 'ecs' in services or 'fargate' in services:
                html += '''
                    <div class="component compute">
                        <div class="component-icon">🐳</div>
                        <div class="component-name">ECS/Fargate</div>
                        <div class="component-desc">Containers</div>
                    </div>
'''
            if 'eks' in services:
                html += '''
                    <div class="component compute">
                        <div class="component-icon">☸️</div>
                        <div class="component-name">EKS</div>
                        <div class="component-desc">Kubernetes</div>
                    </div>
'''
            if 'lambda' in services:
                html += '''
                    <div class="component compute">
                        <div class="component-icon">⚡</div>
                        <div class="component-name">Lambda</div>
                        <div class="component-desc">Serverless</div>
                    </div>
'''
            html += '''
                </div>
            </div>
            <div class="flow-arrow">⬇️</div>
'''
        
        # Cache tier
        if has_cache:
            html += '''
            <div class="tier">
                <div class="tier-header">
                    <span class="tier-title">⚡ Cache Layer</span>
                    <span class="tier-badge">Performance</span>
                </div>
                <div class="tier-content">
                    <div class="component data">
                        <div class="component-icon">⚡</div>
                        <div class="component-name">ElastiCache</div>
                        <div class="component-desc">Redis/Memcached</div>
                    </div>
                </div>
            </div>
            <div class="flow-arrow">⬇️</div>
'''
        
        # Database tier
        if has_db:
            html += '''
            <div class="tier">
                <div class="tier-header">
                    <span class="tier-title">🗄️ Database Layer</span>
                    <span class="tier-badge">Data Persistence</span>
                </div>
                <div class="tier-content">
'''
            if 'aurora' in services:
                html += '''
                    <div class="component data">
                        <div class="component-icon">🌟</div>
                        <div class="component-name">Aurora</div>
                        <div class="component-desc">MySQL/PostgreSQL</div>
                    </div>
'''
            elif 'rds' in services:
                html += '''
                    <div class="component data">
                        <div class="component-icon">🗄️</div>
                        <div class="component-name">RDS</div>
                        <div class="component-desc">Relational DB</div>
                    </div>
'''
            if 'dynamodb' in services:
                html += '''
                    <div class="component data">
                        <div class="component-icon">📊</div>
                        <div class="component-name">DynamoDB</div>
                        <div class="component-desc">NoSQL</div>
                    </div>
'''
            html += '''
                </div>
            </div>
'''
        
        # Storage tier
        if has_storage:
            html += '''
            <div class="flow-arrow">⬇️</div>
            <div class="tier">
                <div class="tier-header">
                    <span class="tier-title">📦 Storage Layer</span>
                    <span class="tier-badge">Object & File Storage</span>
                </div>
                <div class="tier-content">
'''
            if 's3' in services:
                html += '''
                    <div class="component storage">
                        <div class="component-icon">📦</div>
                        <div class="component-name">S3</div>
                        <div class="component-desc">Object Storage</div>
                    </div>
'''
            if 'efs' in services:
                html += '''
                    <div class="component storage">
                        <div class="component-icon">📁</div>
                        <div class="component-name">EFS</div>
                        <div class="component-desc">File System</div>
                    </div>
'''
            html += '''
                </div>
            </div>
'''
        
        # Info panel
        html += f'''
        </div>
        
        <div class="info-panel">
            <div class="info-grid">
                <div class="info-item">
                    <div class="info-value">{len(services)}</div>
                    <div class="info-label">AWS Services</div>
                </div>
                <div class="info-item">
                    <div class="info-value">{len([s for s in services if s in ['waf', 'shield', 'kms', 'guardduty', 'cognito', 'secrets_manager', 'security_hub']])}</div>
                    <div class="info-label">Security Services</div>
                </div>
                <div class="info-item">
                    <div class="info-value">{len(compliance)}</div>
                    <div class="info-label">Compliance Frameworks</div>
                </div>
                <div class="info-item">
                    <div class="info-value">{scale.title()}</div>
                    <div class="info-label">Scale Tier</div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>'''
        
        return html
    
    @staticmethod
    def generate_lld(services: List[str], title: str, config: Dict) -> str:
        """Generate Low-Level Design (LLD) diagram - comprehensive architecture view"""
        
        scale = config.get('scale', 'medium')
        compliance = config.get('compliance', [])
        industry = config.get('industry', '')
        region = config.get('region', 'us-east-1')
        budget = config.get('monthly_budget', 5000)
        
        # Categorize services
        edge_services = [s for s in services if s in ['route53', 'cloudfront', 'global_accelerator']]
        security_services = [s for s in services if s in ['waf', 'shield', 'cognito', 'kms', 'secrets_manager', 'guardduty', 'security_hub', 'macie', 'inspector', 'iam']]
        network_services = [s for s in services if s in ['vpc', 'alb', 'nlb', 'api_gateway', 'direct_connect']]
        compute_services = [s for s in services if s in ['ec2', 'ecs', 'eks', 'lambda', 'fargate', 'auto_scaling']]
        data_services = [s for s in services if s in ['rds', 'aurora', 'dynamodb', 'elasticache', 'rds_proxy', 'redshift']]
        storage_services = [s for s in services if s in ['s3', 'efs', 'ebs', 'backup']]
        integration_services = [s for s in services if s in ['sqs', 'sns', 'eventbridge', 'kinesis', 'step_functions']]
        monitoring_services = [s for s in services if s in ['cloudwatch', 'cloudtrail', 'config', 'xray']]
        analytics_services = [s for s in services if s in ['athena', 'glue', 'sagemaker', 'redshift']]
        
        html = f'''<!DOCTYPE html>
<html>
<head>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: 'Segoe UI', Arial, sans-serif;
            background: linear-gradient(180deg, #0d1b2a 0%, #1b263b 50%, #415a77 100%);
            padding: 20px;
            min-height: 100vh;
        }}
        .container {{ max-width: 1400px; margin: 0 auto; }}
        
        .header {{
            background: linear-gradient(135deg, #FF6B35 0%, #F7931E 100%);
            border-radius: 15px;
            padding: 25px;
            text-align: center;
            color: white;
            margin-bottom: 20px;
            box-shadow: 0 8px 30px rgba(255,107,53,0.3);
        }}
        .header h1 {{ font-size: 26px; margin-bottom: 8px; }}
        .header .subtitle {{ font-size: 13px; opacity: 0.9; }}
        .header-badges {{
            margin-top: 15px;
            display: flex;
            justify-content: center;
            gap: 10px;
            flex-wrap: wrap;
        }}
        .header-badge {{
            background: rgba(255,255,255,0.2);
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 11px;
        }}
        
        .lld-grid {{
            display: grid;
            grid-template-columns: 1fr 3fr 1fr;
            gap: 20px;
            margin-bottom: 20px;
        }}
        
        .sidebar {{
            display: flex;
            flex-direction: column;
            gap: 15px;
        }}
        
        .main-architecture {{
            background: white;
            border-radius: 15px;
            padding: 20px;
            box-shadow: 0 8px 30px rgba(0,0,0,0.2);
        }}
        
        .section {{
            background: rgba(255,255,255,0.95);
            border-radius: 12px;
            padding: 15px;
            margin-bottom: 15px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
        }}
        .section.security {{ border-left: 4px solid #DD344C; }}
        .section.monitoring {{ border-left: 4px solid #E7157B; }}
        .section.compliance {{ border-left: 4px solid #9C27B0; }}
        .section.integration {{ border-left: 4px solid #00BCD4; }}
        
        .section-title {{
            font-size: 12px;
            font-weight: bold;
            color: #333;
            margin-bottom: 12px;
            padding-bottom: 8px;
            border-bottom: 1px solid #eee;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        
        .services-grid {{
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 8px;
        }}
        
        .service-chip {{
            background: #f5f5f5;
            border: 1px solid #ddd;
            border-radius: 8px;
            padding: 8px 10px;
            font-size: 10px;
            display: flex;
            align-items: center;
            gap: 6px;
        }}
        .service-chip.active {{ background: #e3f2fd; border-color: #2196F3; }}
        .service-icon {{ font-size: 16px; }}
        
        .vpc-container {{
            background: linear-gradient(135deg, #e8f5e9 0%, #c8e6c9 100%);
            border: 3px solid #4CAF50;
            border-radius: 15px;
            padding: 20px;
            margin: 15px 0;
        }}
        .vpc-header {{
            text-align: center;
            margin-bottom: 15px;
        }}
        .vpc-title {{
            font-size: 14px;
            font-weight: bold;
            color: #2E7D32;
        }}
        .vpc-cidr {{
            font-size: 11px;
            color: #558B2F;
            font-family: monospace;
        }}
        
        .az-container {{
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 15px;
        }}
        .az {{
            background: white;
            border: 2px dashed #81C784;
            border-radius: 10px;
            padding: 12px;
        }}
        .az-title {{
            text-align: center;
            font-size: 11px;
            font-weight: bold;
            color: #388E3C;
            margin-bottom: 10px;
        }}
        
        .subnet {{
            border-radius: 8px;
            padding: 10px;
            margin-bottom: 8px;
        }}
        .subnet.public {{
            background: #fff3e0;
            border: 1px solid #FF9800;
        }}
        .subnet.private {{
            background: #e3f2fd;
            border: 1px solid #2196F3;
        }}
        .subnet-title {{
            font-size: 9px;
            font-weight: bold;
            margin-bottom: 6px;
        }}
        .subnet.public .subnet-title {{ color: #E65100; }}
        .subnet.private .subnet-title {{ color: #1565C0; }}
        
        .resource {{
            background: white;
            border: 1px solid #ddd;
            border-radius: 6px;
            padding: 6px 8px;
            margin: 4px 0;
            font-size: 9px;
            display: flex;
            align-items: center;
            gap: 5px;
        }}
        .resource-icon {{ font-size: 14px; }}
        
        .data-flow {{
            background: #fce4ec;
            border: 2px solid #E91E63;
            border-radius: 10px;
            padding: 12px;
            margin-top: 15px;
        }}
        .data-flow-title {{
            font-size: 11px;
            font-weight: bold;
            color: #C2185B;
            margin-bottom: 10px;
            text-align: center;
        }}
        .flow-row {{
            display: flex;
            justify-content: center;
            align-items: center;
            gap: 10px;
            margin: 8px 0;
            flex-wrap: wrap;
        }}
        .flow-item {{
            background: white;
            border-radius: 6px;
            padding: 6px 12px;
            font-size: 10px;
            display: flex;
            align-items: center;
            gap: 5px;
        }}
        .flow-arrow {{ color: #E91E63; font-weight: bold; }}
        
        .metrics-row {{
            display: grid;
            grid-template-columns: repeat(6, 1fr);
            gap: 10px;
            margin-top: 20px;
        }}
        .metric {{
            background: rgba(255,255,255,0.1);
            border-radius: 10px;
            padding: 15px;
            text-align: center;
            color: white;
        }}
        .metric-value {{ font-size: 22px; font-weight: bold; }}
        .metric-label {{ font-size: 9px; opacity: 0.8; margin-top: 4px; }}
        
        .legend {{
            display: flex;
            justify-content: center;
            gap: 20px;
            margin-top: 20px;
            padding: 15px;
            background: rgba(255,255,255,0.1);
            border-radius: 10px;
            flex-wrap: wrap;
        }}
        .legend-item {{
            display: flex;
            align-items: center;
            gap: 6px;
            font-size: 10px;
            color: white;
        }}
        .legend-color {{
            width: 14px;
            height: 14px;
            border-radius: 4px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📐 {title} - Low-Level Design</h1>
            <div class="subtitle">Comprehensive Architecture with Networking, Security & Data Flows</div>
            <div class="header-badges">
                <span class="header-badge">📍 Region: {region}</span>
                <span class="header-badge">📊 Scale: {scale.title()}</span>
                <span class="header-badge">💰 Budget: ${budget:,}/mo</span>
                <span class="header-badge">🔧 Services: {len(services)}</span>
            </div>
        </div>
        
        <div class="lld-grid">
            <!-- Left Sidebar - Security & Monitoring -->
            <div class="sidebar">
                <div class="section security">
                    <div class="section-title">🔒 Security Layer</div>
                    <div class="services-grid">
'''
        
        for svc in security_services:
            info = ArchitectureDiagramGenerator.SERVICE_INFO.get(svc, {'name': svc, 'icon': '📦'})
            html += f'''
                        <div class="service-chip active">
                            <span class="service-icon">{info['icon']}</span>
                            <span>{info['name']}</span>
                        </div>
'''
        
        if not security_services:
            html += '''
                        <div class="service-chip">
                            <span>No security services</span>
                        </div>
'''
        
        html += '''
                    </div>
                </div>
                
                <div class="section monitoring">
                    <div class="section-title">📊 Observability</div>
                    <div class="services-grid">
'''
        
        for svc in monitoring_services:
            info = ArchitectureDiagramGenerator.SERVICE_INFO.get(svc, {'name': svc, 'icon': '📦'})
            html += f'''
                        <div class="service-chip active">
                            <span class="service-icon">{info['icon']}</span>
                            <span>{info['name']}</span>
                        </div>
'''
        
        if not monitoring_services:
            html += '''
                        <div class="service-chip">
                            <span>No monitoring</span>
                        </div>
'''
        
        html += f'''
                    </div>
                </div>
                
                <div class="section compliance">
                    <div class="section-title">📋 Compliance</div>
                    <div class="services-grid">
'''
        
        for comp in compliance[:4]:
            html += f'''
                        <div class="service-chip active">
                            <span class="service-icon">✅</span>
                            <span>{comp}</span>
                        </div>
'''
        
        if not compliance:
            html += '''
                        <div class="service-chip">
                            <span>No compliance requirements</span>
                        </div>
'''
        
        html += '''
                    </div>
                </div>
            </div>
            
            <!-- Main Architecture -->
            <div class="main-architecture">
'''
        
        # Edge Layer
        if edge_services:
            html += '''
                <div style="background: #f3e5f5; border: 2px solid #9C27B0; border-radius: 10px; padding: 12px; margin-bottom: 15px;">
                    <div style="text-align: center; font-size: 12px; font-weight: bold; color: #7B1FA2; margin-bottom: 10px;">🌐 Edge Layer (Global)</div>
                    <div style="display: flex; justify-content: center; gap: 15px;">
'''
            for svc in edge_services:
                info = ArchitectureDiagramGenerator.SERVICE_INFO.get(svc, {'name': svc, 'icon': '📦'})
                html += f'''
                        <div class="resource">
                            <span class="resource-icon">{info['icon']}</span>
                            <span>{info['name']}</span>
                        </div>
'''
            html += '''
                    </div>
                </div>
'''
        
        # VPC Container
        html += '''
                <div class="vpc-container">
                    <div class="vpc-header">
                        <div class="vpc-title">🌐 VPC - Production Environment</div>
                        <div class="vpc-cidr">CIDR: 10.0.0.0/16</div>
                    </div>
                    
                    <div class="az-container">
'''
        
        # Generate 3 AZs
        az_suffixes = ['a', 'b', 'c']
        for i, suffix in enumerate(az_suffixes):
            html += f'''
                        <div class="az">
                            <div class="az-title">AZ-{suffix.upper()} ({region}{suffix})</div>
                            
                            <div class="subnet public">
                                <div class="subnet-title">Public Subnet (10.0.{i*10}.0/24)</div>
'''
            # Add public subnet resources
            if 'alb' in services and i == 0:
                html += '''
                                <div class="resource"><span class="resource-icon">⚖️</span>ALB</div>
'''
            if 'nlb' in services and i == 1:
                html += '''
                                <div class="resource"><span class="resource-icon">⚡</span>NLB</div>
'''
            html += '''
                                <div class="resource"><span class="resource-icon">🌐</span>NAT GW</div>
                            </div>
                            
                            <div class="subnet private">
                                <div class="subnet-title">Private Subnet (10.0.{}{}.0/24)</div>
'''.format(i*10+1, '')
            
            # Add compute resources
            if 'ec2' in services:
                html += '''
                                <div class="resource"><span class="resource-icon">💻</span>EC2</div>
'''
            if 'ecs' in services or 'fargate' in services:
                html += '''
                                <div class="resource"><span class="resource-icon">🐳</span>ECS</div>
'''
            if 'eks' in services:
                html += '''
                                <div class="resource"><span class="resource-icon">☸️</span>EKS</div>
'''
            if 'lambda' in services:
                html += '''
                                <div class="resource"><span class="resource-icon">⚡</span>Lambda</div>
'''
            
            # Add data resources in first AZ
            if i == 0:
                if 'aurora' in services or 'rds' in services:
                    html += '''
                                <div class="resource"><span class="resource-icon">🗄️</span>DB Primary</div>
'''
                if 'elasticache' in services:
                    html += '''
                                <div class="resource"><span class="resource-icon">⚡</span>Cache</div>
'''
            elif i == 1:
                if 'aurora' in services or 'rds' in services:
                    html += '''
                                <div class="resource"><span class="resource-icon">🗄️</span>DB Replica</div>
'''
            
            html += '''
                            </div>
                        </div>
'''
        
        html += '''
                    </div>
                </div>
'''
        
        # Storage Layer
        if storage_services:
            html += '''
                <div style="background: #e8f5e9; border: 2px solid #4CAF50; border-radius: 10px; padding: 12px; margin-top: 15px;">
                    <div style="text-align: center; font-size: 12px; font-weight: bold; color: #2E7D32; margin-bottom: 10px;">📦 Storage Layer</div>
                    <div style="display: flex; justify-content: center; gap: 15px;">
'''
            for svc in storage_services:
                info = ArchitectureDiagramGenerator.SERVICE_INFO.get(svc, {'name': svc, 'icon': '📦'})
                html += f'''
                        <div class="resource">
                            <span class="resource-icon">{info['icon']}</span>
                            <span>{info['name']}</span>
                        </div>
'''
            html += '''
                    </div>
                </div>
'''
        
        # Data Flow
        html += '''
                <div class="data-flow">
                    <div class="data-flow-title">📊 Data Flow</div>
                    <div class="flow-row">
                        <div class="flow-item"><span class="resource-icon">👥</span>Users</div>
                        <span class="flow-arrow">→</span>
'''
        if 'cloudfront' in services:
            html += '''
                        <div class="flow-item"><span class="resource-icon">🌍</span>CDN</div>
                        <span class="flow-arrow">→</span>
'''
        if 'waf' in services:
            html += '''
                        <div class="flow-item"><span class="resource-icon">🛡️</span>WAF</div>
                        <span class="flow-arrow">→</span>
'''
        if 'alb' in services or 'api_gateway' in services:
            html += '''
                        <div class="flow-item"><span class="resource-icon">⚖️</span>LB/API</div>
                        <span class="flow-arrow">→</span>
'''
        html += '''
                        <div class="flow-item"><span class="resource-icon">💻</span>Compute</div>
                        <span class="flow-arrow">→</span>
'''
        if 'elasticache' in services:
            html += '''
                        <div class="flow-item"><span class="resource-icon">⚡</span>Cache</div>
                        <span class="flow-arrow">→</span>
'''
        html += '''
                        <div class="flow-item"><span class="resource-icon">🗄️</span>Database</div>
                    </div>
                </div>
            </div>
            
            <!-- Right Sidebar - Integration & Analytics -->
            <div class="sidebar">
                <div class="section integration">
                    <div class="section-title">🔗 Integration</div>
                    <div class="services-grid">
'''
        
        for svc in integration_services:
            info = ArchitectureDiagramGenerator.SERVICE_INFO.get(svc, {'name': svc, 'icon': '📦'})
            html += f'''
                        <div class="service-chip active">
                            <span class="service-icon">{info['icon']}</span>
                            <span>{info['name']}</span>
                        </div>
'''
        
        if not integration_services:
            html += '''
                        <div class="service-chip">
                            <span>No integration services</span>
                        </div>
'''
        
        html += '''
                    </div>
                </div>
'''
        
        if analytics_services:
            html += '''
                <div class="section" style="border-left: 4px solid #FF9800;">
                    <div class="section-title">📈 Analytics & ML</div>
                    <div class="services-grid">
'''
            for svc in analytics_services:
                info = ArchitectureDiagramGenerator.SERVICE_INFO.get(svc, {'name': svc, 'icon': '📦'})
                html += f'''
                        <div class="service-chip active">
                            <span class="service-icon">{info['icon']}</span>
                            <span>{info['name']}</span>
                        </div>
'''
            html += '''
                    </div>
                </div>
'''
        
        html += '''
            </div>
        </div>
        
        <!-- Metrics Row -->
        <div class="metrics-row">
            <div class="metric">
                <div class="metric-value">{}</div>
                <div class="metric-label">Total Services</div>
            </div>
            <div class="metric">
                <div class="metric-value">{}</div>
                <div class="metric-label">Security Services</div>
            </div>
            <div class="metric">
                <div class="metric-value">{}</div>
                <div class="metric-label">Compute Services</div>
            </div>
            <div class="metric">
                <div class="metric-value">{}</div>
                <div class="metric-label">Data Services</div>
            </div>
            <div class="metric">
                <div class="metric-value">3</div>
                <div class="metric-label">Availability Zones</div>
            </div>
            <div class="metric">
                <div class="metric-value">{}</div>
                <div class="metric-label">Compliance</div>
            </div>
        </div>
        
        <!-- Legend -->
        <div class="legend">
            <div class="legend-item">
                <div class="legend-color" style="background: #fff3e0; border: 1px solid #FF9800;"></div>
                <span>Public Subnet</span>
            </div>
            <div class="legend-item">
                <div class="legend-color" style="background: #e3f2fd; border: 1px solid #2196F3;"></div>
                <span>Private Subnet</span>
            </div>
            <div class="legend-item">
                <div class="legend-color" style="background: #e8f5e9; border: 1px solid #4CAF50;"></div>
                <span>VPC Boundary</span>
            </div>
            <div class="legend-item">
                <div class="legend-color" style="background: #f3e5f5; border: 1px solid #9C27B0;"></div>
                <span>Global/Edge</span>
            </div>
            <div class="legend-item">
                <div class="legend-color" style="background: #ffebee; border: 1px solid #DD344C;"></div>
                <span>Security</span>
            </div>
            <div class="legend-item">
                <div class="legend-color" style="background: #fce4ec; border: 1px solid #E91E63;"></div>
                <span>Data Flow</span>
            </div>
        </div>
    </div>
</body>
</html>'''.format(
            len(services),
            len(security_services),
            len(compute_services),
            len(data_services),
            len(compliance)
        )
        
        return html

class ArchitectureDesignerRevamped:
    """Revamped Architecture Designer with real-world use cases"""
    
    @staticmethod
    def render():
        """Main render method"""
        st.title("🎨 Architecture Designer")
        st.markdown("Design AWS architectures aligned with the Well-Architected Framework")
        
        # Use case selection
        selected = st.radio(
            "🎯 What would you like to do?",
            options=list(USE_CASES.keys()),
            format_func=lambda x: USE_CASES[x]['title'],
            horizontal=True,
            key="arch_use_case_radio"
        )
        
        st.markdown("---")
        
        # Render selected use case
        if selected == 'greenfield':
            ArchitectureDesignerRevamped._render_greenfield()
        elif selected == 'migration':
            ArchitectureDesignerRevamped._render_migration()
        elif selected == 'cost_optimization':
            ArchitectureDesignerRevamped._render_cost_optimization()
        elif selected == 'security_hardening':
            ArchitectureDesignerRevamped._render_security_hardening()
        elif selected == 'multi_region':
            ArchitectureDesignerRevamped._render_multi_region()
        elif selected == 'performance':
            ArchitectureDesignerRevamped._render_performance()
    
    @staticmethod
    def _render_greenfield():
        """Render greenfield architecture design"""
        st.markdown("## 🆕 Greenfield Architecture Design")
        st.markdown("Design a new AWS architecture from scratch")
        
        # Initialize session state
        if 'arch_config' not in st.session_state:
            st.session_state.arch_config = {
                'services': [],
                'workload_types': [],
                'scale': 'medium',
                'compliance': [],
                'monthly_budget': 5000
            }
        
        config = st.session_state.arch_config
        
        # Tabs for workflow
        tab1, tab2, tab3, tab4 = st.tabs([
            "📝 Requirements",
            "🏭 Industry Template",
            "🏗️ Architecture",
            "📥 Export"
        ])
        
        with tab1:
            ArchitectureDesignerRevamped._render_requirements_input(config)
        
        with tab2:
            ArchitectureDesignerRevamped._render_industry_templates(config)
        
        with tab3:
            ArchitectureDesignerRevamped._render_architecture_diagram(config)
        
        with tab4:
            ArchitectureDesignerRevamped._render_export(config)
    
    @staticmethod
    def _render_requirements_input(config: Dict):
        """Render requirements input with NLP support"""
        st.markdown("### 📝 Define Your Requirements")
        
        input_mode = st.radio(
            "Choose input method:",
            ["🤖 AI Assistant (Describe in plain English)", "⚙️ Manual Configuration"],
            horizontal=True,
            key="arch_input_mode"
        )
        
        if "AI Assistant" in input_mode:
            # NLP Input
            st.markdown("#### 🤖 Describe Your Architecture Needs")
            
            with st.expander("💡 Example prompts", expanded=False):
                st.markdown("""
**E-Commerce Platform:**
> "I need a scalable e-commerce platform that can handle 10,000 concurrent users. 
> We process credit card payments so need PCI-DSS compliance. Budget is $15,000/month."

**Healthcare Application:**
> "We're building a healthcare application that stores patient data. 
> Must be HIPAA compliant. Expecting 5,000 users. Need high availability."

**Real-Time Analytics:**
> "Need a real-time analytics platform processing IoT sensor data.
> Low latency is critical. Expecting 1 million events per minute."
                """)
            
            requirements_text = st.text_area(
                "Describe your requirements:",
                height=150,
                placeholder="Example: I need a web application for 10,000 users with PCI-DSS compliance...",
                key="arch_nlp_input"
            )
            
            if st.button("🔍 Analyze & Configure", type="primary"):
                if requirements_text:
                    with st.spinner("🤖 Analyzing requirements..."):
                        parsed = ArchitectureNLPParser.parse_requirements(requirements_text)
                        config.update(parsed)
                        st.session_state.arch_config = config
                        st.success("✅ Requirements analyzed!")
                        st.rerun()
        else:
            # Manual Configuration
            st.markdown("#### ⚙️ Manual Configuration")
            
            col1, col2 = st.columns(2)
            
            with col1:
                config['workload_types'] = st.multiselect(
                    "Workload Types",
                    ['web_application', 'api_backend', 'data_analytics', 'ml_ai', 
                     'batch_processing', 'real_time', 'mobile_backend'],
                    default=config.get('workload_types', ['web_application']),
                    format_func=lambda x: x.replace('_', ' ').title()
                )
                
                config['scale'] = st.selectbox(
                    "Expected Scale",
                    ['small', 'medium', 'large', 'massive'],
                    index=['small', 'medium', 'large', 'massive'].index(config.get('scale', 'medium'))
                )
            
            with col2:
                config['compliance'] = st.multiselect(
                    "Compliance Requirements",
                    ['HIPAA', 'PCI-DSS', 'SOC2', 'GDPR', 'FedRAMP'],
                    default=config.get('compliance', [])
                )
                
                config['monthly_budget'] = st.number_input(
                    "Monthly Budget ($)",
                    min_value=100,
                    max_value=1000000,
                    value=config.get('monthly_budget', 5000)
                )
            
            config['performance'] = st.multiselect(
                "Performance Requirements",
                ['low_latency', 'high_throughput', 'high_availability'],
                format_func=lambda x: x.replace('_', ' ').title()
            )
            
            if st.button("🔧 Generate Architecture", type="primary"):
                config['recommended_services'] = ArchitectureNLPParser._recommend_services(config)
                st.session_state.arch_config = config
                st.success("✅ Configuration saved!")
        
        # Show current configuration
        if config.get('recommended_services'):
            st.markdown("---")
            st.markdown("### 📊 Parsed Configuration")
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Workload Types", len(config.get('workload_types', [])))
                st.metric("Scale", config.get('scale', 'medium').title())
            with col2:
                st.metric("Compliance", len(config.get('compliance', [])) or "None")
                st.metric("Budget", f"${config.get('monthly_budget', 0):,}/mo")
            with col3:
                st.metric("Services", len(config.get('recommended_services', [])))
                st.metric("Performance", len(config.get('performance', [])) or "Standard")
    
    @staticmethod
    def _render_industry_templates(config: Dict):
        """Render industry-specific templates"""
        st.markdown("### 🏭 Industry Templates")
        st.markdown("Select a pre-configured template for your industry")
        
        cols = st.columns(3)
        
        for i, (key, template) in enumerate(INDUSTRY_TEMPLATES.items()):
            with cols[i % 3]:
                with st.container():
                    st.markdown(f"#### {template['icon']} {template['name']}")
                    st.caption(f"Compliance: {', '.join(template['compliance'])}")
                    
                    if st.button(f"Apply {template['name']}", key=f"template_{key}"):
                        config['compliance'] = template['compliance']
                        config['industry'] = key
                        # Add required services
                        existing = set(config.get('recommended_services', []))
                        existing.update(template['required_services'])
                        config['recommended_services'] = list(existing)
                        st.session_state.arch_config = config
                        st.success(f"✅ Applied {template['name']} template!")
                        st.rerun()
                    
                    with st.expander("Details"):
                        st.markdown("**Required Services:**")
                        for svc in template['required_services']:
                            st.caption(f"• {svc}")
                        st.markdown("**Notes:**")
                        for note in template['architecture_notes']:
                            st.caption(f"• {note}")
    
    @staticmethod
    def _render_architecture_diagram(config: Dict):
        """Render architecture visualization with HLD and LLD views"""
        st.markdown("### 🏗️ Architecture Visualization")
        
        services = config.get('recommended_services', [])
        
        if not services:
            st.warning("👆 Please configure your requirements first")
            return
        
        # Diagram type selection - HLD vs LLD
        diagram_type = st.radio(
            "Select Diagram Type:",
            ["📊 High-Level Design (HLD)", "📐 Low-Level Design (LLD)"],
            horizontal=True,
            key="arch_diagram_type_selector"
        )
        
        # Allow manual service adjustment
        with st.expander("✏️ Customize Services", expanded=False):
            all_services = list(ArchitectureDiagramGenerator.SERVICE_INFO.keys())
            # Filter services to only include those in SERVICE_INFO
            valid_services = [s for s in services if s in all_services]
            services = st.multiselect(
                "Services in Architecture",
                all_services,
                default=valid_services,
                format_func=lambda x: ArchitectureDiagramGenerator.SERVICE_INFO.get(x, {}).get('name', x)
            )
            config['recommended_services'] = services
        
        # Generate title
        title = f"Architecture - {config.get('scale', 'medium').title()} Scale"
        if config.get('industry'):
            title = f"{INDUSTRY_TEMPLATES.get(config['industry'], {}).get('name', '')} Architecture"
        
        if "High-Level" in diagram_type:
            # Generate HLD diagram
            st.markdown("#### 📊 High-Level Architecture Overview")
            st.caption("Simplified view showing major components, data flow, and service tiers")
            
            diagram_html = ArchitectureDiagramGenerator.generate_hld(services, title, config)
            components.html(diagram_html, height=700, scrolling=True)
            
            col1, col2 = st.columns(2)
            with col1:
                st.download_button(
                    label="📥 Download HLD Diagram",
                    data=diagram_html,
                    file_name=f"architecture_HLD.html",
                    mime="text/html",
                    key="download_arch_hld"
                )
        else:
            # Generate LLD diagram
            st.markdown("#### 📐 Low-Level Design - Complete Architecture")
            st.caption("Comprehensive view with networking, security boundaries, data flows, and all components")
            
            lld_html = ArchitectureDiagramGenerator.generate_lld(services, title, config)
            components.html(lld_html, height=950, scrolling=True)
            
            col1, col2 = st.columns(2)
            with col1:
                st.download_button(
                    label="📥 Download LLD Diagram",
                    data=lld_html,
                    file_name=f"architecture_LLD.html",
                    mime="text/html",
                    key="download_arch_lld"
                )
        
        # WAF Score
        st.markdown("---")
        st.markdown("### 📊 Well-Architected Score")
        
        waf_scores = ArchitectureDesignerRevamped._calculate_waf_scores(services, config)
        
        cols = st.columns(6)
        pillars = [
            ("⚙️ Ops Excellence", waf_scores.get('operational_excellence', 0)),
            ("🔒 Security", waf_scores.get('security', 0)),
            ("🛡️ Reliability", waf_scores.get('reliability', 0)),
            ("⚡ Performance", waf_scores.get('performance', 0)),
            ("💰 Cost", waf_scores.get('cost', 0)),
            ("🌱 Sustainability", waf_scores.get('sustainability', 0)),
        ]
        
        for i, (name, score) in enumerate(pillars):
            with cols[i]:
                color = "#4CAF50" if score >= 80 else "#FF9800" if score >= 60 else "#F44336"
                st.markdown(f"""
                <div style="text-align: center; padding: 10px; background: white; border-radius: 8px;">
                    <div style="font-size: 24px; font-weight: bold; color: {color};">{score}</div>
                    <div style="font-size: 10px; color: #666;">{name}</div>
                </div>
                """, unsafe_allow_html=True)
    
    @staticmethod
    def _calculate_waf_scores(services: List[str], config: Dict) -> Dict[str, int]:
        """Calculate WAF pillar scores based on services"""
        scores = {
            'operational_excellence': 50,
            'security': 50,
            'reliability': 50,
            'performance': 50,
            'cost': 70,
            'sustainability': 60,
        }
        
        # Score boosters based on services
        if 'cloudwatch' in services:
            scores['operational_excellence'] += 15
        if 'cloudtrail' in services:
            scores['operational_excellence'] += 10
            scores['security'] += 10
        if 'config' in services:
            scores['operational_excellence'] += 10
        
        if 'waf' in services:
            scores['security'] += 15
        if 'shield' in services:
            scores['security'] += 10
        if 'kms' in services:
            scores['security'] += 10
        if 'guardduty' in services:
            scores['security'] += 10
        if 'cognito' in services:
            scores['security'] += 10
        
        if 'aurora' in services or 'rds' in services:
            scores['reliability'] += 15
        if config.get('scale') in ['large', 'massive']:
            scores['reliability'] += 10
        
        if 'elasticache' in services:
            scores['performance'] += 15
        if 'cloudfront' in services:
            scores['performance'] += 15
        
        if 'lambda' in services:
            scores['cost'] += 10
            scores['sustainability'] += 15
        
        # Cap at 100
        return {k: min(v, 100) for k, v in scores.items()}
    
    @staticmethod
    def _render_export(config: Dict):
        """Render export options"""
        st.markdown("### 📥 Export Architecture")
        
        services = config.get('recommended_services', [])
        if not services:
            st.warning("Please configure your architecture first")
            return
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.markdown("#### ☁️ CloudFormation")
            cf_template = ArchitectureDesignerRevamped._generate_cloudformation(services, config)
            st.download_button(
                "Download CloudFormation",
                data=cf_template,
                file_name="architecture.yaml",
                mime="text/yaml",
                use_container_width=True
            )
        
        with col2:
            st.markdown("#### 🏗️ Terraform")
            tf_template = ArchitectureDesignerRevamped._generate_terraform(services, config)
            st.download_button(
                "Download Terraform",
                data=tf_template,
                file_name="architecture.tf",
                mime="text/plain",
                use_container_width=True
            )
        
        with col3:
            st.markdown("#### 📋 JSON Export")
            json_export = json.dumps({
                'services': services,
                'config': {k: v for k, v in config.items() if k != 'recommended_services'},
                'waf_scores': ArchitectureDesignerRevamped._calculate_waf_scores(services, config),
                'generated_at': datetime.now().isoformat()
            }, indent=2)
            st.download_button(
                "Download JSON",
                data=json_export,
                file_name="architecture.json",
                mime="application/json",
                use_container_width=True
            )
    
    @staticmethod
    def _generate_cloudformation(services: List[str], config: Dict) -> str:
        """Generate CloudFormation template"""
        template = f"""AWSTemplateFormatVersion: '2010-09-09'
Description: Architecture generated by WAF Scanner - {datetime.now().strftime("%Y-%m-%d")}

# Scale: {config.get('scale', 'medium')}
# Compliance: {', '.join(config.get('compliance', [])) or 'None'}

Parameters:
  Environment:
    Type: String
    Default: production
    AllowedValues:
      - development
      - staging
      - production

Resources:
"""
        
        # Add resources based on services
        if 'vpc' in services:
            template += """
  VPC:
    Type: AWS::EC2::VPC
    Properties:
      CidrBlock: 10.0.0.0/16
      EnableDnsHostnames: true
      EnableDnsSupport: true
      Tags:
        - Key: Name
          Value: !Sub ${AWS::StackName}-vpc
"""
        
        if 'alb' in services:
            template += """
  ApplicationLoadBalancer:
    Type: AWS::ElasticLoadBalancingV2::LoadBalancer
    Properties:
      Name: !Sub ${AWS::StackName}-alb
      Scheme: internet-facing
      Type: application
      Subnets:
        - !Ref PublicSubnet1
        - !Ref PublicSubnet2
"""
        
        if 'rds' in services or 'aurora' in services:
            template += """
  Database:
    Type: AWS::RDS::DBInstance
    Properties:
      DBInstanceClass: db.t3.medium
      Engine: postgres
      EngineVersion: '14'
      MasterUsername: admin
      MasterUserPassword: !Ref DBPassword
      MultiAZ: true
      StorageEncrypted: true
"""
        
        template += """
Outputs:
  StackName:
    Description: Stack Name
    Value: !Ref AWS::StackName
"""
        
        return template
    
    @staticmethod
    def _generate_terraform(services: List[str], config: Dict) -> str:
        """Generate Terraform configuration"""
        template = f"""# Terraform configuration generated by WAF Scanner
# Generated: {datetime.now().strftime("%Y-%m-%d")}
# Scale: {config.get('scale', 'medium')}
# Compliance: {', '.join(config.get('compliance', [])) or 'None'}

terraform {{
  required_providers {{
    aws = {{
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }}
  }}
}}

provider "aws" {{
  region = var.aws_region
}}

variable "aws_region" {{
  description = "AWS region"
  default     = "us-east-1"
}}

variable "environment" {{
  description = "Environment name"
  default     = "production"
}}
"""
        
        if 'vpc' in services:
            template += """
# VPC
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"

  name = "${var.environment}-vpc"
  cidr = "10.0.0.0/16"

  azs             = ["${var.aws_region}a", "${var.aws_region}b", "${var.aws_region}c"]
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnets  = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]

  enable_nat_gateway = true
  single_nat_gateway = false
}
"""
        
        if 'alb' in services:
            template += """
# Application Load Balancer
resource "aws_lb" "main" {
  name               = "${var.environment}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = module.vpc.public_subnets
}
"""
        
        if 'rds' in services or 'aurora' in services:
            template += """
# RDS Database
module "rds" {
  source  = "terraform-aws-modules/rds/aws"
  version = "~> 6.0"

  identifier = "${var.environment}-db"
  
  engine               = "postgres"
  engine_version       = "14"
  instance_class       = "db.t3.medium"
  allocated_storage    = 100
  
  multi_az             = true
  storage_encrypted    = true
  
  vpc_security_group_ids = [aws_security_group.rds.id]
  subnet_ids             = module.vpc.private_subnets
}
"""
        
        return template
    
    # ========================================================================
    # MIGRATION ASSESSMENT - FULL IMPLEMENTATION
    # ========================================================================
    
    @staticmethod
    def _render_migration():
        """Render comprehensive migration planning tool"""
        st.markdown("## 🔄 Migration Planning & Assessment")
        st.markdown("Plan your migration from on-premises or other cloud to AWS")
        
        # Initialize migration session state
        if 'migration_config' not in st.session_state:
            st.session_state.migration_config = {
                'applications': [],
                'source_environment': 'on_premises',
                'timeline_months': 12,
                'budget': 100000,
                'strategy_preferences': {}
            }
        
        mig_config = st.session_state.migration_config
        
        # Migration workflow tabs
        tabs = st.tabs([
            "📋 Discovery",
            "🔍 Assessment",
            "🎯 Strategy (6 Rs)",
            "📊 TCO Analysis",
            "📅 Migration Plan",
            "📐 Target Architecture"
        ])
        
        with tabs[0]:
            ArchitectureDesignerRevamped._render_migration_discovery(mig_config)
        
        with tabs[1]:
            ArchitectureDesignerRevamped._render_migration_assessment(mig_config)
        
        with tabs[2]:
            ArchitectureDesignerRevamped._render_migration_strategy(mig_config)
        
        with tabs[3]:
            ArchitectureDesignerRevamped._render_tco_analysis(mig_config)
        
        with tabs[4]:
            ArchitectureDesignerRevamped._render_migration_plan(mig_config)
        
        with tabs[5]:
            ArchitectureDesignerRevamped._render_target_architecture(mig_config)
    
    @staticmethod
    def _render_migration_discovery(config: Dict):
        """Discovery phase - inventory applications"""
        st.markdown("### 📋 Application Discovery")
        st.markdown("Add applications and workloads to assess for migration")
        
        # Source environment
        col1, col2 = st.columns(2)
        with col1:
            config['source_environment'] = st.selectbox(
                "Source Environment",
                ['on_premises', 'azure', 'gcp', 'other_cloud', 'colocation'],
                format_func=lambda x: {
                    'on_premises': '🏢 On-Premises Data Center',
                    'azure': '☁️ Microsoft Azure',
                    'gcp': '☁️ Google Cloud Platform',
                    'other_cloud': '☁️ Other Cloud Provider',
                    'colocation': '🏗️ Colocation Facility'
                }.get(x, x)
            )
        
        with col2:
            config['timeline_months'] = st.slider(
                "Migration Timeline (months)",
                min_value=3,
                max_value=36,
                value=config.get('timeline_months', 12)
            )
        
        st.markdown("---")
        st.markdown("### ➕ Add Applications")
        
        # Application input form
        with st.expander("Add New Application", expanded=True):
            col1, col2, col3 = st.columns(3)
            
            with col1:
                app_name = st.text_input("Application Name", key="mig_app_name")
                app_type = st.selectbox(
                    "Application Type",
                    ['web_app', 'api_service', 'database', 'batch_job', 
                     'legacy_app', 'commercial_software', 'custom_app'],
                    format_func=lambda x: x.replace('_', ' ').title()
                )
                app_criticality = st.selectbox(
                    "Business Criticality",
                    ['mission_critical', 'business_critical', 'business_operational', 'office_productivity'],
                    format_func=lambda x: x.replace('_', ' ').title()
                )
            
            with col2:
                app_users = st.number_input("Number of Users", min_value=1, value=100)
                app_data_gb = st.number_input("Data Size (GB)", min_value=1, value=100)
                app_tech_stack = st.multiselect(
                    "Technology Stack",
                    ['.NET', 'Java', 'Python', 'Node.js', 'PHP', 'Ruby', 
                     'SQL Server', 'Oracle', 'MySQL', 'PostgreSQL', 'MongoDB',
                     'Windows Server', 'Linux', 'VMware', 'Containers']
                )
            
            with col3:
                app_dependencies = st.text_area(
                    "Dependencies (one per line)",
                    placeholder="Active Directory\nFile Server\nLDAP",
                    height=100
                )
                app_compliance = st.multiselect(
                    "Compliance Requirements",
                    ['HIPAA', 'PCI-DSS', 'SOC2', 'GDPR', 'FedRAMP', 'None']
                )
            
            if st.button("➕ Add Application", type="primary"):
                if app_name:
                    new_app = {
                        'name': app_name,
                        'type': app_type,
                        'criticality': app_criticality,
                        'users': app_users,
                        'data_gb': app_data_gb,
                        'tech_stack': app_tech_stack,
                        'dependencies': [d.strip() for d in app_dependencies.split('\n') if d.strip()],
                        'compliance': app_compliance,
                        'recommended_strategy': None,
                        'complexity_score': 0
                    }
                    config['applications'].append(new_app)
                    st.session_state.migration_config = config
                    st.success(f"✅ Added {app_name}")
                    st.rerun()
        
        # Show application inventory
        if config.get('applications'):
            st.markdown("---")
            st.markdown(f"### 📦 Application Inventory ({len(config['applications'])} apps)")
            
            for i, app in enumerate(config['applications']):
                with st.expander(f"**{app['name']}** - {app['type'].replace('_', ' ').title()}"):
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.markdown(f"**Criticality:** {app['criticality'].replace('_', ' ').title()}")
                        st.markdown(f"**Users:** {app['users']:,}")
                    with col2:
                        st.markdown(f"**Data:** {app['data_gb']:,} GB")
                        st.markdown(f"**Tech:** {', '.join(app['tech_stack'][:3])}")
                    with col3:
                        st.markdown(f"**Compliance:** {', '.join(app['compliance']) or 'None'}")
                        if st.button("🗑️ Remove", key=f"remove_app_{i}"):
                            config['applications'].pop(i)
                            st.rerun()
    
    @staticmethod
    def _render_migration_assessment(config: Dict):
        """Assessment phase - analyze readiness"""
        st.markdown("### 🔍 Migration Readiness Assessment")
        
        if not config.get('applications'):
            st.warning("👆 Please add applications in the Discovery tab first")
            return
        
        apps = config['applications']
        
        # Calculate readiness scores
        st.markdown("#### 📊 Readiness Scores")
        
        total_score = 0
        for i, app in enumerate(apps):
            # Calculate complexity score
            complexity = 0
            
            # Tech stack complexity
            legacy_tech = ['.NET', 'Windows Server', 'SQL Server', 'Oracle']
            modern_tech = ['Containers', 'Python', 'Node.js', 'PostgreSQL', 'Linux']
            
            for tech in app.get('tech_stack', []):
                if tech in legacy_tech:
                    complexity += 2
                elif tech in modern_tech:
                    complexity -= 1
            
            # Data size complexity
            if app.get('data_gb', 0) > 1000:
                complexity += 3
            elif app.get('data_gb', 0) > 500:
                complexity += 2
            elif app.get('data_gb', 0) > 100:
                complexity += 1
            
            # Dependency complexity
            complexity += len(app.get('dependencies', [])) * 0.5
            
            # Compliance complexity
            if 'HIPAA' in app.get('compliance', []) or 'PCI-DSS' in app.get('compliance', []):
                complexity += 2
            
            # Normalize to 0-100 (inverse for readiness)
            readiness = max(0, min(100, 100 - (complexity * 10)))
            app['complexity_score'] = complexity
            app['readiness_score'] = readiness
            total_score += readiness
            
            # Display
            col1, col2, col3, col4 = st.columns([3, 2, 2, 2])
            with col1:
                st.markdown(f"**{app['name']}**")
            with col2:
                color = "#4CAF50" if readiness >= 70 else "#FF9800" if readiness >= 40 else "#F44336"
                st.markdown(f"<span style='color: {color}; font-weight: bold;'>Readiness: {readiness:.0f}%</span>", unsafe_allow_html=True)
            with col3:
                st.markdown(f"Complexity: {complexity:.1f}")
            with col4:
                # Recommend strategy
                if readiness >= 70:
                    strategy = "Rehost"
                elif readiness >= 50:
                    strategy = "Replatform"
                elif readiness >= 30:
                    strategy = "Refactor"
                else:
                    strategy = "Repurchase"
                app['recommended_strategy'] = strategy
                st.markdown(f"Suggested: **{strategy}**")
        
        avg_readiness = total_score / len(apps) if apps else 0
        
        st.markdown("---")
        
        # Summary metrics
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Applications", len(apps))
        with col2:
            st.metric("Avg Readiness", f"{avg_readiness:.0f}%")
        with col3:
            total_data = sum(a.get('data_gb', 0) for a in apps)
            st.metric("Total Data", f"{total_data:,} GB")
        with col4:
            total_users = sum(a.get('users', 0) for a in apps)
            st.metric("Total Users", f"{total_users:,}")
        
        # Readiness distribution chart
        st.markdown("#### 📈 Readiness Distribution")
        
        high_ready = len([a for a in apps if a.get('readiness_score', 0) >= 70])
        med_ready = len([a for a in apps if 40 <= a.get('readiness_score', 0) < 70])
        low_ready = len([a for a in apps if a.get('readiness_score', 0) < 40])
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.markdown(f"""
            <div style="background: #E8F5E9; padding: 15px; border-radius: 8px; text-align: center;">
                <div style="font-size: 24px; color: #4CAF50; font-weight: bold;">{high_ready}</div>
                <div style="font-size: 12px; color: #666;">🟢 High Readiness (70%+)</div>
                <div style="font-size: 10px; color: #888;">Ready for Rehost</div>
            </div>
            """, unsafe_allow_html=True)
        with col2:
            st.markdown(f"""
            <div style="background: #FFF3E0; padding: 15px; border-radius: 8px; text-align: center;">
                <div style="font-size: 24px; color: #FF9800; font-weight: bold;">{med_ready}</div>
                <div style="font-size: 12px; color: #666;">🟡 Medium Readiness (40-70%)</div>
                <div style="font-size: 10px; color: #888;">Consider Replatform</div>
            </div>
            """, unsafe_allow_html=True)
        with col3:
            st.markdown(f"""
            <div style="background: #FFEBEE; padding: 15px; border-radius: 8px; text-align: center;">
                <div style="font-size: 24px; color: #F44336; font-weight: bold;">{low_ready}</div>
                <div style="font-size: 12px; color: #666;">🔴 Low Readiness (&lt;40%)</div>
                <div style="font-size: 10px; color: #888;">Needs Refactor/Repurchase</div>
            </div>
            """, unsafe_allow_html=True)
    
    @staticmethod
    def _render_migration_strategy(config: Dict):
        """Strategy selection - 6 Rs"""
        st.markdown("### 🎯 Migration Strategy (The 6 Rs)")
        
        # 6 Rs explanation
        strategies = {
            'rehost': {
                'name': 'Rehost',
                'subtitle': 'Lift & Shift',
                'icon': '🏗️',
                'color': '#4CAF50',
                'description': 'Move applications without changes to cloud infrastructure',
                'when_to_use': [
                    'Quick migration needed',
                    'Application works well as-is',
                    'Limited cloud expertise',
                    'Legacy apps with no source code'
                ],
                'aws_services': ['EC2', 'EBS', 'VPC', 'Application Migration Service'],
                'effort': 'Low',
                'cost_savings': '20-30%'
            },
            'replatform': {
                'name': 'Replatform',
                'subtitle': 'Lift & Reshape',
                'icon': '🔧',
                'color': '#2196F3',
                'description': 'Make targeted optimizations without changing core architecture',
                'when_to_use': [
                    'Want managed services benefits',
                    'Database migration to RDS',
                    'Containerization opportunities',
                    'Moderate cloud expertise'
                ],
                'aws_services': ['RDS', 'ElastiCache', 'ECS', 'Elastic Beanstalk'],
                'effort': 'Medium',
                'cost_savings': '30-50%'
            },
            'repurchase': {
                'name': 'Repurchase',
                'subtitle': 'Drop & Shop',
                'icon': '🛒',
                'color': '#9C27B0',
                'description': 'Replace with SaaS or cloud-native alternative',
                'when_to_use': [
                    'Commercial software with SaaS alternative',
                    'High maintenance legacy system',
                    'Standard business function (CRM, HR)',
                    'Cost of customization exceeds benefit'
                ],
                'aws_services': ['AWS Marketplace', 'SaaS integrations'],
                'effort': 'Medium',
                'cost_savings': '40-60%'
            },
            'refactor': {
                'name': 'Refactor',
                'subtitle': 'Re-architect',
                'icon': '🏛️',
                'color': '#FF9800',
                'description': 'Re-architect to cloud-native using microservices, serverless',
                'when_to_use': [
                    'Strong business case for modernization',
                    'Need for agility and scale',
                    'Technical debt reduction',
                    'Long-term strategic application'
                ],
                'aws_services': ['Lambda', 'EKS', 'API Gateway', 'DynamoDB', 'Step Functions'],
                'effort': 'High',
                'cost_savings': '50-70%'
            },
            'retire': {
                'name': 'Retire',
                'subtitle': 'Decommission',
                'icon': '🗑️',
                'color': '#607D8B',
                'description': 'Identify and turn off applications no longer needed',
                'when_to_use': [
                    'Duplicate functionality',
                    'No active users',
                    'End-of-life applications',
                    'Consolidation opportunities'
                ],
                'aws_services': ['N/A - Decommission'],
                'effort': 'Low',
                'cost_savings': '100%'
            },
            'retain': {
                'name': 'Retain',
                'subtitle': 'Keep As-Is',
                'icon': '🔒',
                'color': '#795548',
                'description': 'Keep on-premises for now, migrate later',
                'when_to_use': [
                    'Recent major investment',
                    'Regulatory requirements',
                    'Unresolved dependencies',
                    'Not ready for cloud'
                ],
                'aws_services': ['AWS Outposts', 'Direct Connect (hybrid)'],
                'effort': 'None',
                'cost_savings': '0%'
            }
        }
        
        # Display strategy cards
        cols = st.columns(3)
        for i, (key, strategy) in enumerate(strategies.items()):
            with cols[i % 3]:
                st.markdown(f"""
                <div style="background: white; border: 2px solid {strategy['color']}; border-radius: 10px; padding: 15px; margin-bottom: 15px; min-height: 280px;">
                    <div style="font-size: 24px; text-align: center;">{strategy['icon']}</div>
                    <h4 style="text-align: center; color: {strategy['color']}; margin: 10px 0 5px 0;">{strategy['name']}</h4>
                    <p style="text-align: center; font-size: 12px; color: #666; margin-bottom: 10px;">{strategy['subtitle']}</p>
                    <p style="font-size: 11px; color: #333;">{strategy['description']}</p>
                    <p style="font-size: 10px; margin-top: 10px;"><strong>Effort:</strong> {strategy['effort']} | <strong>Savings:</strong> {strategy['cost_savings']}</p>
                </div>
                """, unsafe_allow_html=True)
        
        # Strategy assignment for applications
        if config.get('applications'):
            st.markdown("---")
            st.markdown("### 📝 Assign Strategy to Applications")
            
            for i, app in enumerate(config['applications']):
                col1, col2, col3 = st.columns([3, 2, 2])
                with col1:
                    st.markdown(f"**{app['name']}**")
                    st.caption(f"Recommended: {app.get('recommended_strategy', 'Assess')}")
                with col2:
                    strategy = st.selectbox(
                        "Strategy",
                        list(strategies.keys()),
                        index=list(strategies.keys()).index(app.get('selected_strategy', app.get('recommended_strategy', 'rehost').lower())),
                        format_func=lambda x: f"{strategies[x]['icon']} {strategies[x]['name']}",
                        key=f"strategy_{i}"
                    )
                    app['selected_strategy'] = strategy
                with col3:
                    st.markdown(f"**Effort:** {strategies[strategy]['effort']}")
                    st.markdown(f"**Savings:** {strategies[strategy]['cost_savings']}")
    
    @staticmethod
    def _render_tco_analysis(config: Dict):
        """Total Cost of Ownership analysis"""
        st.markdown("### 📊 TCO Analysis")
        
        if not config.get('applications'):
            st.warning("👆 Please add applications in the Discovery tab first")
            return
        
        st.markdown("#### 💰 Current Infrastructure Costs (Annual)")
        
        col1, col2 = st.columns(2)
        
        with col1:
            hardware_cost = st.number_input("Hardware/Server Costs ($)", min_value=0, value=100000)
            software_cost = st.number_input("Software Licenses ($)", min_value=0, value=50000)
            datacenter_cost = st.number_input("Data Center/Facilities ($)", min_value=0, value=30000)
        
        with col2:
            network_cost = st.number_input("Network/Bandwidth ($)", min_value=0, value=20000)
            staff_cost = st.number_input("IT Staff (infrastructure) ($)", min_value=0, value=150000)
            other_cost = st.number_input("Other Costs ($)", min_value=0, value=10000)
        
        current_total = hardware_cost + software_cost + datacenter_cost + network_cost + staff_cost + other_cost
        
        st.markdown("---")
        
        # Calculate AWS estimated costs
        apps = config.get('applications', [])
        total_data_gb = sum(a.get('data_gb', 0) for a in apps)
        total_users = sum(a.get('users', 0) for a in apps)
        
        # Simplified AWS cost estimation
        ec2_cost = len(apps) * 200 * 12  # Average EC2 per app per month
        rds_cost = len([a for a in apps if 'database' in a.get('type', '')]) * 150 * 12
        storage_cost = total_data_gb * 0.023 * 12  # S3 standard
        transfer_cost = total_users * 0.5 * 12  # Estimated data transfer
        support_cost = (ec2_cost + rds_cost + storage_cost + transfer_cost) * 0.1  # 10% support
        
        aws_total = ec2_cost + rds_cost + storage_cost + transfer_cost + support_cost
        
        # Staff savings (typically 30-50% reduction)
        aws_staff_cost = staff_cost * 0.6
        
        aws_total_with_staff = aws_total + aws_staff_cost
        
        savings = current_total - aws_total_with_staff
        savings_pct = (savings / current_total * 100) if current_total > 0 else 0
        
        # Display comparison
        st.markdown("#### 📈 Cost Comparison (Annual)")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.markdown("""
            <div style="background: #FFEBEE; padding: 20px; border-radius: 10px; text-align: center;">
                <div style="font-size: 12px; color: #666;">Current (On-Premises)</div>
                <div style="font-size: 28px; font-weight: bold; color: #D32F2F;">${:,.0f}</div>
                <div style="font-size: 10px; color: #888;">per year</div>
            </div>
            """.format(current_total), unsafe_allow_html=True)
        
        with col2:
            st.markdown("""
            <div style="background: #E8F5E9; padding: 20px; border-radius: 10px; text-align: center;">
                <div style="font-size: 12px; color: #666;">Estimated (AWS)</div>
                <div style="font-size: 28px; font-weight: bold; color: #388E3C;">${:,.0f}</div>
                <div style="font-size: 10px; color: #888;">per year</div>
            </div>
            """.format(aws_total_with_staff), unsafe_allow_html=True)
        
        with col3:
            color = "#4CAF50" if savings > 0 else "#F44336"
            st.markdown(f"""
            <div style="background: #E3F2FD; padding: 20px; border-radius: 10px; text-align: center;">
                <div style="font-size: 12px; color: #666;">Potential Savings</div>
                <div style="font-size: 28px; font-weight: bold; color: {color};">${savings:,.0f}</div>
                <div style="font-size: 10px; color: #888;">{savings_pct:.1f}% reduction</div>
            </div>
            """, unsafe_allow_html=True)
        
        # Cost breakdown
        st.markdown("---")
        st.markdown("#### 📋 AWS Cost Breakdown (Estimated)")
        
        cost_breakdown = {
            'EC2 Compute': ec2_cost,
            'RDS Databases': rds_cost,
            'S3 Storage': storage_cost,
            'Data Transfer': transfer_cost,
            'Support': support_cost,
            'Reduced IT Staff': aws_staff_cost
        }
        
        for item, cost in cost_breakdown.items():
            col1, col2 = st.columns([3, 1])
            with col1:
                st.markdown(f"**{item}**")
            with col2:
                st.markdown(f"${cost:,.0f}")
    
    @staticmethod
    def _render_migration_plan(config: Dict):
        """Migration timeline and plan"""
        st.markdown("### 📅 Migration Plan")
        
        if not config.get('applications'):
            st.warning("👆 Please add applications in the Discovery tab first")
            return
        
        apps = config.get('applications', [])
        timeline_months = config.get('timeline_months', 12)
        
        # Sort apps by readiness (easiest first)
        sorted_apps = sorted(apps, key=lambda x: x.get('readiness_score', 0), reverse=True)
        
        st.markdown(f"#### 📆 {timeline_months}-Month Migration Timeline")
        
        # Create waves
        apps_per_wave = max(1, len(sorted_apps) // 4)  # 4 waves
        waves = []
        for i in range(0, len(sorted_apps), apps_per_wave):
            waves.append(sorted_apps[i:i + apps_per_wave])
        
        wave_names = ['🌊 Wave 1 (Quick Wins)', '🌊 Wave 2 (Core Apps)', '🌊 Wave 3 (Complex Apps)', '🌊 Wave 4 (Final Migration)']
        wave_months = [
            (1, timeline_months // 4),
            (timeline_months // 4 + 1, timeline_months // 2),
            (timeline_months // 2 + 1, 3 * timeline_months // 4),
            (3 * timeline_months // 4 + 1, timeline_months)
        ]
        
        for i, wave in enumerate(waves):
            if not wave:
                continue
            
            start, end = wave_months[i] if i < len(wave_months) else (1, timeline_months)
            
            st.markdown(f"""
            <div style="background: white; border-left: 4px solid #2196F3; padding: 15px; margin: 10px 0; border-radius: 0 8px 8px 0;">
                <h4 style="color: #1976D2; margin: 0;">{wave_names[i] if i < len(wave_names) else f'Wave {i+1}'}</h4>
                <p style="color: #666; font-size: 12px; margin: 5px 0;">Months {start}-{end}</p>
                <ul style="margin: 10px 0; padding-left: 20px;">
            """, unsafe_allow_html=True)
            
            for app in wave:
                strategy = app.get('selected_strategy', app.get('recommended_strategy', 'rehost')).title()
                st.markdown(f"- **{app['name']}** ({strategy}) - {app.get('data_gb', 0)} GB")
            
            st.markdown("</ul></div>", unsafe_allow_html=True)
        
        # Migration checklist
        st.markdown("---")
        st.markdown("#### ✅ Pre-Migration Checklist")
        
        checklist = [
            "AWS Account setup and organization structure",
            "Landing Zone / Control Tower configured",
            "Network connectivity (Direct Connect / VPN)",
            "Identity federation (SSO / Active Directory)",
            "Security baseline (GuardDuty, Security Hub)",
            "Backup and DR strategy defined",
            "Monitoring and logging (CloudWatch, CloudTrail)",
            "Cost management (Budgets, Cost Explorer)",
            "Training for operations team",
            "Runbook and playbook documentation"
        ]
        
        cols = st.columns(2)
        for i, item in enumerate(checklist):
            with cols[i % 2]:
                st.checkbox(item, key=f"checklist_{i}")
    
    @staticmethod
    def _render_target_architecture(config: Dict):
        """Target AWS architecture visualization"""
        st.markdown("### 📐 Target Architecture")
        
        if not config.get('applications'):
            st.warning("👆 Please add applications in the Discovery tab first")
            return
        
        apps = config.get('applications', [])
        
        # Determine services based on strategies
        services = ['vpc', 'cloudwatch', 'cloudtrail', 'iam']
        
        strategies_used = [a.get('selected_strategy', a.get('recommended_strategy', 'rehost')).lower() for a in apps]
        
        if 'rehost' in strategies_used:
            services.extend(['ec2', 'ebs', 'alb'])
        if 'replatform' in strategies_used:
            services.extend(['rds', 'elasticache', 'ecs'])
        if 'refactor' in strategies_used:
            services.extend(['lambda', 'api_gateway', 'dynamodb', 'eks', 'sqs'])
        
        # Add security services
        compliance = []
        for app in apps:
            compliance.extend(app.get('compliance', []))
        
        if 'HIPAA' in compliance or 'PCI-DSS' in compliance:
            services.extend(['waf', 'shield', 'kms', 'secrets_manager', 'guardduty'])
        
        services = list(dict.fromkeys(services))  # Dedupe
        
        # Generate diagram
        diagram_html = ArchitectureDiagramGenerator.generate_diagram(
            services,
            f"Target Architecture - {len(apps)} Applications",
            config
        )
        
        components.html(diagram_html, height=700, scrolling=True)
        
        st.download_button(
            "📥 Download Target Architecture",
            data=diagram_html,
            file_name="target_architecture.html",
            mime="text/html"
        )
    
    # ========================================================================
    # PERFORMANCE OPTIMIZATION - FULL IMPLEMENTATION
    # ========================================================================
    
    @staticmethod
    def _render_performance():
        """Render comprehensive performance optimization tool"""
        st.markdown("## ⚡ Performance Optimization")
        st.markdown("Analyze and optimize your AWS architecture for performance")
        
        # Initialize performance session state
        if 'perf_config' not in st.session_state:
            st.session_state.perf_config = {
                'workloads': [],
                'current_latency_ms': 500,
                'target_latency_ms': 100,
                'current_throughput': 1000,
                'target_throughput': 10000
            }
        
        perf_config = st.session_state.perf_config
        
        # Performance tabs
        tabs = st.tabs([
            "📊 Current State",
            "🎯 Targets & Analysis",
            "⚡ Optimization Recommendations",
            "🔧 Implementation Plan",
            "📐 Optimized Architecture"
        ])
        
        with tabs[0]:
            ArchitectureDesignerRevamped._render_perf_current_state(perf_config)
        
        with tabs[1]:
            ArchitectureDesignerRevamped._render_perf_analysis(perf_config)
        
        with tabs[2]:
            ArchitectureDesignerRevamped._render_perf_recommendations(perf_config)
        
        with tabs[3]:
            ArchitectureDesignerRevamped._render_perf_implementation(perf_config)
        
        with tabs[4]:
            ArchitectureDesignerRevamped._render_perf_architecture(perf_config)
    
    @staticmethod
    def _render_perf_current_state(config: Dict):
        """Current performance state assessment"""
        st.markdown("### 📊 Current Performance State")
        
        st.markdown("#### 🏷️ Workload Information")
        
        col1, col2 = st.columns(2)
        
        with col1:
            workload_type = st.selectbox(
                "Primary Workload Type",
                ['web_application', 'api_backend', 'data_processing', 'real_time_analytics', 
                 'e_commerce', 'gaming', 'media_streaming'],
                format_func=lambda x: x.replace('_', ' ').title()
            )
            config['workload_type'] = workload_type
            
            user_location = st.multiselect(
                "User Locations",
                ['North America', 'Europe', 'Asia Pacific', 'South America', 'Middle East', 'Africa'],
                default=['North America']
            )
            config['user_locations'] = user_location
        
        with col2:
            peak_users = st.number_input("Peak Concurrent Users", min_value=1, value=1000)
            config['peak_users'] = peak_users
            
            requests_per_sec = st.number_input("Requests per Second (peak)", min_value=1, value=500)
            config['requests_per_sec'] = requests_per_sec
        
        st.markdown("---")
        st.markdown("#### 📈 Current Performance Metrics")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            config['current_latency_ms'] = st.number_input(
                "Current Latency (ms)",
                min_value=1,
                value=config.get('current_latency_ms', 500)
            )
            config['current_p99_latency'] = st.number_input(
                "P99 Latency (ms)",
                min_value=1,
                value=config.get('current_p99_latency', 2000)
            )
        
        with col2:
            config['current_throughput'] = st.number_input(
                "Current Throughput (req/s)",
                min_value=1,
                value=config.get('current_throughput', 1000)
            )
            config['current_error_rate'] = st.number_input(
                "Error Rate (%)",
                min_value=0.0,
                max_value=100.0,
                value=config.get('current_error_rate', 1.0)
            )
        
        with col3:
            config['current_cpu_util'] = st.slider(
                "Avg CPU Utilization (%)",
                min_value=0,
                max_value=100,
                value=config.get('current_cpu_util', 70)
            )
            config['current_mem_util'] = st.slider(
                "Avg Memory Utilization (%)",
                min_value=0,
                max_value=100,
                value=config.get('current_mem_util', 60)
            )
        
        st.markdown("---")
        st.markdown("#### 🏗️ Current Architecture")
        
        current_services = st.multiselect(
            "Current AWS Services in Use",
            ['ec2', 'alb', 'rds', 'aurora', 'dynamodb', 'elasticache', 
             's3', 'cloudfront', 'lambda', 'ecs', 'eks', 'api_gateway',
             'sqs', 'sns', 'kinesis'],
            default=['ec2', 'alb', 'rds'],
            format_func=lambda x: ArchitectureDiagramGenerator.SERVICE_INFO.get(x, {}).get('name', x)
        )
        config['current_services'] = current_services
        
        # Performance health indicator
        latency_health = "🟢" if config['current_latency_ms'] < 200 else "🟡" if config['current_latency_ms'] < 500 else "🔴"
        throughput_health = "🟢" if config['current_throughput'] > 5000 else "🟡" if config['current_throughput'] > 1000 else "🔴"
        error_health = "🟢" if config['current_error_rate'] < 0.5 else "🟡" if config['current_error_rate'] < 2 else "🔴"
        
        st.markdown("---")
        st.markdown("#### 🏥 Performance Health")
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.markdown(f"{latency_health} **Latency:** {config['current_latency_ms']}ms")
        with col2:
            st.markdown(f"{throughput_health} **Throughput:** {config['current_throughput']} req/s")
        with col3:
            st.markdown(f"{error_health} **Error Rate:** {config['current_error_rate']}%")
    
    @staticmethod
    def _render_perf_analysis(config: Dict):
        """Performance targets and gap analysis"""
        st.markdown("### 🎯 Performance Targets & Gap Analysis")
        
        st.markdown("#### 🎯 Define Performance Targets")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            config['target_latency_ms'] = st.number_input(
                "Target Latency (ms)",
                min_value=1,
                value=config.get('target_latency_ms', 100)
            )
            config['target_p99_latency'] = st.number_input(
                "Target P99 Latency (ms)",
                min_value=1,
                value=config.get('target_p99_latency', 500)
            )
        
        with col2:
            config['target_throughput'] = st.number_input(
                "Target Throughput (req/s)",
                min_value=1,
                value=config.get('target_throughput', 10000)
            )
            config['target_error_rate'] = st.number_input(
                "Target Error Rate (%)",
                min_value=0.0,
                max_value=100.0,
                value=config.get('target_error_rate', 0.1)
            )
        
        with col3:
            config['target_availability'] = st.selectbox(
                "Target Availability",
                ['99%', '99.9%', '99.95%', '99.99%'],
                index=1
            )
        
        st.markdown("---")
        st.markdown("#### 📊 Gap Analysis")
        
        # Calculate gaps
        latency_gap = config.get('current_latency_ms', 500) - config.get('target_latency_ms', 100)
        latency_improvement = (latency_gap / config.get('current_latency_ms', 500) * 100) if config.get('current_latency_ms', 500) > 0 else 0
        
        throughput_gap = config.get('target_throughput', 10000) - config.get('current_throughput', 1000)
        throughput_improvement = (throughput_gap / config.get('current_throughput', 1000) * 100) if config.get('current_throughput', 1000) > 0 else 0
        
        error_gap = config.get('current_error_rate', 1.0) - config.get('target_error_rate', 0.1)
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            improvement_color = "#4CAF50" if latency_improvement > 0 else "#F44336"
            st.markdown(f"""
            <div style="background: white; border: 2px solid {improvement_color}; border-radius: 10px; padding: 20px; text-align: center;">
                <div style="font-size: 14px; color: #666;">Latency Improvement Needed</div>
                <div style="font-size: 32px; font-weight: bold; color: {improvement_color};">{latency_improvement:.0f}%</div>
                <div style="font-size: 12px; color: #888;">{config.get('current_latency_ms', 500)}ms → {config.get('target_latency_ms', 100)}ms</div>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            improvement_color = "#4CAF50" if throughput_improvement > 0 else "#F44336"
            st.markdown(f"""
            <div style="background: white; border: 2px solid {improvement_color}; border-radius: 10px; padding: 20px; text-align: center;">
                <div style="font-size: 14px; color: #666;">Throughput Increase Needed</div>
                <div style="font-size: 32px; font-weight: bold; color: {improvement_color};">{throughput_improvement:.0f}%</div>
                <div style="font-size: 12px; color: #888;">{config.get('current_throughput', 1000)} → {config.get('target_throughput', 10000)} req/s</div>
            </div>
            """, unsafe_allow_html=True)
        
        with col3:
            improvement_color = "#4CAF50" if error_gap > 0 else "#F44336"
            st.markdown(f"""
            <div style="background: white; border: 2px solid {improvement_color}; border-radius: 10px; padding: 20px; text-align: center;">
                <div style="font-size: 14px; color: #666;">Error Rate Reduction Needed</div>
                <div style="font-size: 32px; font-weight: bold; color: {improvement_color};">{error_gap:.2f}%</div>
                <div style="font-size: 12px; color: #888;">{config.get('current_error_rate', 1.0)}% → {config.get('target_error_rate', 0.1)}%</div>
            </div>
            """, unsafe_allow_html=True)
        
        # Bottleneck identification
        st.markdown("---")
        st.markdown("#### 🔍 Potential Bottlenecks Identified")
        
        bottlenecks = []
        
        if config.get('current_latency_ms', 500) > 200:
            if 'elasticache' not in config.get('current_services', []):
                bottlenecks.append(("🔴", "No caching layer", "Add ElastiCache for database query caching"))
            if 'cloudfront' not in config.get('current_services', []):
                bottlenecks.append(("🟡", "No CDN", "Add CloudFront for static content and edge caching"))
        
        if config.get('current_throughput', 1000) < 5000:
            if config.get('current_cpu_util', 70) > 70:
                bottlenecks.append(("🔴", "High CPU utilization", "Scale horizontally with Auto Scaling"))
            if 'rds' in config.get('current_services', []) and 'aurora' not in config.get('current_services', []):
                bottlenecks.append(("🟡", "Standard RDS", "Migrate to Aurora for better performance"))
        
        if config.get('current_error_rate', 1.0) > 0.5:
            bottlenecks.append(("🟡", "High error rate", "Implement retry logic and circuit breakers"))
        
        if len(config.get('user_locations', [])) > 1 and 'cloudfront' not in config.get('current_services', []):
            bottlenecks.append(("🟡", "Multi-region users without CDN", "Add CloudFront or Global Accelerator"))
        
        if not bottlenecks:
            bottlenecks.append(("🟢", "No major bottlenecks identified", "Architecture looks well optimized"))
        
        for severity, issue, solution in bottlenecks:
            st.markdown(f"{severity} **{issue}**: {solution}")
    
    @staticmethod
    def _render_perf_recommendations(config: Dict):
        """Performance optimization recommendations"""
        st.markdown("### ⚡ Optimization Recommendations")
        
        # Generate recommendations based on current state
        recommendations = []
        
        # Caching recommendations
        if 'elasticache' not in config.get('current_services', []):
            recommendations.append({
                'category': 'Caching',
                'icon': '⚡',
                'title': 'Add ElastiCache for Database Caching',
                'description': 'Implement Redis or Memcached to cache frequently accessed data',
                'impact': 'Reduce database load by 60-80%, improve latency by 5-10x',
                'effort': 'Medium',
                'priority': 'High',
                'services': ['elasticache'],
                'latency_improvement': 70,
                'throughput_improvement': 50
            })
        
        # CDN recommendations
        if 'cloudfront' not in config.get('current_services', []):
            recommendations.append({
                'category': 'Content Delivery',
                'icon': '🌍',
                'title': 'Implement CloudFront CDN',
                'description': 'Cache static and dynamic content at edge locations worldwide',
                'impact': 'Reduce latency by 50-90% for cached content',
                'effort': 'Low',
                'priority': 'High',
                'services': ['cloudfront'],
                'latency_improvement': 60,
                'throughput_improvement': 30
            })
        
        # Database recommendations
        if 'rds' in config.get('current_services', []) and 'aurora' not in config.get('current_services', []):
            recommendations.append({
                'category': 'Database',
                'icon': '🗄️',
                'title': 'Migrate to Aurora',
                'description': 'Aurora provides up to 5x performance of standard RDS MySQL/PostgreSQL',
                'impact': 'Improve database performance by 3-5x',
                'effort': 'Medium',
                'priority': 'Medium',
                'services': ['aurora'],
                'latency_improvement': 40,
                'throughput_improvement': 60
            })
        
        # Read replicas
        recommendations.append({
            'category': 'Database',
            'icon': '📖',
            'title': 'Add Read Replicas',
            'description': 'Distribute read traffic across multiple database replicas',
            'impact': 'Scale read capacity horizontally',
            'effort': 'Low',
            'priority': 'Medium',
            'services': ['rds', 'aurora'],
            'latency_improvement': 20,
            'throughput_improvement': 40
        })
        
        # Auto Scaling
        if config.get('current_cpu_util', 70) > 60:
            recommendations.append({
                'category': 'Compute',
                'icon': '📈',
                'title': 'Implement Auto Scaling',
                'description': 'Automatically scale EC2 instances based on demand',
                'impact': 'Handle traffic spikes without performance degradation',
                'effort': 'Low',
                'priority': 'High',
                'services': ['ec2', 'auto_scaling'],
                'latency_improvement': 30,
                'throughput_improvement': 100
            })
        
        # Connection pooling
        recommendations.append({
            'category': 'Database',
            'icon': '🔗',
            'title': 'Implement Connection Pooling',
            'description': 'Use RDS Proxy or PgBouncer for connection pooling',
            'impact': 'Reduce database connection overhead by 50%',
            'effort': 'Low',
            'priority': 'Medium',
            'services': ['rds_proxy'],
            'latency_improvement': 15,
            'throughput_improvement': 30
        })
        
        # Async processing
        if 'sqs' not in config.get('current_services', []):
            recommendations.append({
                'category': 'Architecture',
                'icon': '📨',
                'title': 'Implement Async Processing',
                'description': 'Use SQS/SNS to decouple and process tasks asynchronously',
                'impact': 'Improve response times by offloading background tasks',
                'effort': 'Medium',
                'priority': 'Medium',
                'services': ['sqs', 'sns', 'lambda'],
                'latency_improvement': 25,
                'throughput_improvement': 40
            })
        
        # Display recommendations
        for i, rec in enumerate(recommendations):
            priority_color = {'High': '#F44336', 'Medium': '#FF9800', 'Low': '#4CAF50'}.get(rec['priority'], '#666')
            
            with st.expander(f"{rec['icon']} **{rec['title']}** - {rec['category']}", expanded=(i < 3)):
                col1, col2 = st.columns([3, 1])
                
                with col1:
                    st.markdown(f"**Description:** {rec['description']}")
                    st.markdown(f"**Expected Impact:** {rec['impact']}")
                    st.markdown(f"**AWS Services:** {', '.join(rec['services'])}")
                
                with col2:
                    st.markdown(f"<span style='color: {priority_color}; font-weight: bold;'>Priority: {rec['priority']}</span>", unsafe_allow_html=True)
                    st.markdown(f"**Effort:** {rec['effort']}")
                    st.markdown(f"**Latency:** -{rec['latency_improvement']}%")
                    st.markdown(f"**Throughput:** +{rec['throughput_improvement']}%")
                
                if st.checkbox(f"Include in optimization plan", key=f"rec_{i}"):
                    if 'selected_recommendations' not in config:
                        config['selected_recommendations'] = []
                    if rec not in config['selected_recommendations']:
                        config['selected_recommendations'].append(rec)
    
    @staticmethod
    def _render_perf_implementation(config: Dict):
        """Implementation plan for performance optimizations"""
        st.markdown("### 🔧 Implementation Plan")
        
        selected = config.get('selected_recommendations', [])
        
        if not selected:
            st.info("👆 Select recommendations in the previous tab to create an implementation plan")
            
            # Show general implementation phases
            st.markdown("#### 📋 General Implementation Phases")
            
            phases = [
                ("Phase 1: Quick Wins (1-2 weeks)", [
                    "Enable CloudFront CDN",
                    "Configure Auto Scaling",
                    "Enable Enhanced Monitoring"
                ]),
                ("Phase 2: Caching Layer (2-3 weeks)", [
                    "Deploy ElastiCache cluster",
                    "Implement application-level caching",
                    "Cache database queries"
                ]),
                ("Phase 3: Database Optimization (3-4 weeks)", [
                    "Add read replicas",
                    "Implement connection pooling",
                    "Optimize queries and indexes"
                ]),
                ("Phase 4: Architecture Improvements (4-6 weeks)", [
                    "Implement async processing",
                    "Add SQS/SNS for decoupling",
                    "Consider microservices decomposition"
                ])
            ]
            
            for phase_name, tasks in phases:
                st.markdown(f"**{phase_name}**")
                for task in tasks:
                    st.markdown(f"- {task}")
            
            return
        
        # Calculate total improvements
        total_latency_improvement = sum(r.get('latency_improvement', 0) for r in selected)
        total_throughput_improvement = sum(r.get('throughput_improvement', 0) for r in selected)
        
        st.markdown("#### 📊 Expected Improvements")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            new_latency = config.get('current_latency_ms', 500) * (1 - total_latency_improvement / 100)
            st.metric(
                "Expected Latency",
                f"{new_latency:.0f}ms",
                f"-{total_latency_improvement}%"
            )
        
        with col2:
            new_throughput = config.get('current_throughput', 1000) * (1 + total_throughput_improvement / 100)
            st.metric(
                "Expected Throughput",
                f"{new_throughput:.0f} req/s",
                f"+{total_throughput_improvement}%"
            )
        
        with col3:
            st.metric("Recommendations Selected", len(selected))
        
        # Implementation timeline
        st.markdown("---")
        st.markdown("#### 📅 Implementation Timeline")
        
        week = 1
        for i, rec in enumerate(selected):
            effort_weeks = {'Low': 1, 'Medium': 2, 'High': 4}.get(rec.get('effort', 'Medium'), 2)
            
            st.markdown(f"""
            <div style="background: white; border-left: 4px solid #2196F3; padding: 10px 15px; margin: 10px 0; border-radius: 0 8px 8px 0;">
                <strong>Week {week}-{week + effort_weeks - 1}:</strong> {rec['icon']} {rec['title']}
                <br><span style="color: #666; font-size: 12px;">{rec['description']}</span>
            </div>
            """, unsafe_allow_html=True)
            week += effort_weeks
    
    @staticmethod
    def _render_perf_architecture(config: Dict):
        """Optimized architecture visualization"""
        st.markdown("### 📐 Optimized Architecture")
        
        current_services = config.get('current_services', ['ec2', 'alb', 'rds'])
        
        # Add recommended services
        optimized_services = current_services.copy()
        
        for rec in config.get('selected_recommendations', []):
            optimized_services.extend(rec.get('services', []))
        
        # Always add monitoring
        optimized_services.extend(['cloudwatch', 'xray'])
        
        optimized_services = list(dict.fromkeys(optimized_services))  # Dedupe
        
        # Generate diagram
        diagram_html = ArchitectureDiagramGenerator.generate_diagram(
            optimized_services,
            "Optimized Architecture",
            config
        )
        
        components.html(diagram_html, height=700, scrolling=True)
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.download_button(
                "📥 Download Optimized Architecture",
                data=diagram_html,
                file_name="optimized_architecture.html",
                mime="text/html",
                use_container_width=True
            )
        
        with col2:
            st.markdown("#### New Services Added:")
            new_services = set(optimized_services) - set(current_services)
            for svc in new_services:
                svc_info = ArchitectureDiagramGenerator.SERVICE_INFO.get(svc, {'name': svc, 'icon': '📦'})
                st.markdown(f"- {svc_info['icon']} {svc_info['name']}")
    
    @staticmethod
    def _render_cost_optimization():
        """Render cost optimization"""
        st.markdown("## 💰 Architecture Cost Optimization")
        st.info("🔗 For detailed FinOps analysis, use the **Cost Optimization** tab in the main navigation.")
        
        st.markdown("#### Quick Cost Optimization Tips")
        
        tips = [
            ("💡", "Right-size instances", "Use AWS Compute Optimizer to identify over-provisioned resources"),
            ("📅", "Reserved Instances", "Save up to 72% with 1-3 year commitments for steady-state workloads"),
            ("🎯", "Spot Instances", "Save up to 90% for fault-tolerant, flexible workloads"),
            ("💾", "Storage tiering", "Use S3 Intelligent-Tiering and lifecycle policies"),
            ("🔄", "Serverless", "Consider Lambda for variable workloads - pay only for what you use"),
            ("📊", "Monitoring", "Enable Cost Explorer and set up AWS Budgets alerts"),
        ]
        
        for icon, title, description in tips:
            st.markdown(f"{icon} **{title}**: {description}")
    
    @staticmethod
    def _render_security_hardening():
        """Render security hardening"""
        st.markdown("## 🔒 Security Hardening")
        st.info("🔗 For detailed security analysis, use the **WAF Assessment** tab in the main navigation.")
        
        st.markdown("#### Quick Security Hardening Checklist")
        
        checklist = [
            ("IAM", "Implement least privilege access and use IAM roles"),
            ("MFA", "Enable MFA for all human users and root account"),
            ("Encryption", "Encrypt data at rest (KMS) and in transit (TLS)"),
            ("Network", "Use VPC, security groups, and NACLs for network isolation"),
            ("Logging", "Enable CloudTrail, VPC Flow Logs, and AWS Config"),
            ("Detection", "Enable GuardDuty and Security Hub"),
            ("Secrets", "Use Secrets Manager or Parameter Store for credentials"),
            ("Patching", "Enable Systems Manager Patch Manager for OS updates"),
        ]
        
        for area, description in checklist:
            st.checkbox(f"**{area}**: {description}", key=f"sec_{area}")
    
    # ========================================================================
    # MULTI-REGION & DR - FULL IMPLEMENTATION
    # ========================================================================
    
    @staticmethod
    def _render_multi_region():
        """Render comprehensive multi-region and disaster recovery design"""
        st.markdown("## 🌍 Multi-Region & Disaster Recovery")
        st.markdown("Design for global deployment, high availability, and disaster recovery")
        
        # Initialize multi-region session state
        if 'mr_config' not in st.session_state:
            st.session_state.mr_config = {
                'primary_region': 'us-east-1',
                'secondary_regions': [],
                'dr_strategy': 'warm_standby',
                'rto_hours': 4,
                'rpo_hours': 1,
                'workload_type': 'web_application',
                'data_services': [],
                'replication_config': {}
            }
        
        mr_config = st.session_state.mr_config
        
        # Multi-region workflow tabs
        tabs = st.tabs([
            "🎯 Requirements",
            "📋 DR Strategy",
            "🌍 Region Selection",
            "🔄 Data Replication",
            "🚨 Failover Design",
            "📐 Architecture"
        ])
        
        with tabs[0]:
            ArchitectureDesignerRevamped._render_mr_requirements(mr_config)
        
        with tabs[1]:
            ArchitectureDesignerRevamped._render_dr_strategy(mr_config)
        
        with tabs[2]:
            ArchitectureDesignerRevamped._render_region_selection(mr_config)
        
        with tabs[3]:
            ArchitectureDesignerRevamped._render_data_replication(mr_config)
        
        with tabs[4]:
            ArchitectureDesignerRevamped._render_failover_design(mr_config)
        
        with tabs[5]:
            ArchitectureDesignerRevamped._render_mr_architecture(mr_config)
    
    @staticmethod
    def _render_mr_requirements(config: Dict):
        """Define multi-region requirements"""
        st.markdown("### 🎯 Define Requirements")
        
        st.markdown("#### 📊 Business Requirements")
        
        col1, col2 = st.columns(2)
        
        with col1:
            config['workload_type'] = st.selectbox(
                "Workload Type",
                ['web_application', 'api_backend', 'e_commerce', 'financial_services',
                 'healthcare', 'gaming', 'media_streaming', 'saas_platform'],
                format_func=lambda x: x.replace('_', ' ').title(),
                key="mr_workload"
            )
            
            config['criticality'] = st.selectbox(
                "Business Criticality",
                ['mission_critical', 'business_critical', 'business_operational'],
                format_func=lambda x: x.replace('_', ' ').title()
            )
            
            config['compliance'] = st.multiselect(
                "Compliance Requirements",
                ['HIPAA', 'PCI-DSS', 'SOC2', 'GDPR', 'FedRAMP', 'Data Residency'],
                key="mr_compliance"
            )
        
        with col2:
            config['monthly_revenue'] = st.number_input(
                "Monthly Revenue Impact of Downtime ($)",
                min_value=0,
                value=100000,
                step=10000
            )
            
            config['users_affected'] = st.number_input(
                "Users Affected by Outage",
                min_value=0,
                value=10000
            )
            
            config['data_size_tb'] = st.number_input(
                "Total Data Size (TB)",
                min_value=0.1,
                value=1.0,
                step=0.1
            )
        
        st.markdown("---")
        st.markdown("#### ⏱️ Recovery Objectives")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**RTO (Recovery Time Objective)** - Maximum acceptable time to restore service")
            
            rto_options = {
                0.25: '15 minutes (Mission Critical)',
                1: '1 hour (Business Critical)',
                4: '4 hours (Important)',
                12: '12 hours (Standard)',
                24: '24 hours (Low Priority)'
            }
            
            config['rto_hours'] = st.select_slider(
                "RTO",
                options=list(rto_options.keys()),
                value=config.get('rto_hours', 4),
                format_func=lambda x: rto_options[x]
            )
        
        with col2:
            st.markdown("**RPO (Recovery Point Objective)** - Maximum acceptable data loss")
            
            rpo_options = {
                0: 'Zero (No data loss)',
                0.25: '15 minutes',
                1: '1 hour',
                4: '4 hours',
                24: '24 hours'
            }
            
            config['rpo_hours'] = st.select_slider(
                "RPO",
                options=list(rpo_options.keys()),
                value=config.get('rpo_hours', 1),
                format_func=lambda x: rpo_options[x]
            )
        
        # Cost of downtime calculation
        st.markdown("---")
        st.markdown("#### 💰 Downtime Cost Analysis")
        
        hourly_cost = config['monthly_revenue'] / 720
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("Hourly Downtime Cost", f"${hourly_cost:,.0f}")
        
        with col2:
            rto_cost = hourly_cost * config['rto_hours']
            st.metric(f"Max Loss at RTO ({config['rto_hours']}h)", f"${rto_cost:,.0f}")
        
        with col3:
            annual_risk = rto_cost * 2
            st.metric("Annual Risk (2 incidents)", f"${annual_risk:,.0f}")
        
        # Recommended strategy
        st.markdown("---")
        if config['rto_hours'] <= 0.25 and config['rpo_hours'] == 0:
            recommended = 'active_active'
        elif config['rto_hours'] <= 1:
            recommended = 'warm_standby'
        elif config['rto_hours'] <= 4:
            recommended = 'pilot_light'
        else:
            recommended = 'backup_restore'
        
        config['recommended_strategy'] = recommended
        
        strategy_names = {
            'active_active': '🌐 Active-Active',
            'warm_standby': '🔥 Warm Standby',
            'pilot_light': '💡 Pilot Light',
            'backup_restore': '💾 Backup & Restore'
        }
        
        st.success(f"**Recommended Strategy:** {strategy_names[recommended]}")
    
    @staticmethod
    def _render_dr_strategy(config: Dict):
        """Select and configure DR strategy"""
        st.markdown("### 📋 DR Strategy Selection")
        
        strategies = {
            'backup_restore': {
                'name': 'Backup & Restore', 'icon': '💾', 'rto': '24+ hours', 'rpo': '1-24 hours',
                'cost': '$', 'cost_multiplier': 1.1,
                'description': 'Regular backups to DR region. Restore when disaster occurs.',
                'pros': ['Lowest cost', 'Simple to implement'],
                'cons': ['Longest recovery time', 'Data loss up to last backup'],
                'aws_services': ['S3 Cross-Region Replication', 'AWS Backup', 'CloudFormation']
            },
            'pilot_light': {
                'name': 'Pilot Light', 'icon': '💡', 'rto': '4-8 hours', 'rpo': '1-4 hours',
                'cost': '$$', 'cost_multiplier': 1.3,
                'description': 'Core infrastructure (DB) always running. Scale up compute on failover.',
                'pros': ['Lower cost than warm standby', 'Data always replicated'],
                'cons': ['Requires scale-up time', 'Some manual steps'],
                'aws_services': ['RDS Read Replicas', 'Aurora Global Database', 'Route 53']
            },
            'warm_standby': {
                'name': 'Warm Standby', 'icon': '🔥', 'rto': '1-4 hours', 'rpo': 'Minutes',
                'cost': '$$$', 'cost_multiplier': 1.6,
                'description': 'Scaled-down but fully functional environment in DR region.',
                'pros': ['Fast failover', 'Can handle some traffic'],
                'cons': ['Higher cost', 'Ongoing maintenance'],
                'aws_services': ['Aurora Global Database', 'DynamoDB Global Tables', 'Auto Scaling']
            },
            'active_active': {
                'name': 'Active-Active', 'icon': '🌐', 'rto': 'Minutes', 'rpo': 'Zero',
                'cost': '$$$$', 'cost_multiplier': 2.0,
                'description': 'Full production in multiple regions. Traffic served from nearest.',
                'pros': ['Instant failover', 'No data loss', 'Best UX'],
                'cons': ['Highest cost', 'Complex data sync'],
                'aws_services': ['Global Accelerator', 'Aurora Global', 'DynamoDB Global Tables']
            }
        }
        
        cols = st.columns(4)
        for i, (key, strategy) in enumerate(strategies.items()):
            with cols[i]:
                is_recommended = config.get('recommended_strategy') == key
                is_selected = config.get('dr_strategy') == key
                border = "#4CAF50" if is_recommended else "#2196F3" if is_selected else "#ddd"
                
                st.markdown(f"""
                <div style="background: white; border: 2px solid {border}; border-radius: 10px; padding: 12px; min-height: 280px;">
                    <div style="font-size: 24px; text-align: center;">{strategy['icon']}</div>
                    <h4 style="text-align: center; color: #1976D2; margin: 8px 0;">{strategy['name']}</h4>
                    <p style="font-size: 10px;">{strategy['description']}</p>
                    <p style="font-size: 10px; margin-top: 8px;">
                        <strong>RTO:</strong> {strategy['rto']}<br>
                        <strong>RPO:</strong> {strategy['rpo']}<br>
                        <strong>Cost:</strong> {strategy['cost']}
                    </p>
                    {'<div style="background: #4CAF50; color: white; padding: 2px 6px; border-radius: 4px; font-size: 9px; text-align: center;">RECOMMENDED</div>' if is_recommended else ''}
                </div>
                """, unsafe_allow_html=True)
                
                if st.button(f"Select", key=f"dr_{key}", use_container_width=True):
                    config['dr_strategy'] = key
                    st.rerun()
        
        # Cost estimate
        if config.get('dr_strategy'):
            selected = strategies[config['dr_strategy']]
            st.markdown("---")
            
            base_cost = st.number_input("Current Monthly AWS Cost ($)", min_value=100, value=10000)
            dr_cost = base_cost * selected['cost_multiplier']
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Current", f"${base_cost:,.0f}/mo")
            with col2:
                st.metric("With DR", f"${dr_cost:,.0f}/mo", f"+{selected['cost_multiplier']-1:.0%}")
            with col3:
                st.metric("Services", ", ".join(selected['aws_services'][:2]))
    
    @staticmethod
    def _render_region_selection(config: Dict):
        """Select primary and secondary regions"""
        st.markdown("### 🌍 Region Selection")
        
        aws_regions = {
            'us-east-1': 'US East (N. Virginia)', 'us-east-2': 'US East (Ohio)',
            'us-west-1': 'US West (N. California)', 'us-west-2': 'US West (Oregon)',
            'eu-west-1': 'EU (Ireland)', 'eu-west-2': 'EU (London)', 'eu-central-1': 'EU (Frankfurt)',
            'ap-southeast-1': 'Asia Pacific (Singapore)', 'ap-southeast-2': 'Asia Pacific (Sydney)',
            'ap-northeast-1': 'Asia Pacific (Tokyo)', 'ap-south-1': 'Asia Pacific (Mumbai)',
            'sa-east-1': 'South America (São Paulo)', 'ca-central-1': 'Canada (Central)'
        }
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("#### 🏠 Primary Region")
            config['primary_region'] = st.selectbox(
                "Primary Region",
                list(aws_regions.keys()),
                format_func=lambda x: f"{aws_regions[x]} ({x})",
                index=list(aws_regions.keys()).index(config.get('primary_region', 'us-east-1'))
            )
        
        with col2:
            st.markdown("#### 🔄 Secondary Region(s)")
            available = [r for r in aws_regions.keys() if r != config['primary_region']]
            config['secondary_regions'] = st.multiselect(
                "Secondary Regions",
                available,
                default=config.get('secondary_regions', []),
                format_func=lambda x: f"{aws_regions[x]} ({x})"
            )
        
        # Recommended pairs
        st.markdown("---")
        pairs = {'us-east-1': 'us-west-2', 'us-west-2': 'us-east-1', 'eu-west-1': 'eu-central-1'}
        recommended = pairs.get(config['primary_region'], 'us-west-2')
        st.info(f"💡 Recommended DR pair for {config['primary_region']}: **{recommended}**")
    
    @staticmethod
    def _render_data_replication(config: Dict):
        """Configure data replication"""
        st.markdown("### 🔄 Data Replication Configuration")
        
        if not config.get('secondary_regions'):
            st.warning("👆 Please select secondary region(s) first")
            return
        
        config['data_services'] = st.multiselect(
            "Data Services to Replicate",
            ['RDS/Aurora', 'DynamoDB', 'S3', 'ElastiCache', 'EFS'],
            default=config.get('data_services', ['RDS/Aurora', 'S3'])
        )
        
        for service in config.get('data_services', []):
            with st.expander(f"⚙️ {service} Replication", expanded=True):
                if service == 'RDS/Aurora':
                    st.selectbox("Engine", ['Aurora MySQL', 'Aurora PostgreSQL', 'RDS MySQL'], key=f"db_{service}")
                    st.selectbox("Type", ['Aurora Global Database', 'Cross-Region Read Replica'], key=f"repl_{service}")
                    st.checkbox("Auto failover", value=True, key=f"auto_{service}")
                elif service == 'DynamoDB':
                    st.markdown("✅ DynamoDB Global Tables - Multi-region, multi-active")
                elif service == 'S3':
                    st.selectbox("Scope", ['Entire bucket', 'Prefix-based'], key=f"s3_{service}")
                    st.checkbox("Replicate deletes", value=False, key=f"del_{service}")
    
    @staticmethod
    def _render_failover_design(config: Dict):
        """Design failover automation"""
        st.markdown("### 🚨 Failover Design")
        
        col1, col2 = st.columns(2)
        
        with col1:
            config['routing_policy'] = st.selectbox(
                "Route 53 Routing",
                ['Failover (Active-Passive)', 'Latency (Active-Active)', 'Weighted', 'Geolocation']
            )
            config['failover_threshold'] = st.slider("Failover threshold (failures)", 1, 10, 3)
        
        with col2:
            config['auto_failover'] = st.checkbox("Automatic failover", value=True)
            config['health_checks'] = st.multiselect(
                "Health Checks",
                ['App /health', 'Database', 'External APIs'],
                default=['App /health']
            )
        
        st.markdown("---")
        st.markdown("#### 📋 Failover Runbook")
        
        steps = [
            "1. Route 53 detects health check failures",
            f"2. After {config['failover_threshold']} failures, traffic reroutes",
            "3. Verify DR region serving traffic",
            "4. Investigate primary failure",
            "5. Plan failback during maintenance window"
        ]
        
        for step in steps:
            st.markdown(step)
        
        st.markdown("---")
        config['test_frequency'] = st.selectbox("DR Test Frequency", ['Monthly', 'Quarterly', 'Annually'], index=1)
    
    @staticmethod
    def _render_mr_architecture(config: Dict):
        """Visualize multi-region architecture"""
        st.markdown("### 📐 Multi-Region Architecture")
        
        if not config.get('secondary_regions'):
            st.warning("👆 Please configure regions first")
            return
        
        diagram_html = ArchitectureDesignerRevamped._generate_mr_diagram(config)
        components.html(diagram_html, height=600, scrolling=True)
        
        col1, col2 = st.columns(2)
        with col1:
            st.download_button("📥 Download Diagram", diagram_html, "multi_region.html", "text/html", use_container_width=True)
        with col2:
            st.download_button("📋 Export Config", json.dumps(config, indent=2, default=str), "dr_config.json", "application/json", use_container_width=True)
    
    @staticmethod
    def _generate_mr_diagram(config: Dict) -> str:
        """Generate multi-region architecture diagram"""
        primary = config.get('primary_region', 'us-east-1')
        secondary_list = config.get('secondary_regions', ['us-west-2'])
        strategy = config.get('dr_strategy', 'warm_standby')
        
        strategy_names = {'backup_restore': 'Backup & Restore', 'pilot_light': 'Pilot Light',
                         'warm_standby': 'Warm Standby', 'active_active': 'Active-Active'}
        
        html = f'''<!DOCTYPE html>
<html><head><style>
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ font-family: Arial, sans-serif; background: linear-gradient(135deg, #1a237e, #0d47a1); padding: 20px; }}
.container {{ max-width: 1000px; margin: 0 auto; }}
.header {{ text-align: center; color: white; padding: 15px; }}
.global {{ background: #FF9800; border-radius: 8px; padding: 12px; margin-bottom: 15px; color: white; text-align: center; }}
.regions {{ display: flex; gap: 15px; justify-content: center; flex-wrap: wrap; }}
.region {{ background: white; border-radius: 10px; padding: 15px; min-width: 280px; }}
.region.primary {{ border: 3px solid #4CAF50; }}
.region.secondary {{ border: 3px solid #2196F3; }}
.region h3 {{ text-align: center; margin-bottom: 10px; }}
.badge {{ display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 10px; color: white; }}
.badge.primary {{ background: #4CAF50; }}
.badge.secondary {{ background: #2196F3; }}
.services {{ margin: 10px 0; }}
.service {{ background: #f5f5f5; border: 1px solid #ddd; border-radius: 5px; padding: 6px 10px; margin: 4px; display: inline-block; font-size: 11px; }}
.service.active {{ background: #E8F5E9; border-color: #4CAF50; }}
.service.standby {{ background: #FFF3E0; border-color: #FF9800; }}
.arrow {{ text-align: center; color: white; font-size: 24px; padding: 10px; }}
.summary {{ background: rgba(255,255,255,0.1); border-radius: 8px; padding: 12px; margin-top: 15px; color: white; display: flex; justify-content: space-around; }}
.summary-item {{ text-align: center; }}
.summary-value {{ font-size: 18px; font-weight: bold; }}
.summary-label {{ font-size: 10px; opacity: 0.8; }}
</style></head><body>
<div class="container">
  <div class="header"><h2>🌍 Multi-Region Architecture</h2><p>{strategy_names.get(strategy)} | RTO: {config.get('rto_hours',4)}h | RPO: {config.get('rpo_hours',1)}h</p></div>
  <div class="global"><strong>🌐 Global:</strong> Route 53 | CloudFront | Global Accelerator</div>
  <div class="regions">
    <div class="region primary">
      <h3>📍 {primary} <span class="badge primary">PRIMARY</span></h3>
      <div class="services">
        <span class="service active">💻 EC2/ECS</span>
        <span class="service active">⚖️ ALB</span>
        <span class="service active">🗄️ Aurora Primary</span>
        <span class="service active">📦 S3</span>
      </div>
    </div>
    <div class="arrow">⟷</div>'''
        
        for sec in secondary_list:
            status = 'active' if strategy == 'active_active' else 'standby'
            html += f'''
    <div class="region secondary">
      <h3>📍 {sec} <span class="badge secondary">DR</span></h3>
      <div class="services">
        <span class="service {status}">💻 EC2/ECS</span>
        <span class="service {status}">⚖️ ALB</span>
        <span class="service active">🗄️ Aurora Replica</span>
        <span class="service active">📦 S3 Replica</span>
      </div>
    </div>'''
        
        html += f'''
  </div>
  <div class="summary">
    <div class="summary-item"><div class="summary-value">{strategy_names.get(strategy)}</div><div class="summary-label">Strategy</div></div>
    <div class="summary-item"><div class="summary-value">{config.get('rto_hours',4)}h</div><div class="summary-label">RTO</div></div>
    <div class="summary-item"><div class="summary-value">{config.get('rpo_hours',1)}h</div><div class="summary-label">RPO</div></div>
    <div class="summary-item"><div class="summary-value">{len(secondary_list)+1}</div><div class="summary-label">Regions</div></div>
  </div>
</div></body></html>'''
        return html


# ============================================================================
# RENDER FUNCTION
# ============================================================================

def render_architecture_designer_revamped():
    """Main entry point for the revamped Architecture Designer"""
    ArchitectureDesignerRevamped.render()
