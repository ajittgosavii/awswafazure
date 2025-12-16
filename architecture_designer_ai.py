"""
AI-Powered AWS Architecture Designer
=====================================
Interactive architecture design tool aligned with AWS Well-Architected Framework.

Features:
- AI-assisted service selection and recommendations
- Progressive complexity (Simple → Standard → Enterprise → Production)
- Real-time WAF alignment scoring
- Interactive SVG diagram visualization
- Multiple architecture patterns and templates
- Export to SVG, CloudFormation, Terraform

Version: 4.0.0
"""

import streamlit as st
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
import json

# Import SVG generator
from svg_diagram_generator import (
    AWS_SERVICES, Architecture, ServiceNode, Connection, Group,
    AWSDiagramGenerator, generate_architecture_svg
)

# ============================================================================
# ARCHITECTURE PATTERNS & TEMPLATES
# ============================================================================

ARCHITECTURE_PATTERNS = {
    "web_application": {
        "name": "Web Application",
        "icon": "🌐",
        "description": "Scalable web application with load balancing and database",
        "complexity_levels": {
            "simple": {
                "name": "Simple (Single Instance)",
                "services": ["route53", "cloudfront", "alb", "ec2", "rds"],
                "description": "Basic web app with single EC2 and RDS"
            },
            "standard": {
                "name": "Standard (Auto-Scaling)",
                "services": ["route53", "cloudfront", "waf", "alb", "ec2", "ec2", "rds", "elasticache", "s3"],
                "description": "Auto-scaling EC2 with caching and CDN"
            },
            "enterprise": {
                "name": "Enterprise (Multi-AZ)",
                "services": ["route53", "cloudfront", "waf", "shield", "alb", "ec2", "ec2", "ec2", "aurora", "elasticache", "s3", "cloudwatch", "guardduty"],
                "description": "Highly available multi-AZ deployment"
            },
            "production": {
                "name": "Production (Full Stack)",
                "services": ["route53", "cloudfront", "waf", "shield", "alb", "nlb", "eks", "aurora", "dynamodb", "elasticache", "s3", "efs", "sqs", "sns", "kms", "secrets_manager", "cloudwatch", "cloudtrail", "guardduty", "security_hub"],
                "description": "Production-grade with containers and full security"
            }
        }
    },
    "api_backend": {
        "name": "API Backend",
        "icon": "🔌",
        "description": "RESTful or GraphQL API with serverless or container options",
        "complexity_levels": {
            "simple": {
                "name": "Simple (Serverless)",
                "services": ["api_gateway", "lambda", "dynamodb"],
                "description": "Simple serverless API"
            },
            "standard": {
                "name": "Standard (With Auth)",
                "services": ["route53", "api_gateway", "cognito", "lambda", "dynamodb", "s3"],
                "description": "API with authentication and storage"
            },
            "enterprise": {
                "name": "Enterprise (Container)",
                "services": ["route53", "api_gateway", "cognito", "waf", "alb", "ecs", "rds", "elasticache", "s3", "sqs", "cloudwatch"],
                "description": "Containerized API with full stack"
            },
            "production": {
                "name": "Production (Kubernetes)",
                "services": ["route53", "api_gateway", "cognito", "waf", "shield", "alb", "eks", "aurora", "elasticache", "dynamodb", "s3", "sqs", "sns", "eventbridge", "kms", "secrets_manager", "cloudwatch", "cloudtrail", "guardduty"],
                "description": "Production Kubernetes-based API platform"
            }
        }
    },
    "data_lake": {
        "name": "Data Lake & Analytics",
        "icon": "📊",
        "description": "Data lake for analytics, ML, and business intelligence",
        "complexity_levels": {
            "simple": {
                "name": "Simple (S3 + Athena)",
                "services": ["s3", "glue", "athena"],
                "description": "Basic data lake with SQL queries"
            },
            "standard": {
                "name": "Standard (ETL Pipeline)",
                "services": ["kinesis", "s3", "glue", "athena", "quicksight", "cloudwatch"],
                "description": "ETL pipeline with visualization"
            },
            "enterprise": {
                "name": "Enterprise (Lake Formation)",
                "services": ["kinesis", "s3", "lake_formation", "glue", "athena", "redshift", "quicksight", "kms", "cloudwatch"],
                "description": "Governed data lake with warehouse"
            },
            "production": {
                "name": "Production (Full Analytics)",
                "services": ["kinesis", "s3", "lake_formation", "glue", "emr", "athena", "redshift", "opensearch", "quicksight", "sagemaker", "kms", "secrets_manager", "cloudwatch", "cloudtrail"],
                "description": "Complete analytics platform with ML"
            }
        }
    },
    "ml_platform": {
        "name": "ML/AI Platform",
        "icon": "🤖",
        "description": "Machine learning training and inference platform",
        "complexity_levels": {
            "simple": {
                "name": "Simple (SageMaker)",
                "services": ["s3", "sagemaker"],
                "description": "Basic ML with SageMaker"
            },
            "standard": {
                "name": "Standard (MLOps)",
                "services": ["s3", "sagemaker", "ecr", "lambda", "step_functions", "cloudwatch"],
                "description": "MLOps pipeline with automation"
            },
            "enterprise": {
                "name": "Enterprise (Feature Store)",
                "services": ["kinesis", "s3", "glue", "sagemaker", "ecr", "lambda", "step_functions", "api_gateway", "dynamodb", "cloudwatch"],
                "description": "Feature store and model registry"
            },
            "production": {
                "name": "Production (Full MLOps)",
                "services": ["kinesis", "s3", "lake_formation", "glue", "sagemaker", "bedrock", "ecr", "eks", "lambda", "step_functions", "api_gateway", "dynamodb", "elasticache", "kms", "secrets_manager", "cloudwatch", "cloudtrail"],
                "description": "Production MLOps with GenAI"
            }
        }
    },
    "microservices": {
        "name": "Microservices",
        "icon": "🧩",
        "description": "Distributed microservices architecture",
        "complexity_levels": {
            "simple": {
                "name": "Simple (ECS)",
                "services": ["alb", "ecs", "rds", "s3"],
                "description": "Basic containerized microservices"
            },
            "standard": {
                "name": "Standard (Service Mesh)",
                "services": ["route53", "alb", "ecs", "ecr", "rds", "dynamodb", "sqs", "sns", "s3", "cloudwatch"],
                "description": "Microservices with messaging"
            },
            "enterprise": {
                "name": "Enterprise (EKS)",
                "services": ["route53", "cloudfront", "waf", "alb", "eks", "ecr", "aurora", "dynamodb", "elasticache", "sqs", "sns", "eventbridge", "s3", "kms", "cloudwatch"],
                "description": "Kubernetes microservices platform"
            },
            "production": {
                "name": "Production (Full Platform)",
                "services": ["route53", "cloudfront", "waf", "shield", "alb", "nlb", "eks", "ecr", "aurora", "dynamodb", "elasticache", "opensearch", "sqs", "sns", "eventbridge", "kinesis", "s3", "efs", "kms", "secrets_manager", "cloudwatch", "cloudtrail", "guardduty", "security_hub"],
                "description": "Production microservices platform"
            }
        }
    },
    "event_driven": {
        "name": "Event-Driven Architecture",
        "icon": "⚡",
        "description": "Asynchronous event-driven system",
        "complexity_levels": {
            "simple": {
                "name": "Simple (SQS + Lambda)",
                "services": ["sqs", "lambda", "dynamodb"],
                "description": "Basic event processing"
            },
            "standard": {
                "name": "Standard (EventBridge)",
                "services": ["api_gateway", "eventbridge", "sqs", "lambda", "step_functions", "dynamodb", "s3"],
                "description": "Event bus with orchestration"
            },
            "enterprise": {
                "name": "Enterprise (Streaming)",
                "services": ["api_gateway", "kinesis", "eventbridge", "sqs", "sns", "lambda", "step_functions", "dynamodb", "s3", "cloudwatch"],
                "description": "Real-time streaming events"
            },
            "production": {
                "name": "Production (Full Event Platform)",
                "services": ["api_gateway", "kinesis", "mq", "eventbridge", "sqs", "sns", "lambda", "step_functions", "ecs", "dynamodb", "elasticache", "s3", "opensearch", "kms", "secrets_manager", "cloudwatch", "cloudtrail"],
                "description": "Production event-driven platform"
            }
        }
    },
    "hybrid_cloud": {
        "name": "Hybrid Cloud",
        "icon": "🔗",
        "description": "Hybrid on-premises and cloud architecture",
        "complexity_levels": {
            "simple": {
                "name": "Simple (VPN)",
                "services": ["vpc", "nat_gateway", "ec2", "rds", "s3"],
                "description": "Basic VPN connectivity"
            },
            "standard": {
                "name": "Standard (Direct Connect)",
                "services": ["direct_connect", "vpc", "transit_gateway", "alb", "ec2", "rds", "s3", "cloudwatch"],
                "description": "Direct Connect hybrid"
            },
            "enterprise": {
                "name": "Enterprise (Multi-VPC)",
                "services": ["direct_connect", "transit_gateway", "vpc", "vpc", "alb", "eks", "aurora", "s3", "efs", "kms", "cloudwatch"],
                "description": "Multi-VPC with Transit Gateway"
            },
            "production": {
                "name": "Production (Full Hybrid)",
                "services": ["direct_connect", "transit_gateway", "vpc", "vpc", "vpc", "waf", "alb", "nlb", "eks", "aurora", "dynamodb", "s3", "efs", "fsx", "kms", "secrets_manager", "systems_manager", "cloudwatch", "cloudtrail", "guardduty"],
                "description": "Production hybrid infrastructure"
            }
        }
    },
    "disaster_recovery": {
        "name": "Disaster Recovery",
        "icon": "🛡️",
        "description": "Multi-region disaster recovery setup",
        "complexity_levels": {
            "simple": {
                "name": "Simple (Backup)",
                "services": ["ec2", "rds", "s3"],
                "description": "Basic backup and restore"
            },
            "standard": {
                "name": "Standard (Pilot Light)",
                "services": ["route53", "alb", "ec2", "aurora", "s3", "cloudwatch"],
                "description": "Pilot light DR strategy"
            },
            "enterprise": {
                "name": "Enterprise (Warm Standby)",
                "services": ["route53", "cloudfront", "alb", "ec2", "ec2", "aurora", "dynamodb", "s3", "sqs", "cloudwatch"],
                "description": "Warm standby multi-region"
            },
            "production": {
                "name": "Production (Active-Active)",
                "services": ["route53", "cloudfront", "waf", "shield", "alb", "nlb", "eks", "aurora", "dynamodb", "elasticache", "s3", "sqs", "sns", "kms", "secrets_manager", "cloudwatch", "cloudtrail", "guardduty"],
                "description": "Active-active multi-region"
            }
        }
    }
}

# ============================================================================
# WAF ALIGNMENT SCORING
# ============================================================================

WAF_PILLAR_WEIGHTS = {
    "security": 0.25,
    "reliability": 0.20,
    "performance": 0.15,
    "cost": 0.15,
    "operational": 0.15,
    "sustainability": 0.10
}

SERVICE_WAF_SCORES = {
    # Security-enhancing services
    "waf": {"security": 20, "reliability": 5, "performance": 0, "cost": -5, "operational": 5, "sustainability": 0},
    "shield": {"security": 25, "reliability": 10, "performance": 0, "cost": -10, "operational": 5, "sustainability": 0},
    "guardduty": {"security": 15, "reliability": 5, "performance": 0, "cost": -3, "operational": 10, "sustainability": 0},
    "security_hub": {"security": 15, "reliability": 5, "performance": 0, "cost": -3, "operational": 15, "sustainability": 0},
    "kms": {"security": 20, "reliability": 5, "performance": -2, "cost": -2, "operational": 5, "sustainability": 0},
    "secrets_manager": {"security": 15, "reliability": 5, "performance": 0, "cost": -2, "operational": 10, "sustainability": 0},
    "cognito": {"security": 15, "reliability": 10, "performance": 5, "cost": 5, "operational": 10, "sustainability": 5},
    "acm": {"security": 10, "reliability": 5, "performance": 0, "cost": 5, "operational": 5, "sustainability": 0},
    "iam": {"security": 15, "reliability": 5, "performance": 0, "cost": 0, "operational": 5, "sustainability": 0},
    
    # Reliability-enhancing services
    "aurora": {"security": 10, "reliability": 25, "performance": 15, "cost": -10, "operational": 10, "sustainability": 10},
    "elasticache": {"security": 5, "reliability": 15, "performance": 25, "cost": -5, "operational": 5, "sustainability": 5},
    "alb": {"security": 5, "reliability": 20, "performance": 15, "cost": 0, "operational": 10, "sustainability": 5},
    "nlb": {"security": 5, "reliability": 20, "performance": 20, "cost": 0, "operational": 5, "sustainability": 5},
    "route53": {"security": 5, "reliability": 20, "performance": 10, "cost": 5, "operational": 10, "sustainability": 5},
    "cloudfront": {"security": 10, "reliability": 15, "performance": 25, "cost": 10, "operational": 5, "sustainability": 10},
    
    # Operational excellence
    "cloudwatch": {"security": 5, "reliability": 15, "performance": 10, "cost": 0, "operational": 25, "sustainability": 5},
    "cloudtrail": {"security": 15, "reliability": 5, "performance": 0, "cost": -2, "operational": 20, "sustainability": 0},
    "config": {"security": 10, "reliability": 5, "performance": 0, "cost": -2, "operational": 20, "sustainability": 5},
    "systems_manager": {"security": 5, "reliability": 10, "performance": 0, "cost": 5, "operational": 25, "sustainability": 5},
    
    # Cost-optimized services
    "lambda": {"security": 5, "reliability": 10, "performance": 10, "cost": 20, "operational": 10, "sustainability": 15},
    "fargate": {"security": 10, "reliability": 15, "performance": 10, "cost": 15, "operational": 15, "sustainability": 15},
    "s3": {"security": 10, "reliability": 20, "performance": 10, "cost": 20, "operational": 10, "sustainability": 15},
    "dynamodb": {"security": 10, "reliability": 20, "performance": 20, "cost": 10, "operational": 10, "sustainability": 10},
    
    # Performance services
    "eks": {"security": 10, "reliability": 20, "performance": 20, "cost": -5, "operational": 15, "sustainability": 10},
    "ecs": {"security": 10, "reliability": 15, "performance": 15, "cost": 5, "operational": 15, "sustainability": 10},
    "ec2": {"security": 5, "reliability": 10, "performance": 15, "cost": 0, "operational": 5, "sustainability": 5},
    "rds": {"security": 10, "reliability": 15, "performance": 10, "cost": 0, "operational": 10, "sustainability": 5},
    
    # Integration services
    "sqs": {"security": 5, "reliability": 20, "performance": 10, "cost": 15, "operational": 15, "sustainability": 10},
    "sns": {"security": 5, "reliability": 15, "performance": 10, "cost": 15, "operational": 15, "sustainability": 10},
    "eventbridge": {"security": 5, "reliability": 15, "performance": 10, "cost": 10, "operational": 20, "sustainability": 10},
    "step_functions": {"security": 5, "reliability": 15, "performance": 5, "cost": 10, "operational": 20, "sustainability": 10},
    "kinesis": {"security": 5, "reliability": 15, "performance": 20, "cost": -5, "operational": 10, "sustainability": 5},
    
    # Analytics & ML
    "sagemaker": {"security": 5, "reliability": 10, "performance": 15, "cost": -10, "operational": 10, "sustainability": 5},
    "bedrock": {"security": 10, "reliability": 10, "performance": 15, "cost": -5, "operational": 15, "sustainability": 5},
    "athena": {"security": 5, "reliability": 10, "performance": 15, "cost": 15, "operational": 10, "sustainability": 10},
    "glue": {"security": 5, "reliability": 10, "performance": 10, "cost": 5, "operational": 15, "sustainability": 10},
    "quicksight": {"security": 5, "reliability": 10, "performance": 10, "cost": 5, "operational": 15, "sustainability": 10},
    
    # Default for unlisted services
    "default": {"security": 0, "reliability": 5, "performance": 5, "cost": 0, "operational": 5, "sustainability": 5},
}


def calculate_waf_scores(services: List[str]) -> Dict[str, Any]:
    """Calculate WAF alignment scores for a list of services"""
    
    pillar_scores = {
        "security": 50,
        "reliability": 50,
        "performance": 50,
        "cost": 50,
        "operational": 50,
        "sustainability": 50
    }
    
    for service in services:
        service_scores = SERVICE_WAF_SCORES.get(service, SERVICE_WAF_SCORES["default"])
        for pillar, score in service_scores.items():
            pillar_scores[pillar] = min(100, max(0, pillar_scores[pillar] + score / len(services) * 2))
    
    # Calculate overall score
    overall_score = sum(
        pillar_scores[pillar] * weight 
        for pillar, weight in WAF_PILLAR_WEIGHTS.items()
    )
    
    return {
        "pillar_scores": pillar_scores,
        "overall_score": round(overall_score, 1),
        "service_count": len(services),
        "recommendations": generate_waf_recommendations(services, pillar_scores)
    }


def generate_waf_recommendations(services: List[str], pillar_scores: Dict[str, float]) -> List[Dict[str, str]]:
    """Generate recommendations to improve WAF alignment"""
    
    recommendations = []
    service_set = set(services)
    
    # Security recommendations
    if pillar_scores["security"] < 70:
        if "waf" not in service_set:
            recommendations.append({
                "pillar": "Security",
                "priority": "High",
                "recommendation": "Add AWS WAF for web application protection",
                "service": "waf"
            })
        if "guardduty" not in service_set:
            recommendations.append({
                "pillar": "Security",
                "priority": "High",
                "recommendation": "Enable GuardDuty for threat detection",
                "service": "guardduty"
            })
        if "kms" not in service_set:
            recommendations.append({
                "pillar": "Security",
                "priority": "Medium",
                "recommendation": "Use KMS for encryption key management",
                "service": "kms"
            })
    
    # Reliability recommendations
    if pillar_scores["reliability"] < 70:
        if "alb" not in service_set and "nlb" not in service_set:
            recommendations.append({
                "pillar": "Reliability",
                "priority": "High",
                "recommendation": "Add load balancer for high availability",
                "service": "alb"
            })
        if "aurora" not in service_set and "rds" in service_set:
            recommendations.append({
                "pillar": "Reliability",
                "priority": "Medium",
                "recommendation": "Consider Aurora for improved reliability",
                "service": "aurora"
            })
    
    # Operational recommendations
    if pillar_scores["operational"] < 70:
        if "cloudwatch" not in service_set:
            recommendations.append({
                "pillar": "Operational Excellence",
                "priority": "High",
                "recommendation": "Add CloudWatch for monitoring and observability",
                "service": "cloudwatch"
            })
        if "cloudtrail" not in service_set:
            recommendations.append({
                "pillar": "Operational Excellence",
                "priority": "Medium",
                "recommendation": "Enable CloudTrail for audit logging",
                "service": "cloudtrail"
            })
    
    # Performance recommendations
    if pillar_scores["performance"] < 70:
        if "elasticache" not in service_set and ("rds" in service_set or "aurora" in service_set):
            recommendations.append({
                "pillar": "Performance Efficiency",
                "priority": "Medium",
                "recommendation": "Add ElastiCache for database caching",
                "service": "elasticache"
            })
        if "cloudfront" not in service_set:
            recommendations.append({
                "pillar": "Performance Efficiency",
                "priority": "Medium",
                "recommendation": "Use CloudFront CDN for content delivery",
                "service": "cloudfront"
            })
    
    # Cost recommendations
    if pillar_scores["cost"] < 70:
        if "ec2" in service_set and "lambda" not in service_set:
            recommendations.append({
                "pillar": "Cost Optimization",
                "priority": "Medium",
                "recommendation": "Consider Lambda for event-driven workloads",
                "service": "lambda"
            })
    
    return recommendations


# ============================================================================
# AI SUGGESTIONS ENGINE
# ============================================================================

def get_ai_suggestions(
    pattern: str,
    complexity: str,
    requirements: Dict[str, Any],
    current_services: List[str]
) -> Dict[str, Any]:
    """Generate AI-powered architecture suggestions"""
    
    suggestions = {
        "recommended_services": [],
        "configuration_tips": [],
        "best_practices": [],
        "estimated_cost_tier": "",
        "scaling_recommendations": []
    }
    
    # Analyze requirements
    needs_high_availability = requirements.get("high_availability", False)
    needs_compliance = requirements.get("compliance", [])
    expected_users = requirements.get("expected_users", "medium")
    data_sensitivity = requirements.get("data_sensitivity", "standard")
    
    # Recommend services based on requirements
    if needs_high_availability and "aurora" not in current_services and "rds" in current_services:
        suggestions["recommended_services"].append({
            "service": "aurora",
            "reason": "Aurora provides better HA than standard RDS with automatic failover"
        })
    
    if needs_high_availability and "elasticache" not in current_services:
        suggestions["recommended_services"].append({
            "service": "elasticache",
            "reason": "Caching reduces database load and improves availability"
        })
    
    # Compliance requirements
    if "hipaa" in needs_compliance or "pci" in needs_compliance:
        if "kms" not in current_services:
            suggestions["recommended_services"].append({
                "service": "kms",
                "reason": f"KMS required for {'HIPAA' if 'hipaa' in needs_compliance else 'PCI-DSS'} encryption"
            })
        if "cloudtrail" not in current_services:
            suggestions["recommended_services"].append({
                "service": "cloudtrail",
                "reason": "CloudTrail required for compliance audit logging"
            })
        if "config" not in current_services:
            suggestions["recommended_services"].append({
                "service": "config",
                "reason": "AWS Config for compliance monitoring"
            })
    
    # Scale recommendations
    if expected_users == "high":
        suggestions["scaling_recommendations"].extend([
            "Implement auto-scaling groups for compute resources",
            "Use read replicas for database read scaling",
            "Consider DynamoDB for unlimited scaling needs",
            "Implement CloudFront for global content delivery"
        ])
    
    # Data sensitivity
    if data_sensitivity == "high":
        if "secrets_manager" not in current_services:
            suggestions["recommended_services"].append({
                "service": "secrets_manager",
                "reason": "Secure storage for sensitive credentials"
            })
        if "guardduty" not in current_services:
            suggestions["recommended_services"].append({
                "service": "guardduty",
                "reason": "Threat detection for sensitive workloads"
            })
    
    # Configuration tips based on pattern
    pattern_tips = {
        "web_application": [
            "Enable WAF rules for OWASP Top 10 protection",
            "Configure CloudFront with proper cache behaviors",
            "Use connection pooling for database connections",
            "Implement health checks on all load balancer targets"
        ],
        "api_backend": [
            "Implement API throttling and rate limiting",
            "Use request validation in API Gateway",
            "Enable API caching for frequently accessed endpoints",
            "Implement proper CORS configuration"
        ],
        "data_lake": [
            "Implement data lifecycle policies in S3",
            "Use columnar formats (Parquet) for analytics",
            "Partition data for efficient querying",
            "Implement proper IAM data access controls"
        ],
        "microservices": [
            "Implement circuit breakers for resilience",
            "Use service mesh for traffic management",
            "Implement distributed tracing with X-Ray",
            "Use async communication where possible"
        ]
    }
    
    suggestions["configuration_tips"] = pattern_tips.get(pattern, [])[:4]
    
    # Best practices
    suggestions["best_practices"] = [
        "Use Infrastructure as Code (CloudFormation/Terraform)",
        "Implement least privilege IAM policies",
        "Enable encryption at rest and in transit",
        "Set up comprehensive monitoring and alerting",
        "Document architecture decisions and runbooks"
    ]
    
    # Cost tier estimation
    service_count = len(current_services)
    if service_count <= 5:
        suggestions["estimated_cost_tier"] = "Low ($100-500/month)"
    elif service_count <= 10:
        suggestions["estimated_cost_tier"] = "Medium ($500-2,000/month)"
    elif service_count <= 15:
        suggestions["estimated_cost_tier"] = "High ($2,000-10,000/month)"
    else:
        suggestions["estimated_cost_tier"] = "Enterprise ($10,000+/month)"
    
    return suggestions


# ============================================================================
# MAIN ARCHITECTURE DESIGNER
# ============================================================================

class ArchitectureDesignerAI:
    """AI-Powered Architecture Designer with WAF alignment"""
    
    @staticmethod
    def render():
        """Main render method for the Architecture Designer"""
        
        st.markdown("## 🎨 AI-Powered Architecture Designer")
        st.markdown("Design AWS architectures aligned with the Well-Architected Framework")
        
        # Initialize session state
        if 'arch_design' not in st.session_state:
            st.session_state.arch_design = {
                'pattern': None,
                'complexity': None,
                'services': [],
                'requirements': {},
                'custom_services': [],
                'connections': []
            }
        
        # Design workflow tabs - now with 5 tabs including Upload & Analyze
        tabs = st.tabs([
            "1️⃣ Select Pattern",
            "2️⃣ Configure Services",
            "3️⃣ AI Recommendations",
            "4️⃣ Visualize & Export",
            "📤 Upload & Analyze"
        ])
        
        with tabs[0]:
            ArchitectureDesignerAI._render_pattern_selection()
        
        with tabs[1]:
            ArchitectureDesignerAI._render_service_configuration()
        
        with tabs[2]:
            ArchitectureDesignerAI._render_ai_recommendations()
        
        with tabs[3]:
            ArchitectureDesignerAI._render_visualization()
        
        with tabs[4]:
            ArchitectureDesignerAI._render_upload_analyze()
    
    @staticmethod
    def _render_pattern_selection():
        """Render pattern selection UI"""
        
        st.markdown("### 📋 Select Architecture Pattern")
        st.markdown("Choose a starting pattern that best matches your use case")
        
        # Pattern cards
        cols = st.columns(4)
        
        for i, (pattern_key, pattern_data) in enumerate(ARCHITECTURE_PATTERNS.items()):
            with cols[i % 4]:
                selected = st.session_state.arch_design.get('pattern') == pattern_key
                
                if st.button(
                    f"{pattern_data['icon']} {pattern_data['name']}",
                    key=f"pattern_{pattern_key}",
                    type="primary" if selected else "secondary",
                    use_container_width=True
                ):
                    st.session_state.arch_design['pattern'] = pattern_key
                    st.session_state.arch_design['complexity'] = None
                    st.session_state.arch_design['services'] = []
                    st.rerun()
                
                st.caption(pattern_data['description'])
        
        # Show complexity levels if pattern selected
        if st.session_state.arch_design.get('pattern'):
            pattern = st.session_state.arch_design['pattern']
            pattern_data = ARCHITECTURE_PATTERNS[pattern]
            
            st.markdown("---")
            st.markdown(f"### 📊 Select Complexity Level for {pattern_data['name']}")
            
            cols = st.columns(4)
            
            for i, (complexity_key, complexity_data) in enumerate(pattern_data['complexity_levels'].items()):
                with cols[i]:
                    selected = st.session_state.arch_design.get('complexity') == complexity_key
                    
                    # Color based on complexity
                    colors = {"simple": "🟢", "standard": "🟡", "enterprise": "🟠", "production": "🔴"}
                    
                    if st.button(
                        f"{colors[complexity_key]} {complexity_data['name']}",
                        key=f"complexity_{complexity_key}",
                        type="primary" if selected else "secondary",
                        use_container_width=True
                    ):
                        st.session_state.arch_design['complexity'] = complexity_key
                        st.session_state.arch_design['services'] = complexity_data['services'].copy()
                        st.rerun()
                    
                    st.caption(complexity_data['description'])
                    st.caption(f"📦 {len(complexity_data['services'])} services")
        
        # Requirements questionnaire
        if st.session_state.arch_design.get('complexity'):
            st.markdown("---")
            st.markdown("### 📝 Requirements (Optional)")
            
            col1, col2 = st.columns(2)
            
            with col1:
                ha = st.checkbox("High Availability Required", key="req_ha")
                st.session_state.arch_design['requirements']['high_availability'] = ha
                
                users = st.select_slider(
                    "Expected User Scale",
                    options=["low", "medium", "high", "very_high"],
                    value="medium",
                    key="req_users"
                )
                st.session_state.arch_design['requirements']['expected_users'] = users
            
            with col2:
                compliance = st.multiselect(
                    "Compliance Requirements",
                    ["hipaa", "pci", "soc2", "gdpr", "fedramp"],
                    key="req_compliance"
                )
                st.session_state.arch_design['requirements']['compliance'] = compliance
                
                data_sens = st.select_slider(
                    "Data Sensitivity",
                    options=["standard", "sensitive", "high"],
                    value="standard",
                    key="req_data"
                )
                st.session_state.arch_design['requirements']['data_sensitivity'] = data_sens
    
    @staticmethod
    def _render_service_configuration():
        """Render service configuration UI"""
        
        if not st.session_state.arch_design.get('services'):
            st.info("👆 Please select a pattern and complexity level first")
            return
        
        st.markdown("### 🔧 Configure Services")
        st.markdown("Add, remove, or modify services in your architecture")
        
        current_services = st.session_state.arch_design['services']
        
        # Current services
        st.markdown("#### Current Services")
        
        # Group services by category
        services_by_category = {}
        for service in current_services:
            service_info = AWS_SERVICES.get(service, {"category": "other", "name": service})
            category = service_info.get("category", "other")
            if category not in services_by_category:
                services_by_category[category] = []
            services_by_category[category].append(service)
        
        # Display by category
        for category, services in services_by_category.items():
            with st.expander(f"📁 {category.title()} ({len(services)} services)", expanded=True):
                cols = st.columns(4)
                for i, service in enumerate(services):
                    service_info = AWS_SERVICES.get(service, {"name": service, "color": "#999"})
                    with cols[i % 4]:
                        col1, col2 = st.columns([3, 1])
                        with col1:
                            st.markdown(f"**{service_info['name']}**")
                        with col2:
                            if st.button("❌", key=f"remove_{service}_{i}", help="Remove service"):
                                st.session_state.arch_design['services'].remove(service)
                                st.rerun()
        
        st.markdown("---")
        
        # Add services
        st.markdown("#### ➕ Add Services")
        
        # Category filter
        categories = list(set(s["category"] for s in AWS_SERVICES.values()))
        selected_category = st.selectbox("Filter by Category", ["All"] + sorted(categories))
        
        # Service selector
        available_services = []
        for service_key, service_info in AWS_SERVICES.items():
            if selected_category == "All" or service_info["category"] == selected_category:
                if service_key not in current_services:
                    available_services.append((service_key, service_info["name"]))
        
        if available_services:
            cols = st.columns(4)
            for i, (service_key, service_name) in enumerate(sorted(available_services, key=lambda x: x[1])):
                with cols[i % 4]:
                    if st.button(f"➕ {service_name}", key=f"add_{service_key}", use_container_width=True):
                        st.session_state.arch_design['services'].append(service_key)
                        st.rerun()
        else:
            st.info("All services in this category are already added")
        
        # Quick add common combinations
        st.markdown("---")
        st.markdown("#### ⚡ Quick Add Service Groups")
        
        quick_adds = {
            "Security Stack": ["waf", "shield", "guardduty", "security_hub", "kms", "secrets_manager"],
            "Monitoring Stack": ["cloudwatch", "cloudtrail", "config", "systems_manager"],
            "Caching Layer": ["elasticache", "cloudfront"],
            "Message Queue": ["sqs", "sns", "eventbridge"],
            "ML Platform": ["sagemaker", "bedrock", "s3"],
        }
        
        cols = st.columns(5)
        for i, (group_name, services) in enumerate(quick_adds.items()):
            with cols[i % 5]:
                if st.button(f"➕ {group_name}", key=f"quick_{group_name}", use_container_width=True):
                    for service in services:
                        if service not in st.session_state.arch_design['services']:
                            st.session_state.arch_design['services'].append(service)
                    st.rerun()
    
    @staticmethod
    def _render_ai_recommendations():
        """Render AI recommendations UI"""
        
        if not st.session_state.arch_design.get('services'):
            st.info("👆 Please select a pattern and services first")
            return
        
        st.markdown("### 🤖 AI-Powered Recommendations")
        
        current_services = st.session_state.arch_design['services']
        pattern = st.session_state.arch_design.get('pattern', 'web_application')
        complexity = st.session_state.arch_design.get('complexity', 'standard')
        requirements = st.session_state.arch_design.get('requirements', {})
        
        # Calculate WAF scores
        waf_scores = calculate_waf_scores(current_services)
        
        # WAF Score Overview
        st.markdown("#### 📊 WAF Alignment Score")
        
        col1, col2 = st.columns([1, 2])
        
        with col1:
            # Overall score gauge
            score = waf_scores['overall_score']
            color = "#4CAF50" if score >= 80 else "#FF9800" if score >= 60 else "#F44336"
            
            st.markdown(f"""
            <div style="text-align: center; padding: 20px; background: linear-gradient(135deg, {color}22, {color}44); 
                        border-radius: 10px; border: 2px solid {color};">
                <h1 style="margin: 0; color: {color}; font-size: 3rem;">{score}</h1>
                <p style="margin: 5px 0 0 0; color: #666;">Overall WAF Score</p>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            # Pillar scores
            import plotly.graph_objects as go
            
            pillar_scores = waf_scores['pillar_scores']
            
            fig = go.Figure()
            
            categories = list(pillar_scores.keys())
            values = list(pillar_scores.values())
            
            fig.add_trace(go.Scatterpolar(
                r=values + [values[0]],
                theta=[c.title() for c in categories] + [categories[0].title()],
                fill='toself',
                name='Current Score',
                line_color='#FF9900',
                fillcolor='rgba(255, 153, 0, 0.3)'
            ))
            
            # Add target line
            fig.add_trace(go.Scatterpolar(
                r=[80] * (len(categories) + 1),
                theta=[c.title() for c in categories] + [categories[0].title()],
                name='Target (80)',
                line_color='#4CAF50',
                line_dash='dash'
            ))
            
            fig.update_layout(
                polar=dict(radialaxis=dict(visible=True, range=[0, 100])),
                showlegend=True,
                height=300,
                margin=dict(l=50, r=50, t=30, b=30)
            )
            
            st.plotly_chart(fig, use_container_width=True)
        
        # Get AI suggestions
        suggestions = get_ai_suggestions(pattern, complexity, requirements, current_services)
        
        st.markdown("---")
        
        # Recommended services
        if suggestions['recommended_services']:
            st.markdown("#### 💡 Recommended Services to Add")
            
            for rec in suggestions['recommended_services']:
                service_info = AWS_SERVICES.get(rec['service'], {"name": rec['service'], "color": "#999"})
                
                col1, col2, col3 = st.columns([1, 3, 1])
                with col1:
                    st.markdown(f"**{service_info['name']}**")
                with col2:
                    st.caption(rec['reason'])
                with col3:
                    if st.button("➕ Add", key=f"ai_add_{rec['service']}", use_container_width=True):
                        st.session_state.arch_design['services'].append(rec['service'])
                        st.rerun()
        
        # WAF Recommendations
        if waf_scores['recommendations']:
            st.markdown("#### 🎯 WAF Improvement Recommendations")
            
            for rec in waf_scores['recommendations'][:5]:
                priority_color = {"High": "🔴", "Medium": "🟡", "Low": "🟢"}
                
                col1, col2, col3 = st.columns([1, 3, 1])
                with col1:
                    st.markdown(f"{priority_color[rec['priority']]} **{rec['pillar']}**")
                with col2:
                    st.caption(rec['recommendation'])
                with col3:
                    if rec['service'] not in current_services:
                        if st.button("➕ Add", key=f"waf_add_{rec['service']}", use_container_width=True):
                            st.session_state.arch_design['services'].append(rec['service'])
                            st.rerun()
        
        # Configuration tips
        st.markdown("---")
        st.markdown("#### 📝 Configuration Best Practices")
        
        for tip in suggestions['configuration_tips']:
            st.markdown(f"• {tip}")
        
        # Cost estimate
        st.markdown("---")
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("#### 💰 Estimated Cost Tier")
            st.info(suggestions['estimated_cost_tier'])
        
        with col2:
            st.markdown("#### 📈 Service Count")
            st.metric("Total Services", len(current_services))
    
    @staticmethod
    def _render_visualization():
        """Render architecture visualization"""
        
        if not st.session_state.arch_design.get('services'):
            st.info("👆 Please configure your architecture first")
            return
        
        st.markdown("### 📐 Architecture Visualization")
        
        current_services = st.session_state.arch_design['services']
        pattern = st.session_state.arch_design.get('pattern', 'custom')
        pattern_data = ARCHITECTURE_PATTERNS.get(pattern, {"name": "Custom Architecture"})
        
        # Generate architecture
        architecture = ArchitectureDesignerAI._create_architecture_from_services(
            current_services, 
            pattern_data['name']
        )
        
        # Generate SVG
        svg_content = generate_architecture_svg(architecture, width=1000, height=600)
        
        # Display SVG
        st.markdown("#### 🖼️ Architecture Diagram")
        st.markdown(svg_content, unsafe_allow_html=True)
        
        # Export options
        st.markdown("---")
        st.markdown("#### 📥 Export Options")
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.download_button(
                "📄 Download SVG",
                data=svg_content,
                file_name=f"architecture_{pattern}.svg",
                mime="image/svg+xml",
                use_container_width=True
            )
        
        with col2:
            # Generate CloudFormation template
            cf_template = ArchitectureDesignerAI._generate_cloudformation(current_services, pattern)
            st.download_button(
                "☁️ CloudFormation",
                data=cf_template,
                file_name=f"architecture_{pattern}.yaml",
                mime="text/yaml",
                use_container_width=True
            )
        
        with col3:
            # Generate Terraform
            tf_template = ArchitectureDesignerAI._generate_terraform(current_services, pattern)
            st.download_button(
                "🏗️ Terraform",
                data=tf_template,
                file_name=f"architecture_{pattern}.tf",
                mime="text/plain",
                use_container_width=True
            )
        
        with col4:
            # Export as JSON
            arch_json = json.dumps({
                "pattern": pattern,
                "services": current_services,
                "requirements": st.session_state.arch_design.get('requirements', {}),
                "waf_scores": calculate_waf_scores(current_services),
                "generated_at": datetime.now().isoformat()
            }, indent=2)
            st.download_button(
                "📋 Export JSON",
                data=arch_json,
                file_name=f"architecture_{pattern}.json",
                mime="application/json",
                use_container_width=True
            )
        
        # Service list
        st.markdown("---")
        st.markdown("#### 📦 Services in Architecture")
        
        services_by_category = {}
        for service in current_services:
            service_info = AWS_SERVICES.get(service, {"category": "other", "name": service})
            category = service_info.get("category", "other")
            if category not in services_by_category:
                services_by_category[category] = []
            services_by_category[category].append(service_info['name'])
        
        cols = st.columns(4)
        for i, (category, services) in enumerate(sorted(services_by_category.items())):
            with cols[i % 4]:
                st.markdown(f"**{category.title()}**")
                for service in services:
                    st.caption(f"• {service}")
    
    @staticmethod
    def _create_architecture_from_services(services: List[str], name: str) -> Architecture:
        """Create architecture definition from service list"""
        
        nodes = []
        connections = []
        
        # Create nodes
        for i, service in enumerate(services):
            service_info = AWS_SERVICES.get(service, {"name": service})
            nodes.append(ServiceNode(
                id=f"node_{i}",
                service_type=service,
                label=service_info.get("name", service)
            ))
        
        # Create logical connections based on service types
        # This is a simplified version - could be enhanced with more sophisticated logic
        
        # Find entry points (users, internet, api_gateway, cloudfront, route53)
        entry_services = ["users", "internet", "route53", "cloudfront", "api_gateway"]
        entry_nodes = [n for n in nodes if n.service_type in entry_services]
        
        # Find load balancers
        lb_services = ["alb", "nlb"]
        lb_nodes = [n for n in nodes if n.service_type in lb_services]
        
        # Find compute
        compute_services = ["ec2", "ecs", "eks", "lambda", "fargate"]
        compute_nodes = [n for n in nodes if n.service_type in compute_services]
        
        # Find databases
        db_services = ["rds", "aurora", "dynamodb", "elasticache", "redshift"]
        db_nodes = [n for n in nodes if n.service_type in db_services]
        
        # Find storage
        storage_services = ["s3", "efs", "ebs"]
        storage_nodes = [n for n in nodes if n.service_type in storage_services]
        
        # Create connections
        # Entry -> LB
        for entry in entry_nodes:
            for lb in lb_nodes:
                connections.append(Connection(source_id=entry.id, target_id=lb.id))
        
        # If no LB, entry -> compute
        if not lb_nodes:
            for entry in entry_nodes:
                for compute in compute_nodes[:1]:  # Just first compute
                    connections.append(Connection(source_id=entry.id, target_id=compute.id))
        
        # LB -> Compute
        for lb in lb_nodes:
            for compute in compute_nodes:
                connections.append(Connection(source_id=lb.id, target_id=compute.id))
        
        # Compute -> DB
        for compute in compute_nodes:
            for db in db_nodes:
                connections.append(Connection(source_id=compute.id, target_id=db.id, bidirectional=True))
        
        # Compute -> Storage
        for compute in compute_nodes:
            for storage in storage_nodes:
                connections.append(Connection(source_id=compute.id, target_id=storage.id, bidirectional=True))
        
        return Architecture(
            name=name,
            description=f"Architecture with {len(services)} services",
            nodes=nodes,
            connections=connections
        )
    
    @staticmethod
    def _generate_cloudformation(services: List[str], pattern: str) -> str:
        """Generate CloudFormation template stub"""
        
        template = f"""AWSTemplateFormatVersion: '2010-09-09'
Description: '{pattern} Architecture - Generated by AWS WAF Scanner Enterprise'

# ============================================================================
# This is a starter template. Customize parameters, resources, and outputs
# based on your specific requirements.
# ============================================================================

Parameters:
  Environment:
    Type: String
    Default: production
    AllowedValues:
      - development
      - staging
      - production
    Description: Environment name

  VPCCidr:
    Type: String
    Default: 10.0.0.0/16
    Description: VPC CIDR block

Resources:
  # VPC
  VPC:
    Type: AWS::EC2::VPC
    Properties:
      CidrBlock: !Ref VPCCidr
      EnableDnsHostnames: true
      EnableDnsSupport: true
      Tags:
        - Key: Name
          Value: !Sub '${{Environment}}-vpc'

"""
        
        # Add resource stubs for each service
        for service in services:
            service_info = AWS_SERVICES.get(service, {"name": service})
            template += f"""
  # {service_info['name']}
  # TODO: Configure {service_info['name']} resource
  # {service.upper().replace('_', '')}:
  #   Type: AWS::...
  #   Properties:
  #     ...

"""
        
        template += """
Outputs:
  VPCId:
    Description: VPC ID
    Value: !Ref VPC
    Export:
      Name: !Sub '${Environment}-vpc-id'
"""
        
        return template
    
    @staticmethod
    def _generate_terraform(services: List[str], pattern: str) -> str:
        """Generate Terraform template stub"""
        
        template = f"""# {pattern} Architecture
# Generated by AWS WAF Scanner Enterprise
# ============================================================================

terraform {{
  required_version = ">= 1.0"
  
  required_providers {{
    aws = {{
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }}
  }}
}}

# Variables
variable "environment" {{
  description = "Environment name"
  type        = string
  default     = "production"
}}

variable "region" {{
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}}

# Provider
provider "aws" {{
  region = var.region
  
  default_tags {{
    tags = {{
      Environment = var.environment
      ManagedBy   = "Terraform"
      Project     = "{pattern}"
    }}
  }}
}}

# VPC
resource "aws_vpc" "main" {{
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true
  
  tags = {{
    Name = "${{var.environment}}-vpc"
  }}
}}

"""
        
        # Add resource stubs
        for service in services:
            service_info = AWS_SERVICES.get(service, {"name": service})
            template += f"""
# {service_info['name']}
# TODO: Configure {service_info['name']} resource
# resource "aws_..." "{service}" {{
#   ...
# }}

"""
        
        template += """
# Outputs
output "vpc_id" {
  description = "VPC ID"
  value       = aws_vpc.main.id
}
"""
        
        return template
    
    @staticmethod
    def _render_upload_analyze():
        """Render the Upload & Analyze tab"""
        try:
            from architecture_upload_analyzer import render_upload_analyzer_tab
            render_upload_analyzer_tab()
        except ImportError as e:
            st.error(f"Upload Analyzer module not available: {e}")
            st.info("The Upload & Analyze feature requires the architecture_upload_analyzer module.")
        except Exception as e:
            st.error(f"Error loading Upload Analyzer: {e}")
            import traceback
            with st.expander("Error Details"):
                st.code(traceback.format_exc())


# ============================================================================
# RENDER FUNCTION
# ============================================================================

def render_architecture_designer_ai():
    """Main entry point for the Architecture Designer"""
    ArchitectureDesignerAI.render()
