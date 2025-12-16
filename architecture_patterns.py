"""
Architecture Patterns & Implementation Roadmap Module
Comprehensive enterprise architecture patterns, implementation guides, and cost analysis

Features:
- Industry-standard architectural patterns
- Detailed implementation roadmaps
- Cost analysis and TCO calculators
- Best practices by workload type
- Reference architectures with diagrams
"""

import streamlit as st
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass, field

# ============================================================================
# ARCHITECTURAL PATTERNS CATALOG
# ============================================================================

ARCHITECTURE_PATTERNS = {
    "microservices": {
        "name": "Microservices Architecture",
        "icon": "🔲",
        "category": "Application Architecture",
        "maturity": "Established",
        "complexity": "High",
        "description": "Decompose applications into loosely coupled, independently deployable services",
        "when_to_use": [
            "Large, complex applications requiring frequent updates",
            "Teams that can work independently on different services",
            "Applications requiring high scalability and resilience",
            "Organizations with mature DevOps practices"
        ],
        "when_to_avoid": [
            "Small applications or MVPs",
            "Teams without container/orchestration experience",
            "Applications with tightly coupled data requirements",
            "Limited operational capacity"
        ],
        "aws_services": {
            "Compute": ["EKS", "ECS", "Fargate", "Lambda"],
            "Networking": ["API Gateway", "App Mesh", "ALB", "Cloud Map"],
            "Data": ["DynamoDB", "Aurora", "ElastiCache"],
            "Messaging": ["SQS", "SNS", "EventBridge", "MSK"],
            "Observability": ["CloudWatch", "X-Ray", "OpenSearch"]
        },
        "implementation_phases": [
            {
                "phase": "Phase 1: Foundation",
                "duration": "4-6 weeks",
                "activities": [
                    "Define service boundaries using Domain-Driven Design",
                    "Set up container orchestration (EKS/ECS)",
                    "Implement CI/CD pipelines per service",
                    "Establish service mesh (App Mesh/Istio)",
                    "Configure centralized logging and monitoring"
                ],
                "deliverables": ["Service catalog", "Container platform", "CI/CD templates", "Monitoring dashboards"],
                "cost_estimate": "$5,000-15,000/month base infrastructure"
            },
            {
                "phase": "Phase 2: Core Services",
                "duration": "8-12 weeks",
                "activities": [
                    "Implement authentication/authorization service",
                    "Build API gateway and service discovery",
                    "Create shared libraries and SDKs",
                    "Implement distributed tracing",
                    "Set up database per service pattern"
                ],
                "deliverables": ["Auth service", "API gateway config", "Service SDKs", "Tracing setup"],
                "cost_estimate": "$10,000-25,000/month operational"
            },
            {
                "phase": "Phase 3: Migration",
                "duration": "12-24 weeks",
                "activities": [
                    "Identify strangler fig candidates",
                    "Extract services incrementally",
                    "Implement event-driven communication",
                    "Set up saga pattern for distributed transactions",
                    "Configure auto-scaling policies"
                ],
                "deliverables": ["Migrated services", "Event schemas", "Scaling policies"],
                "cost_estimate": "$15,000-40,000/month at scale"
            },
            {
                "phase": "Phase 4: Optimization",
                "duration": "Ongoing",
                "activities": [
                    "Implement circuit breakers and bulkheads",
                    "Optimize service-to-service communication",
                    "Fine-tune resource allocation",
                    "Implement chaos engineering",
                    "Continuous cost optimization"
                ],
                "deliverables": ["Resilience patterns", "Performance baselines", "Cost reports"],
                "cost_estimate": "10-30% reduction through optimization"
            }
        ],
        "cost_factors": {
            "compute": "40-50% of total cost",
            "networking": "10-15% (data transfer, load balancers)",
            "storage": "15-20% (databases, caches)",
            "observability": "10-15% (logging, monitoring, tracing)",
            "management": "10-20% (orchestration, service mesh)"
        },
        "reference_customers": ["Netflix", "Amazon", "Uber", "Airbnb"],
        "documentation": "https://microservices.io/"
    },
    
    "serverless": {
        "name": "Serverless Architecture",
        "icon": "⚡",
        "category": "Application Architecture",
        "maturity": "Established",
        "complexity": "Medium",
        "description": "Build applications using managed services that automatically scale and require no server management",
        "when_to_use": [
            "Variable or unpredictable workloads",
            "Event-driven processing requirements",
            "Rapid development with minimal ops overhead",
            "Cost optimization for sporadic workloads"
        ],
        "when_to_avoid": [
            "Long-running processes (>15 min)",
            "Applications requiring persistent connections",
            "Workloads with consistent high throughput",
            "Strict latency requirements (cold starts)"
        ],
        "aws_services": {
            "Compute": ["Lambda", "Fargate", "Step Functions"],
            "API": ["API Gateway", "AppSync"],
            "Data": ["DynamoDB", "Aurora Serverless", "S3"],
            "Messaging": ["SQS", "SNS", "EventBridge"],
            "Integration": ["Step Functions", "EventBridge Pipes"]
        },
        "implementation_phases": [
            {
                "phase": "Phase 1: Setup",
                "duration": "2-3 weeks",
                "activities": [
                    "Set up SAM or Serverless Framework",
                    "Configure IAM roles with least privilege",
                    "Implement Infrastructure as Code",
                    "Set up local development environment",
                    "Configure CI/CD for Lambda deployments"
                ],
                "deliverables": ["IaC templates", "CI/CD pipeline", "Dev environment"],
                "cost_estimate": "$100-500/month initial (pay-per-use)"
            },
            {
                "phase": "Phase 2: Core Functions",
                "duration": "4-8 weeks",
                "activities": [
                    "Implement core business logic as functions",
                    "Set up API Gateway endpoints",
                    "Configure DynamoDB tables with proper indexes",
                    "Implement authentication with Cognito",
                    "Set up event-driven triggers"
                ],
                "deliverables": ["Lambda functions", "API endpoints", "Data layer"],
                "cost_estimate": "$500-2,000/month moderate traffic"
            },
            {
                "phase": "Phase 3: Orchestration",
                "duration": "4-6 weeks",
                "activities": [
                    "Implement Step Functions for workflows",
                    "Set up EventBridge for event routing",
                    "Configure dead letter queues",
                    "Implement retry and error handling",
                    "Set up X-Ray tracing"
                ],
                "deliverables": ["Workflow definitions", "Event schemas", "Error handling"],
                "cost_estimate": "$1,000-5,000/month with orchestration"
            },
            {
                "phase": "Phase 4: Production",
                "duration": "2-4 weeks",
                "activities": [
                    "Configure provisioned concurrency for critical paths",
                    "Implement Lambda layers for shared code",
                    "Set up CloudWatch alarms and dashboards",
                    "Configure reserved concurrency limits",
                    "Implement cost allocation tags"
                ],
                "deliverables": ["Production config", "Monitoring", "Cost controls"],
                "cost_estimate": "Scales with usage, typically 60-80% less than EC2"
            }
        ],
        "cost_factors": {
            "compute": "Pay per invocation + duration",
            "api_gateway": "$3.50/million requests",
            "dynamodb": "Pay per request or provisioned capacity",
            "step_functions": "$0.025/1000 state transitions",
            "data_transfer": "Standard AWS rates apply"
        },
        "reference_customers": ["Coca-Cola", "iRobot", "Thomson Reuters"],
        "documentation": "https://aws.amazon.com/serverless/"
    },
    
    "event_driven": {
        "name": "Event-Driven Architecture",
        "icon": "📨",
        "category": "Integration Architecture",
        "maturity": "Established",
        "complexity": "Medium-High",
        "description": "Loosely coupled systems that communicate through events for real-time responsiveness",
        "when_to_use": [
            "Real-time data processing requirements",
            "Systems requiring loose coupling",
            "Complex integration scenarios",
            "Audit and compliance requirements"
        ],
        "when_to_avoid": [
            "Simple CRUD applications",
            "Strong consistency requirements",
            "Teams unfamiliar with async patterns",
            "Debugging complexity is a concern"
        ],
        "aws_services": {
            "Event Routing": ["EventBridge", "SNS", "Kinesis"],
            "Queuing": ["SQS", "MSK (Kafka)"],
            "Processing": ["Lambda", "ECS", "Kinesis Data Analytics"],
            "Storage": ["S3", "DynamoDB Streams"],
            "Orchestration": ["Step Functions"]
        },
        "implementation_phases": [
            {
                "phase": "Phase 1: Event Design",
                "duration": "3-4 weeks",
                "activities": [
                    "Define event schema standards (CloudEvents, AsyncAPI)",
                    "Create event catalog and registry",
                    "Design event naming conventions",
                    "Identify event producers and consumers",
                    "Plan event versioning strategy"
                ],
                "deliverables": ["Event catalog", "Schema registry", "Design standards"],
                "cost_estimate": "$500-1,500/month base"
            },
            {
                "phase": "Phase 2: Event Infrastructure",
                "duration": "4-6 weeks",
                "activities": [
                    "Set up EventBridge event bus",
                    "Configure event rules and targets",
                    "Implement schema registry",
                    "Set up dead letter queues",
                    "Configure event archival"
                ],
                "deliverables": ["Event bus", "Routing rules", "DLQ setup"],
                "cost_estimate": "$1,000-3,000/month"
            },
            {
                "phase": "Phase 3: Producer/Consumer",
                "duration": "6-10 weeks",
                "activities": [
                    "Implement event producers",
                    "Build event consumers with idempotency",
                    "Set up event replay capabilities",
                    "Implement saga pattern for distributed transactions",
                    "Configure monitoring and alerting"
                ],
                "deliverables": ["Producers", "Consumers", "Saga implementations"],
                "cost_estimate": "$2,000-8,000/month operational"
            }
        ],
        "cost_factors": {
            "eventbridge": "$1/million events",
            "sqs": "$0.40/million requests",
            "sns": "$0.50/million publishes",
            "kinesis": "$0.015/shard-hour + data",
            "msk": "$0.21/hour per broker minimum"
        },
        "reference_customers": ["Zalando", "Capital One", "Lego"],
        "documentation": "https://aws.amazon.com/event-driven-architecture/"
    },
    
    "data_lake": {
        "name": "Data Lake Architecture",
        "icon": "🏊",
        "category": "Data Architecture",
        "maturity": "Established",
        "complexity": "High",
        "description": "Centralized repository for structured and unstructured data at any scale",
        "when_to_use": [
            "Large volumes of diverse data sources",
            "Advanced analytics and ML requirements",
            "Need for data exploration and discovery",
            "Long-term data retention requirements"
        ],
        "when_to_avoid": [
            "Small data volumes (<100GB)",
            "Real-time transactional requirements",
            "Strict data governance not in place",
            "Limited data engineering expertise"
        ],
        "aws_services": {
            "Storage": ["S3", "S3 Glacier"],
            "Catalog": ["Glue Data Catalog", "Lake Formation"],
            "Processing": ["Glue ETL", "EMR", "Athena"],
            "Analytics": ["Redshift", "QuickSight", "SageMaker"],
            "Governance": ["Lake Formation", "Macie"]
        },
        "implementation_phases": [
            {
                "phase": "Phase 1: Foundation",
                "duration": "4-6 weeks",
                "activities": [
                    "Design S3 bucket structure (raw/curated/analytics zones)",
                    "Set up Lake Formation with fine-grained access",
                    "Implement data catalog with Glue",
                    "Configure encryption and security policies",
                    "Set up cross-account access patterns"
                ],
                "deliverables": ["S3 structure", "Lake Formation setup", "Data catalog"],
                "cost_estimate": "$2,000-5,000/month storage + compute"
            },
            {
                "phase": "Phase 2: Ingestion",
                "duration": "6-8 weeks",
                "activities": [
                    "Build batch ingestion pipelines with Glue",
                    "Set up streaming ingestion with Kinesis",
                    "Implement data quality checks",
                    "Configure change data capture (CDC)",
                    "Set up data lineage tracking"
                ],
                "deliverables": ["ETL jobs", "Streaming pipelines", "Quality framework"],
                "cost_estimate": "$3,000-10,000/month with processing"
            },
            {
                "phase": "Phase 3: Analytics",
                "duration": "6-10 weeks",
                "activities": [
                    "Configure Athena for ad-hoc queries",
                    "Set up Redshift for data warehouse",
                    "Implement QuickSight dashboards",
                    "Build ML feature store with SageMaker",
                    "Create self-service analytics capabilities"
                ],
                "deliverables": ["Query layer", "Dashboards", "ML infrastructure"],
                "cost_estimate": "$5,000-25,000/month at scale"
            }
        ],
        "cost_factors": {
            "s3_storage": "$0.023/GB/month (Standard)",
            "s3_glacier": "$0.004/GB/month",
            "glue_etl": "$0.44/DPU-hour",
            "athena": "$5/TB scanned",
            "redshift": "$0.25/hour per node"
        },
        "reference_customers": ["Netflix", "Expedia", "Johnson & Johnson"],
        "documentation": "https://aws.amazon.com/big-data/datalakes-and-analytics/"
    },
    
    "multi_tier": {
        "name": "Multi-Tier Web Architecture",
        "icon": "🏗️",
        "category": "Application Architecture",
        "maturity": "Well-Established",
        "complexity": "Low-Medium",
        "description": "Traditional layered architecture with presentation, application, and data tiers",
        "when_to_use": [
            "Standard web applications",
            "Clear separation of concerns required",
            "Moderate scalability requirements",
            "Teams familiar with traditional architectures"
        ],
        "when_to_avoid": [
            "Highly dynamic scaling requirements",
            "Real-time applications",
            "When microservices benefits outweigh complexity"
        ],
        "aws_services": {
            "Presentation": ["CloudFront", "S3", "Amplify"],
            "Load Balancing": ["ALB", "NLB"],
            "Application": ["EC2", "ECS", "Elastic Beanstalk"],
            "Data": ["RDS", "ElastiCache", "DynamoDB"],
            "Caching": ["ElastiCache", "CloudFront"]
        },
        "implementation_phases": [
            {
                "phase": "Phase 1: Infrastructure",
                "duration": "2-3 weeks",
                "activities": [
                    "Set up VPC with public/private subnets",
                    "Configure security groups and NACLs",
                    "Set up bastion hosts or Systems Manager",
                    "Configure NAT gateways",
                    "Implement IaC with CloudFormation/Terraform"
                ],
                "deliverables": ["VPC architecture", "Security config", "IaC templates"],
                "cost_estimate": "$500-1,500/month base"
            },
            {
                "phase": "Phase 2: Application Layer",
                "duration": "3-4 weeks",
                "activities": [
                    "Deploy application servers in Auto Scaling groups",
                    "Configure Application Load Balancer",
                    "Set up session management",
                    "Implement health checks",
                    "Configure CloudWatch monitoring"
                ],
                "deliverables": ["ASG config", "ALB setup", "Monitoring"],
                "cost_estimate": "$1,500-5,000/month with compute"
            },
            {
                "phase": "Phase 3: Data Layer",
                "duration": "2-3 weeks",
                "activities": [
                    "Deploy RDS with Multi-AZ",
                    "Configure read replicas if needed",
                    "Set up ElastiCache for session/caching",
                    "Implement automated backups",
                    "Configure parameter groups and monitoring"
                ],
                "deliverables": ["Database setup", "Cache layer", "Backup config"],
                "cost_estimate": "$1,000-4,000/month for data"
            },
            {
                "phase": "Phase 4: CDN & Security",
                "duration": "1-2 weeks",
                "activities": [
                    "Configure CloudFront distribution",
                    "Set up WAF rules",
                    "Implement SSL/TLS certificates",
                    "Configure security headers",
                    "Set up DDoS protection with Shield"
                ],
                "deliverables": ["CDN config", "WAF rules", "SSL setup"],
                "cost_estimate": "$200-1,000/month for CDN"
            }
        ],
        "cost_factors": {
            "ec2": "Based on instance type, ~$50-500/month per instance",
            "rds": "$100-1,000/month per instance",
            "alb": "$16/month + LCU charges",
            "cloudfront": "$0.085/GB first 10TB",
            "nat_gateway": "$32/month + data processing"
        },
        "reference_customers": ["Most traditional enterprises"],
        "documentation": "https://aws.amazon.com/architecture/reference-architecture-diagrams/"
    },
    
    "multi_region": {
        "name": "Multi-Region Active-Active",
        "icon": "🌍",
        "category": "Resilience Architecture",
        "maturity": "Advanced",
        "complexity": "Very High",
        "description": "Deploy applications across multiple AWS regions for global availability and disaster recovery",
        "when_to_use": [
            "Global user base requiring low latency",
            "Near-zero RPO/RTO requirements",
            "Regulatory requirements for data residency",
            "Mission-critical applications"
        ],
        "when_to_avoid": [
            "Regional-only user base",
            "Cost is a primary constraint",
            "Application doesn't support multi-region",
            "Limited operational expertise"
        ],
        "aws_services": {
            "Global": ["Route 53", "Global Accelerator", "CloudFront"],
            "Compute": ["EKS/ECS per region", "Lambda@Edge"],
            "Data": ["Aurora Global Database", "DynamoDB Global Tables", "S3 Cross-Region Replication"],
            "Networking": ["Transit Gateway", "PrivateLink"],
            "Orchestration": ["CloudFormation StackSets"]
        },
        "implementation_phases": [
            {
                "phase": "Phase 1: Design",
                "duration": "4-6 weeks",
                "activities": [
                    "Define active-active vs active-passive strategy",
                    "Design data replication approach",
                    "Plan traffic routing strategy",
                    "Define failover procedures",
                    "Document RTO/RPO requirements"
                ],
                "deliverables": ["Architecture design", "DR runbooks", "RTO/RPO targets"],
                "cost_estimate": "Architecture review costs"
            },
            {
                "phase": "Phase 2: Infrastructure",
                "duration": "6-8 weeks",
                "activities": [
                    "Deploy infrastructure in secondary region(s)",
                    "Set up cross-region networking",
                    "Configure Global Accelerator/Route 53",
                    "Implement Infrastructure as Code for all regions",
                    "Set up cross-region monitoring"
                ],
                "deliverables": ["Multi-region infra", "Networking", "Global routing"],
                "cost_estimate": "2x single-region cost minimum"
            },
            {
                "phase": "Phase 3: Data Replication",
                "duration": "4-8 weeks",
                "activities": [
                    "Configure Aurora Global Database",
                    "Set up DynamoDB Global Tables",
                    "Implement S3 Cross-Region Replication",
                    "Configure ElastiCache Global Datastore",
                    "Test replication lag and consistency"
                ],
                "deliverables": ["Data replication", "Consistency testing"],
                "cost_estimate": "$5,000-20,000/month for data replication"
            },
            {
                "phase": "Phase 4: Testing & Validation",
                "duration": "4-6 weeks",
                "activities": [
                    "Conduct regional failover tests",
                    "Validate data consistency after failover",
                    "Test application behavior during failure",
                    "Document and automate failover procedures",
                    "Establish regular DR testing schedule"
                ],
                "deliverables": ["DR test results", "Automated failover", "Test schedule"],
                "cost_estimate": "Ongoing testing costs"
            }
        ],
        "cost_factors": {
            "infrastructure": "2-3x single region",
            "data_transfer": "$0.02/GB inter-region",
            "global_accelerator": "$0.025/hour + data",
            "aurora_global": "Standard RDS + replication",
            "dynamodb_global": "Standard + 0.25 WCU per replicated write"
        },
        "reference_customers": ["Netflix", "Spotify", "Capital One"],
        "documentation": "https://aws.amazon.com/solutions/implementations/multi-region-application-architecture/"
    }
}

# ============================================================================
# INDUSTRY BEST PRACTICES
# ============================================================================

INDUSTRY_BEST_PRACTICES = {
    "financial_services": {
        "name": "Financial Services",
        "icon": "🏦",
        "compliance": ["PCI DSS", "SOX", "GLBA", "SOC 2"],
        "key_patterns": [
            "Multi-region active-active for availability",
            "Zero-trust security architecture",
            "Real-time fraud detection with ML",
            "Event sourcing for audit trails"
        ],
        "aws_services": ["KMS", "CloudHSM", "Macie", "GuardDuty", "Config", "CloudTrail"],
        "architecture_considerations": [
            "Data encryption at rest and in transit (mandatory)",
            "Strict network segmentation",
            "Immutable audit logs",
            "Real-time monitoring and alerting",
            "Disaster recovery with <1 hour RTO"
        ],
        "typical_costs": {
            "small": "$10,000-30,000/month",
            "medium": "$50,000-150,000/month",
            "enterprise": "$200,000-1,000,000/month"
        }
    },
    
    "healthcare": {
        "name": "Healthcare & Life Sciences",
        "icon": "🏥",
        "compliance": ["HIPAA", "HITRUST", "FDA 21 CFR Part 11"],
        "key_patterns": [
            "PHI data isolation and encryption",
            "Audit logging for all data access",
            "Secure data sharing with external parties",
            "AI/ML for diagnostics and research"
        ],
        "aws_services": ["HealthLake", "Comprehend Medical", "Macie", "Lake Formation"],
        "architecture_considerations": [
            "BAA (Business Associate Agreement) with AWS",
            "HIPAA-eligible services only",
            "Patient data de-identification",
            "Cross-organization data sharing",
            "Research data lakes with governance"
        ],
        "typical_costs": {
            "small": "$5,000-20,000/month",
            "medium": "$30,000-100,000/month",
            "enterprise": "$150,000-500,000/month"
        }
    },
    
    "ecommerce": {
        "name": "E-Commerce & Retail",
        "icon": "🛒",
        "compliance": ["PCI DSS", "GDPR", "CCPA"],
        "key_patterns": [
            "Elastic scaling for traffic spikes",
            "Real-time personalization",
            "Multi-region for global reach",
            "Event-driven inventory management"
        ],
        "aws_services": ["Personalize", "Pinpoint", "Kinesis", "ElastiCache"],
        "architecture_considerations": [
            "Handle 10-100x normal traffic (Black Friday)",
            "Sub-second response times",
            "Cart and session persistence",
            "Fraud detection at checkout",
            "Real-time inventory sync"
        ],
        "typical_costs": {
            "small": "$3,000-15,000/month",
            "medium": "$20,000-80,000/month",
            "enterprise": "$100,000-400,000/month"
        }
    },
    
    "saas": {
        "name": "SaaS / Multi-tenant",
        "icon": "☁️",
        "compliance": ["SOC 2", "ISO 27001", "GDPR"],
        "key_patterns": [
            "Multi-tenant data isolation",
            "Tenant-aware scaling",
            "Usage-based billing integration",
            "Feature flagging per tenant"
        ],
        "aws_services": ["Control Tower", "Organizations", "Cognito", "AppSync"],
        "architecture_considerations": [
            "Silo vs pool vs bridge tenancy models",
            "Noisy neighbor prevention",
            "Tenant onboarding automation",
            "Per-tenant cost allocation",
            "Self-service tenant management"
        ],
        "typical_costs": {
            "startup": "$2,000-10,000/month",
            "growth": "$15,000-60,000/month",
            "scale": "$80,000-300,000/month"
        }
    },
    
    "media_entertainment": {
        "name": "Media & Entertainment",
        "icon": "🎬",
        "compliance": ["MPAA", "Content protection"],
        "key_patterns": [
            "Global content delivery",
            "Live streaming at scale",
            "Media asset management",
            "AI-powered content analysis"
        ],
        "aws_services": ["MediaLive", "MediaConvert", "CloudFront", "Rekognition"],
        "architecture_considerations": [
            "Low-latency streaming (<5s)",
            "4K/HDR transcoding at scale",
            "DRM and content protection",
            "Global edge caching",
            "AI content moderation"
        ],
        "typical_costs": {
            "small": "$5,000-25,000/month",
            "medium": "$40,000-150,000/month",
            "enterprise": "$200,000-1,000,000/month"
        }
    }
}

# ============================================================================
# IMPLEMENTATION ROADMAP TEMPLATES
# ============================================================================

IMPLEMENTATION_ROADMAPS = {
    "cloud_native_modernization": {
        "name": "Cloud-Native Modernization",
        "duration": "12-18 months",
        "phases": [
            {
                "name": "Discovery & Assessment",
                "duration": "4-6 weeks",
                "objectives": [
                    "Inventory existing applications and dependencies",
                    "Assess application modernization candidates",
                    "Define target architecture",
                    "Establish success metrics"
                ],
                "deliverables": [
                    "Application portfolio analysis",
                    "Modernization prioritization matrix",
                    "Target state architecture",
                    "Business case with ROI"
                ],
                "team": ["Solutions Architect", "Application Owners", "Business Stakeholders"],
                "tools": ["AWS Migration Hub", "CloudEndure", "Application Discovery Service"],
                "risks": ["Incomplete discovery", "Underestimated dependencies"],
                "cost": "$20,000-50,000 (assessment)"
            },
            {
                "name": "Foundation",
                "duration": "6-8 weeks",
                "objectives": [
                    "Establish landing zone with Control Tower",
                    "Implement network architecture",
                    "Set up security baselines",
                    "Create CI/CD pipelines"
                ],
                "deliverables": [
                    "Multi-account structure",
                    "Network connectivity (VPC, Transit Gateway)",
                    "Security controls and guardrails",
                    "CI/CD platform"
                ],
                "team": ["Cloud Architect", "Security Engineer", "DevOps Engineer"],
                "tools": ["Control Tower", "Organizations", "Service Catalog", "CodePipeline"],
                "risks": ["Security gaps", "Network complexity"],
                "cost": "$30,000-80,000 (setup)"
            },
            {
                "name": "Pilot Migration",
                "duration": "8-12 weeks",
                "objectives": [
                    "Migrate 2-3 pilot applications",
                    "Validate architecture patterns",
                    "Establish operational procedures",
                    "Train operations team"
                ],
                "deliverables": [
                    "Migrated pilot applications",
                    "Runbooks and playbooks",
                    "Monitoring and alerting",
                    "Trained team"
                ],
                "team": ["Migration Team", "Application Teams", "Operations"],
                "tools": ["AWS Migration Hub", "DMS", "CloudEndure"],
                "risks": ["Performance issues", "Integration failures"],
                "cost": "$50,000-150,000 (pilot)"
            },
            {
                "name": "Scale Migration",
                "duration": "6-12 months",
                "objectives": [
                    "Migrate remaining applications in waves",
                    "Implement automation at scale",
                    "Optimize for cost and performance",
                    "Decommission legacy infrastructure"
                ],
                "deliverables": [
                    "Fully migrated portfolio",
                    "Optimized architecture",
                    "Cost savings realization",
                    "Decommissioned data centers"
                ],
                "team": ["Migration Factory", "Application Teams", "Project Management"],
                "tools": ["AWS Migration Hub", "CloudFormation/Terraform", "Cost Explorer"],
                "risks": ["Timeline slippage", "Budget overrun", "Business disruption"],
                "cost": "$200,000-1,000,000+ (migration)"
            }
        ],
        "success_metrics": [
            "Application availability (99.9%+)",
            "Cost reduction (20-40%)",
            "Deployment frequency (10x improvement)",
            "Mean time to recovery (<1 hour)"
        ]
    },
    
    "containerization": {
        "name": "Container Modernization",
        "duration": "6-12 months",
        "phases": [
            {
                "name": "Container Strategy",
                "duration": "2-4 weeks",
                "objectives": [
                    "Define container platform (EKS/ECS)",
                    "Assess applications for containerization",
                    "Design CI/CD for containers",
                    "Plan skill development"
                ],
                "deliverables": [
                    "Platform selection rationale",
                    "Containerization candidates",
                    "CI/CD design",
                    "Training plan"
                ],
                "team": ["Platform Architect", "DevOps Lead"],
                "tools": ["EKS", "ECS", "ECR", "Copilot"],
                "cost": "$10,000-30,000"
            },
            {
                "name": "Platform Setup",
                "duration": "4-6 weeks",
                "objectives": [
                    "Deploy container platform",
                    "Configure networking and security",
                    "Set up container registry",
                    "Implement GitOps pipeline"
                ],
                "deliverables": [
                    "Production-ready cluster",
                    "Security policies",
                    "Container registry",
                    "GitOps pipeline"
                ],
                "team": ["Platform Team", "Security"],
                "tools": ["EKS", "ECR", "ArgoCD/Flux", "OPA Gatekeeper"],
                "cost": "$20,000-60,000"
            },
            {
                "name": "Application Containerization",
                "duration": "8-16 weeks",
                "objectives": [
                    "Containerize priority applications",
                    "Implement Kubernetes manifests/Helm charts",
                    "Set up service mesh (optional)",
                    "Configure auto-scaling"
                ],
                "deliverables": [
                    "Containerized applications",
                    "Helm charts",
                    "Service mesh (if needed)",
                    "Scaling policies"
                ],
                "team": ["Application Teams", "Platform Team"],
                "tools": ["Docker", "Helm", "Karpenter", "App Mesh/Istio"],
                "cost": "$40,000-150,000"
            },
            {
                "name": "Operations & Optimization",
                "duration": "Ongoing",
                "objectives": [
                    "Implement observability stack",
                    "Fine-tune resource allocation",
                    "Optimize costs with Spot/Graviton",
                    "Establish SRE practices"
                ],
                "deliverables": [
                    "Observability platform",
                    "Resource optimization",
                    "Cost reports",
                    "SRE runbooks"
                ],
                "team": ["SRE", "Platform Team"],
                "tools": ["Prometheus", "Grafana", "CloudWatch", "Karpenter"],
                "cost": "Ongoing operational cost"
            }
        ],
        "success_metrics": [
            "Container density improvement",
            "Deployment time reduction",
            "Infrastructure cost savings",
            "Developer productivity increase"
        ]
    }
}

# ============================================================================
# COST ESTIMATION MODELS
# ============================================================================

COST_MODELS = {
    "small_startup": {
        "name": "Startup / Small Business",
        "users": "1K-10K",
        "requests": "1M-10M/month",
        "data": "100GB-1TB",
        "monthly_estimate": {
            "min": 500,
            "max": 3000,
            "typical": 1500
        },
        "breakdown": {
            "Compute (EC2/Lambda)": "30-40%",
            "Database (RDS/DynamoDB)": "25-35%",
            "Storage (S3)": "5-10%",
            "Networking": "10-15%",
            "Other services": "10-20%"
        },
        "optimization_potential": "20-40%"
    },
    "mid_market": {
        "name": "Mid-Market",
        "users": "10K-100K",
        "requests": "10M-100M/month",
        "data": "1TB-10TB",
        "monthly_estimate": {
            "min": 5000,
            "max": 25000,
            "typical": 12000
        },
        "breakdown": {
            "Compute": "35-45%",
            "Database": "20-30%",
            "Storage": "10-15%",
            "Networking": "10-15%",
            "Observability": "5-10%",
            "Security": "5-10%"
        },
        "optimization_potential": "25-45%"
    },
    "enterprise": {
        "name": "Enterprise",
        "users": "100K-1M+",
        "requests": "100M-1B+/month",
        "data": "10TB-1PB+",
        "monthly_estimate": {
            "min": 50000,
            "max": 500000,
            "typical": 150000
        },
        "breakdown": {
            "Compute": "30-40%",
            "Database": "20-25%",
            "Storage": "10-15%",
            "Networking/CDN": "10-15%",
            "Analytics/ML": "10-15%",
            "Security/Compliance": "5-10%",
            "Observability": "5-10%"
        },
        "optimization_potential": "30-50%"
    }
}

# ============================================================================
# TCO CALCULATOR
# ============================================================================

def calculate_tco(
    compute_hours: int,
    storage_gb: int,
    data_transfer_gb: int,
    database_hours: int,
    commitment_level: str = "on_demand"
) -> Dict:
    """Calculate Total Cost of Ownership"""
    
    # Base rates (simplified)
    rates = {
        "compute_hourly": 0.10,  # t3.medium equivalent
        "storage_gb": 0.023,
        "transfer_gb": 0.09,
        "database_hourly": 0.25  # db.t3.medium equivalent
    }
    
    # Discount factors
    discounts = {
        "on_demand": 1.0,
        "1yr_reserved": 0.6,
        "3yr_reserved": 0.4,
        "spot": 0.3
    }
    
    discount = discounts.get(commitment_level, 1.0)
    
    compute_cost = compute_hours * rates["compute_hourly"] * discount
    storage_cost = storage_gb * rates["storage_gb"]
    transfer_cost = data_transfer_gb * rates["transfer_gb"]
    database_cost = database_hours * rates["database_hourly"] * discount
    
    total = compute_cost + storage_cost + transfer_cost + database_cost
    
    return {
        "compute": compute_cost,
        "storage": storage_cost,
        "data_transfer": transfer_cost,
        "database": database_cost,
        "total_monthly": total,
        "total_annual": total * 12,
        "commitment": commitment_level,
        "potential_savings": (1 - discount) * (compute_cost / discount + database_cost / discount)
    }

# ============================================================================
# RENDER FUNCTIONS
# ============================================================================

def render_architecture_patterns_tab():
    """Render architecture patterns and implementation tab"""
    st.markdown("""
    <div style="background: linear-gradient(135deg, #1565C0 0%, #0D47A1 100%); padding: 1.5rem 2rem; border-radius: 12px; margin-bottom: 1.5rem;">
        <h2 style="color: white; margin: 0;">🏛️ Architecture Patterns & Implementation Roadmaps</h2>
        <p style="color: #BBDEFB; margin: 0.3rem 0 0 0;">Industry-standard patterns, implementation guides, and cost analysis</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Sub-tabs
    tabs = st.tabs(["🏗️ Architecture Patterns", "📋 Implementation Roadmaps", "💰 Cost Analysis", "🏢 Industry Best Practices"])
    
    with tabs[0]:
        render_patterns_section()
    
    with tabs[1]:
        render_roadmaps_section()
    
    with tabs[2]:
        render_cost_analysis_section()
    
    with tabs[3]:
        render_industry_practices_section()

def render_patterns_section():
    """Render architecture patterns"""
    st.markdown("### 🏗️ Enterprise Architecture Patterns")
    
    # Pattern selector
    col1, col2 = st.columns([1, 2])
    
    with col1:
        st.markdown("**Select Pattern:**")
        # Use radio buttons to avoid duplicate key errors
        pattern_options = [f"{pattern['icon']} {pattern['name']}" for key, pattern in ARCHITECTURE_PATTERNS.items()]
        pattern_keys = list(ARCHITECTURE_PATTERNS.keys())
        
        # Get current selection index
        current_key = st.session_state.get('selected_pattern', 'microservices')
        current_index = pattern_keys.index(current_key) if current_key in pattern_keys else 0
        
        selected_index = st.radio(
            "Choose a pattern:",
            range(len(pattern_options)),
            format_func=lambda i: pattern_options[i],
            index=current_index,
            key="pattern_selector",
            label_visibility="collapsed"
        )
        
        # Update session state
        st.session_state.selected_pattern = pattern_keys[selected_index]
    
    with col2:
        selected = st.session_state.get('selected_pattern', 'microservices')
        pattern = ARCHITECTURE_PATTERNS.get(selected, ARCHITECTURE_PATTERNS['microservices'])
        
        st.markdown(f"## {pattern['icon']} {pattern['name']}")
        st.markdown(f"**Category:** {pattern['category']} | **Complexity:** {pattern['complexity']} | **Maturity:** {pattern['maturity']}")
        st.markdown(f"_{pattern['description']}_")
        
        # When to use
        col_a, col_b = st.columns(2)
        with col_a:
            st.markdown("**✅ When to Use:**")
            for item in pattern['when_to_use']:
                st.markdown(f"- {item}")
        with col_b:
            st.markdown("**❌ When to Avoid:**")
            for item in pattern['when_to_avoid']:
                st.markdown(f"- {item}")
        
        # AWS Services
        st.markdown("---")
        st.markdown("**🔧 AWS Services:**")
        cols = st.columns(len(pattern['aws_services']))
        for idx, (category, services) in enumerate(pattern['aws_services'].items()):
            with cols[idx]:
                st.markdown(f"**{category}**")
                for svc in services:
                    st.markdown(f"- {svc}")
        
        # Implementation phases
        st.markdown("---")
        st.markdown("### 📅 Implementation Phases")
        
        for phase in pattern['implementation_phases']:
            with st.expander(f"**{phase['phase']}** ({phase['duration']})", expanded=False):
                st.markdown("**Activities:**")
                for activity in phase['activities']:
                    st.markdown(f"- {activity}")
                
                st.markdown("**Deliverables:**")
                st.markdown(", ".join(phase['deliverables']))
                
                st.info(f"💰 **Estimated Cost:** {phase['cost_estimate']}")
        
        # Cost factors
        st.markdown("---")
        st.markdown("### 💰 Cost Breakdown")
        for factor, pct in pattern['cost_factors'].items():
            st.markdown(f"- **{factor.replace('_', ' ').title()}:** {pct}")
        
        # Reference
        st.markdown("---")
        st.markdown(f"**Reference Customers:** {', '.join(pattern['reference_customers'])}")
        st.markdown(f"[📖 Documentation]({pattern['documentation']})")

def render_roadmaps_section():
    """Render implementation roadmaps"""
    st.markdown("### 📋 Implementation Roadmaps")
    
    roadmap_choice = st.selectbox(
        "Select Roadmap",
        list(IMPLEMENTATION_ROADMAPS.keys()),
        format_func=lambda x: IMPLEMENTATION_ROADMAPS[x]['name']
    )
    
    roadmap = IMPLEMENTATION_ROADMAPS[roadmap_choice]
    
    st.markdown(f"## {roadmap['name']}")
    st.markdown(f"**Total Duration:** {roadmap['duration']}")
    
    # Timeline visualization
    st.markdown("### 📅 Phase Timeline")
    
    total_phases = len(roadmap['phases'])
    cols = st.columns(total_phases)
    
    for idx, phase in enumerate(roadmap['phases']):
        with cols[idx]:
            st.markdown(f"""
            <div style="background: linear-gradient(135deg, #FF9900 0%, #FF6600 100%); padding: 1rem; border-radius: 8px; color: white; text-align: center;">
                <strong>Phase {idx + 1}</strong><br>
                <span style="font-size: 0.8rem;">{phase['name']}</span><br>
                <span style="font-size: 0.7rem;">{phase['duration']}</span>
            </div>
            """, unsafe_allow_html=True)
    
    st.markdown("---")
    
    # Detailed phases
    for idx, phase in enumerate(roadmap['phases']):
        with st.expander(f"**Phase {idx + 1}: {phase['name']}** - {phase['duration']}", expanded=idx == 0):
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("**🎯 Objectives:**")
                for obj in phase['objectives']:
                    st.markdown(f"- {obj}")
                
                st.markdown("**📦 Deliverables:**")
                for deliv in phase['deliverables']:
                    st.markdown(f"- {deliv}")
            
            with col2:
                st.markdown("**👥 Team:**")
                st.markdown(", ".join(phase['team']))
                
                st.markdown("**🔧 Tools:**")
                st.markdown(", ".join(phase['tools']))
                
                st.markdown("**⚠️ Risks:**")
                for risk in phase['risks']:
                    st.markdown(f"- {risk}")
            
            st.info(f"💰 **Estimated Cost:** {phase['cost']}")
    
    # Success metrics
    st.markdown("---")
    st.markdown("### 📊 Success Metrics")
    for metric in roadmap['success_metrics']:
        st.markdown(f"- ✅ {metric}")

def render_cost_analysis_section():
    """Render cost analysis and TCO calculator"""
    st.markdown("### 💰 Cost Analysis & TCO Calculator")
    
    # Cost models overview
    st.markdown("#### 📊 Cost Models by Business Size")
    
    cols = st.columns(3)
    for idx, (key, model) in enumerate(COST_MODELS.items()):
        with cols[idx]:
            st.markdown(f"""
            <div style="background: white; padding: 1.5rem; border-radius: 10px; border: 1px solid #e0e0e0; text-align: center;">
                <h3 style="color: #232F3E; margin: 0;">{model['name']}</h3>
                <p style="color: #666; font-size: 0.8rem;">Users: {model['users']}<br>Requests: {model['requests']}</p>
                <div style="font-size: 2rem; color: #FF9900; font-weight: bold;">${model['monthly_estimate']['typical']:,}/mo</div>
                <p style="color: #666; font-size: 0.8rem;">Range: ${model['monthly_estimate']['min']:,} - ${model['monthly_estimate']['max']:,}</p>
                <p style="color: #388E3C; font-weight: bold;">Optimization: {model['optimization_potential']}</p>
            </div>
            """, unsafe_allow_html=True)
    
    st.markdown("---")
    
    # TCO Calculator
    st.markdown("#### 🧮 TCO Calculator")
    
    col1, col2 = st.columns(2)
    
    with col1:
        compute_hours = st.slider("Compute Hours/Month", 100, 10000, 2000)
        storage_gb = st.slider("Storage (GB)", 10, 10000, 500)
        data_transfer_gb = st.slider("Data Transfer (GB)", 10, 5000, 200)
        database_hours = st.slider("Database Hours/Month", 100, 5000, 1000)
        
        commitment = st.selectbox(
            "Commitment Level",
            ["on_demand", "1yr_reserved", "3yr_reserved", "spot"],
            format_func=lambda x: {
                "on_demand": "On-Demand (No commitment)",
                "1yr_reserved": "1-Year Reserved (40% savings)",
                "3yr_reserved": "3-Year Reserved (60% savings)",
                "spot": "Spot Instances (70% savings)"
            }[x]
        )
    
    with col2:
        tco = calculate_tco(compute_hours, storage_gb, data_transfer_gb, database_hours, commitment)
        
        st.markdown(f"""
        <div style="background: linear-gradient(135deg, #232F3E 0%, #37475A 100%); padding: 2rem; border-radius: 12px; color: white;">
            <h3 style="color: #FF9900; margin: 0;">Estimated Monthly Cost</h3>
            <div style="font-size: 3rem; font-weight: bold; margin: 1rem 0;">${tco['total_monthly']:,.2f}</div>
            <p style="color: #ccc;">Annual: ${tco['total_annual']:,.2f}</p>
            
            <h4 style="color: #FF9900; margin-top: 1.5rem;">Breakdown</h4>
            <p>Compute: ${tco['compute']:,.2f}</p>
            <p>Database: ${tco['database']:,.2f}</p>
            <p>Storage: ${tco['storage']:,.2f}</p>
            <p>Data Transfer: ${tco['data_transfer']:,.2f}</p>
            
            <div style="background: #388E3C; padding: 0.5rem 1rem; border-radius: 5px; margin-top: 1rem;">
                <strong>💰 Savings with {commitment}: ${tco['potential_savings']:,.2f}/month</strong>
            </div>
        </div>
        """, unsafe_allow_html=True)

def render_industry_practices_section():
    """Render industry best practices"""
    st.markdown("### 🏢 Industry Best Practices")
    
    industry = st.selectbox(
        "Select Industry",
        list(INDUSTRY_BEST_PRACTICES.keys()),
        format_func=lambda x: f"{INDUSTRY_BEST_PRACTICES[x]['icon']} {INDUSTRY_BEST_PRACTICES[x]['name']}"
    )
    
    practice = INDUSTRY_BEST_PRACTICES[industry]
    
    st.markdown(f"## {practice['icon']} {practice['name']}")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("**📋 Compliance Requirements:**")
        for comp in practice['compliance']:
            st.markdown(f"- {comp}")
        
        st.markdown("**🏗️ Key Architecture Patterns:**")
        for pattern in practice['key_patterns']:
            st.markdown(f"- {pattern}")
    
    with col2:
        st.markdown("**🔧 Recommended AWS Services:**")
        st.markdown(", ".join(practice['aws_services']))
        
        st.markdown("**⚠️ Architecture Considerations:**")
        for consideration in practice['architecture_considerations']:
            st.markdown(f"- {consideration}")
    
    st.markdown("---")
    st.markdown("### 💰 Typical Cost Ranges")
    
    cols = st.columns(3)
    for idx, (size, cost) in enumerate(practice['typical_costs'].items()):
        with cols[idx]:
            st.markdown(f"""
            <div style="background: #f5f5f5; padding: 1rem; border-radius: 8px; text-align: center;">
                <strong>{size.replace('_', ' ').title()}</strong><br>
                <span style="font-size: 1.2rem; color: #FF9900;">{cost}</span>
            </div>
            """, unsafe_allow_html=True)

# ============================================================================
# EXPORT
# ============================================================================

__all__ = [
    'ARCHITECTURE_PATTERNS',
    'INDUSTRY_BEST_PRACTICES', 
    'IMPLEMENTATION_ROADMAPS',
    'COST_MODELS',
    'calculate_tco',
    'render_architecture_patterns_tab'
]