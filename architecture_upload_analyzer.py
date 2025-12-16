"""
Architecture Upload & Analyzer
==============================
AI-powered analysis of existing architecture designs with WAF scoring.

Supported Formats:
- PDF (Architecture diagrams and documentation)
- PowerPoint (.pptx) - Presentation slides
- Word Documents (.docx) - Architecture documentation
- Terraform (.tf, .tfvars) - Infrastructure as Code
- AWS CDK (Python, TypeScript)
- CloudFormation (YAML, JSON)
- Draw.io / Lucidchart exports

Features:
- Automatic service detection
- WAF pillar scoring
- Improvement recommendations
- Gap analysis
- Remediation roadmap
- Cost impact estimation

Version: 4.1.0
"""

import streamlit as st
import json
import re
import yaml
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
import io

# Import WAF scoring from architecture designer
try:
    from architecture_designer_ai import (
        calculate_waf_scores, 
        AWS_SERVICES,
        generate_waf_recommendations
    )
except ImportError:
    # Fallback if not available
    AWS_SERVICES = {}
    def calculate_waf_scores(services):
        return {"overall_score": 50, "pillar_scores": {}}
    def generate_waf_recommendations(services, scores):
        return []

# ============================================================================
# SERVICE DETECTION PATTERNS
# ============================================================================

# Terraform resource patterns
TERRAFORM_PATTERNS = {
    "aws_instance": "ec2",
    "aws_launch_template": "ec2",
    "aws_autoscaling_group": "ec2",
    "aws_lb": "alb",
    "aws_alb": "alb",
    "aws_elb": "alb",
    "aws_lb_target_group": "alb",
    "aws_s3_bucket": "s3",
    "aws_s3_bucket_versioning": "s3",
    "aws_rds_instance": "rds",
    "aws_db_instance": "rds",
    "aws_rds_cluster": "aurora",
    "aws_aurora_cluster": "aurora",
    "aws_dynamodb_table": "dynamodb",
    "aws_lambda_function": "lambda",
    "aws_lambda_permission": "lambda",
    "aws_ecs_cluster": "ecs",
    "aws_ecs_service": "ecs",
    "aws_ecs_task_definition": "ecs",
    "aws_eks_cluster": "eks",
    "aws_eks_node_group": "eks",
    "aws_vpc": "vpc",
    "aws_subnet": "vpc",
    "aws_internet_gateway": "vpc",
    "aws_nat_gateway": "nat_gateway",
    "aws_route53_zone": "route53",
    "aws_route53_record": "route53",
    "aws_cloudfront_distribution": "cloudfront",
    "aws_api_gateway_rest_api": "api_gateway",
    "aws_apigatewayv2_api": "api_gateway",
    "aws_sqs_queue": "sqs",
    "aws_sns_topic": "sns",
    "aws_kinesis_stream": "kinesis",
    "aws_elasticache_cluster": "elasticache",
    "aws_elasticache_replication_group": "elasticache",
    "aws_kms_key": "kms",
    "aws_secretsmanager_secret": "secrets_manager",
    "aws_cognito_user_pool": "cognito",
    "aws_waf_web_acl": "waf",
    "aws_wafv2_web_acl": "waf",
    "aws_shield_protection": "shield",
    "aws_guardduty_detector": "guardduty",
    "aws_securityhub_account": "security_hub",
    "aws_cloudwatch_log_group": "cloudwatch",
    "aws_cloudwatch_metric_alarm": "cloudwatch",
    "aws_cloudtrail": "cloudtrail",
    "aws_config_configuration_recorder": "config",
    "aws_iam_role": "iam",
    "aws_iam_policy": "iam",
    "aws_sagemaker_notebook_instance": "sagemaker",
    "aws_sagemaker_endpoint": "sagemaker",
    "aws_glue_catalog_database": "glue",
    "aws_glue_crawler": "glue",
    "aws_athena_workgroup": "athena",
    "aws_redshift_cluster": "redshift",
    "aws_efs_file_system": "efs",
    "aws_fsx_lustre_file_system": "fsx",
    "aws_mq_broker": "mq",
    "aws_sfn_state_machine": "step_functions",
    "aws_eventbridge_rule": "eventbridge",
    "aws_events_rule": "eventbridge",
    "aws_acm_certificate": "acm",
    "aws_ssm_parameter": "systems_manager",
}

# CloudFormation resource patterns
CLOUDFORMATION_PATTERNS = {
    "AWS::EC2::Instance": "ec2",
    "AWS::EC2::LaunchTemplate": "ec2",
    "AWS::AutoScaling::AutoScalingGroup": "ec2",
    "AWS::ElasticLoadBalancingV2::LoadBalancer": "alb",
    "AWS::ElasticLoadBalancing::LoadBalancer": "alb",
    "AWS::S3::Bucket": "s3",
    "AWS::RDS::DBInstance": "rds",
    "AWS::RDS::DBCluster": "aurora",
    "AWS::DynamoDB::Table": "dynamodb",
    "AWS::Lambda::Function": "lambda",
    "AWS::ECS::Cluster": "ecs",
    "AWS::ECS::Service": "ecs",
    "AWS::ECS::TaskDefinition": "ecs",
    "AWS::EKS::Cluster": "eks",
    "AWS::EKS::Nodegroup": "eks",
    "AWS::EC2::VPC": "vpc",
    "AWS::EC2::Subnet": "vpc",
    "AWS::EC2::NatGateway": "nat_gateway",
    "AWS::Route53::HostedZone": "route53",
    "AWS::CloudFront::Distribution": "cloudfront",
    "AWS::ApiGateway::RestApi": "api_gateway",
    "AWS::ApiGatewayV2::Api": "api_gateway",
    "AWS::SQS::Queue": "sqs",
    "AWS::SNS::Topic": "sns",
    "AWS::Kinesis::Stream": "kinesis",
    "AWS::ElastiCache::CacheCluster": "elasticache",
    "AWS::ElastiCache::ReplicationGroup": "elasticache",
    "AWS::KMS::Key": "kms",
    "AWS::SecretsManager::Secret": "secrets_manager",
    "AWS::Cognito::UserPool": "cognito",
    "AWS::WAFv2::WebACL": "waf",
    "AWS::Shield::Protection": "shield",
    "AWS::GuardDuty::Detector": "guardduty",
    "AWS::SecurityHub::Hub": "security_hub",
    "AWS::Logs::LogGroup": "cloudwatch",
    "AWS::CloudWatch::Alarm": "cloudwatch",
    "AWS::CloudTrail::Trail": "cloudtrail",
    "AWS::Config::ConfigurationRecorder": "config",
    "AWS::IAM::Role": "iam",
    "AWS::IAM::Policy": "iam",
    "AWS::SageMaker::NotebookInstance": "sagemaker",
    "AWS::Glue::Database": "glue",
    "AWS::Athena::WorkGroup": "athena",
    "AWS::Redshift::Cluster": "redshift",
    "AWS::EFS::FileSystem": "efs",
    "AWS::StepFunctions::StateMachine": "step_functions",
    "AWS::Events::Rule": "eventbridge",
    "AWS::CertificateManager::Certificate": "acm",
    "AWS::SSM::Parameter": "systems_manager",
}

# Text-based service detection (for PDFs, Word docs, etc.)
TEXT_SERVICE_PATTERNS = {
    r'\bEC2\b|\bElastic Compute\b|\binstance[s]?\b': 'ec2',
    r'\bLambda\b|\bserverless function[s]?\b': 'lambda',
    r'\bS3\b|\bSimple Storage\b|\bobject storage\b': 's3',
    r'\bRDS\b|\bRelational Database\b|\bMySQL\b|\bPostgreSQL\b|\bMariaDB\b': 'rds',
    r'\bAurora\b': 'aurora',
    r'\bDynamoDB\b|\bNoSQL\b': 'dynamodb',
    r'\bECS\b|\bElastic Container Service\b': 'ecs',
    r'\bEKS\b|\bElastic Kubernetes\b|\bKubernetes\b': 'eks',
    r'\bFargate\b': 'fargate',
    r'\bALB\b|\bApplication Load Balancer\b|\bload balanc': 'alb',
    r'\bNLB\b|\bNetwork Load Balancer\b': 'nlb',
    r'\bCloudFront\b|\bCDN\b|\bcontent delivery\b': 'cloudfront',
    r'\bRoute\s?53\b|\bDNS\b': 'route53',
    r'\bAPI Gateway\b|\bREST API\b|\bHTTP API\b': 'api_gateway',
    r'\bVPC\b|\bVirtual Private Cloud\b': 'vpc',
    r'\bNAT Gateway\b': 'nat_gateway',
    r'\bSQS\b|\bSimple Queue\b|\bmessage queue\b': 'sqs',
    r'\bSNS\b|\bSimple Notification\b|\bpush notification\b': 'sns',
    r'\bKinesis\b|\bstreaming\b': 'kinesis',
    r'\bElastiCache\b|\bRedis\b|\bMemcached\b|\bcaching\b': 'elasticache',
    r'\bCognito\b|\buser pool\b|\bidentity pool\b': 'cognito',
    r'\bWAF\b|\bWeb Application Firewall\b': 'waf',
    r'\bShield\b|\bDDoS\b': 'shield',
    r'\bGuardDuty\b|\bthreat detection\b': 'guardduty',
    r'\bSecurity Hub\b': 'security_hub',
    r'\bKMS\b|\bKey Management\b|\bencryption key\b': 'kms',
    r'\bSecrets Manager\b|\bsecret[s]?\b': 'secrets_manager',
    r'\bCloudWatch\b|\bmonitoring\b|\bmetric[s]?\b|\balarm[s]?\b': 'cloudwatch',
    r'\bCloudTrail\b|\baudit\b|\blogging\b': 'cloudtrail',
    r'\bConfig\b|\bcompliance\b': 'config',
    r'\bIAM\b|\bidentity\b|\baccess management\b': 'iam',
    r'\bSageMaker\b|\bmachine learning\b|\bML\b': 'sagemaker',
    r'\bBedrock\b|\bGenerative AI\b|\bLLM\b': 'bedrock',
    r'\bGlue\b|\bETL\b': 'glue',
    r'\bAthena\b|\bquery\b': 'athena',
    r'\bRedshift\b|\bdata warehouse\b': 'redshift',
    r'\bQuickSight\b|\bBI\b|\bdashboard\b': 'quicksight',
    r'\bEFS\b|\bElastic File System\b|\bfile storage\b': 'efs',
    r'\bFSx\b': 'fsx',
    r'\bStep Functions\b|\bworkflow\b|\borchestration\b': 'step_functions',
    r'\bEventBridge\b|\bevent[s]?\b': 'eventbridge',
    r'\bACM\b|\bcertificate\b|\bSSL\b|\bTLS\b': 'acm',
    r'\bSystems Manager\b|\bSSM\b|\bParameter Store\b': 'systems_manager',
    r'\bDirect Connect\b': 'direct_connect',
    r'\bTransit Gateway\b': 'transit_gateway',
}

# Security best practices to check
SECURITY_CHECKS = {
    "encryption_at_rest": {
        "patterns": [r'encrypt', r'kms', r'sse-s3', r'sse-kms', r'aws:kms'],
        "recommendation": "Enable encryption at rest for all data stores",
        "pillar": "security",
        "weight": 10
    },
    "encryption_in_transit": {
        "patterns": [r'https', r'tls', r'ssl', r'acm', r'certificate'],
        "recommendation": "Enable encryption in transit (TLS/SSL)",
        "pillar": "security",
        "weight": 10
    },
    "waf_protection": {
        "patterns": [r'waf', r'web.*acl', r'firewall'],
        "recommendation": "Add AWS WAF for web application protection",
        "pillar": "security",
        "weight": 15
    },
    "ddos_protection": {
        "patterns": [r'shield', r'ddos'],
        "recommendation": "Enable AWS Shield for DDoS protection",
        "pillar": "security",
        "weight": 10
    },
    "monitoring": {
        "patterns": [r'cloudwatch', r'alarm', r'metric', r'monitor'],
        "recommendation": "Implement CloudWatch monitoring and alarms",
        "pillar": "operational",
        "weight": 15
    },
    "logging": {
        "patterns": [r'cloudtrail', r'log.*group', r'audit', r'logging'],
        "recommendation": "Enable CloudTrail and centralized logging",
        "pillar": "operational",
        "weight": 10
    },
    "backup": {
        "patterns": [r'backup', r'snapshot', r'recovery', r'replica'],
        "recommendation": "Implement backup and disaster recovery",
        "pillar": "reliability",
        "weight": 15
    },
    "multi_az": {
        "patterns": [r'multi.?az', r'availability.*zone', r'az-[a-z]'],
        "recommendation": "Deploy across multiple Availability Zones",
        "pillar": "reliability",
        "weight": 15
    },
    "auto_scaling": {
        "patterns": [r'auto.*scal', r'scaling.*policy', r'target.*tracking'],
        "recommendation": "Implement auto-scaling for variable workloads",
        "pillar": "performance",
        "weight": 10
    },
    "caching": {
        "patterns": [r'elasticache', r'redis', r'memcached', r'cloudfront', r'cache'],
        "recommendation": "Add caching layer for improved performance",
        "pillar": "performance",
        "weight": 10
    },
    "cost_tags": {
        "patterns": [r'tags', r'cost.*center', r'environment', r'project'],
        "recommendation": "Implement tagging strategy for cost allocation",
        "pillar": "cost",
        "weight": 10
    },
    "right_sizing": {
        "patterns": [r't3\.', r't4g\.', r'graviton', r'spot', r'reserved'],
        "recommendation": "Consider right-sizing and cost-optimized instance types",
        "pillar": "cost",
        "weight": 10
    },
}


# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class AnalysisResult:
    """Results of architecture analysis"""
    detected_services: List[str]
    service_counts: Dict[str, int]
    waf_scores: Dict[str, Any]
    security_findings: List[Dict[str, Any]]
    recommendations: List[Dict[str, Any]]
    gaps: List[Dict[str, Any]]
    improvement_roadmap: List[Dict[str, Any]]
    estimated_improvement: float
    source_type: str
    raw_content: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


# ============================================================================
# FILE PARSERS
# ============================================================================

class ArchitectureParser:
    """Parse various architecture file formats"""
    
    @staticmethod
    def parse_terraform(content: str) -> Tuple[List[str], Dict[str, int]]:
        """Parse Terraform files to extract AWS services"""
        services = []
        service_counts = {}
        
        for pattern, service in TERRAFORM_PATTERNS.items():
            # Count resource declarations
            matches = re.findall(rf'resource\s+"{pattern}"', content)
            if matches:
                count = len(matches)
                services.append(service)
                service_counts[service] = service_counts.get(service, 0) + count
        
        # Also check for module references
        module_services = re.findall(r'source\s*=\s*"[^"]*/([\w-]+)"', content)
        for mod in module_services:
            mod_lower = mod.lower()
            for tf_pattern, service in TERRAFORM_PATTERNS.items():
                if service in mod_lower:
                    if service not in services:
                        services.append(service)
        
        return list(set(services)), service_counts
    
    @staticmethod
    def parse_cloudformation(content: str) -> Tuple[List[str], Dict[str, int]]:
        """Parse CloudFormation templates (YAML or JSON)"""
        services = []
        service_counts = {}
        
        try:
            # Try YAML first
            try:
                template = yaml.safe_load(content)
            except:
                # Try JSON
                template = json.loads(content)
            
            if template and 'Resources' in template:
                for resource_name, resource_def in template['Resources'].items():
                    resource_type = resource_def.get('Type', '')
                    if resource_type in CLOUDFORMATION_PATTERNS:
                        service = CLOUDFORMATION_PATTERNS[resource_type]
                        services.append(service)
                        service_counts[service] = service_counts.get(service, 0) + 1
        except:
            # Fallback to pattern matching
            for pattern, service in CLOUDFORMATION_PATTERNS.items():
                if pattern in content:
                    services.append(service)
                    service_counts[service] = service_counts.get(service, 0) + 1
        
        return list(set(services)), service_counts
    
    @staticmethod
    def parse_cdk(content: str) -> Tuple[List[str], Dict[str, int]]:
        """Parse AWS CDK code (Python or TypeScript)"""
        services = []
        service_counts = {}
        
        # CDK import patterns
        cdk_patterns = {
            r'aws_ec2|ec2\.Instance|ec2\.Vpc': 'ec2',
            r'aws_lambda|lambda_\.Function': 'lambda',
            r'aws_s3|s3\.Bucket': 's3',
            r'aws_rds|rds\.DatabaseInstance': 'rds',
            r'aws_dynamodb|dynamodb\.Table': 'dynamodb',
            r'aws_ecs|ecs\.Cluster|ecs\.FargateService': 'ecs',
            r'aws_eks|eks\.Cluster': 'eks',
            r'aws_elasticloadbalancingv2|elbv2\.ApplicationLoadBalancer': 'alb',
            r'aws_cloudfront|cloudfront\.Distribution': 'cloudfront',
            r'aws_apigateway|apigateway\.RestApi': 'api_gateway',
            r'aws_sqs|sqs\.Queue': 'sqs',
            r'aws_sns|sns\.Topic': 'sns',
            r'aws_cognito|cognito\.UserPool': 'cognito',
            r'aws_wafv2|wafv2\.WebAcl': 'waf',
            r'aws_kms|kms\.Key': 'kms',
            r'aws_secretsmanager|secretsmanager\.Secret': 'secrets_manager',
            r'aws_cloudwatch|cloudwatch\.Alarm': 'cloudwatch',
            r'aws_iam|iam\.Role': 'iam',
        }
        
        for pattern, service in cdk_patterns.items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                services.append(service)
                service_counts[service] = service_counts.get(service, 0) + len(matches)
        
        return list(set(services)), service_counts
    
    @staticmethod
    def parse_text(content: str) -> Tuple[List[str], Dict[str, int]]:
        """Parse text content (PDF, Word, etc.) for service mentions"""
        services = []
        service_counts = {}
        
        content_lower = content.lower()
        
        for pattern, service in TEXT_SERVICE_PATTERNS.items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                if service not in services:
                    services.append(service)
                service_counts[service] = service_counts.get(service, 0) + len(matches)
        
        return services, service_counts


# ============================================================================
# SECURITY ANALYZER
# ============================================================================

class SecurityAnalyzer:
    """Analyze security posture of architecture"""
    
    @staticmethod
    def analyze(content: str, detected_services: List[str]) -> Tuple[List[Dict], List[Dict]]:
        """Analyze content for security best practices"""
        findings = []
        gaps = []
        
        content_lower = content.lower()
        
        for check_name, check_config in SECURITY_CHECKS.items():
            found = False
            for pattern in check_config['patterns']:
                if re.search(pattern, content_lower):
                    found = True
                    break
            
            if found:
                findings.append({
                    "check": check_name,
                    "status": "✅ Implemented",
                    "pillar": check_config['pillar'],
                    "details": f"Found evidence of {check_name.replace('_', ' ')}"
                })
            else:
                gaps.append({
                    "check": check_name,
                    "status": "❌ Missing",
                    "pillar": check_config['pillar'],
                    "recommendation": check_config['recommendation'],
                    "weight": check_config['weight']
                })
        
        # Service-specific checks
        if 's3' in detected_services:
            if not re.search(r'versioning|bucket.*version', content_lower):
                gaps.append({
                    "check": "s3_versioning",
                    "status": "❌ Missing",
                    "pillar": "reliability",
                    "recommendation": "Enable S3 bucket versioning for data protection",
                    "weight": 5
                })
            if not re.search(r'block.*public|public.*access.*block', content_lower):
                gaps.append({
                    "check": "s3_public_access",
                    "status": "⚠️ Review",
                    "pillar": "security",
                    "recommendation": "Block public access to S3 buckets",
                    "weight": 10
                })
        
        if 'rds' in detected_services or 'aurora' in detected_services:
            if not re.search(r'multi.?az|availability.*zone', content_lower):
                gaps.append({
                    "check": "rds_multi_az",
                    "status": "❌ Missing",
                    "pillar": "reliability",
                    "recommendation": "Enable Multi-AZ for database high availability",
                    "weight": 15
                })
            if not re.search(r'automated.*backup|backup.*retention', content_lower):
                gaps.append({
                    "check": "rds_backup",
                    "status": "⚠️ Review",
                    "pillar": "reliability",
                    "recommendation": "Configure automated backups with appropriate retention",
                    "weight": 10
                })
        
        if 'ec2' in detected_services:
            if not re.search(r'security.*group|sg-', content_lower):
                gaps.append({
                    "check": "ec2_security_groups",
                    "status": "⚠️ Review",
                    "pillar": "security",
                    "recommendation": "Define restrictive security group rules",
                    "weight": 10
                })
        
        if 'lambda' in detected_services:
            if not re.search(r'vpc|subnet', content_lower):
                gaps.append({
                    "check": "lambda_vpc",
                    "status": "⚠️ Review",
                    "pillar": "security",
                    "recommendation": "Consider VPC configuration for Lambda if accessing private resources",
                    "weight": 5
                })
        
        return findings, gaps


# ============================================================================
# MAIN ANALYZER
# ============================================================================

class ArchitectureAnalyzer:
    """Main architecture analyzer class"""
    
    @staticmethod
    def analyze_file(file_content: bytes, file_name: str, file_type: str) -> AnalysisResult:
        """Analyze uploaded file and return results"""
        
        # Decode content based on file type
        content = ""
        source_type = "unknown"
        
        try:
            if file_type in ['tf', 'tfvars']:
                content = file_content.decode('utf-8')
                source_type = "terraform"
                services, service_counts = ArchitectureParser.parse_terraform(content)
                
            elif file_type in ['yaml', 'yml', 'json'] or 'cloudformation' in file_name.lower():
                content = file_content.decode('utf-8')
                source_type = "cloudformation"
                services, service_counts = ArchitectureParser.parse_cloudformation(content)
                
            elif file_type == 'py' and ('cdk' in file_name.lower() or 'stack' in file_name.lower()):
                content = file_content.decode('utf-8')
                source_type = "cdk_python"
                services, service_counts = ArchitectureParser.parse_cdk(content)
                
            elif file_type == 'ts' and ('cdk' in file_name.lower() or 'stack' in file_name.lower()):
                content = file_content.decode('utf-8')
                source_type = "cdk_typescript"
                services, service_counts = ArchitectureParser.parse_cdk(content)
                
            elif file_type == 'txt' or file_type == 'md':
                content = file_content.decode('utf-8')
                source_type = "text"
                services, service_counts = ArchitectureParser.parse_text(content)
                
            else:
                # Try to decode as text
                try:
                    content = file_content.decode('utf-8')
                    source_type = "text"
                    services, service_counts = ArchitectureParser.parse_text(content)
                except:
                    content = str(file_content)
                    source_type = "binary"
                    services, service_counts = ArchitectureParser.parse_text(content)
        
        except Exception as e:
            services = []
            service_counts = {}
            content = f"Error parsing file: {str(e)}"
        
        # Calculate WAF scores
        waf_scores = calculate_waf_scores(services)
        
        # Analyze security
        security_findings, gaps = SecurityAnalyzer.analyze(content, services)
        
        # Generate recommendations
        recommendations = ArchitectureAnalyzer._generate_recommendations(services, gaps, waf_scores)
        
        # Generate improvement roadmap
        roadmap = ArchitectureAnalyzer._generate_roadmap(gaps, recommendations)
        
        # Calculate potential improvement
        current_score = waf_scores.get('overall_score', 50)
        potential_improvement = min(100 - current_score, sum(g.get('weight', 5) for g in gaps) * 0.5)
        
        return AnalysisResult(
            detected_services=services,
            service_counts=service_counts,
            waf_scores=waf_scores,
            security_findings=security_findings,
            recommendations=recommendations,
            gaps=gaps,
            improvement_roadmap=roadmap,
            estimated_improvement=potential_improvement,
            source_type=source_type,
            raw_content=content[:5000],  # Limit stored content
            metadata={
                "file_name": file_name,
                "file_type": file_type,
                "analyzed_at": datetime.now().isoformat()
            }
        )
    
    @staticmethod
    def _generate_recommendations(services: List[str], gaps: List[Dict], waf_scores: Dict) -> List[Dict]:
        """Generate prioritized recommendations"""
        recommendations = []
        
        pillar_scores = waf_scores.get('pillar_scores', {})
        
        # Priority 1: Critical security gaps
        security_gaps = [g for g in gaps if g['pillar'] == 'security']
        for gap in security_gaps[:3]:
            recommendations.append({
                "priority": "🔴 Critical",
                "category": "Security",
                "recommendation": gap['recommendation'],
                "impact": f"+{gap['weight']} points",
                "effort": "Medium",
                "pillar": "security"
            })
        
        # Priority 2: Reliability gaps
        reliability_gaps = [g for g in gaps if g['pillar'] == 'reliability']
        for gap in reliability_gaps[:2]:
            recommendations.append({
                "priority": "🟠 High",
                "category": "Reliability",
                "recommendation": gap['recommendation'],
                "impact": f"+{gap['weight']} points",
                "effort": "Medium",
                "pillar": "reliability"
            })
        
        # Priority 3: Service-specific recommendations
        if 'waf' not in services and any(s in services for s in ['alb', 'api_gateway', 'cloudfront']):
            recommendations.append({
                "priority": "🔴 Critical",
                "category": "Security",
                "recommendation": "Add AWS WAF to protect web-facing resources",
                "impact": "+15-20 points",
                "effort": "Low",
                "pillar": "security",
                "service_to_add": "waf"
            })
        
        if 'guardduty' not in services:
            recommendations.append({
                "priority": "🟠 High",
                "category": "Security",
                "recommendation": "Enable GuardDuty for threat detection",
                "impact": "+10-15 points",
                "effort": "Low",
                "pillar": "security",
                "service_to_add": "guardduty"
            })
        
        if 'cloudwatch' not in services:
            recommendations.append({
                "priority": "🟠 High",
                "category": "Operations",
                "recommendation": "Implement CloudWatch monitoring and alerting",
                "impact": "+15-20 points",
                "effort": "Medium",
                "pillar": "operational",
                "service_to_add": "cloudwatch"
            })
        
        if 'cloudtrail' not in services:
            recommendations.append({
                "priority": "🟡 Medium",
                "category": "Compliance",
                "recommendation": "Enable CloudTrail for audit logging",
                "impact": "+10-15 points",
                "effort": "Low",
                "pillar": "operational",
                "service_to_add": "cloudtrail"
            })
        
        # Priority 4: Performance & Cost
        if 'elasticache' not in services and any(s in services for s in ['rds', 'aurora', 'dynamodb']):
            recommendations.append({
                "priority": "🟡 Medium",
                "category": "Performance",
                "recommendation": "Add ElastiCache for database query caching",
                "impact": "+10 points",
                "effort": "Medium",
                "pillar": "performance",
                "service_to_add": "elasticache"
            })
        
        if 'cloudfront' not in services and 's3' in services:
            recommendations.append({
                "priority": "🟡 Medium",
                "category": "Performance & Cost",
                "recommendation": "Use CloudFront CDN for S3 content delivery",
                "impact": "+10-15 points",
                "effort": "Low",
                "pillar": "performance",
                "service_to_add": "cloudfront"
            })
        
        return recommendations[:10]  # Top 10 recommendations
    
    @staticmethod
    def _generate_roadmap(gaps: List[Dict], recommendations: List[Dict]) -> List[Dict]:
        """Generate improvement roadmap"""
        roadmap = []
        
        # Phase 1: Quick Wins (Low effort, high impact)
        quick_wins = [r for r in recommendations if r.get('effort') == 'Low']
        if quick_wins:
            roadmap.append({
                "phase": "Phase 1: Quick Wins",
                "timeline": "Week 1-2",
                "items": quick_wins[:3],
                "expected_improvement": "+15-25 points"
            })
        
        # Phase 2: Security Hardening
        security_items = [r for r in recommendations if r['pillar'] == 'security' and r.get('effort') != 'Low']
        if security_items:
            roadmap.append({
                "phase": "Phase 2: Security Hardening",
                "timeline": "Week 3-4",
                "items": security_items[:3],
                "expected_improvement": "+10-20 points"
            })
        
        # Phase 3: Operational Excellence
        ops_items = [r for r in recommendations if r['pillar'] == 'operational']
        reliability_items = [r for r in recommendations if r['pillar'] == 'reliability']
        if ops_items or reliability_items:
            roadmap.append({
                "phase": "Phase 3: Operational Excellence",
                "timeline": "Week 5-6",
                "items": (ops_items + reliability_items)[:3],
                "expected_improvement": "+10-15 points"
            })
        
        # Phase 4: Optimization
        perf_items = [r for r in recommendations if r['pillar'] in ['performance', 'cost']]
        if perf_items:
            roadmap.append({
                "phase": "Phase 4: Optimization",
                "timeline": "Week 7-8",
                "items": perf_items[:3],
                "expected_improvement": "+5-15 points"
            })
        
        return roadmap


# ============================================================================
# STREAMLIT UI
# ============================================================================

def render_upload_analyzer_tab():
    """Render the Upload & Analyze tab"""
    
    st.markdown("## 📤 Upload & Analyze Architecture")
    st.markdown("Upload your existing architecture for AI-powered WAF assessment")
    
    # File upload section
    st.markdown("### 📁 Upload Architecture Files")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        uploaded_files = st.file_uploader(
            "Upload architecture files",
            type=['tf', 'tfvars', 'yaml', 'yml', 'json', 'py', 'ts', 'txt', 'md', 'pdf', 'docx', 'pptx'],
            accept_multiple_files=True,
            help="Supported: Terraform, CloudFormation, CDK, PDF, Word, PowerPoint, or text descriptions"
        )
    
    with col2:
        st.markdown("**Supported Formats:**")
        st.markdown("""
        - 📜 Terraform (`.tf`, `.tfvars`)
        - ☁️ CloudFormation (`.yaml`, `.json`)
        - 🔧 AWS CDK (`.py`, `.ts`)
        - 📄 PDF Documents (`.pdf`)
        - 📝 Word Documents (`.docx`)
        - 📊 PowerPoint (`.pptx`)
        - 📝 Text/Markdown (`.txt`, `.md`)
        """)
    
    # Text input option
    st.markdown("### ✏️ Or Paste Architecture Description")
    
    text_input = st.text_area(
        "Paste your architecture code or description",
        height=200,
        placeholder="""Paste Terraform code, CloudFormation template, or describe your architecture:

Example:
"Our application uses CloudFront for CDN, ALB for load balancing, 
ECS Fargate for containers, Aurora PostgreSQL for database, 
and S3 for static assets. We have CloudWatch for monitoring."
"""
    )
    
    # Analyze button
    col1, col2, col3 = st.columns([1, 1, 2])
    
    with col1:
        analyze_files = st.button("🔍 Analyze Files", type="primary", disabled=not uploaded_files)
    
    with col2:
        analyze_text = st.button("🔍 Analyze Text", type="primary", disabled=not text_input)
    
    # Process analysis
    if analyze_files and uploaded_files:
        _process_file_analysis(uploaded_files)
    
    if analyze_text and text_input:
        _process_text_analysis(text_input)
    
    # Show results if available
    if 'architecture_analysis' in st.session_state:
        _display_analysis_results(st.session_state.architecture_analysis)


def _process_file_analysis(uploaded_files):
    """Process uploaded files for analysis"""
    
    with st.spinner("🔄 Analyzing architecture files..."):
        all_services = []
        all_service_counts = {}
        all_content = ""
        
        for uploaded_file in uploaded_files:
            file_content = uploaded_file.read()
            file_name = uploaded_file.name
            file_type = file_name.split('.')[-1].lower()
            
            result = ArchitectureAnalyzer.analyze_file(file_content, file_name, file_type)
            
            all_services.extend(result.detected_services)
            for svc, count in result.service_counts.items():
                all_service_counts[svc] = all_service_counts.get(svc, 0) + count
            all_content += result.raw_content + "\n"
        
        # Combine results
        all_services = list(set(all_services))
        waf_scores = calculate_waf_scores(all_services)
        security_findings, gaps = SecurityAnalyzer.analyze(all_content, all_services)
        recommendations = ArchitectureAnalyzer._generate_recommendations(all_services, gaps, waf_scores)
        roadmap = ArchitectureAnalyzer._generate_roadmap(gaps, recommendations)
        
        current_score = waf_scores.get('overall_score', 50)
        potential_improvement = min(100 - current_score, sum(g.get('weight', 5) for g in gaps) * 0.5)
        
        st.session_state.architecture_analysis = AnalysisResult(
            detected_services=all_services,
            service_counts=all_service_counts,
            waf_scores=waf_scores,
            security_findings=security_findings,
            recommendations=recommendations,
            gaps=gaps,
            improvement_roadmap=roadmap,
            estimated_improvement=potential_improvement,
            source_type="multiple_files",
            metadata={
                "file_count": len(uploaded_files),
                "analyzed_at": datetime.now().isoformat()
            }
        )
    
    st.success(f"✅ Analyzed {len(uploaded_files)} file(s) - Found {len(all_services)} AWS services")
    st.rerun()


def _process_text_analysis(text_input: str):
    """Process text input for analysis"""
    
    with st.spinner("🔄 Analyzing architecture description..."):
        # Detect if it's IaC or plain text
        if 'resource "aws_' in text_input or 'resource "aws_' in text_input:
            source_type = "terraform"
            services, service_counts = ArchitectureParser.parse_terraform(text_input)
        elif 'AWS::' in text_input or 'AWSTemplateFormatVersion' in text_input:
            source_type = "cloudformation"
            services, service_counts = ArchitectureParser.parse_cloudformation(text_input)
        elif 'from aws_cdk' in text_input or 'import * as' in text_input:
            source_type = "cdk"
            services, service_counts = ArchitectureParser.parse_cdk(text_input)
        else:
            source_type = "text"
            services, service_counts = ArchitectureParser.parse_text(text_input)
        
        waf_scores = calculate_waf_scores(services)
        security_findings, gaps = SecurityAnalyzer.analyze(text_input, services)
        recommendations = ArchitectureAnalyzer._generate_recommendations(services, gaps, waf_scores)
        roadmap = ArchitectureAnalyzer._generate_roadmap(gaps, recommendations)
        
        current_score = waf_scores.get('overall_score', 50)
        potential_improvement = min(100 - current_score, sum(g.get('weight', 5) for g in gaps) * 0.5)
        
        st.session_state.architecture_analysis = AnalysisResult(
            detected_services=services,
            service_counts=service_counts,
            waf_scores=waf_scores,
            security_findings=security_findings,
            recommendations=recommendations,
            gaps=gaps,
            improvement_roadmap=roadmap,
            estimated_improvement=potential_improvement,
            source_type=source_type,
            raw_content=text_input[:5000],
            metadata={
                "analyzed_at": datetime.now().isoformat()
            }
        )
    
    st.success(f"✅ Analysis complete - Found {len(services)} AWS services")
    st.rerun()


def _display_analysis_results(result: AnalysisResult):
    """Display analysis results"""
    
    st.markdown("---")
    st.markdown("## 📊 Analysis Results")
    
    # Score summary
    col1, col2, col3, col4 = st.columns(4)
    
    current_score = result.waf_scores.get('overall_score', 50)
    potential_score = min(100, current_score + result.estimated_improvement)
    
    with col1:
        score_color = "#4CAF50" if current_score >= 80 else "#FF9800" if current_score >= 60 else "#F44336"
        st.markdown(f"""
        <div style="text-align: center; padding: 15px; background: linear-gradient(135deg, {score_color}22, {score_color}44); border-radius: 10px; border: 2px solid {score_color};">
            <h2 style="margin: 0; color: {score_color};">{current_score:.0f}</h2>
            <p style="margin: 5px 0 0 0; color: #666; font-size: 12px;">Current WAF Score</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown(f"""
        <div style="text-align: center; padding: 15px; background: linear-gradient(135deg, #4CAF5022, #4CAF5044); border-radius: 10px; border: 2px solid #4CAF50;">
            <h2 style="margin: 0; color: #4CAF50;">{potential_score:.0f}</h2>
            <p style="margin: 5px 0 0 0; color: #666; font-size: 12px;">Potential Score</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.metric("Services Detected", len(result.detected_services))
    
    with col4:
        st.metric("Gaps Identified", len(result.gaps))
    
    # Tabs for detailed results
    tabs = st.tabs([
        "📊 WAF Scores",
        "🔍 Detected Services",
        "⚠️ Gaps & Findings",
        "💡 Recommendations",
        "🗺️ Improvement Roadmap",
        "✅ Best Practices Checklist",
        "📜 Compliance Gaps"
    ])
    
    # Tab 1: WAF Scores
    with tabs[0]:
        _render_waf_scores_tab(result)
    
    # Tab 2: Detected Services
    with tabs[1]:
        _render_services_tab(result)
    
    # Tab 3: Gaps & Findings
    with tabs[2]:
        _render_gaps_tab(result)
    
    # Tab 4: Recommendations
    with tabs[3]:
        _render_recommendations_tab(result)
    
    # Tab 5: Roadmap
    with tabs[4]:
        _render_roadmap_tab(result)
    
    # Tab 6: Best Practices Checklist
    with tabs[5]:
        _render_best_practices_tab(result)
    
    # Tab 7: Compliance Gaps
    with tabs[6]:
        _render_compliance_gaps_tab(result)


def _render_waf_scores_tab(result: AnalysisResult):
    """Render WAF scores visualization"""
    
    st.markdown("### 📊 WAF Pillar Scores")
    
    pillar_scores = result.waf_scores.get('pillar_scores', {})
    
    if pillar_scores:
        import plotly.graph_objects as go
        
        # Radar chart
        categories = list(pillar_scores.keys())
        values = list(pillar_scores.values())
        
        fig = go.Figure()
        
        # Current scores
        fig.add_trace(go.Scatterpolar(
            r=values + [values[0]],
            theta=[c.title() for c in categories] + [categories[0].title()],
            fill='toself',
            name='Current Score',
            line_color='#FF9900',
            fillcolor='rgba(255, 153, 0, 0.3)'
        ))
        
        # Target line at 80
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
            height=400
        )
        
        st.plotly_chart(fig, use_container_width=True)
        
        # Score breakdown
        st.markdown("#### Score Breakdown")
        
        for pillar, score in pillar_scores.items():
            status = "✅" if score >= 80 else "⚠️" if score >= 60 else "❌"
            color = "#4CAF50" if score >= 80 else "#FF9800" if score >= 60 else "#F44336"
            st.markdown(f"{status} **{pillar.title()}**: {score:.0f}/100")
            st.progress(score / 100)


def _render_services_tab(result: AnalysisResult):
    """Render detected services"""
    
    st.markdown("### 🔍 Detected AWS Services")
    
    if result.detected_services:
        # Group by category
        categories = {}
        for service in result.detected_services:
            service_info = AWS_SERVICES.get(service, {"category": "other", "name": service})
            category = service_info.get("category", "other")
            if category not in categories:
                categories[category] = []
            categories[category].append({
                "service": service,
                "name": service_info.get("name", service),
                "count": result.service_counts.get(service, 1)
            })
        
        for category, services in sorted(categories.items()):
            with st.expander(f"📁 {category.title()} ({len(services)} services)", expanded=True):
                cols = st.columns(3)
                for i, svc in enumerate(services):
                    with cols[i % 3]:
                        st.markdown(f"**{svc['name']}** x{svc['count']}")
    else:
        st.warning("No AWS services detected. Try uploading IaC files or providing more details.")


def _render_gaps_tab(result: AnalysisResult):
    """Render gaps and findings"""
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### ✅ Implemented")
        for finding in result.security_findings:
            st.success(f"**{finding['check'].replace('_', ' ').title()}**\n\n{finding['details']}")
    
    with col2:
        st.markdown("### ❌ Gaps Identified")
        for gap in result.gaps:
            pillar_icons = {
                "security": "🔒",
                "reliability": "🔄",
                "performance": "⚡",
                "operational": "🛠️",
                "cost": "💰"
            }
            icon = pillar_icons.get(gap['pillar'], "📋")
            st.error(f"{icon} **{gap['check'].replace('_', ' ').title()}**\n\n{gap['recommendation']}")


def _render_recommendations_tab(result: AnalysisResult):
    """Render recommendations"""
    
    st.markdown("### 💡 Prioritized Recommendations")
    
    for i, rec in enumerate(result.recommendations, 1):
        with st.expander(f"{rec['priority']} {rec['recommendation']}", expanded=(i <= 3)):
            col1, col2, col3 = st.columns(3)
            with col1:
                st.markdown(f"**Category:** {rec['category']}")
            with col2:
                st.markdown(f"**Impact:** {rec['impact']}")
            with col3:
                st.markdown(f"**Effort:** {rec.get('effort', 'Medium')}")
            
            if 'service_to_add' in rec:
                st.info(f"💡 Add service: **{rec['service_to_add'].upper()}**")


def _render_roadmap_tab(result: AnalysisResult):
    """Render improvement roadmap"""
    
    st.markdown("### 🗺️ Improvement Roadmap")
    
    for phase in result.improvement_roadmap:
        st.markdown(f"#### {phase['phase']}")
        st.markdown(f"**Timeline:** {phase['timeline']} | **Expected Improvement:** {phase['expected_improvement']}")
        
        for item in phase['items']:
            st.markdown(f"- {item['priority']} {item['recommendation']}")
        
        st.markdown("---")
    
    # Export options
    st.markdown("### 📥 Export Analysis")
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Export as JSON
        export_data = {
            "analysis_date": datetime.now().isoformat(),
            "current_score": result.waf_scores.get('overall_score', 0),
            "potential_score": result.waf_scores.get('overall_score', 0) + result.estimated_improvement,
            "detected_services": result.detected_services,
            "pillar_scores": result.waf_scores.get('pillar_scores', {}),
            "gaps": result.gaps,
            "recommendations": result.recommendations,
            "roadmap": result.improvement_roadmap
        }
        
        st.download_button(
            "📋 Download JSON Report",
            data=json.dumps(export_data, indent=2),
            file_name="architecture_analysis.json",
            mime="application/json"
        )
    
    with col2:
        # Export as Markdown
        md_report = _generate_markdown_report(result)
        st.download_button(
            "📄 Download Markdown Report",
            data=md_report,
            file_name="architecture_analysis.md",
            mime="text/markdown"
        )


def _generate_markdown_report(result: AnalysisResult) -> str:
    """Generate markdown report"""
    
    current_score = result.waf_scores.get('overall_score', 50)
    potential_score = current_score + result.estimated_improvement
    
    report = f"""# Architecture Analysis Report

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M')}

## Executive Summary

| Metric | Value |
|--------|-------|
| Current WAF Score | {current_score:.0f}/100 |
| Potential Score | {potential_score:.0f}/100 |
| Services Detected | {len(result.detected_services)} |
| Gaps Identified | {len(result.gaps)} |

## WAF Pillar Scores

"""
    
    for pillar, score in result.waf_scores.get('pillar_scores', {}).items():
        status = "✅" if score >= 80 else "⚠️" if score >= 60 else "❌"
        report += f"- {status} **{pillar.title()}**: {score:.0f}/100\n"
    
    report += """

## Detected Services

"""
    
    for service in result.detected_services:
        report += f"- {service}\n"
    
    report += """

## Gaps & Recommendations

"""
    
    for rec in result.recommendations:
        report += f"### {rec['priority']} {rec['recommendation']}\n\n"
        report += f"- **Category:** {rec['category']}\n"
        report += f"- **Impact:** {rec['impact']}\n"
        report += f"- **Effort:** {rec.get('effort', 'Medium')}\n\n"
    
    report += """

## Improvement Roadmap

"""
    
    for phase in result.improvement_roadmap:
        report += f"### {phase['phase']}\n\n"
        report += f"**Timeline:** {phase['timeline']}\n\n"
        for item in phase['items']:
            report += f"- {item['recommendation']}\n"
        report += "\n"
    
    return report


def _render_best_practices_tab(result: AnalysisResult):
    """Render Best Practices Checklist"""
    
    st.markdown("### ✅ AWS Well-Architected Best Practices Checklist")
    
    # Define comprehensive checklist
    best_practices = {
        "Security": [
            ("Enable encryption at rest for all data stores", "kms" in result.detected_services or any('encrypt' in str(g) for g in result.security_findings)),
            ("Enable encryption in transit (TLS/SSL)", "acm" in result.detected_services or "cloudfront" in result.detected_services),
            ("Implement WAF for web applications", "waf" in result.detected_services),
            ("Enable GuardDuty for threat detection", "guardduty" in result.detected_services),
            ("Use Secrets Manager for credentials", "secrets_manager" in result.detected_services),
            ("Implement least privilege IAM policies", "iam" in result.detected_services),
            ("Enable Security Hub for centralized security", "security_hub" in result.detected_services),
            ("Use VPC for network isolation", "vpc" in result.detected_services),
            ("Enable DDoS protection (Shield)", "shield" in result.detected_services),
            ("Implement Cognito for user authentication", "cognito" in result.detected_services),
        ],
        "Reliability": [
            ("Deploy across multiple Availability Zones", any(s in result.detected_services for s in ['aurora', 'alb', 'nlb'])),
            ("Implement auto-scaling", any(s in result.detected_services for s in ['ec2', 'ecs', 'eks'])),
            ("Enable automated backups", any(s in result.detected_services for s in ['rds', 'aurora', 'dynamodb'])),
            ("Use managed database services", any(s in result.detected_services for s in ['rds', 'aurora', 'dynamodb'])),
            ("Implement health checks", any(s in result.detected_services for s in ['alb', 'nlb', 'route53'])),
            ("Use S3 for durable storage", "s3" in result.detected_services),
            ("Implement disaster recovery strategy", any(s in result.detected_services for s in ['s3', 'aurora'])),
        ],
        "Performance Efficiency": [
            ("Use caching layer (ElastiCache)", "elasticache" in result.detected_services),
            ("Implement CDN (CloudFront)", "cloudfront" in result.detected_services),
            ("Use right-sized compute resources", any(s in result.detected_services for s in ['ec2', 'lambda', 'fargate'])),
            ("Implement read replicas for databases", any(s in result.detected_services for s in ['rds', 'aurora'])),
            ("Use serverless where appropriate", "lambda" in result.detected_services),
            ("Implement async processing", any(s in result.detected_services for s in ['sqs', 'sns', 'eventbridge'])),
        ],
        "Operational Excellence": [
            ("Enable CloudWatch monitoring", "cloudwatch" in result.detected_services),
            ("Enable CloudTrail audit logging", "cloudtrail" in result.detected_services),
            ("Use AWS Config for compliance", "config" in result.detected_services),
            ("Implement Infrastructure as Code", result.source_type in ['terraform', 'cloudformation', 'cdk_python', 'cdk_typescript']),
            ("Use Systems Manager for operations", "systems_manager" in result.detected_services),
            ("Implement centralized logging", "cloudwatch" in result.detected_services),
        ],
        "Cost Optimization": [
            ("Use appropriate instance types", any(s in result.detected_services for s in ['ec2', 'rds'])),
            ("Implement auto-scaling policies", any(s in result.detected_services for s in ['ec2', 'ecs', 'eks'])),
            ("Use serverless for variable workloads", "lambda" in result.detected_services),
            ("Implement S3 lifecycle policies", "s3" in result.detected_services),
            ("Use Reserved Instances or Savings Plans", False),  # Can't detect from IaC
            ("Enable cost allocation tags", True),  # Assume if using IaC
        ],
        "Sustainability": [
            ("Use managed services", len([s for s in result.detected_services if s in ['lambda', 'fargate', 'aurora', 'dynamodb']]) >= 2),
            ("Implement auto-scaling to right-size", any(s in result.detected_services for s in ['ec2', 'ecs', 'eks'])),
            ("Use Graviton processors where available", False),  # Can't easily detect
            ("Optimize data transfer", "cloudfront" in result.detected_services),
        ]
    }
    
    total_checks = 0
    passed_checks = 0
    
    for pillar, checks in best_practices.items():
        pillar_icons = {
            "Security": "🔒",
            "Reliability": "🔄",
            "Performance Efficiency": "⚡",
            "Operational Excellence": "🛠️",
            "Cost Optimization": "💰",
            "Sustainability": "🌱"
        }
        
        pillar_passed = sum(1 for _, status in checks if status)
        pillar_total = len(checks)
        total_checks += pillar_total
        passed_checks += pillar_passed
        
        pct = (pillar_passed / pillar_total * 100) if pillar_total > 0 else 0
        
        with st.expander(f"{pillar_icons.get(pillar, '📋')} {pillar} ({pillar_passed}/{pillar_total} - {pct:.0f}%)", expanded=False):
            for check_name, status in checks:
                icon = "✅" if status else "❌"
                st.markdown(f"{icon} {check_name}")
    
    # Summary
    overall_pct = (passed_checks / total_checks * 100) if total_checks > 0 else 0
    
    st.markdown("---")
    st.markdown(f"### Overall Best Practices Score: **{passed_checks}/{total_checks}** ({overall_pct:.0f}%)")
    
    st.progress(overall_pct / 100)
    
    if overall_pct >= 80:
        st.success("🏆 Excellent! Your architecture follows most best practices.")
    elif overall_pct >= 60:
        st.warning("⚠️ Good start, but there's room for improvement.")
    else:
        st.error("❌ Significant gaps in best practices. Review recommendations.")


def _render_compliance_gaps_tab(result: AnalysisResult):
    """Render Compliance Gap Analysis"""
    
    st.markdown("### 📜 Compliance Gap Analysis")
    
    # Define compliance frameworks and their requirements
    compliance_frameworks = {
        "CIS AWS Foundations": {
            "description": "Center for Internet Security benchmark for AWS",
            "requirements": [
                ("IAM password policies", "iam" in result.detected_services, "High"),
                ("CloudTrail enabled in all regions", "cloudtrail" in result.detected_services, "High"),
                ("CloudWatch log metric filters", "cloudwatch" in result.detected_services, "Medium"),
                ("VPC flow logs enabled", "vpc" in result.detected_services, "Medium"),
                ("S3 bucket logging", "s3" in result.detected_services, "Medium"),
                ("EBS encryption", "kms" in result.detected_services, "High"),
                ("RDS encryption", "kms" in result.detected_services and any(s in result.detected_services for s in ['rds', 'aurora']), "High"),
                ("AWS Config enabled", "config" in result.detected_services, "Medium"),
            ]
        },
        "PCI-DSS": {
            "description": "Payment Card Industry Data Security Standard",
            "requirements": [
                ("Network segmentation (VPC)", "vpc" in result.detected_services, "High"),
                ("Encryption at rest", "kms" in result.detected_services, "High"),
                ("Encryption in transit", "acm" in result.detected_services or "cloudfront" in result.detected_services, "High"),
                ("WAF protection", "waf" in result.detected_services, "High"),
                ("Audit logging (CloudTrail)", "cloudtrail" in result.detected_services, "High"),
                ("Intrusion detection (GuardDuty)", "guardduty" in result.detected_services, "Medium"),
                ("Secrets management", "secrets_manager" in result.detected_services, "High"),
                ("Access control (IAM)", "iam" in result.detected_services, "High"),
            ]
        },
        "HIPAA": {
            "description": "Health Insurance Portability and Accountability Act",
            "requirements": [
                ("Encryption at rest", "kms" in result.detected_services, "High"),
                ("Encryption in transit", "acm" in result.detected_services or "cloudfront" in result.detected_services, "High"),
                ("Audit controls (CloudTrail)", "cloudtrail" in result.detected_services, "High"),
                ("Access controls (IAM)", "iam" in result.detected_services, "High"),
                ("Backup and recovery", any(s in result.detected_services for s in ['rds', 'aurora', 's3']), "High"),
                ("Network controls (VPC)", "vpc" in result.detected_services, "High"),
                ("Monitoring (CloudWatch)", "cloudwatch" in result.detected_services, "Medium"),
            ]
        },
        "SOC 2": {
            "description": "Service Organization Control 2",
            "requirements": [
                ("Access control (IAM)", "iam" in result.detected_services, "High"),
                ("System monitoring (CloudWatch)", "cloudwatch" in result.detected_services, "High"),
                ("Change management (CloudTrail)", "cloudtrail" in result.detected_services, "High"),
                ("Incident response capability", "guardduty" in result.detected_services or "security_hub" in result.detected_services, "Medium"),
                ("Data encryption", "kms" in result.detected_services, "High"),
                ("Network security (VPC)", "vpc" in result.detected_services, "High"),
                ("Availability (Multi-AZ)", any(s in result.detected_services for s in ['aurora', 'alb', 'nlb']), "Medium"),
            ]
        },
        "NIST CSF": {
            "description": "NIST Cybersecurity Framework",
            "requirements": [
                ("Asset management (Config)", "config" in result.detected_services, "Medium"),
                ("Identity management (IAM, Cognito)", "iam" in result.detected_services or "cognito" in result.detected_services, "High"),
                ("Data security (KMS)", "kms" in result.detected_services, "High"),
                ("Protective technology (WAF, Shield)", "waf" in result.detected_services or "shield" in result.detected_services, "High"),
                ("Detection (GuardDuty)", "guardduty" in result.detected_services, "High"),
                ("Security monitoring (Security Hub)", "security_hub" in result.detected_services, "Medium"),
                ("Response planning", "sns" in result.detected_services or "eventbridge" in result.detected_services, "Medium"),
                ("Recovery (Backup)", any(s in result.detected_services for s in ['rds', 'aurora', 's3']), "Medium"),
            ]
        }
    }
    
    # Calculate compliance scores
    compliance_scores = {}
    
    for framework, details in compliance_frameworks.items():
        passed = sum(1 for _, status, _ in details['requirements'] if status)
        total = len(details['requirements'])
        high_priority_passed = sum(1 for _, status, priority in details['requirements'] if status and priority == "High")
        high_priority_total = sum(1 for _, _, priority in details['requirements'] if priority == "High")
        
        compliance_scores[framework] = {
            "passed": passed,
            "total": total,
            "percentage": (passed / total * 100) if total > 0 else 0,
            "high_priority_passed": high_priority_passed,
            "high_priority_total": high_priority_total,
            "description": details['description']
        }
    
    # Summary cards
    cols = st.columns(len(compliance_frameworks))
    for i, (framework, scores) in enumerate(compliance_scores.items()):
        with cols[i]:
            pct = scores['percentage']
            color = "#4CAF50" if pct >= 80 else "#FF9800" if pct >= 60 else "#F44336"
            
            st.markdown(f"""
            <div style="text-align: center; padding: 10px; background: linear-gradient(135deg, {color}22, {color}44); 
                        border-radius: 8px; border: 1px solid {color}; margin-bottom: 10px;">
                <h4 style="margin: 0; font-size: 14px;">{framework}</h4>
                <h2 style="margin: 5px 0; color: {color};">{pct:.0f}%</h2>
                <p style="margin: 0; font-size: 11px; color: #666;">{scores['passed']}/{scores['total']}</p>
            </div>
            """, unsafe_allow_html=True)
    
    # Detailed breakdown
    st.markdown("---")
    st.markdown("### Detailed Compliance Requirements")
    
    selected_framework = st.selectbox(
        "Select Framework for Details",
        list(compliance_frameworks.keys())
    )
    
    if selected_framework:
        framework_details = compliance_frameworks[selected_framework]
        scores = compliance_scores[selected_framework]
        
        st.markdown(f"**{selected_framework}**: {framework_details['description']}")
        st.markdown(f"**Score**: {scores['passed']}/{scores['total']} ({scores['percentage']:.0f}%)")
        st.markdown(f"**High Priority**: {scores['high_priority_passed']}/{scores['high_priority_total']}")
        
        st.markdown("#### Requirements Checklist")
        
        for req_name, status, priority in framework_details['requirements']:
            priority_icon = "🔴" if priority == "High" else "🟡"
            status_icon = "✅" if status else "❌"
            st.markdown(f"{status_icon} {priority_icon} {req_name}")
    
    # Export compliance report
    st.markdown("---")
    
    if st.button("📋 Generate Compliance Report"):
        report = f"""# Compliance Gap Analysis Report

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M')}

## Summary

"""
        for framework, scores in compliance_scores.items():
            status = "✅" if scores['percentage'] >= 80 else "⚠️" if scores['percentage'] >= 60 else "❌"
            report += f"- {status} **{framework}**: {scores['percentage']:.0f}% ({scores['passed']}/{scores['total']})\n"
        
        report += "\n## Detailed Requirements\n\n"
        
        for framework, details in compliance_frameworks.items():
            report += f"### {framework}\n\n"
            report += f"{details['description']}\n\n"
            
            for req_name, status, priority in details['requirements']:
                icon = "✅" if status else "❌"
                report += f"- {icon} [{priority}] {req_name}\n"
            
            report += "\n"
        
        st.download_button(
            "📥 Download Report",
            data=report,
            file_name="compliance_gap_analysis.md",
            mime="text/markdown"
        )
