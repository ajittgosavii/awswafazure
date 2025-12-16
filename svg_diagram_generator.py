"""
AWS Architecture SVG Diagram Generator
======================================
Generates professional SVG architecture diagrams for AWS solutions.

Features:
- AWS service icons (simplified representations)
- Connection lines with arrows
- Grouping (VPC, Subnets, AZs)
- Labels and annotations
- Multiple layout styles
- Export to SVG, PNG, PDF

Version: 4.0.0
"""

from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
import math
import json

# ============================================================================
# AWS SERVICE DEFINITIONS
# ============================================================================

AWS_SERVICES = {
    # Compute
    "ec2": {"name": "EC2", "category": "compute", "color": "#FF9900", "icon": "server"},
    "lambda": {"name": "Lambda", "category": "compute", "color": "#FF9900", "icon": "function"},
    "ecs": {"name": "ECS", "category": "compute", "color": "#FF9900", "icon": "container"},
    "eks": {"name": "EKS", "category": "compute", "color": "#FF9900", "icon": "kubernetes"},
    "fargate": {"name": "Fargate", "category": "compute", "color": "#FF9900", "icon": "serverless"},
    "batch": {"name": "Batch", "category": "compute", "color": "#FF9900", "icon": "batch"},
    
    # Storage
    "s3": {"name": "S3", "category": "storage", "color": "#3F8624", "icon": "bucket"},
    "ebs": {"name": "EBS", "category": "storage", "color": "#3F8624", "icon": "disk"},
    "efs": {"name": "EFS", "category": "storage", "color": "#3F8624", "icon": "filesystem"},
    "glacier": {"name": "Glacier", "category": "storage", "color": "#3F8624", "icon": "archive"},
    "fsx": {"name": "FSx", "category": "storage", "color": "#3F8624", "icon": "filesystem"},
    
    # Database
    "rds": {"name": "RDS", "category": "database", "color": "#3B48CC", "icon": "database"},
    "aurora": {"name": "Aurora", "category": "database", "color": "#3B48CC", "icon": "database"},
    "dynamodb": {"name": "DynamoDB", "category": "database", "color": "#3B48CC", "icon": "nosql"},
    "elasticache": {"name": "ElastiCache", "category": "database", "color": "#3B48CC", "icon": "cache"},
    "redshift": {"name": "Redshift", "category": "database", "color": "#3B48CC", "icon": "warehouse"},
    "documentdb": {"name": "DocumentDB", "category": "database", "color": "#3B48CC", "icon": "document"},
    "neptune": {"name": "Neptune", "category": "database", "color": "#3B48CC", "icon": "graph"},
    
    # Networking
    "vpc": {"name": "VPC", "category": "networking", "color": "#8C4FFF", "icon": "network"},
    "alb": {"name": "ALB", "category": "networking", "color": "#8C4FFF", "icon": "loadbalancer"},
    "nlb": {"name": "NLB", "category": "networking", "color": "#8C4FFF", "icon": "loadbalancer"},
    "cloudfront": {"name": "CloudFront", "category": "networking", "color": "#8C4FFF", "icon": "cdn"},
    "route53": {"name": "Route 53", "category": "networking", "color": "#8C4FFF", "icon": "dns"},
    "api_gateway": {"name": "API Gateway", "category": "networking", "color": "#8C4FFF", "icon": "api"},
    "direct_connect": {"name": "Direct Connect", "category": "networking", "color": "#8C4FFF", "icon": "connection"},
    "transit_gateway": {"name": "Transit Gateway", "category": "networking", "color": "#8C4FFF", "icon": "hub"},
    "nat_gateway": {"name": "NAT Gateway", "category": "networking", "color": "#8C4FFF", "icon": "nat"},
    
    # Security
    "iam": {"name": "IAM", "category": "security", "color": "#DD344C", "icon": "identity"},
    "cognito": {"name": "Cognito", "category": "security", "color": "#DD344C", "icon": "users"},
    "waf": {"name": "WAF", "category": "security", "color": "#DD344C", "icon": "firewall"},
    "shield": {"name": "Shield", "category": "security", "color": "#DD344C", "icon": "shield"},
    "kms": {"name": "KMS", "category": "security", "color": "#DD344C", "icon": "key"},
    "secrets_manager": {"name": "Secrets Manager", "category": "security", "color": "#DD344C", "icon": "secret"},
    "guardduty": {"name": "GuardDuty", "category": "security", "color": "#DD344C", "icon": "detective"},
    "security_hub": {"name": "Security Hub", "category": "security", "color": "#DD344C", "icon": "hub"},
    "acm": {"name": "ACM", "category": "security", "color": "#DD344C", "icon": "certificate"},
    
    # Integration
    "sqs": {"name": "SQS", "category": "integration", "color": "#FF4F8B", "icon": "queue"},
    "sns": {"name": "SNS", "category": "integration", "color": "#FF4F8B", "icon": "notification"},
    "eventbridge": {"name": "EventBridge", "category": "integration", "color": "#FF4F8B", "icon": "events"},
    "step_functions": {"name": "Step Functions", "category": "integration", "color": "#FF4F8B", "icon": "workflow"},
    "mq": {"name": "Amazon MQ", "category": "integration", "color": "#FF4F8B", "icon": "message"},
    "kinesis": {"name": "Kinesis", "category": "integration", "color": "#FF4F8B", "icon": "stream"},
    
    # Analytics
    "athena": {"name": "Athena", "category": "analytics", "color": "#00A4A6", "icon": "query"},
    "emr": {"name": "EMR", "category": "analytics", "color": "#00A4A6", "icon": "spark"},
    "glue": {"name": "Glue", "category": "analytics", "color": "#00A4A6", "icon": "etl"},
    "quicksight": {"name": "QuickSight", "category": "analytics", "color": "#00A4A6", "icon": "dashboard"},
    "opensearch": {"name": "OpenSearch", "category": "analytics", "color": "#00A4A6", "icon": "search"},
    "lake_formation": {"name": "Lake Formation", "category": "analytics", "color": "#00A4A6", "icon": "lake"},
    
    # ML/AI
    "sagemaker": {"name": "SageMaker", "category": "ml", "color": "#01A88D", "icon": "ml"},
    "bedrock": {"name": "Bedrock", "category": "ml", "color": "#01A88D", "icon": "ai"},
    "rekognition": {"name": "Rekognition", "category": "ml", "color": "#01A88D", "icon": "vision"},
    "comprehend": {"name": "Comprehend", "category": "ml", "color": "#01A88D", "icon": "nlp"},
    "textract": {"name": "Textract", "category": "ml", "color": "#01A88D", "icon": "ocr"},
    
    # Management
    "cloudwatch": {"name": "CloudWatch", "category": "management", "color": "#FF4F8B", "icon": "monitoring"},
    "cloudtrail": {"name": "CloudTrail", "category": "management", "color": "#FF4F8B", "icon": "audit"},
    "config": {"name": "Config", "category": "management", "color": "#FF4F8B", "icon": "config"},
    "systems_manager": {"name": "Systems Manager", "category": "management", "color": "#FF4F8B", "icon": "management"},
    "cloudformation": {"name": "CloudFormation", "category": "management", "color": "#FF4F8B", "icon": "iac"},
    
    # External
    "users": {"name": "Users", "category": "external", "color": "#232F3E", "icon": "users"},
    "internet": {"name": "Internet", "category": "external", "color": "#232F3E", "icon": "cloud"},
    "on_premises": {"name": "On-Premises", "category": "external", "color": "#232F3E", "icon": "datacenter"},
    "mobile": {"name": "Mobile App", "category": "external", "color": "#232F3E", "icon": "mobile"},
}

# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class ServiceNode:
    """Represents a service in the architecture"""
    id: str
    service_type: str
    label: str
    x: float = 0
    y: float = 0
    width: float = 100
    height: float = 80
    properties: Dict[str, Any] = field(default_factory=dict)
    group: Optional[str] = None

@dataclass
class Connection:
    """Represents a connection between services"""
    source_id: str
    target_id: str
    label: str = ""
    connection_type: str = "solid"  # solid, dashed, dotted
    bidirectional: bool = False
    color: str = "#666666"

@dataclass
class Group:
    """Represents a grouping (VPC, Subnet, AZ, etc.)"""
    id: str
    name: str
    group_type: str  # vpc, subnet, az, region, security_group
    x: float = 0
    y: float = 0
    width: float = 400
    height: float = 300
    color: str = "#E8E8E8"
    children: List[str] = field(default_factory=list)

@dataclass
class Architecture:
    """Complete architecture definition"""
    name: str
    description: str
    nodes: List[ServiceNode] = field(default_factory=list)
    connections: List[Connection] = field(default_factory=list)
    groups: List[Group] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

# ============================================================================
# SVG ICON GENERATORS
# ============================================================================

class SVGIconGenerator:
    """Generates simplified SVG icons for AWS services"""
    
    @staticmethod
    def get_icon(icon_type: str, x: float, y: float, size: float = 40, color: str = "#FF9900") -> str:
        """Generate SVG icon based on type"""
        
        icons = {
            "server": SVGIconGenerator._server_icon,
            "function": SVGIconGenerator._function_icon,
            "container": SVGIconGenerator._container_icon,
            "kubernetes": SVGIconGenerator._kubernetes_icon,
            "bucket": SVGIconGenerator._bucket_icon,
            "database": SVGIconGenerator._database_icon,
            "nosql": SVGIconGenerator._nosql_icon,
            "cache": SVGIconGenerator._cache_icon,
            "loadbalancer": SVGIconGenerator._loadbalancer_icon,
            "cdn": SVGIconGenerator._cdn_icon,
            "api": SVGIconGenerator._api_icon,
            "dns": SVGIconGenerator._dns_icon,
            "identity": SVGIconGenerator._identity_icon,
            "firewall": SVGIconGenerator._firewall_icon,
            "key": SVGIconGenerator._key_icon,
            "queue": SVGIconGenerator._queue_icon,
            "notification": SVGIconGenerator._notification_icon,
            "stream": SVGIconGenerator._stream_icon,
            "ml": SVGIconGenerator._ml_icon,
            "monitoring": SVGIconGenerator._monitoring_icon,
            "users": SVGIconGenerator._users_icon,
            "cloud": SVGIconGenerator._cloud_icon,
            "network": SVGIconGenerator._network_icon,
            "default": SVGIconGenerator._default_icon,
        }
        
        generator = icons.get(icon_type, SVGIconGenerator._default_icon)
        return generator(x, y, size, color)
    
    @staticmethod
    def _server_icon(x: float, y: float, size: float, color: str) -> str:
        return f'''<g transform="translate({x},{y})">
            <rect x="5" y="2" width="{size-10}" height="{size-4}" rx="3" fill="{color}" opacity="0.2"/>
            <rect x="5" y="2" width="{size-10}" height="{size/3}" rx="3" fill="{color}"/>
            <circle cx="{size/2}" cy="{size/6+2}" r="3" fill="white"/>
            <line x1="10" y1="{size/2}" x2="{size-10}" y2="{size/2}" stroke="{color}" stroke-width="2"/>
            <line x1="10" y1="{size*0.7}" x2="{size-10}" y2="{size*0.7}" stroke="{color}" stroke-width="2"/>
        </g>'''
    
    @staticmethod
    def _function_icon(x: float, y: float, size: float, color: str) -> str:
        return f'''<g transform="translate({x},{y})">
            <path d="M{size/2} 2 L{size-2} {size/2} L{size/2} {size-2} L2 {size/2} Z" fill="{color}"/>
            <text x="{size/2}" y="{size/2+5}" text-anchor="middle" fill="white" font-size="14" font-weight="bold">λ</text>
        </g>'''
    
    @staticmethod
    def _container_icon(x: float, y: float, size: float, color: str) -> str:
        return f'''<g transform="translate({x},{y})">
            <rect x="2" y="8" width="{size-4}" height="{size-16}" rx="2" fill="{color}" opacity="0.3"/>
            <rect x="6" y="12" width="{size-12}" height="{(size-20)/3}" fill="{color}"/>
            <rect x="6" y="{14+(size-20)/3}" width="{size-12}" height="{(size-20)/3}" fill="{color}" opacity="0.7"/>
            <rect x="6" y="{16+2*(size-20)/3}" width="{size-12}" height="{(size-20)/3}" fill="{color}" opacity="0.4"/>
        </g>'''
    
    @staticmethod
    def _kubernetes_icon(x: float, y: float, size: float, color: str) -> str:
        cx, cy = size/2, size/2
        r = size/2 - 4
        return f'''<g transform="translate({x},{y})">
            <circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{color}" stroke-width="3"/>
            <path d="M{cx} {cy-r+8} L{cx} {cy+r-8}" stroke="{color}" stroke-width="2"/>
            <path d="M{cx-r+8} {cy} L{cx+r-8} {cy}" stroke="{color}" stroke-width="2"/>
            <circle cx="{cx}" cy="{cy}" r="6" fill="{color}"/>
        </g>'''
    
    @staticmethod
    def _bucket_icon(x: float, y: float, size: float, color: str) -> str:
        return f'''<g transform="translate({x},{y})">
            <ellipse cx="{size/2}" cy="8" rx="{size/2-4}" ry="6" fill="{color}"/>
            <path d="M4 8 L4 {size-8} Q4 {size-2} {size/2} {size-2} Q{size-4} {size-2} {size-4} {size-8} L{size-4} 8" fill="{color}" opacity="0.7"/>
            <ellipse cx="{size/2}" cy="{size-8}" rx="{size/2-4}" ry="6" fill="{color}" opacity="0.5"/>
        </g>'''
    
    @staticmethod
    def _database_icon(x: float, y: float, size: float, color: str) -> str:
        return f'''<g transform="translate({x},{y})">
            <ellipse cx="{size/2}" cy="10" rx="{size/2-4}" ry="8" fill="{color}"/>
            <rect x="4" y="10" width="{size-8}" height="{size-20}" fill="{color}" opacity="0.7"/>
            <ellipse cx="{size/2}" cy="{size-10}" rx="{size/2-4}" ry="8" fill="{color}" opacity="0.5"/>
            <ellipse cx="{size/2}" cy="{size/2}" rx="{size/2-4}" ry="4" fill="none" stroke="white" stroke-width="1" opacity="0.5"/>
        </g>'''
    
    @staticmethod
    def _nosql_icon(x: float, y: float, size: float, color: str) -> str:
        return f'''<g transform="translate({x},{y})">
            <rect x="4" y="4" width="{size-8}" height="{size-8}" rx="4" fill="{color}"/>
            <line x1="4" y1="{size/3}" x2="{size-4}" y2="{size/3}" stroke="white" stroke-width="2"/>
            <line x1="4" y1="{size*2/3}" x2="{size-4}" y2="{size*2/3}" stroke="white" stroke-width="2"/>
            <line x1="{size/3}" y1="4" x2="{size/3}" y2="{size-4}" stroke="white" stroke-width="2"/>
        </g>'''
    
    @staticmethod
    def _cache_icon(x: float, y: float, size: float, color: str) -> str:
        return f'''<g transform="translate({x},{y})">
            <circle cx="{size/2}" cy="{size/2}" r="{size/2-4}" fill="{color}" opacity="0.3"/>
            <circle cx="{size/2}" cy="{size/2}" r="{size/3}" fill="{color}"/>
            <path d="M{size/2} {size/4} L{size/2} {size/2} L{size*3/4} {size/2}" stroke="white" stroke-width="2" fill="none"/>
        </g>'''
    
    @staticmethod
    def _loadbalancer_icon(x: float, y: float, size: float, color: str) -> str:
        return f'''<g transform="translate({x},{y})">
            <circle cx="{size/2}" cy="{size/2}" r="{size/2-4}" fill="{color}"/>
            <path d="M{size/4} {size/2} L{size*3/4} {size/3} M{size/4} {size/2} L{size*3/4} {size/2} M{size/4} {size/2} L{size*3/4} {size*2/3}" stroke="white" stroke-width="2" fill="none"/>
            <circle cx="{size/4}" cy="{size/2}" r="4" fill="white"/>
        </g>'''
    
    @staticmethod
    def _cdn_icon(x: float, y: float, size: float, color: str) -> str:
        return f'''<g transform="translate({x},{y})">
            <circle cx="{size/2}" cy="{size/2}" r="{size/2-4}" fill="{color}" opacity="0.3"/>
            <circle cx="{size/2}" cy="{size/2}" r="{size/3}" fill="none" stroke="{color}" stroke-width="2"/>
            <circle cx="{size/2}" cy="{size/2}" r="{size/6}" fill="{color}"/>
            <line x1="{size/2}" y1="4" x2="{size/2}" y2="{size-4}" stroke="{color}" stroke-width="1"/>
            <line x1="4" y1="{size/2}" x2="{size-4}" y2="{size/2}" stroke="{color}" stroke-width="1"/>
        </g>'''
    
    @staticmethod
    def _api_icon(x: float, y: float, size: float, color: str) -> str:
        return f'''<g transform="translate({x},{y})">
            <rect x="4" y="4" width="{size-8}" height="{size-8}" rx="4" fill="{color}"/>
            <text x="{size/2}" y="{size/2+4}" text-anchor="middle" fill="white" font-size="10" font-weight="bold">API</text>
        </g>'''
    
    @staticmethod
    def _dns_icon(x: float, y: float, size: float, color: str) -> str:
        return f'''<g transform="translate({x},{y})">
            <circle cx="{size/2}" cy="{size/2}" r="{size/2-4}" fill="{color}"/>
            <text x="{size/2}" y="{size/2+4}" text-anchor="middle" fill="white" font-size="9" font-weight="bold">DNS</text>
        </g>'''
    
    @staticmethod
    def _identity_icon(x: float, y: float, size: float, color: str) -> str:
        return f'''<g transform="translate({x},{y})">
            <circle cx="{size/2}" cy="{size/3}" r="{size/5}" fill="{color}"/>
            <path d="M{size/4} {size-6} Q{size/4} {size/2} {size/2} {size/2} Q{size*3/4} {size/2} {size*3/4} {size-6}" fill="{color}"/>
        </g>'''
    
    @staticmethod
    def _firewall_icon(x: float, y: float, size: float, color: str) -> str:
        return f'''<g transform="translate({x},{y})">
            <rect x="4" y="4" width="{size-8}" height="{size-8}" fill="{color}"/>
            <rect x="8" y="8" width="{(size-16)/2-2}" height="{(size-16)/2-2}" fill="white"/>
            <rect x="{size/2+2}" y="8" width="{(size-16)/2-2}" height="{(size-16)/2-2}" fill="white"/>
            <rect x="8" y="{size/2+2}" width="{(size-16)/2-2}" height="{(size-16)/2-2}" fill="white"/>
            <rect x="{size/2+2}" y="{size/2+2}" width="{(size-16)/2-2}" height="{(size-16)/2-2}" fill="white"/>
        </g>'''
    
    @staticmethod
    def _key_icon(x: float, y: float, size: float, color: str) -> str:
        return f'''<g transform="translate({x},{y})">
            <circle cx="{size/3}" cy="{size/3}" r="{size/4}" fill="{color}"/>
            <rect x="{size/3}" y="{size/3-3}" width="{size/2}" height="6" fill="{color}"/>
            <rect x="{size*2/3}" y="{size/3}" width="4" height="8" fill="{color}"/>
            <rect x="{size*0.8}" y="{size/3}" width="4" height="6" fill="{color}"/>
        </g>'''
    
    @staticmethod
    def _queue_icon(x: float, y: float, size: float, color: str) -> str:
        return f'''<g transform="translate({x},{y})">
            <rect x="4" y="{size/3}" width="{size-8}" height="{size/3}" rx="2" fill="{color}"/>
            <rect x="8" y="{size/3+4}" width="{(size-16)/4}" height="{size/3-8}" fill="white"/>
            <rect x="{size/3}" y="{size/3+4}" width="{(size-16)/4}" height="{size/3-8}" fill="white"/>
            <rect x="{size*0.55}" y="{size/3+4}" width="{(size-16)/4}" height="{size/3-8}" fill="white"/>
        </g>'''
    
    @staticmethod
    def _notification_icon(x: float, y: float, size: float, color: str) -> str:
        return f'''<g transform="translate({x},{y})">
            <path d="M{size/2} 4 L{size-4} {size/2} L{size/2} {size-4} L4 {size/2} Z" fill="{color}"/>
            <circle cx="{size/2}" cy="{size/2}" r="{size/6}" fill="white"/>
        </g>'''
    
    @staticmethod
    def _stream_icon(x: float, y: float, size: float, color: str) -> str:
        return f'''<g transform="translate({x},{y})">
            <path d="M4 {size/3} Q{size/3} {size/4} {size/2} {size/3} T{size-4} {size/3}" fill="none" stroke="{color}" stroke-width="3"/>
            <path d="M4 {size/2} Q{size/3} {size/2-4} {size/2} {size/2} T{size-4} {size/2}" fill="none" stroke="{color}" stroke-width="3"/>
            <path d="M4 {size*2/3} Q{size/3} {size*2/3-4} {size/2} {size*2/3} T{size-4} {size*2/3}" fill="none" stroke="{color}" stroke-width="3"/>
        </g>'''
    
    @staticmethod
    def _ml_icon(x: float, y: float, size: float, color: str) -> str:
        return f'''<g transform="translate({x},{y})">
            <circle cx="{size/4}" cy="{size/4}" r="6" fill="{color}"/>
            <circle cx="{size*3/4}" cy="{size/4}" r="6" fill="{color}"/>
            <circle cx="{size/2}" cy="{size*3/4}" r="8" fill="{color}"/>
            <line x1="{size/4}" y1="{size/4+6}" x2="{size/2-4}" y2="{size*3/4-8}" stroke="{color}" stroke-width="2"/>
            <line x1="{size*3/4}" y1="{size/4+6}" x2="{size/2+4}" y2="{size*3/4-8}" stroke="{color}" stroke-width="2"/>
        </g>'''
    
    @staticmethod
    def _monitoring_icon(x: float, y: float, size: float, color: str) -> str:
        return f'''<g transform="translate({x},{y})">
            <rect x="4" y="4" width="{size-8}" height="{size-8}" rx="2" fill="{color}" opacity="0.2"/>
            <polyline points="{8},{size*2/3} {size/3},{size/2} {size/2},{size*2/3} {size*2/3},{size/4} {size-8},{size/2}" fill="none" stroke="{color}" stroke-width="3"/>
        </g>'''
    
    @staticmethod
    def _users_icon(x: float, y: float, size: float, color: str) -> str:
        return f'''<g transform="translate({x},{y})">
            <circle cx="{size/2}" cy="{size/3}" r="{size/5}" fill="{color}"/>
            <ellipse cx="{size/2}" cy="{size*0.75}" rx="{size/3}" ry="{size/5}" fill="{color}"/>
            <circle cx="{size/4}" cy="{size/3+4}" r="{size/7}" fill="{color}" opacity="0.6"/>
            <circle cx="{size*3/4}" cy="{size/3+4}" r="{size/7}" fill="{color}" opacity="0.6"/>
        </g>'''
    
    @staticmethod
    def _cloud_icon(x: float, y: float, size: float, color: str) -> str:
        return f'''<g transform="translate({x},{y})">
            <ellipse cx="{size/2}" cy="{size*0.6}" rx="{size/2.5}" ry="{size/4}" fill="{color}"/>
            <circle cx="{size/3}" cy="{size/2}" r="{size/4}" fill="{color}"/>
            <circle cx="{size*2/3}" cy="{size/2}" r="{size/5}" fill="{color}"/>
        </g>'''
    
    @staticmethod
    def _network_icon(x: float, y: float, size: float, color: str) -> str:
        return f'''<g transform="translate({x},{y})">
            <rect x="4" y="4" width="{size-8}" height="{size-8}" rx="4" fill="none" stroke="{color}" stroke-width="2" stroke-dasharray="4"/>
            <circle cx="{size/2}" cy="{size/2}" r="{size/5}" fill="{color}"/>
        </g>'''
    
    @staticmethod
    def _default_icon(x: float, y: float, size: float, color: str) -> str:
        return f'''<g transform="translate({x},{y})">
            <rect x="4" y="4" width="{size-8}" height="{size-8}" rx="4" fill="{color}"/>
        </g>'''


# ============================================================================
# SVG DIAGRAM GENERATOR
# ============================================================================

class AWSDiagramGenerator:
    """Generates SVG architecture diagrams"""
    
    def __init__(self, width: int = 1200, height: int = 800):
        self.width = width
        self.height = height
        self.padding = 50
        self.node_width = 100
        self.node_height = 80
    
    def generate_svg(self, architecture: Architecture) -> str:
        """Generate complete SVG diagram"""
        
        # Auto-layout if positions not set
        self._auto_layout(architecture)
        
        svg_parts = [
            self._svg_header(),
            self._svg_defs(),
            self._render_groups(architecture.groups),
            self._render_connections(architecture),
            self._render_nodes(architecture.nodes),
            self._svg_footer()
        ]
        
        return "\n".join(svg_parts)
    
    def _svg_header(self) -> str:
        return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {self.width} {self.height}" width="{self.width}" height="{self.height}">
        <style>
            .node-label {{ font-family: Arial, sans-serif; font-size: 11px; fill: #333; text-anchor: middle; }}
            .group-label {{ font-family: Arial, sans-serif; font-size: 12px; fill: #666; font-weight: bold; }}
            .connection-label {{ font-family: Arial, sans-serif; font-size: 9px; fill: #666; }}
        </style>'''
    
    def _svg_defs(self) -> str:
        return '''
        <defs>
            <marker id="arrowhead" markerWidth="10" markerHeight="7" refX="9" refY="3.5" orient="auto">
                <polygon points="0 0, 10 3.5, 0 7" fill="#666"/>
            </marker>
            <marker id="arrowhead-reverse" markerWidth="10" markerHeight="7" refX="1" refY="3.5" orient="auto">
                <polygon points="10 0, 0 3.5, 10 7" fill="#666"/>
            </marker>
            <filter id="shadow" x="-20%" y="-20%" width="140%" height="140%">
                <feDropShadow dx="2" dy="2" stdDeviation="3" flood-opacity="0.2"/>
            </filter>
        </defs>'''
    
    def _svg_footer(self) -> str:
        return '</svg>'
    
    def _render_groups(self, groups: List[Group]) -> str:
        """Render group backgrounds (VPCs, subnets, etc.)"""
        svg_parts = []
        
        group_colors = {
            "vpc": "#E8F4E8",
            "subnet_public": "#FFF3E0",
            "subnet_private": "#E3F2FD",
            "az": "#F5F5F5",
            "region": "#FAFAFA",
            "security_group": "#FFEBEE",
        }
        
        group_borders = {
            "vpc": "#4CAF50",
            "subnet_public": "#FF9800",
            "subnet_private": "#2196F3",
            "az": "#9E9E9E",
            "region": "#757575",
            "security_group": "#F44336",
        }
        
        for group in sorted(groups, key=lambda g: g.width * g.height, reverse=True):
            fill = group_colors.get(group.group_type, "#F5F5F5")
            border = group_borders.get(group.group_type, "#999")
            
            svg_parts.append(f'''
            <g class="group" id="group-{group.id}">
                <rect x="{group.x}" y="{group.y}" width="{group.width}" height="{group.height}" 
                      fill="{fill}" stroke="{border}" stroke-width="2" rx="8" 
                      stroke-dasharray="{'5,5' if group.group_type == 'az' else 'none'}"/>
                <text x="{group.x + 10}" y="{group.y + 20}" class="group-label" fill="{border}">{group.name}</text>
            </g>''')
        
        return "\n".join(svg_parts)
    
    def _render_connections(self, architecture: Architecture) -> str:
        """Render connections between nodes"""
        svg_parts = []
        
        node_positions = {node.id: (node.x + node.width/2, node.y + node.height/2) 
                         for node in architecture.nodes}
        
        for conn in architecture.connections:
            if conn.source_id not in node_positions or conn.target_id not in node_positions:
                continue
            
            x1, y1 = node_positions[conn.source_id]
            x2, y2 = node_positions[conn.target_id]
            
            # Calculate path with some curve
            mid_x = (x1 + x2) / 2
            mid_y = (y1 + y2) / 2
            
            # Offset for curved lines
            dx = x2 - x1
            dy = y2 - y1
            offset = 20 if abs(dx) > abs(dy) else 0
            
            dash = ""
            if conn.connection_type == "dashed":
                dash = 'stroke-dasharray="5,5"'
            elif conn.connection_type == "dotted":
                dash = 'stroke-dasharray="2,2"'
            
            marker_end = 'marker-end="url(#arrowhead)"'
            marker_start = 'marker-start="url(#arrowhead-reverse)"' if conn.bidirectional else ''
            
            svg_parts.append(f'''
            <g class="connection">
                <path d="M{x1},{y1} Q{mid_x},{mid_y + offset} {x2},{y2}" 
                      fill="none" stroke="{conn.color}" stroke-width="2" {dash}
                      {marker_end} {marker_start}/>
                {f'<text x="{mid_x}" y="{mid_y - 5}" class="connection-label">{conn.label}</text>' if conn.label else ''}
            </g>''')
        
        return "\n".join(svg_parts)
    
    def _render_nodes(self, nodes: List[ServiceNode]) -> str:
        """Render service nodes"""
        svg_parts = []
        
        for node in nodes:
            service_info = AWS_SERVICES.get(node.service_type, {
                "name": node.service_type,
                "color": "#999999",
                "icon": "default"
            })
            
            color = service_info["color"]
            icon_type = service_info["icon"]
            
            # Node background
            svg_parts.append(f'''
            <g class="node" id="node-{node.id}" filter="url(#shadow)">
                <rect x="{node.x}" y="{node.y}" width="{node.width}" height="{node.height}" 
                      fill="white" stroke="{color}" stroke-width="2" rx="8"/>
                {SVGIconGenerator.get_icon(icon_type, node.x + (node.width - 40)/2, node.y + 8, 40, color)}
                <text x="{node.x + node.width/2}" y="{node.y + node.height - 12}" class="node-label">{node.label}</text>
            </g>''')
        
        return "\n".join(svg_parts)
    
    def _auto_layout(self, architecture: Architecture):
        """Auto-arrange nodes if positions not set"""
        
        # Group nodes by category
        categories = {}
        for node in architecture.nodes:
            service_info = AWS_SERVICES.get(node.service_type, {"category": "other"})
            category = service_info.get("category", "other")
            if category not in categories:
                categories[category] = []
            categories[category].append(node)
        
        # Layout order
        category_order = [
            "external", "networking", "security", "compute", 
            "database", "storage", "integration", "analytics", "ml", "management"
        ]
        
        # Position nodes
        y_offset = self.padding
        for category in category_order:
            if category not in categories:
                continue
            
            nodes = categories[category]
            x_offset = self.padding
            
            for node in nodes:
                if node.x == 0 and node.y == 0:  # Only if not already positioned
                    node.x = x_offset
                    node.y = y_offset
                    x_offset += node.width + 30
                    
                    if x_offset > self.width - self.padding - node.width:
                        x_offset = self.padding
                        y_offset += node.height + 40
            
            y_offset += self.node_height + 60


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def create_simple_architecture(name: str, services: List[str]) -> Architecture:
    """Create a simple architecture from a list of services"""
    
    nodes = []
    for i, service in enumerate(services):
        service_info = AWS_SERVICES.get(service, {"name": service})
        nodes.append(ServiceNode(
            id=f"node_{i}",
            service_type=service,
            label=service_info.get("name", service)
        ))
    
    # Create simple linear connections
    connections = []
    for i in range(len(nodes) - 1):
        connections.append(Connection(
            source_id=nodes[i].id,
            target_id=nodes[i + 1].id
        ))
    
    return Architecture(
        name=name,
        description=f"Architecture with {len(services)} services",
        nodes=nodes,
        connections=connections
    )


def generate_architecture_svg(architecture: Architecture, width: int = 1200, height: int = 800) -> str:
    """Generate SVG from architecture definition"""
    generator = AWSDiagramGenerator(width, height)
    return generator.generate_svg(architecture)
