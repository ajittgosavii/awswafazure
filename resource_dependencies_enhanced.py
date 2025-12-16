"""
Enhanced Resource Dependencies Section
Allows users to select and view dependencies for specific applications
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
from typing import Dict, List

def render_resource_dependencies_enhanced(account_mgr):
    """Enhanced resource dependencies with application selector - REAL MODE READY"""
    
    st.markdown("### 🔗 Resource Dependencies & Relationships")
    st.caption("Visualize connections between resources - Select an application to view its dependency tree")
    
    st.info("""
    **Resource Dependency Mapping:**
    - EC2 Instances → VPC, Security Groups, EBS Volumes, Elastic IPs
    - RDS Databases → VPC, Security Groups, Parameter Groups
    - Load Balancers → Target Groups, EC2 Instances, VPC
    - Lambda Functions → VPC, IAM Roles, API Gateway
    - S3 Buckets → CloudFront Distributions, IAM Policies
    """)
    
    # ========================================================================
    # APPLICATION/RESOURCE SELECTOR
    # ========================================================================
    
    st.markdown("---")
    st.markdown("#### 🎯 Select Application or Resource")
    
    col1, col2, col3 = st.columns([2, 2, 1])
    
    with col1:
        # View mode selection
        view_mode = st.radio(
            "View Mode",
            ["Demo Mode", "Real Mode"],
            horizontal=True,
            key="dep_view_mode",
            help="Demo Mode: Sample data | Real Mode: Your actual AWS resources"
        )
    
    # ========================================================================
    # DEMO MODE - Sample Applications
    # ========================================================================
    
    if view_mode == "Demo Mode":
        # Define sample applications with their dependencies
        demo_applications = {
            "Production Web Application": {
                "root": "ALB: prod-alb-main",
                "dependencies": [
                    {
                        'Resource': 'ALB: prod-alb-main',
                        'Type': 'Application Load Balancer',
                        'Status': 'Active',
                        'Depends On': '-',
                        'Critical': 'Yes'
                    },
                    {
                        'Resource': '└─ Target Group: prod-web-tg',
                        'Type': 'Target Group',
                        'Status': 'Healthy',
                        'Depends On': 'ALB',
                        'Critical': 'Yes'
                    },
                    {
                        'Resource': '   └─ EC2: prod-web-server-01',
                        'Type': 'EC2 Instance',
                        'Status': 'Running',
                        'Depends On': 'Target Group',
                        'Critical': 'Yes'
                    },
                    {
                        'Resource': '      ├─ VPC: vpc-prod',
                        'Type': 'VPC',
                        'Status': 'Available',
                        'Depends On': 'EC2',
                        'Critical': 'Yes'
                    },
                    {
                        'Resource': '      ├─ Security Group: sg-prod-web',
                        'Type': 'Security Group',
                        'Status': 'Active',
                        'Depends On': 'EC2',
                        'Critical': 'Yes'
                    },
                    {
                        'Resource': '      ├─ EBS Volume: vol-0abc123',
                        'Type': 'EBS Volume',
                        'Status': 'In-use',
                        'Depends On': 'EC2',
                        'Critical': 'Yes'
                    },
                    {
                        'Resource': '      └─ Elastic IP: 54.123.45.67',
                        'Type': 'Elastic IP',
                        'Status': 'Associated',
                        'Depends On': 'EC2',
                        'Critical': 'No'
                    },
                    {
                        'Resource': '   └─ EC2: prod-web-server-02',
                        'Type': 'EC2 Instance',
                        'Status': 'Running',
                        'Depends On': 'Target Group',
                        'Critical': 'Yes'
                    },
                    {
                        'Resource': '└─ CloudFront: E1ABC2DEF3GHI',
                        'Type': 'CloudFront Distribution',
                        'Status': 'Deployed',
                        'Depends On': 'ALB',
                        'Critical': 'No'
                    }
                ]
            },
            "E-Commerce Platform": {
                "root": "ALB: ecommerce-alb",
                "dependencies": [
                    {
                        'Resource': 'ALB: ecommerce-alb',
                        'Type': 'Application Load Balancer',
                        'Status': 'Active',
                        'Depends On': '-',
                        'Critical': 'Yes'
                    },
                    {
                        'Resource': '└─ Target Group: ecommerce-app-tg',
                        'Type': 'Target Group',
                        'Status': 'Healthy',
                        'Depends On': 'ALB',
                        'Critical': 'Yes'
                    },
                    {
                        'Resource': '   ├─ ECS Service: ecommerce-app',
                        'Type': 'ECS Service',
                        'Status': 'Running',
                        'Depends On': 'Target Group',
                        'Critical': 'Yes'
                    },
                    {
                        'Resource': '   │  ├─ Task Definition: ecommerce-app:v12',
                        'Type': 'ECS Task',
                        'Status': 'Active',
                        'Depends On': 'ECS Service',
                        'Critical': 'Yes'
                    },
                    {
                        'Resource': '   │  ├─ ECR: ecommerce/app-image',
                        'Type': 'Container Registry',
                        'Status': 'Active',
                        'Depends On': 'Task',
                        'Critical': 'Yes'
                    },
                    {
                        'Resource': '   │  └─ IAM Role: ecommerce-task-role',
                        'Type': 'IAM Role',
                        'Status': 'Active',
                        'Depends On': 'Task',
                        'Critical': 'Yes'
                    },
                    {
                        'Resource': '   └─ RDS: ecommerce-db',
                        'Type': 'RDS PostgreSQL',
                        'Status': 'Available',
                        'Depends On': 'ECS Service',
                        'Critical': 'Yes'
                    },
                    {
                        'Resource': '      ├─ DB Subnet Group: ecommerce-subnet',
                        'Type': 'DB Subnet Group',
                        'Status': 'Active',
                        'Depends On': 'RDS',
                        'Critical': 'Yes'
                    },
                    {
                        'Resource': '      └─ Security Group: sg-ecommerce-db',
                        'Type': 'Security Group',
                        'Status': 'Active',
                        'Depends On': 'RDS',
                        'Critical': 'Yes'
                    },
                    {
                        'Resource': '└─ ElastiCache: ecommerce-redis',
                        'Type': 'Redis Cluster',
                        'Status': 'Available',
                        'Depends On': 'ALB',
                        'Critical': 'No'
                    }
                ]
            },
            "Data Processing Pipeline": {
                "root": "Lambda: data-processor",
                "dependencies": [
                    {
                        'Resource': 'Lambda: data-processor',
                        'Type': 'Lambda Function',
                        'Status': 'Active',
                        'Depends On': '-',
                        'Critical': 'Yes'
                    },
                    {
                        'Resource': '├─ S3 Bucket: raw-data-bucket',
                        'Type': 'S3 Bucket',
                        'Status': 'Active',
                        'Depends On': 'Lambda',
                        'Critical': 'Yes'
                    },
                    {
                        'Resource': '│  └─ S3 Event Notification',
                        'Type': 'S3 Event',
                        'Status': 'Enabled',
                        'Depends On': 'S3',
                        'Critical': 'Yes'
                    },
                    {
                        'Resource': '├─ DynamoDB: processing-state',
                        'Type': 'DynamoDB Table',
                        'Status': 'Active',
                        'Depends On': 'Lambda',
                        'Critical': 'Yes'
                    },
                    {
                        'Resource': '│  ├─ DynamoDB Stream',
                        'Type': 'DynamoDB Stream',
                        'Status': 'Enabled',
                        'Depends On': 'DynamoDB',
                        'Critical': 'No'
                    },
                    {
                        'Resource': '│  └─ Global Table Replica: us-west-2',
                        'Type': 'DynamoDB Replica',
                        'Status': 'Active',
                        'Depends On': 'DynamoDB',
                        'Critical': 'No'
                    },
                    {
                        'Resource': '├─ SQS Queue: data-processing-queue',
                        'Type': 'SQS Queue',
                        'Status': 'Active',
                        'Depends On': 'Lambda',
                        'Critical': 'Yes'
                    },
                    {
                        'Resource': '│  └─ DLQ: data-processing-dlq',
                        'Type': 'Dead Letter Queue',
                        'Status': 'Active',
                        'Depends On': 'SQS',
                        'Critical': 'Yes'
                    },
                    {
                        'Resource': '├─ SNS Topic: processing-notifications',
                        'Type': 'SNS Topic',
                        'Status': 'Active',
                        'Depends On': 'Lambda',
                        'Critical': 'No'
                    },
                    {
                        'Resource': '└─ IAM Role: lambda-execution-role',
                        'Type': 'IAM Role',
                        'Status': 'Active',
                        'Depends On': 'Lambda',
                        'Critical': 'Yes'
                    }
                ]
            },
            "Mobile API Backend": {
                "root": "API Gateway: mobile-api",
                "dependencies": [
                    {
                        'Resource': 'API Gateway: mobile-api',
                        'Type': 'API Gateway REST',
                        'Status': 'Deployed',
                        'Depends On': '-',
                        'Critical': 'Yes'
                    },
                    {
                        'Resource': '├─ Lambda: auth-handler',
                        'Type': 'Lambda Function',
                        'Status': 'Active',
                        'Depends On': 'API Gateway',
                        'Critical': 'Yes'
                    },
                    {
                        'Resource': '│  └─ Cognito: mobile-user-pool',
                        'Type': 'Cognito User Pool',
                        'Status': 'Active',
                        'Depends On': 'Lambda',
                        'Critical': 'Yes'
                    },
                    {
                        'Resource': '├─ Lambda: user-profile-api',
                        'Type': 'Lambda Function',
                        'Status': 'Active',
                        'Depends On': 'API Gateway',
                        'Critical': 'Yes'
                    },
                    {
                        'Resource': '│  └─ Aurora: user-profiles-db',
                        'Type': 'Aurora MySQL',
                        'Status': 'Available',
                        'Depends On': 'Lambda',
                        'Critical': 'Yes'
                    },
                    {
                        'Resource': '├─ Lambda: content-api',
                        'Type': 'Lambda Function',
                        'Status': 'Active',
                        'Depends On': 'API Gateway',
                        'Critical': 'Yes'
                    },
                    {
                        'Resource': '│  ├─ S3 Bucket: mobile-content',
                        'Type': 'S3 Bucket',
                        'Status': 'Active',
                        'Depends On': 'Lambda',
                        'Critical': 'Yes'
                    },
                    {
                        'Resource': '│  └─ CloudFront: mobile-cdn',
                        'Type': 'CloudFront Distribution',
                        'Status': 'Deployed',
                        'Depends On': 'S3',
                        'Critical': 'No'
                    },
                    {
                        'Resource': '└─ WAF: mobile-api-waf',
                        'Type': 'AWS WAF',
                        'Status': 'Active',
                        'Depends On': 'API Gateway',
                        'Critical': 'Yes'
                    }
                ]
            },
            "Analytics Dashboard": {
                "root": "QuickSight: analytics-dashboard",
                "dependencies": [
                    {
                        'Resource': 'QuickSight: analytics-dashboard',
                        'Type': 'QuickSight Dashboard',
                        'Status': 'Active',
                        'Depends On': '-',
                        'Critical': 'Yes'
                    },
                    {
                        'Resource': '├─ Athena: analytics-queries',
                        'Type': 'Athena Workgroup',
                        'Status': 'Active',
                        'Depends On': 'QuickSight',
                        'Critical': 'Yes'
                    },
                    {
                        'Resource': '│  └─ S3 Bucket: query-results',
                        'Type': 'S3 Bucket',
                        'Status': 'Active',
                        'Depends On': 'Athena',
                        'Critical': 'Yes'
                    },
                    {
                        'Resource': '├─ Glue: analytics-catalog',
                        'Type': 'Glue Data Catalog',
                        'Status': 'Active',
                        'Depends On': 'QuickSight',
                        'Critical': 'Yes'
                    },
                    {
                        'Resource': '│  ├─ Glue Crawler: data-discovery',
                        'Type': 'Glue Crawler',
                        'Status': 'Ready',
                        'Depends On': 'Glue',
                        'Critical': 'Yes'
                    },
                    {
                        'Resource': '│  └─ S3 Bucket: analytics-data-lake',
                        'Type': 'S3 Bucket',
                        'Status': 'Active',
                        'Depends On': 'Glue',
                        'Critical': 'Yes'
                    },
                    {
                        'Resource': '├─ Redshift: analytics-warehouse',
                        'Type': 'Redshift Cluster',
                        'Status': 'Available',
                        'Depends On': 'QuickSight',
                        'Critical': 'No'
                    },
                    {
                        'Resource': '│  └─ Redshift Spectrum',
                        'Type': 'Spectrum Query',
                        'Status': 'Enabled',
                        'Depends On': 'Redshift',
                        'Critical': 'No'
                    },
                    {
                        'Resource': '└─ IAM Role: quicksight-access-role',
                        'Type': 'IAM Role',
                        'Status': 'Active',
                        'Depends On': 'QuickSight',
                        'Critical': 'Yes'
                    }
                ]
            }
        }
        
        with col2:
            selected_app = st.selectbox(
                "Select Application",
                options=list(demo_applications.keys()),
                key="demo_app_selector",
                help="Choose an application to view its resource dependencies"
            )
        
        with col3:
            show_critical_only = st.checkbox(
                "Critical Only",
                value=False,
                key="show_critical_only",
                help="Show only critical dependencies"
            )
        
        # Display selected application dependencies
        st.markdown(f"#### 🔍 {selected_app} - Dependency Tree")
        
        # Get dependencies for selected application
        app_data = demo_applications[selected_app]
        dependencies = app_data['dependencies']
        
        # Filter if critical only
        if show_critical_only:
            dependencies = [d for d in dependencies if d['Critical'] == 'Yes']
        
        df = pd.DataFrame(dependencies)
        
        # Color code by status
        def style_status(val):
            colors = {
                'Active': 'background-color: #d4edda',
                'Running': 'background-color: #d4edda',
                'Available': 'background-color: #d4edda',
                'Healthy': 'background-color: #d1ecf1',
                'Deployed': 'background-color: #d1ecf1',
                'Enabled': 'background-color: #fff3cd',
                'Ready': 'background-color: #fff3cd'
            }
            return colors.get(val, '')
        
        st.dataframe(df, use_container_width=True, hide_index=True)
        
        # Summary metrics
        st.markdown("---")
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Resources", len(dependencies))
        
        with col2:
            critical_count = sum(1 for d in dependencies if d['Critical'] == 'Yes')
            st.metric("Critical Resources", critical_count)
        
        with col3:
            unique_types = len(set(d['Type'] for d in dependencies))
            st.metric("Resource Types", unique_types)
        
        with col4:
            active_count = sum(1 for d in dependencies if d['Status'] in ['Active', 'Running', 'Available'])
            st.metric("Active/Healthy", active_count)
    
    # ========================================================================
    # REAL MODE - Actual AWS Resources
    # ========================================================================
    
    else:  # Real Mode
        st.markdown("#### 🔄 Real Mode - Your AWS Resources")
        
        # In real mode, you would fetch actual AWS resources
        # Here's the framework for implementation:
        
        with col2:
            # Get actual applications from AWS
            # This would query your AWS environment for tagged resources
            
            # Example: Query resources with 'Application' tag
            st.info("🔧 **Setup Required:** Tag your AWS resources with 'Application' tag to enable auto-discovery")
            
            # Placeholder for real implementation
            real_applications = st.selectbox(
                "Select Application",
                options=["No applications found - Add 'Application' tags to your resources"],
                key="real_app_selector",
                disabled=True,
                help="Tag your AWS resources with 'Application' to auto-discover them"
            )
        
        st.markdown("##### 📋 How to Enable Real Mode:")
        st.code("""
# Tag your AWS resources with 'Application' tag:
# 
# For EC2:
aws ec2 create-tags --resources i-1234567890abcdef0 \\
  --tags Key=Application,Value="Production Web Application"

# For RDS:
aws rds add-tags-to-resource --resource-name arn:aws:rds:... \\
  --tags Key=Application,Value="Production Web Application"

# For Load Balancers:
aws elbv2 add-tags --resource-arns arn:aws:elasticloadbalancing:... \\
  --tags Key=Application,Value="Production Web Application"
        """, language="bash")
        
        # Implementation template
        st.markdown("---")
        st.markdown("##### 🔨 Real Mode Implementation (for developers):")
        
        with st.expander("View Real Mode Implementation Code"):
            st.code('''
def get_application_dependencies(application_name: str, session, region: str):
    """
    Query AWS to build dependency tree for an application
    """
    import boto3
    
    # Initialize AWS clients
    ec2 = session.client('ec2', region_name=region)
    elb = session.client('elbv2', region_name=region)
    rds = session.client('rds', region_name=region)
    lambda_client = session.client('lambda', region_name=region)
    
    dependencies = []
    
    # 1. Find all resources tagged with this application
    ec2_resources = ec2.describe_instances(
        Filters=[{'Name': 'tag:Application', 'Values': [application_name]}]
    )
    
    # 2. For each resource, find its dependencies
    for reservation in ec2_resources['Reservations']:
        for instance in reservation['Instances']:
            # Get VPC
            vpc_id = instance.get('VpcId')
            
            # Get Security Groups
            sg_ids = [sg['GroupId'] for sg in instance.get('SecurityGroups', [])]
            
            # Get EBS Volumes
            volumes = [bdm['Ebs']['VolumeId'] for bdm in instance.get('BlockDeviceMappings', [])]
            
            # Get Elastic IPs
            # ... and so on
    
    # 3. Find load balancers for this application
    load_balancers = elb.describe_load_balancers()
    for lb in load_balancers['LoadBalancers']:
        tags = elb.describe_tags(ResourceArns=[lb['LoadBalancerArn']])
        # Check if tagged with application
        # Get target groups
        # Get EC2 instances in target groups
        # ... and so on
    
    # 4. Build dependency tree
    # ... organize resources into parent-child relationships
    
    return dependencies
            ''', language='python')
    
    # ========================================================================
    # ADDITIONAL FEATURES
    # ========================================================================
    
    st.markdown("---")
    st.markdown("### 🎨 Additional Visualization Options")
    
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("📊 View Network Graph", use_container_width=True, key="view_network_graph"):
            st.info("Network graph visualization coming soon! Will show interactive node-based dependency graph.")
    
    with col2:
        if st.button("📥 Export Dependencies", use_container_width=True, key="export_dependencies"):
            st.success("Export functionality coming soon! Will export to CSV, JSON, or Visio format.")
    
    st.markdown("---")
    st.success("💡 **Tip:** Understanding resource dependencies helps identify impact of changes, optimize costs, and ensure high availability")


# ========================================================================
# USAGE IN YOUR MODULE
# ========================================================================

# To replace the existing _render_resource_dependencies method in your module:
# 
# Simply replace this section (around line 1253):
#
# @staticmethod
# def _render_resource_dependencies(account_mgr):
#     render_resource_dependencies_enhanced(account_mgr)
#