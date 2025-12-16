"""
Application Configuration and Settings - Multi-Cloud Support
Supports AWS, Azure, and GCP
"""

import streamlit as st
from typing import Dict, List, Optional
from dataclasses import dataclass
from enum import Enum
import json

class CloudProvider(Enum):
    """Supported cloud providers"""
    AWS = "AWS"
    AZURE = "Azure"
    GCP = "GCP"

@dataclass
class AWSAccountConfig:
    """Configuration for a single AWS account"""
    account_id: str
    account_name: str
    role_arn: str
    regions: List[str]
    environment: str  # production, development, staging, etc.
    cost_center: Optional[str] = None
    owner_email: Optional[str] = None
    status: str = "active"  # active, suspended, offboarding

@dataclass
class AzureSubscriptionConfig:
    """Configuration for a single Azure subscription"""
    subscription_id: str
    subscription_name: str
    tenant_id: str
    regions: List[str]  # Azure regions/locations
    environment: str
    resource_groups: Optional[List[str]] = None
    cost_center: Optional[str] = None
    owner_email: Optional[str] = None
    status: str = "active"

@dataclass
class GCPProjectConfig:
    """Configuration for a single GCP project"""
    project_id: str
    project_name: str
    project_number: str
    billing_account_id: str
    regions: List[str]  # GCP regions
    environment: str
    organization_id: Optional[str] = None
    folder_id: Optional[str] = None
    cost_center: Optional[str] = None
    owner_email: Optional[str] = None
    status: str = "active"

class AppConfig:
    """Global application configuration"""
    
    # Application metadata
    APP_NAME = "CloudIDP v3.0 Tri-Cloud"
    APP_VERSION = "3.0.0"
    
    # AWS Configuration
    AWS_REGIONS = [
        "us-east-1",
        "us-east-2", 
        "us-west-1",
        "us-west-2",
        "eu-west-1",
        "eu-central-1",
        "ap-southeast-1",
        "ap-northeast-1"
    ]
    
    # Azure Configuration
    AZURE_REGIONS = [
        "East US",
        "East US 2",
        "West US",
        "West US 2",
        "Central US",
        "North Europe",
        "West Europe",
        "Southeast Asia",
        "East Asia",
        "UK South",
        "Canada Central",
        "Australia East"
    ]
    
    # GCP Configuration
    GCP_REGIONS = [
        "us-central1",
        "us-east1",
        "us-west1",
        "europe-west1",
        "europe-west2",
        "asia-southeast1",
        "asia-northeast1",
        "australia-southeast1"
    ]
    
    # Backwards compatibility
    DEFAULT_REGIONS = AWS_REGIONS
    
    # Cache TTL (seconds)
    CACHE_TTL_ACCOUNTS = 300  # 5 minutes
    CACHE_TTL_RESOURCES = 60  # 1 minute
    CACHE_TTL_COSTS = 3600    # 1 hour
    CACHE_TTL_SECURITY = 300  # 5 minutes
    
    # Pagination
    DEFAULT_PAGE_SIZE = 50
    MAX_PAGE_SIZE = 500
    
    # Cost thresholds
    COST_WARNING_THRESHOLD = 0.8  # 80% of budget
    COST_CRITICAL_THRESHOLD = 0.95  # 95% of budget
    
    @staticmethod
    def load_aws_accounts() -> List[AWSAccountConfig]:
        """Load AWS account configurations from Streamlit secrets"""
        accounts = []
        
        try:
            # Load from st.secrets
            if "aws" in st.secrets and "accounts" in st.secrets["aws"]:
                for account_key, account_data in st.secrets["aws"]["accounts"].items():
                    accounts.append(AWSAccountConfig(
                        account_id=account_data["account_id"],
                        account_name=account_data.get("account_name", account_key),
                        role_arn=account_data["role_arn"],
                        regions=account_data.get("regions", AppConfig.DEFAULT_REGIONS[:2]),
                        environment=account_data.get("environment", "production"),
                        cost_center=account_data.get("cost_center"),
                        owner_email=account_data.get("owner_email"),
                        status=account_data.get("status", "active")
                    ))
        except Exception as e:
            st.error(f"Error loading AWS account configuration: {e}")
        
        return accounts
    
    @staticmethod
    def get_management_credentials() -> Optional[Dict[str, str]]:
        """Get management account credentials for role assumption"""
        try:
            if "aws" in st.secrets:
                return {
                    "access_key_id": st.secrets["aws"].get("management_access_key_id"),
                    "secret_access_key": st.secrets["aws"].get("management_secret_access_key"),
                    "region": st.secrets["aws"].get("default_region", "us-east-1")
                }
        except Exception:
            pass
        
        # Demo mode fallback
        return {
            "access_key_id": "DEMO_ACCESS_KEY",
            "secret_access_key": "DEMO_SECRET_KEY",
            "region": "us-east-1"
        }
    
    @staticmethod
    def load_azure_subscriptions() -> List[AzureSubscriptionConfig]:
        """Load Azure subscription configurations from Streamlit secrets or demo data"""
        subscriptions = []
        
        try:
            if "azure" in st.secrets and "subscriptions" in st.secrets["azure"]:
                for sub_key, sub_data in st.secrets["azure"]["subscriptions"].items():
                    subscriptions.append(AzureSubscriptionConfig(
                        subscription_id=sub_data["subscription_id"],
                        subscription_name=sub_data.get("subscription_name", sub_key),
                        tenant_id=sub_data["tenant_id"],
                        regions=sub_data.get("regions", AppConfig.AZURE_REGIONS[:2]),
                        environment=sub_data.get("environment", "production"),
                        resource_groups=sub_data.get("resource_groups"),
                        cost_center=sub_data.get("cost_center"),
                        owner_email=sub_data.get("owner_email"),
                        status=sub_data.get("status", "active")
                    ))
        except Exception:
            pass
        
        # Demo data if no real subscriptions
        if not subscriptions:
            subscriptions = [
                AzureSubscriptionConfig(
                    subscription_id="12345678-1234-1234-1234-123456789012",
                    subscription_name="Production-Main",
                    tenant_id="87654321-4321-4321-4321-210987654321",
                    regions=["East US", "West US", "North Europe"],
                    environment="production",
                    resource_groups=["rg-prod-app", "rg-prod-data"],
                    cost_center="PROD-AZURE-001",
                    owner_email="azure-prod@company.com",
                    status="active"
                ),
                AzureSubscriptionConfig(
                    subscription_id="23456789-2345-2345-2345-234567890123",
                    subscription_name="Development",
                    tenant_id="87654321-4321-4321-4321-210987654321",
                    regions=["East US 2"],
                    environment="development",
                    resource_groups=["rg-dev-app"],
                    cost_center="DEV-AZURE-002",
                    owner_email="azure-dev@company.com",
                    status="active"
                )
            ]
        
        return subscriptions
    
    @staticmethod
    def load_gcp_projects() -> List[GCPProjectConfig]:
        """Load GCP project configurations from Streamlit secrets or demo data"""
        projects = []
        
        try:
            if "gcp" in st.secrets and "projects" in st.secrets["gcp"]:
                for proj_key, proj_data in st.secrets["gcp"]["projects"].items():
                    projects.append(GCPProjectConfig(
                        project_id=proj_data["project_id"],
                        project_name=proj_data.get("project_name", proj_key),
                        project_number=proj_data["project_number"],
                        billing_account_id=proj_data["billing_account_id"],
                        regions=proj_data.get("regions", AppConfig.GCP_REGIONS[:2]),
                        environment=proj_data.get("environment", "production"),
                        organization_id=proj_data.get("organization_id"),
                        folder_id=proj_data.get("folder_id"),
                        cost_center=proj_data.get("cost_center"),
                        owner_email=proj_data.get("owner_email"),
                        status=proj_data.get("status", "active")
                    ))
        except Exception:
            pass
        
        # Demo data if no real projects
        if not projects:
            projects = [
                GCPProjectConfig(
                    project_id="prod-main-project",
                    project_name="Production Main",
                    project_number="123456789012",
                    billing_account_id="012345-6789AB-CDEF01",
                    regions=["us-central1", "us-east1", "europe-west1"],
                    environment="production",
                    organization_id="987654321098",
                    folder_id="folders/123456",
                    cost_center="PROD-GCP-001",
                    owner_email="gcp-prod@company.com",
                    status="active"
                ),
                GCPProjectConfig(
                    project_id="dev-project",
                    project_name="Development",
                    project_number="234567890123",
                    billing_account_id="012345-6789AB-CDEF01",
                    regions=["us-central1"],
                    environment="development",
                    organization_id="987654321098",
                    cost_center="DEV-GCP-002",
                    owner_email="gcp-dev@company.com",
                    status="active"
                )
            ]
        
        return projects
    
    @staticmethod
    def get_azure_credentials() -> Optional[Dict[str, str]]:
        """Get Azure credentials from Streamlit secrets or demo"""
        try:
            if "azure" in st.secrets:
                return {
                    "subscription_id": st.secrets["azure"].get("subscription_id"),
                    "tenant_id": st.secrets["azure"].get("tenant_id"),
                    "client_id": st.secrets["azure"].get("client_id"),
                    "client_secret": st.secrets["azure"].get("client_secret")
                }
        except Exception:
            pass
        
        # Demo mode fallback
        return {
            "subscription_id": "DEMO-SUBSCRIPTION-ID",
            "tenant_id": "DEMO-TENANT-ID",
            "client_id": "DEMO-CLIENT-ID",
            "client_secret": "DEMO-CLIENT-SECRET"
        }
    
    @staticmethod
    def get_gcp_credentials() -> Optional[Dict[str, str]]:
        """Get GCP credentials from Streamlit secrets or demo"""
        try:
            if "gcp" in st.secrets:
                return {
                    "project_id": st.secrets["gcp"].get("project_id"),
                    "credentials_json": st.secrets["gcp"].get("credentials_json"),
                    "billing_account_id": st.secrets["gcp"].get("billing_account_id")
                }
        except Exception:
            pass
        
        # Demo mode fallback
        return {
            "project_id": "DEMO-PROJECT-ID",
            "credentials_json": "{}",
            "billing_account_id": "DEMO-BILLING-ID"
        }
    
    @staticmethod
    def get_supported_services() -> List[str]:
        """List of AWS services supported by CloudIDP"""
        return [
            "ec2",
            "rds",
            "dynamodb",
            "s3",
            "lambda",
            "ecs",
            "eks",
            "elasticache",
            "elasticsearch",
            "vpc",
            "elb",
            "elbv2",
            "cloudfront",
            "route53",
            "iam",
            "kms",
            "secretsmanager",
            "cloudwatch",
            "cloudtrail",
            "config",
            "securityhub",
            "guardduty"
        ]
    
    @staticmethod
    def get_compliance_frameworks() -> List[str]:
        """List of supported compliance frameworks"""
        return [
            "CIS AWS Foundations Benchmark",
            "PCI-DSS",
            "HIPAA",
            "SOC 2",
            "ISO 27001",
            "NIST 800-53",
            "GDPR"
        ]
