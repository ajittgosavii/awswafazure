"""
Data Provider - Demo/Live Mode Abstraction Layer
Provides unified interface for demo and live AWS data
"""

import streamlit as st
from typing import Any, Callable, Optional, Dict, List
from datetime import datetime, timedelta
import random

class DataProvider:
    """Abstract data provider with demo/live mode support"""
    
    def __init__(self, mode: str = "demo"):
        """
        Initialize data provider
        
        Args:
            mode: "demo" or "live"
        """
        self.mode = mode.lower()
    
    def get(
        self, 
        key: str,
        demo_value: Any,
        live_fn: Optional[Callable] = None,
        cache_ttl: int = 60
    ) -> Any:
        """
        Get data based on current mode
        
        Args:
            key: Unique key for the data
            demo_value: Value to return in demo mode
            live_fn: Function to call in live mode (returns data)
            cache_ttl: Cache time-to-live in seconds
        
        Returns:
            Data based on current mode
        """
        if self.mode == "demo":
            return demo_value
        elif self.mode == "live" and live_fn:
            try:
                # Try to get live data
                return live_fn()
            except Exception as e:
                st.warning(f"⚠️ Failed to fetch live data for {key}: {e}")
                st.info("Falling back to demo data")
                return demo_value
        else:
            return demo_value
    
    def is_demo_mode(self) -> bool:
        """Check if in demo mode"""
        return self.mode == "demo"
    
    def is_live_mode(self) -> bool:
        """Check if in live mode"""
        return self.mode == "live"
    
    def set_mode(self, mode: str):
        """Set current mode"""
        self.mode = mode.lower()


class LiveDataService:
    """Service for fetching live AWS data"""
    
    def __init__(self):
        """Initialize live data service"""
        from core_account_manager import get_account_manager
        self.account_mgr = get_account_manager()
    
    def get_ec2_instances(
        self, 
        account_name: str = None,
        region: str = "us-east-1"
    ) -> List[Dict]:
        """Get real EC2 instances"""
        try:
            if not self.account_mgr:
                return []
            
            from config_settings import AppConfig
            accounts = AppConfig.load_aws_accounts()
            
            instances = []
            for account in accounts:
                if account_name and account.account_name != account_name:
                    continue
                
                session = self.account_mgr.assume_role(
                    account.account_id,
                    account.account_name,
                    account.role_arn
                )
                
                if session:
                    from aws_ec2 import EC2Service
                    ec2_service = EC2Service(session.session, region)
                    result = ec2_service.list_instances()
                    instances.extend(result.get('instances', []))
            
            return instances
        except Exception as e:
            st.error(f"Error fetching EC2 instances: {e}")
            return []
    
    def get_monthly_cost(self, account_name: str = None) -> str:
        """Get real monthly cost from Cost Explorer"""
        try:
            if not self.account_mgr:
                return "$0"
            
            # This would integrate with Cost Explorer
            # Placeholder for now
            return "$0"
        except Exception:
            return "$0"
    
    def get_security_findings(self, account_name: str = None) -> List[Dict]:
        """Get real security findings from Security Hub"""
        try:
            if not self.account_mgr:
                return []
            
            # This would integrate with Security Hub
            # Placeholder for now
            return []
        except Exception:
            return []


class DemoDataGenerator:
    """Generate realistic demo data for testing"""
    
    @staticmethod
    def generate_ec2_instances(count: int = 10) -> List[Dict]:
        """Generate demo EC2 instances"""
        instance_types = ['t3.micro', 't3.small', 't3.medium', 't3.large', 'm5.large', 'm5.xlarge']
        states = ['running', 'stopped', 'pending']
        environments = ['production', 'staging', 'development']
        
        instances = []
        for i in range(count):
            instances.append({
                'InstanceId': f'i-{random.randint(1000000000, 9999999999):010x}',
                'InstanceType': random.choice(instance_types),
                'State': {'Name': random.choice(states)},
                'LaunchTime': datetime.now() - timedelta(days=random.randint(1, 365)),
                'Tags': [
                    {'Key': 'Name', 'Value': f'web-server-{i+1}'},
                    {'Key': 'Environment', 'Value': random.choice(environments)},
                    {'Key': 'Owner', 'Value': f'team-{random.randint(1, 5)}'}
                ],
                'PrivateIpAddress': f'10.0.{random.randint(1, 255)}.{random.randint(1, 255)}',
                'PublicIpAddress': f'{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}' if random.random() > 0.3 else None
            })
        
        return instances
    
    @staticmethod
    def generate_cost_data(months: int = 6) -> List[Dict]:
        """Generate demo cost data"""
        services = ['EC2', 'RDS', 'S3', 'Lambda', 'ECS', 'CloudWatch']
        base_costs = {'EC2': 5000, 'RDS': 3000, 'S3': 500, 'Lambda': 200, 'ECS': 1500, 'CloudWatch': 300}
        
        cost_data = []
        for month_offset in range(months):
            date = datetime.now() - timedelta(days=30 * month_offset)
            
            for service in services:
                base = base_costs[service]
                variation = random.uniform(0.8, 1.2)
                cost = base * variation
                
                cost_data.append({
                    'service': service,
                    'date': date.strftime('%Y-%m'),
                    'cost': round(cost, 2),
                    'currency': 'USD'
                })
        
        return cost_data
    
    @staticmethod
    def generate_security_findings(count: int = 15) -> List[Dict]:
        """Generate demo security findings"""
        severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL']
        titles = [
            'S3 bucket with public read access',
            'Security group allows unrestricted SSH access',
            'IAM user with unused credentials',
            'Unencrypted EBS volume detected',
            'CloudTrail logging not enabled',
            'RDS instance without backup',
            'Lambda function with overly permissive role',
            'EC2 instance with IMDSv1 enabled',
            'Unused security group detected',
            'VPC flow logs not enabled'
        ]
        
        findings = []
        for i in range(count):
            findings.append({
                'Id': f'finding-{i+1}',
                'Title': random.choice(titles),
                'Severity': {'Label': random.choice(severities)},
                'CreatedAt': (datetime.now() - timedelta(days=random.randint(0, 30))).isoformat(),
                'UpdatedAt': (datetime.now() - timedelta(days=random.randint(0, 7))).isoformat(),
                'Resources': [
                    {
                        'Type': random.choice(['AwsEc2Instance', 'AwsS3Bucket', 'AwsIamRole', 'AwsRdsDbInstance']),
                        'Id': f'arn:aws:service:us-east-1:123456789012:resource/demo-{i+1}'
                    }
                ],
                'Compliance': {
                    'Status': random.choice(['PASSED', 'FAILED', 'WARNING'])
                }
            })
        
        return findings
    
    @staticmethod
    def generate_accounts(count: int = 5) -> List[Dict]:
        """Generate demo AWS accounts"""
        environments = ['Production', 'Staging', 'Development', 'Security', 'Shared Services']
        
        accounts = []
        for i in range(count):
            account_id = f"{random.randint(100000000000, 999999999999)}"
            accounts.append({
                'Id': account_id,
                'Name': environments[i] if i < len(environments) else f'Account-{i+1}',
                'Email': f'aws-{environments[i].lower().replace(" ", "-")}@company.com',
                'Status': 'ACTIVE',
                'JoinedMethod': 'CREATED' if i == 0 else 'INVITED',
                'Environment': environments[i] if i < len(environments) else 'Other',
                'Owner': f'team-{random.randint(1, 5)}@company.com',
                'CostCenter': f'CC-{random.randint(1000, 9999)}'
            })
        
        return accounts
    
    @staticmethod
    def generate_rds_instances(count: int = 5) -> List[Dict]:
        """Generate demo RDS instances"""
        engines = ['mysql', 'postgres', 'aurora-mysql', 'aurora-postgresql', 'mariadb']
        instance_classes = ['db.t3.micro', 'db.t3.small', 'db.t3.medium', 'db.r5.large']
        
        instances = []
        for i in range(count):
            instances.append({
                'DBInstanceIdentifier': f'database-{i+1}',
                'Engine': random.choice(engines),
                'DBInstanceClass': random.choice(instance_classes),
                'DBInstanceStatus': random.choice(['available', 'backing-up', 'stopped']),
                'AllocatedStorage': random.choice([20, 50, 100, 200, 500]),
                'MultiAZ': random.choice([True, False]),
                'EngineVersion': '8.0.28' if 'mysql' in random.choice(engines) else '14.5',
                'Endpoint': {
                    'Address': f'database-{i+1}.abc123xyz.us-east-1.rds.amazonaws.com',
                    'Port': 3306 if 'mysql' in random.choice(engines) else 5432
                }
            })
        
        return instances


# Global instances
@st.cache_resource
def get_data_provider() -> DataProvider:
    """Get cached data provider instance"""
    mode = st.session_state.get('mode', 'Demo').lower()
    return DataProvider(mode)

@st.cache_resource
def get_live_service() -> LiveDataService:
    """Get cached live data service"""
    return LiveDataService()

@st.cache_resource
def get_demo_generator() -> DemoDataGenerator:
    """Get cached demo data generator"""
    return DemoDataGenerator()
