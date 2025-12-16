"""
AWS RDS Service Integration
"""

import streamlit as st
from typing import List, Dict, Optional
import boto3
from botocore.exceptions import ClientError

class RDSService:
    """RDS operations across accounts and regions"""
    
    def __init__(self, session: boto3.Session, region: str = 'us-east-1'):
        """Initialize RDS service"""
        self.session = session
        self.region = region
        self.client = session.client('rds', region_name=region)
    
    def list_db_instances(_self) -> Dict:
        """List all RDS database instances"""
        try:
            instances = []
            paginator = _self.client.get_paginator('describe_db_instances')
            
            for page in paginator.paginate():
                for db in page['DBInstances']:
                    instances.append({
                        'db_instance_id': db['DBInstanceIdentifier'],
                        'db_instance_class': db['DBInstanceClass'],
                        'engine': db['Engine'],
                        'engine_version': db['EngineVersion'],
                        'status': db['DBInstanceStatus'],
                        'endpoint': db.get('Endpoint', {}).get('Address', 'N/A'),
                        'port': db.get('Endpoint', {}).get('Port', 'N/A'),
                        'availability_zone': db.get('AvailabilityZone', 'N/A'),
                        'multi_az': db.get('MultiAZ', False),
                        'storage_type': db.get('StorageType', 'N/A'),
                        'allocated_storage': db.get('AllocatedStorage', 0),
                        'backup_retention': db.get('BackupRetentionPeriod', 0),
                        'created_time': db.get('InstanceCreateTime'),
                        'tags': {tag['Key']: tag['Value'] for tag in db.get('TagList', [])}
                    })
            
            return {
                'success': True,
                'count': len(instances),
                'instances': instances,
                'region': _self.region
            }
        except ClientError as e:
            return {
                'success': False,
                'error': str(e),
                'count': 0,
                'instances': []
            }
    
    def get_cost_estimate(self, instance_class: str, storage_gb: int = 100, hours_per_month: int = 730) -> float:
        """Estimate monthly cost for RDS instance"""
        # Simplified pricing
        pricing = {
            'db.t3.micro': 0.017,
            'db.t3.small': 0.034,
            'db.t3.medium': 0.068,
            'db.t3.large': 0.136,
            'db.m5.large': 0.192,
            'db.m5.xlarge': 0.384,
            'db.r5.large': 0.24,
            'db.r5.xlarge': 0.48
        }
        
        hourly_rate = pricing.get(instance_class, 0.10)
        instance_cost = hourly_rate * hours_per_month
        storage_cost = storage_gb * 0.115  # $0.115/GB/month for gp2
        
        return instance_cost + storage_cost
