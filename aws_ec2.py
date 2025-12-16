"""
AWS EC2 Service Integration
"""

import streamlit as st
from typing import List, Dict, Optional
from datetime import datetime
import boto3
from botocore.exceptions import ClientError

class EC2Service:
    """EC2 operations across accounts and regions"""
    
    def __init__(self, session: boto3.Session, region: str = 'us-east-1'):
        """Initialize EC2 service"""
        self.session = session
        self.region = region
        self.client = session.client('ec2', region_name=region)
    
    def list_instances(_self, filters: Optional[List[Dict]] = None) -> Dict:
        """
        List all EC2 instances
        
        Returns:
            Dict with instances list and metadata
        """
        try:
            params = {}
            if filters:
                params['Filters'] = filters
            
            instances = []
            paginator = _self.client.get_paginator('describe_instances')
            
            for page in paginator.paginate(**params):
                for reservation in page['Reservations']:
                    for instance in reservation['Instances']:
                        instances.append({
                            'instance_id': instance['InstanceId'],
                            'instance_type': instance['InstanceType'],
                            'state': instance['State']['Name'],
                            'launch_time': instance['LaunchTime'],
                            'availability_zone': instance['Placement']['AvailabilityZone'],
                            'private_ip': instance.get('PrivateIpAddress', 'N/A'),
                            'public_ip': instance.get('PublicIpAddress', 'N/A'),
                            'vpc_id': instance.get('VpcId', 'N/A'),
                            'subnet_id': instance.get('SubnetId', 'N/A'),
                            'tags': {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])},
                            'platform': instance.get('Platform', 'Linux'),
                            'monitoring': instance['Monitoring']['State'],
                            'key_name': instance.get('KeyName', 'N/A')
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
    
    def get_instance_details(self, instance_id: str) -> Optional[Dict]:
        """Get detailed information about an instance"""
        try:
            response = self.client.describe_instances(InstanceIds=[instance_id])
            
            if response['Reservations']:
                instance = response['Reservations'][0]['Instances'][0]
                return {
                    'instance_id': instance['InstanceId'],
                    'instance_type': instance['InstanceType'],
                    'state': instance['State']['Name'],
                    'launch_time': instance['LaunchTime'],
                    'availability_zone': instance['Placement']['AvailabilityZone'],
                    'private_ip': instance.get('PrivateIpAddress'),
                    'public_ip': instance.get('PublicIpAddress'),
                    'vpc_id': instance.get('VpcId'),
                    'subnet_id': instance.get('SubnetId'),
                    'security_groups': [sg['GroupId'] for sg in instance.get('SecurityGroups', [])],
                    'iam_profile': instance.get('IamInstanceProfile', {}).get('Arn'),
                    'tags': {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])},
                    'monitoring': instance['Monitoring']['State'],
                    'platform': instance.get('Platform', 'Linux'),
                    'root_device_type': instance.get('RootDeviceType'),
                    'virtualization_type': instance.get('VirtualizationType')
                }
            return None
            
        except ClientError:
            return None
    
    def start_instance(self, instance_id: str) -> bool:
        """Start an EC2 instance"""
        try:
            self.client.start_instances(InstanceIds=[instance_id])
            return True
        except ClientError:
            return False
    
    def stop_instance(self, instance_id: str) -> bool:
        """Stop an EC2 instance"""
        try:
            self.client.stop_instances(InstanceIds=[instance_id])
            return True
        except ClientError:
            return False
    
    def reboot_instance(self, instance_id: str) -> bool:
        """Reboot an EC2 instance"""
        try:
            self.client.reboot_instances(InstanceIds=[instance_id])
            return True
        except ClientError:
            return False
    
    def add_tags(self, instance_id: str, tags: Dict[str, str]) -> bool:
        """Add tags to an instance"""
        try:
            tag_list = [{'Key': k, 'Value': v} for k, v in tags.items()]
            self.client.create_tags(
                Resources=[instance_id],
                Tags=tag_list
            )
            return True
        except ClientError:
            return False
    
    def get_instance_types(_self) -> List[str]:
        """Get list of available instance types"""
        try:
            response = _self.client.describe_instance_types()
            return sorted([it['InstanceType'] for it in response['InstanceTypes']])
        except ClientError:
            return []
    
    def get_ami_list(_self, owners: List[str] = ['amazon']) -> List[Dict]:
        """Get list of available AMIs"""
        try:
            response = _self.client.describe_images(
                Owners=owners,
                Filters=[
                    {'Name': 'state', 'Values': ['available']},
                    {'Name': 'architecture', 'Values': ['x86_64']}
                ]
            )
            
            amis = []
            for image in response['Images'][:50]:  # Limit to 50 most recent
                amis.append({
                    'ami_id': image['ImageId'],
                    'name': image.get('Name', 'N/A'),
                    'description': image.get('Description', 'N/A'),
                    'creation_date': image.get('CreationDate', 'N/A'),
                    'platform': image.get('PlatformDetails', 'Linux/UNIX')
                })
            
            return sorted(amis, key=lambda x: x['creation_date'], reverse=True)
            
        except ClientError:
            return []
    
    def get_cost_estimate(self, instance_type: str, hours_per_month: int = 730) -> float:
        """Estimate monthly cost for instance type (simplified)"""
        # Simplified pricing - in production, use AWS Pricing API
        pricing = {
            't2.micro': 0.0116,
            't2.small': 0.023,
            't2.medium': 0.0464,
            't3.micro': 0.0104,
            't3.small': 0.0208,
            't3.medium': 0.0416,
            'm5.large': 0.096,
            'm5.xlarge': 0.192,
            'c5.large': 0.085,
            'r5.large': 0.126
        }
        
        hourly_rate = pricing.get(instance_type, 0.10)  # Default to $0.10/hr
        return hourly_rate * hours_per_month
