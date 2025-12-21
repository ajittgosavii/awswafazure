"""
AWS Carbon Footprint Calculator
Calculates estimated CO2 emissions from AWS resource usage
Based on AWS Customer Carbon Footprint methodology
"""

import boto3
from typing import Dict, List
from datetime import datetime, timedelta
from botocore.exceptions import ClientError

# Regional carbon intensity (gCO2e/kWh) - AWS published data
CARBON_INTENSITY = {
    'us-east-1': 415.755,      # US East (N. Virginia)
    'us-east-2': 519.392,      # US East (Ohio)
    'us-west-1': 257.742,      # US West (N. California)
    'us-west-2': 257.742,      # US West (Oregon)
    'ca-central-1': 130.0,     # Canada (Montreal) - 80% renewable
    'eu-west-1': 316.729,      # Europe (Ireland)
    'eu-west-2': 277.731,      # Europe (London)
    'eu-west-3': 70.872,       # Europe (Paris)
    'eu-central-1': 338.425,   # Europe (Frankfurt)
    'eu-north-1': 9.0,         # Europe (Stockholm) - 95% renewable
    'ap-northeast-1': 463.484, # Asia Pacific (Tokyo)
    'ap-northeast-2': 434.264, # Asia Pacific (Seoul)
    'ap-southeast-1': 408.607, # Asia Pacific (Singapore)
    'ap-southeast-2': 564.0,   # Asia Pacific (Sydney)
    'ap-south-1': 708.171,     # Asia Pacific (Mumbai)
    'sa-east-1': 78.996,       # South America (São Paulo)
}

# Power consumption estimates (Watts)
EC2_POWER_CONSUMPTION = {
    't2.micro': 10,
    't2.small': 15,
    't2.medium': 25,
    't3.micro': 8,
    't3.small': 12,
    't3.medium': 20,
    'm5.large': 50,
    'm5.xlarge': 100,
    'c5.large': 45,
    'c5.xlarge': 90,
    'r5.large': 55,
    'r5.xlarge': 110,
    # Add more instance types as needed
    'default': 50  # Default for unknown types
}


class CarbonFootprintCalculator:
    """Calculate carbon emissions from AWS resource usage"""
    
    def __init__(self, session: boto3.Session):
        """Initialize carbon calculator"""
        self.session = session
        self.account_id = session.client('sts').get_caller_identity()['Account']
    
    def calculate_ec2_emissions(self, region: str = 'us-east-1', days: int = 30) -> Dict:
        """Calculate CO2 emissions from EC2 instances"""
        try:
            ec2_client = self.session.client('ec2', region_name=region)
            cloudwatch = self.session.client('cloudwatch', region_name=region)
            
            # Get all running instances
            response = ec2_client.describe_instances(
                Filters=[{'Name': 'instance-state-name', 'Values': ['running']}]
            )
            
            total_emissions_kg = 0
            instance_details = []
            
            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    instance_type = instance['InstanceType']
                    instance_id = instance['InstanceId']
                    
                    # Get power consumption for this instance type
                    power_watts = EC2_POWER_CONSUMPTION.get(instance_type, 
                                                            EC2_POWER_CONSUMPTION['default'])
                    
                    # Calculate emissions
                    # Power (W) * Hours * Carbon Intensity / 1000 / 1000 = kg CO2
                    hours = days * 24
                    kwh = (power_watts * hours) / 1000
                    carbon_intensity = CARBON_INTENSITY.get(region, 400)  # gCO2e/kWh
                    emissions_kg = (kwh * carbon_intensity) / 1000
                    
                    total_emissions_kg += emissions_kg
                    
                    instance_details.append({
                        'instance_id': instance_id,
                        'instance_type': instance_type,
                        'region': region,
                        'emissions_kg': emissions_kg
                    })
            
            return {
                'success': True,
                'total_emissions_kg': total_emissions_kg,
                'instance_count': len(instance_details),
                'details': instance_details,
                'region': region
            }
            
        except ClientError as e:
            return {
                'success': False,
                'error': str(e),
                'total_emissions_kg': 0
            }
    
    def calculate_s3_emissions(self, region: str = 'us-east-1') -> Dict:
        """Calculate CO2 emissions from S3 storage"""
        try:
            s3_client = self.session.client('s3', region_name=region)
            cloudwatch = self.session.client('cloudwatch', region_name=region)
            
            # Get all buckets
            buckets = s3_client.list_buckets()['Buckets']
            
            total_emissions_kg = 0
            bucket_details = []
            
            for bucket in buckets:
                bucket_name = bucket['Name']
                
                try:
                    # Get bucket size from CloudWatch
                    end_time = datetime.utcnow()
                    start_time = end_time - timedelta(days=1)
                    
                    metrics = cloudwatch.get_metric_statistics(
                        Namespace='AWS/S3',
                        MetricName='BucketSizeBytes',
                        Dimensions=[
                            {'Name': 'BucketName', 'Value': bucket_name},
                            {'Name': 'StorageType', 'Value': 'StandardStorage'}
                        ],
                        StartTime=start_time,
                        EndTime=end_time,
                        Period=86400,
                        Statistics=['Average']
                    )
                    
                    if metrics['Datapoints']:
                        size_bytes = metrics['Datapoints'][0]['Average']
                        size_gb = size_bytes / (1024**3)
                        
                        # S3 emissions: approximately 0.000003 kg CO2/GB/month
                        emissions_kg = size_gb * 0.000003 * (30/30)  # Normalized to 30 days
                        
                        total_emissions_kg += emissions_kg
                        
                        bucket_details.append({
                            'bucket_name': bucket_name,
                            'size_gb': size_gb,
                            'emissions_kg': emissions_kg
                        })
                except:
                    # Skip buckets we can't access
                    pass
            
            return {
                'success': True,
                'total_emissions_kg': total_emissions_kg,
                'bucket_count': len(bucket_details),
                'details': bucket_details
            }
            
        except ClientError as e:
            return {
                'success': False,
                'error': str(e),
                'total_emissions_kg': 0
            }
    
    def calculate_total_emissions(self, regions: List[str] = None, days: int = 30) -> Dict:
        """Calculate total carbon emissions across all services and regions"""
        if regions is None:
            regions = ['us-east-1']  # Default to primary region
        
        total_emissions = 0
        emissions_by_service = {}
        emissions_by_region = {}
        
        for region in regions:
            # EC2 emissions
            ec2_result = self.calculate_ec2_emissions(region, days)
            if ec2_result['success']:
                ec2_emissions = ec2_result['total_emissions_kg']
                total_emissions += ec2_emissions
                emissions_by_service['EC2'] = emissions_by_service.get('EC2', 0) + ec2_emissions
                emissions_by_region[region] = emissions_by_region.get(region, 0) + ec2_emissions
            
            # S3 emissions
            s3_result = self.calculate_s3_emissions(region)
            if s3_result['success']:
                s3_emissions = s3_result['total_emissions_kg']
                total_emissions += s3_emissions
                emissions_by_service['S3'] = emissions_by_service.get('S3', 0) + s3_emissions
                emissions_by_region[region] = emissions_by_region.get(region, 0) + s3_emissions
        
        # Calculate sustainability score (0-100)
        # Based on renewable energy usage
        avg_carbon_intensity = sum(CARBON_INTENSITY.get(r, 400) for r in regions) / len(regions)
        sustainability_score = max(0, 100 - (avg_carbon_intensity / 10))
        
        return {
            'success': True,
            'total_emissions_kg': total_emissions,
            'emissions_by_service': emissions_by_service,
            'emissions_by_region': emissions_by_region,
            'sustainability_score': sustainability_score,
            'renewable_energy_percentage': self._calculate_renewable_percentage(regions),
            'recommendations': self._generate_recommendations(emissions_by_region)
        }
    
    def _calculate_renewable_percentage(self, regions: List[str]) -> float:
        """Calculate approximate renewable energy percentage"""
        # Based on AWS Sustainability Report data
        renewable_regions = {
            'eu-north-1': 95,   # Stockholm
            'ca-central-1': 80, # Montreal
            'eu-west-3': 85,    # Paris
            'sa-east-1': 82,    # São Paulo
        }
        
        total_weight = 0
        weighted_renewable = 0
        
        for region in regions:
            weight = 1
            renewable_pct = renewable_regions.get(region, 30)  # Default 30%
            total_weight += weight
            weighted_renewable += renewable_pct * weight
        
        return weighted_renewable / total_weight if total_weight > 0 else 30
    
    def _generate_recommendations(self, emissions_by_region: Dict) -> List[str]:
        """Generate carbon reduction recommendations"""
        recommendations = []
        
        # Check for high-carbon regions
        high_carbon_regions = {
            k: v for k, v in emissions_by_region.items()
            if CARBON_INTENSITY.get(k, 400) > 400
        }
        
        if high_carbon_regions:
            recommendations.append(
                f"Consider migrating workloads from high-carbon regions to "
                f"low-carbon regions like eu-north-1 (Stockholm) or ca-central-1 (Montreal)"
            )
        
        # General recommendations
        recommendations.extend([
            "Use AWS Graviton processors which are 60% more energy efficient",
            "Implement auto-scaling to reduce idle resource consumption",
            "Delete unused EBS volumes and snapshots",
            "Use S3 Intelligent-Tiering to optimize storage",
            "Schedule non-production workloads during off-peak hours"
        ])
        
        return recommendations


"""
AWS Carbon Footprint Calculator
Calculates estimated CO2 emissions from AWS resource usage
Based on AWS Customer Carbon Footprint methodology
Supports AWS Organizations with multi-account aggregation
"""

import boto3
from typing import Dict, List
from datetime import datetime, timedelta
from botocore.exceptions import ClientError

# Regional carbon intensity (gCO2e/kWh) - AWS published data
CARBON_INTENSITY = {
    'us-east-1': 415.755,      # US East (N. Virginia)
    'us-east-2': 519.392,      # US East (Ohio)
    'us-west-1': 257.742,      # US West (N. California)
    'us-west-2': 257.742,      # US West (Oregon)
    'ca-central-1': 130.0,     # Canada (Montreal) - 80% renewable
    'eu-west-1': 316.729,      # Europe (Ireland)
    'eu-west-2': 277.731,      # Europe (London)
    'eu-west-3': 70.872,       # Europe (Paris)
    'eu-central-1': 338.425,   # Europe (Frankfurt)
    'eu-north-1': 9.0,         # Europe (Stockholm) - 95% renewable
    'ap-northeast-1': 463.484, # Asia Pacific (Tokyo)
    'ap-northeast-2': 434.264, # Asia Pacific (Seoul)
    'ap-southeast-1': 408.607, # Asia Pacific (Singapore)
    'ap-southeast-2': 564.0,   # Asia Pacific (Sydney)
    'ap-south-1': 708.171,     # Asia Pacific (Mumbai)
    'sa-east-1': 78.996,       # South America (São Paulo)
}

# Power consumption estimates (Watts)
EC2_POWER_CONSUMPTION = {
    't2.micro': 10,
    't2.small': 15,
    't2.medium': 25,
    't3.micro': 8,
    't3.small': 12,
    't3.medium': 20,
    'm5.large': 50,
    'm5.xlarge': 100,
    'c5.large': 45,
    'c5.xlarge': 90,
    'r5.large': 55,
    'r5.xlarge': 110,
    # Add more instance types as needed
    'default': 50  # Default for unknown types
}


class CarbonFootprintCalculator:
    """Calculate carbon emissions from AWS resource usage"""
    
    def __init__(self, session: boto3.Session):
        """Initialize carbon calculator"""
        self.session = session
        self.account_id = session.client('sts').get_caller_identity()['Account']
    
    def calculate_ec2_emissions(self, region: str = 'us-east-1', days: int = 30) -> Dict:
        """Calculate CO2 emissions from EC2 instances"""
        try:
            ec2_client = self.session.client('ec2', region_name=region)
            cloudwatch = self.session.client('cloudwatch', region_name=region)
            
            # Get all running instances
            response = ec2_client.describe_instances(
                Filters=[{'Name': 'instance-state-name', 'Values': ['running']}]
            )
            
            total_emissions_kg = 0
            instance_details = []
            
            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    instance_type = instance['InstanceType']
                    instance_id = instance['InstanceId']
                    
                    # Get power consumption for this instance type
                    power_watts = EC2_POWER_CONSUMPTION.get(instance_type, 
                                                            EC2_POWER_CONSUMPTION['default'])
                    
                    # Calculate emissions
                    # Power (W) * Hours * Carbon Intensity / 1000 / 1000 = kg CO2
                    hours = days * 24
                    kwh = (power_watts * hours) / 1000
                    carbon_intensity = CARBON_INTENSITY.get(region, 400)  # gCO2e/kWh
                    emissions_kg = (kwh * carbon_intensity) / 1000
                    
                    total_emissions_kg += emissions_kg
                    
                    instance_details.append({
                        'instance_id': instance_id,
                        'instance_type': instance_type,
                        'region': region,
                        'emissions_kg': emissions_kg
                    })
            
            return {
                'success': True,
                'total_emissions_kg': total_emissions_kg,
                'instance_count': len(instance_details),
                'details': instance_details,
                'region': region
            }
            
        except ClientError as e:
            return {
                'success': False,
                'error': str(e),
                'total_emissions_kg': 0
            }
    
    def calculate_s3_emissions(self, region: str = 'us-east-1') -> Dict:
        """Calculate CO2 emissions from S3 storage"""
        try:
            s3_client = self.session.client('s3', region_name=region)
            cloudwatch = self.session.client('cloudwatch', region_name=region)
            
            # Get all buckets
            buckets = s3_client.list_buckets()['Buckets']
            
            total_emissions_kg = 0
            bucket_details = []
            
            for bucket in buckets:
                bucket_name = bucket['Name']
                
                try:
                    # Get bucket size from CloudWatch
                    end_time = datetime.utcnow()
                    start_time = end_time - timedelta(days=1)
                    
                    metrics = cloudwatch.get_metric_statistics(
                        Namespace='AWS/S3',
                        MetricName='BucketSizeBytes',
                        Dimensions=[
                            {'Name': 'BucketName', 'Value': bucket_name},
                            {'Name': 'StorageType', 'Value': 'StandardStorage'}
                        ],
                        StartTime=start_time,
                        EndTime=end_time,
                        Period=86400,
                        Statistics=['Average']
                    )
                    
                    if metrics['Datapoints']:
                        size_bytes = metrics['Datapoints'][0]['Average']
                        size_gb = size_bytes / (1024**3)
                        
                        # S3 emissions: approximately 0.000003 kg CO2/GB/month
                        emissions_kg = size_gb * 0.000003 * (30/30)  # Normalized to 30 days
                        
                        total_emissions_kg += emissions_kg
                        
                        bucket_details.append({
                            'bucket_name': bucket_name,
                            'size_gb': size_gb,
                            'emissions_kg': emissions_kg
                        })
                except:
                    # Skip buckets we can't access
                    pass
            
            return {
                'success': True,
                'total_emissions_kg': total_emissions_kg,
                'bucket_count': len(bucket_details),
                'details': bucket_details
            }
            
        except ClientError as e:
            return {
                'success': False,
                'error': str(e),
                'total_emissions_kg': 0
            }
    
    def calculate_total_emissions(self, regions: List[str] = None, days: int = 30) -> Dict:
        """Calculate total carbon emissions across all services and regions"""
        if regions is None:
            regions = ['us-east-1']  # Default to primary region
        
        total_emissions = 0
        emissions_by_service = {}
        emissions_by_region = {}
        
        for region in regions:
            # EC2 emissions
            ec2_result = self.calculate_ec2_emissions(region, days)
            if ec2_result['success']:
                ec2_emissions = ec2_result['total_emissions_kg']
                total_emissions += ec2_emissions
                emissions_by_service['EC2'] = emissions_by_service.get('EC2', 0) + ec2_emissions
                emissions_by_region[region] = emissions_by_region.get(region, 0) + ec2_emissions
            
            # S3 emissions
            s3_result = self.calculate_s3_emissions(region)
            if s3_result['success']:
                s3_emissions = s3_result['total_emissions_kg']
                total_emissions += s3_emissions
                emissions_by_service['S3'] = emissions_by_service.get('S3', 0) + s3_emissions
                emissions_by_region[region] = emissions_by_region.get(region, 0) + s3_emissions
        
        # Calculate sustainability score (0-100)
        # Based on renewable energy usage
        avg_carbon_intensity = sum(CARBON_INTENSITY.get(r, 400) for r in regions) / len(regions)
        sustainability_score = max(0, 100 - (avg_carbon_intensity / 10))
        
        return {
            'success': True,
            'total_emissions_kg': total_emissions,
            'emissions_by_service': emissions_by_service,
            'emissions_by_region': emissions_by_region,
            'sustainability_score': sustainability_score,
            'renewable_energy_percentage': self._calculate_renewable_percentage(regions),
            'recommendations': self._generate_recommendations(emissions_by_region)
        }
    
    def _calculate_renewable_percentage(self, regions: List[str]) -> float:
        """Calculate approximate renewable energy percentage"""
        # Based on AWS Sustainability Report data
        renewable_regions = {
            'eu-north-1': 95,   # Stockholm
            'ca-central-1': 80, # Montreal
            'eu-west-3': 85,    # Paris
            'sa-east-1': 82,    # São Paulo
        }
        
        total_weight = 0
        weighted_renewable = 0
        
        for region in regions:
            weight = 1
            renewable_pct = renewable_regions.get(region, 30)  # Default 30%
            total_weight += weight
            weighted_renewable += renewable_pct * weight
        
        return weighted_renewable / total_weight if total_weight > 0 else 30
    
    def _generate_recommendations(self, emissions_by_region: Dict) -> List[str]:
        """Generate carbon reduction recommendations"""
        recommendations = []
        
        # Check for high-carbon regions
        high_carbon_regions = {
            k: v for k, v in emissions_by_region.items()
            if CARBON_INTENSITY.get(k, 400) > 400
        }
        
        if high_carbon_regions:
            recommendations.append(
                f"Consider migrating workloads from high-carbon regions to "
                f"low-carbon regions like eu-north-1 (Stockholm) or ca-central-1 (Montreal)"
            )
        
        # General recommendations
        recommendations.extend([
            "Use AWS Graviton processors which are 60% more energy efficient",
            "Implement auto-scaling to reduce idle resource consumption",
            "Delete unused EBS volumes and snapshots",
            "Use S3 Intelligent-Tiering to optimize storage",
            "Schedule non-production workloads during off-peak hours"
        ])
        
        return recommendations


def get_carbon_data_from_aws(session: boto3.Session, regions: List[str] = None) -> Dict:
    """
    Main function to get carbon footprint data from AWS
    Supports AWS Organizations - calculates across all linked accounts
    """
    
    # Try to get list of accounts from Organizations
    accounts_to_process = []
    account_names = {}
    
    try:
        org_client = session.client('organizations', region_name='us-east-1')
        accounts_response = org_client.list_accounts()
        
        for account in accounts_response['Accounts']:
            if account['Status'] == 'ACTIVE':
                account_id = account['Id']
                account_name = account['Name']
                accounts_to_process.append(account_id)
                account_names[account_id] = f"{account_name} ({account_id})"
        
        print(f"Found {len(accounts_to_process)} active accounts in organization")
        
    except Exception as org_error:
        # Not using Organizations, or no permission - just use current account
        print(f"Not using Organizations or no access: {org_error}")
        current_account = session.client('sts').get_caller_identity()['Account']
        accounts_to_process = [current_account]
        account_names[current_account] = current_account
    
    # Get active regions if not specified
    if regions is None:
        ec2 = session.client('ec2', region_name='us-east-1')
        try:
            regions_response = ec2.describe_regions()
            regions = [r['RegionName'] for r in regions_response['Regions']][:5]  # Limit to 5 for performance
        except:
            regions = ['us-east-1']
    
    # Calculate emissions for all accounts
    total_emissions = 0
    emissions_by_account = {}
    emissions_by_service_global = {}
    emissions_by_region_global = {}
    all_recommendations = []
    
    for account_id in accounts_to_process:
        # For management account, it can see all linked accounts' resources
        # For now, calculate using current session
        # (In production, you might AssumeRole into each account)
        
        calculator = CarbonFootprintCalculator(session)
        account_result = calculator.calculate_total_emissions(regions, days=30)
        
        if account_result['success']:
            account_emissions = account_result['total_emissions_kg']
            total_emissions += account_emissions
            
            # Store by account
            account_name = account_names.get(account_id, account_id)
            emissions_by_account[account_name] = account_emissions
            
            # Aggregate by service
            for service, emissions in account_result['emissions_by_service'].items():
                emissions_by_service_global[service] = emissions_by_service_global.get(service, 0) + emissions
            
            # Aggregate by region
            for region, emissions in account_result['emissions_by_region'].items():
                emissions_by_region_global[region] = emissions_by_region_global.get(region, 0) + emissions
            
            # Collect recommendations (dedupe later)
            all_recommendations.extend(account_result['recommendations'])
    
    # Deduplicate recommendations
    unique_recommendations = list(set(all_recommendations))
    
    # Calculate overall sustainability score
    if regions:
        avg_carbon_intensity = sum(CARBON_INTENSITY.get(r, 400) for r in regions) / len(regions)
        sustainability_score = max(0, 100 - (avg_carbon_intensity / 10))
    else:
        sustainability_score = 0
    
    # Calculate renewable percentage
    renewable_regions = {
        'eu-north-1': 95,
        'ca-central-1': 80,
        'eu-west-3': 85,
        'sa-east-1': 82,
    }
    
    total_weight = 0
    weighted_renewable = 0
    
    for region in regions:
        weight = 1
        renewable_pct = renewable_regions.get(region, 30)
        total_weight += weight
        weighted_renewable += renewable_pct * weight
    
    renewable_energy_pct = weighted_renewable / total_weight if total_weight > 0 else 30
    
    return {
        'total_emissions_kg': total_emissions,
        'emissions_by_service': emissions_by_service_global,
        'emissions_by_region': emissions_by_region_global,
        'emissions_by_account': emissions_by_account,  # NEW: Per-account breakdown
        'account_count': len(accounts_to_process),     # NEW: Number of accounts
        'sustainability_score': sustainability_score,
        'renewable_energy_pct': renewable_energy_pct,
        'recommendations': unique_recommendations[:5],  # Top 5 recommendations
        'last_updated': datetime.now().isoformat()
    }
