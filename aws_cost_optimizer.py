"""
AWS Cost Optimizer
Fetches real cost optimization recommendations from AWS Cost Explorer
Includes: Rightsizing, Reserved Instances, Savings Plans, Unused Resources
"""

import boto3
from typing import List, Dict
from datetime import datetime, timedelta
from botocore.exceptions import ClientError


class AWSCostOptimizer:
    """Fetch cost optimization recommendations from AWS"""
    
    def __init__(self, session: boto3.Session):
        """Initialize cost optimizer"""
        self.session = session
        self.ce_client = session.client('ce', region_name='us-east-1')
        self.compute_optimizer_client = None
        try:
            self.compute_optimizer_client = session.client('compute-optimizer', region_name='us-east-1')
        except:
            pass  # Compute Optimizer might not be enabled
    
    def get_rightsizing_recommendations(self) -> List[Dict]:
        """Get EC2 rightsizing recommendations from Cost Explorer"""
        recommendations = []
        
        try:
            response = self.ce_client.get_rightsizing_recommendation(
                Service='AmazonEC2',
                Configuration={
                    'RecommendationTarget': 'SAME_INSTANCE_FAMILY',
                    'BenefitsConsidered': True
                }
            )
            
            for rec in response.get('RightsizingRecommendations', [])[:10]:  # Top 10
                current_instance = rec.get('CurrentInstance', {})
                recommendation_type = rec.get('RightsizingType', 'ModifyCurrentInstanceType')
                
                if recommendation_type == 'Terminate':
                    # Unused instance
                    recommendations.append({
                        'type': 'Unused Resources',
                        'resource': current_instance.get('ResourceId', 'Unknown'),
                        'current_cost': f"${float(current_instance.get('MonthlyCost', 0)):.2f}/month",
                        'optimized_cost': '$0/month',
                        'savings': f"${float(current_instance.get('MonthlyCost', 0)):.2f}/month",
                        'savings_percentage': '100%',
                        'priority': 'High',
                        'implementation': 'Terminate unused EC2 instance'
                    })
                elif recommendation_type == 'ModifyCurrentInstanceType':
                    # Rightsizing
                    modify_rec = rec.get('ModifyRecommendationDetail', {})
                    target_instances = modify_rec.get('TargetInstances', [])
                    
                    if target_instances:
                        target = target_instances[0]
                        current_cost = float(current_instance.get('MonthlyCost', 0))
                        estimated_cost = float(target.get('EstimatedMonthlyCost', 0))
                        savings = current_cost - estimated_cost
                        savings_pct = (savings / current_cost * 100) if current_cost > 0 else 0
                        
                        recommendations.append({
                            'type': 'Right-Sizing',
                            'resource': f"{current_instance.get('ResourceId', 'Unknown')} → {target.get('ResourceDetails', {}).get('EC2ResourceDetails', {}).get('InstanceType', 'Unknown')}",
                            'current_cost': f"${current_cost:.2f}/month",
                            'optimized_cost': f"${estimated_cost:.2f}/month",
                            'savings': f"${savings:.2f}/month",
                            'savings_percentage': f"{savings_pct:.0f}%",
                            'priority': 'High' if savings_pct > 30 else 'Medium',
                            'implementation': f"Resize from {current_instance.get('ResourceDetails', {}).get('EC2ResourceDetails', {}).get('InstanceType', 'current')} to {target.get('ResourceDetails', {}).get('EC2ResourceDetails', {}).get('InstanceType', 'target')}"
                        })
        
        except ClientError as e:
            print(f"Error fetching rightsizing recommendations: {e}")
        
        return recommendations
    
    def get_savings_plans_recommendations(self) -> List[Dict]:
        """Get Savings Plans recommendations from Cost Explorer"""
        recommendations = []
        
        try:
            response = self.ce_client.get_savings_plans_purchase_recommendation(
                SavingsPlansType='COMPUTE_SP',
                LookbackPeriodInDays='SIXTY_DAYS',
                TermInYears='ONE_YEAR',
                PaymentOption='NO_UPFRONT'
            )
            
            savings_plans_recs = response.get('SavingsPlansPurchaseRecommendation', {})
            details = savings_plans_recs.get('SavingsPlansPurchaseRecommendationDetails', [])
            
            for detail in details[:5]:  # Top 5
                hourly_commit = float(detail.get('HourlyCommitmentToPurchase', 0))
                estimated_monthly_savings = float(detail.get('EstimatedMonthlySavingsAmount', 0))
                estimated_savings_pct = float(detail.get('EstimatedSavingsPercentage', 0))
                
                if estimated_monthly_savings > 0:
                    recommendations.append({
                        'type': 'Savings Plans',
                        'resource': f"Compute SP - ${hourly_commit:.2f}/hour commitment",
                        'current_cost': f"${estimated_monthly_savings / (estimated_savings_pct/100) if estimated_savings_pct > 0 else 0:.2f}/month",
                        'optimized_cost': f"${(estimated_monthly_savings / (estimated_savings_pct/100) - estimated_monthly_savings) if estimated_savings_pct > 0 else 0:.2f}/month",
                        'savings': f"${estimated_monthly_savings:.2f}/month",
                        'savings_percentage': f"{estimated_savings_pct:.0f}%",
                        'priority': 'High' if estimated_savings_pct > 20 else 'Medium',
                        'implementation': f"Purchase 1-year Compute Savings Plan with ${hourly_commit:.2f}/hour commitment"
                    })
        
        except ClientError as e:
            print(f"Error fetching Savings Plans recommendations: {e}")
        
        return recommendations
    
    def get_reserved_instance_recommendations(self) -> List[Dict]:
        """Get Reserved Instance recommendations from Cost Explorer"""
        recommendations = []
        
        try:
            response = self.ce_client.get_reservation_purchase_recommendation(
                Service='Amazon Elastic Compute Cloud - Compute',
                LookbackPeriodInDays='SIXTY_DAYS',
                TermInYears='ONE_YEAR',
                PaymentOption='NO_UPFRONT'
            )
            
            ri_recs = response.get('Recommendations', [])
            
            for rec in ri_recs[:5]:  # Top 5
                details = rec.get('RecommendationDetails', [])
                
                for detail in details:
                    instance_details = detail.get('InstanceDetails', {}).get('EC2InstanceDetails', {})
                    estimated_monthly_savings = float(detail.get('EstimatedMonthlySavingsAmount', 0))
                    estimated_savings_pct = float(detail.get('EstimatedMonthlySavingsPercentage', 0))
                    
                    if estimated_monthly_savings > 0:
                        recommendations.append({
                            'type': 'Reserved Instances',
                            'resource': f"EC2 - {instance_details.get('InstanceType', 'Unknown')}",
                            'current_cost': f"${estimated_monthly_savings / (estimated_savings_pct/100) if estimated_savings_pct > 0 else 0:.2f}/month",
                            'optimized_cost': f"${(estimated_monthly_savings / (estimated_savings_pct/100) - estimated_monthly_savings) if estimated_savings_pct > 0 else 0:.2f}/month",
                            'savings': f"${estimated_monthly_savings:.2f}/month",
                            'savings_percentage': f"{estimated_savings_pct:.0f}%",
                            'priority': 'High' if estimated_savings_pct > 30 else 'Medium',
                            'implementation': f"Purchase 1-year Reserved Instance for {instance_details.get('InstanceType', 'instance')}"
                        })
        
        except ClientError as e:
            print(f"Error fetching RI recommendations: {e}")
        
        return recommendations
    
    def get_unused_ebs_volumes(self) -> List[Dict]:
        """Find unattached EBS volumes"""
        recommendations = []
        
        try:
            ec2 = self.session.client('ec2', region_name='us-east-1')
            
            # Get all unattached volumes
            response = ec2.describe_volumes(
                Filters=[
                    {'Name': 'status', 'Values': ['available']}  # Unattached
                ]
            )
            
            for volume in response.get('Volumes', [])[:20]:  # Top 20
                volume_id = volume['VolumeId']
                size_gb = volume['Size']
                volume_type = volume['VolumeType']
                
                # Estimate cost (simplified: ~$0.10/GB/month for gp3)
                estimated_cost_per_gb = {
                    'gp3': 0.08,
                    'gp2': 0.10,
                    'io1': 0.125,
                    'io2': 0.125,
                    'st1': 0.045,
                    'sc1': 0.015,
                    'standard': 0.05
                }.get(volume_type, 0.10)
                
                monthly_cost = size_gb * estimated_cost_per_gb
                
                if monthly_cost > 1:  # Only show if > $1/month
                    recommendations.append({
                        'type': 'Unused Resources',
                        'resource': f"{size_gb}GB Unattached EBS Volume - {volume_id}",
                        'current_cost': f"${monthly_cost:.2f}/month",
                        'optimized_cost': '$0/month',
                        'savings': f"${monthly_cost:.2f}/month",
                        'savings_percentage': '100%',
                        'priority': 'Medium',
                        'implementation': f"Delete unattached {volume_type} EBS volume"
                    })
        
        except ClientError as e:
            print(f"Error fetching EBS volumes: {e}")
        
        return recommendations
    
    def get_all_recommendations(self) -> List[Dict]:
        """Get all cost optimization recommendations"""
        all_recommendations = []
        
        # Rightsizing
        all_recommendations.extend(self.get_rightsizing_recommendations())
        
        # Reserved Instances
        all_recommendations.extend(self.get_reserved_instance_recommendations())
        
        # Savings Plans
        all_recommendations.extend(self.get_savings_plans_recommendations())
        
        # Unused EBS Volumes
        all_recommendations.extend(self.get_unused_ebs_volumes())
        
        # Sort by savings (highest first)
        all_recommendations.sort(
            key=lambda x: float(x['savings'].replace('$', '').replace(',', '').replace('/month', '')),
            reverse=True
        )
        
        return all_recommendations[:10]  # Top 10


def get_cost_optimization_recommendations(session: boto3.Session) -> List[Dict]:
    """
    Main function to get cost optimization recommendations from AWS
    This replaces dummy data in Live mode
    """
    optimizer = AWSCostOptimizer(session)
    return optimizer.get_all_recommendations()
