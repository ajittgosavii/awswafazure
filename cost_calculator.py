"""
Cost Impact Calculator
Quantifies financial impact of WAF findings including waste and risk costs
"""

from typing import Dict, Optional
from datetime import datetime
import json


class CostImpactCalculator:
    """Calculate cost impact of security and optimization findings"""
    
    def __init__(self):
        self.pricing = self._load_aws_pricing()
        self.risk_multipliers = self._load_risk_multipliers()
    
    def _load_aws_pricing(self) -> Dict:
        """Load AWS pricing data (simplified - in production, use AWS Price List API)"""
        return {
            # EC2 pricing (USD/month for us-east-1)
            'ec2': {
                't3.nano': 3.80,
                't3.micro': 7.59,
                't3.small': 15.18,
                't3.medium': 30.37,
                't3.large': 60.74,
                't3.xlarge': 121.47,
                't3.2xlarge': 242.94,
                'm5.large': 69.35,
                'm5.xlarge': 138.70,
                'm5.2xlarge': 277.39,
                'm5.4xlarge': 554.78,
                'c5.large': 61.58,
                'c5.xlarge': 123.16,
                'c5.2xlarge': 246.33,
                'r5.large': 90.54,
                'r5.xlarge': 181.07,
                'r5.2xlarge': 362.14,
            },
            
            # S3 pricing (USD/GB/month)
            's3': {
                'standard': 0.023,
                'intelligent_tiering': 0.023,
                'standard_ia': 0.0125,
                'one_zone_ia': 0.01,
                'glacier_instant': 0.004,
                'glacier_flexible': 0.0036,
                'glacier_deep': 0.00099,
            },
            
            # RDS pricing (USD/month for db.t3 instances)
            'rds': {
                'db.t3.micro': 12.41,
                'db.t3.small': 24.82,
                'db.t3.medium': 49.64,
                'db.t3.large': 99.28,
                'db.t3.xlarge': 198.56,
                'db.m5.large': 116.80,
                'db.m5.xlarge': 233.60,
                'db.r5.large': 151.20,
                'db.r5.xlarge': 302.40,
            },
            
            # EBS pricing (USD/GB/month)
            'ebs': {
                'gp3': 0.08,
                'gp2': 0.10,
                'io2': 0.125,
                'st1': 0.045,
                'sc1': 0.015,
            },
            
            # NAT Gateway pricing (USD/month)
            'nat_gateway': {
                'hourly': 0.045 * 730,  # $0.045/hour
                'data_processing_gb': 0.045,
            },
            
            # Load Balancer pricing
            'load_balancer': {
                'alb_monthly': 0.0225 * 730,  # $0.0225/hour
                'nlb_monthly': 0.0225 * 730,
            }
        }
    
    def _load_risk_multipliers(self) -> Dict:
        """Load risk cost multipliers based on severity and exposure"""
        return {
            'base_risk': {
                'CRITICAL': 100000,  # $100k potential incident cost
                'HIGH': 25000,       # $25k
                'MEDIUM': 5000,      # $5k
                'LOW': 1000,         # $1k
            },
            'exposure': {
                'public': 3.0,        # 3x multiplier for public exposure
                'internet_facing': 2.5,
                'internal': 1.0,
            },
            'data_sensitivity': {
                'pii': 5.0,           # 5x for PII data
                'financial': 4.0,
                'healthcare': 6.0,
                'confidential': 2.0,
                'public': 1.0,
            },
            'compliance': {
                'pci_dss': 3.0,       # 3x for PCI compliance violations
                'hipaa': 4.0,
                'sox': 2.5,
                'gdpr': 3.5,
            }
        }
    
    def calculate_finding_impact(self, finding: Dict, resources: Optional[Dict] = None) -> Dict:
        """Calculate comprehensive cost impact for a finding"""
        
        service = finding.get('service', '').lower()
        title = finding.get('title', '').lower()
        severity = finding.get('severity', 'MEDIUM')
        resource_details = finding.get('resource_details', {})
        
        impact = {
            'monthly_waste': 0.0,
            'annual_waste': 0.0,
            'risk_cost': 0.0,
            'total_impact': 0.0,
            'breakdown': {},
            'recommendations': []
        }
        
        # Calculate waste costs
        if service == 'ec2':
            waste = self._calculate_ec2_waste(title, resource_details)
            impact['monthly_waste'] = waste['monthly']
            impact['breakdown']['ec2_waste'] = waste
            impact['recommendations'].extend(waste.get('recommendations', []))
        
        elif service == 's3':
            waste = self._calculate_s3_waste(title, resource_details)
            impact['monthly_waste'] = waste['monthly']
            impact['breakdown']['s3_waste'] = waste
            impact['recommendations'].extend(waste.get('recommendations', []))
        
        elif service == 'rds':
            waste = self._calculate_rds_waste(title, resource_details)
            impact['monthly_waste'] = waste['monthly']
            impact['breakdown']['rds_waste'] = waste
            impact['recommendations'].extend(waste.get('recommendations', []))
        
        elif service == 'ebs':
            waste = self._calculate_ebs_waste(title, resource_details)
            impact['monthly_waste'] = waste['monthly']
            impact['breakdown']['ebs_waste'] = waste
            impact['recommendations'].extend(waste.get('recommendations', []))
        
        elif service == 'vpc':
            waste = self._calculate_vpc_waste(title, resource_details)
            impact['monthly_waste'] = waste['monthly']
            impact['breakdown']['vpc_waste'] = waste
            impact['recommendations'].extend(waste.get('recommendations', []))
        
        # Calculate risk costs
        risk = self._calculate_risk_cost(finding, resource_details)
        impact['risk_cost'] = risk['total_risk']
        impact['breakdown']['risk'] = risk
        
        # Calculate totals
        impact['annual_waste'] = impact['monthly_waste'] * 12
        impact['total_impact'] = impact['annual_waste'] + impact['risk_cost']
        
        return impact
    
    def _calculate_ec2_waste(self, title: str, details: Dict) -> Dict:
        """Calculate EC2-related waste"""
        
        waste = {'monthly': 0.0, 'recommendations': []}
        
        instance_type = details.get('instance_type', 't3.medium')
        cpu_utilization = details.get('cpu_utilization', 50)
        
        if 'underutilized' in title or cpu_utilization < 20:
            # Recommend downsizing
            current_cost = self.pricing['ec2'].get(instance_type, 30.37)
            
            # Suggest smaller instance (rough heuristic)
            instance_family = instance_type.split('.')[0]
            instance_size = instance_type.split('.')[1]
            
            size_map = {
                '2xlarge': 'xlarge',
                'xlarge': 'large',
                'large': 'medium',
                'medium': 'small',
                'small': 'micro'
            }
            
            new_size = size_map.get(instance_size, instance_size)
            new_instance = f"{instance_family}.{new_size}"
            new_cost = self.pricing['ec2'].get(new_instance, current_cost * 0.5)
            
            waste['monthly'] = max(current_cost - new_cost, 0)
            waste['current_cost'] = current_cost
            waste['recommended_cost'] = new_cost
            waste['recommendations'].append(
                f"Downsize from {instance_type} to {new_instance} (Save ${waste['monthly']:.2f}/month)"
            )
        
        elif 'stopped' in title or 'unused' in title:
            # Instance is stopped but still has EBS costs
            waste['monthly'] = self.pricing['ec2'].get(instance_type, 30.37)
            waste['recommendations'].append(
                f"Terminate unused instance (Save ${waste['monthly']:.2f}/month)"
            )
        
        return waste
    
    def _calculate_s3_waste(self, title: str, details: Dict) -> Dict:
        """Calculate S3-related waste"""
        
        waste = {'monthly': 0.0, 'recommendations': []}
        
        bucket_size_gb = details.get('size_gb', 0)
        
        if 'lifecycle' in title or 'old data' in title:
            # Estimate savings from lifecycle policies
            # Assume 30% of data is old and can be moved to Glacier
            old_data_pct = 0.30
            old_data_gb = bucket_size_gb * old_data_pct
            
            standard_cost = old_data_gb * self.pricing['s3']['standard']
            glacier_cost = old_data_gb * self.pricing['s3']['glacier_flexible']
            
            waste['monthly'] = standard_cost - glacier_cost
            waste['recommendations'].append(
                f"Implement lifecycle policy to move {old_data_gb:.0f}GB to Glacier "
                f"(Save ${waste['monthly']:.2f}/month)"
            )
        
        elif 'intelligent tiering' in title:
            # Savings from intelligent tiering
            if bucket_size_gb > 1000:  # Only recommend for large buckets
                # Assume 40% savings on average
                current_cost = bucket_size_gb * self.pricing['s3']['standard']
                estimated_savings = current_cost * 0.20  # Conservative 20% savings
                
                waste['monthly'] = estimated_savings
                waste['recommendations'].append(
                    f"Enable S3 Intelligent-Tiering (Save ~${waste['monthly']:.2f}/month)"
                )
        
        return waste
    
    def _calculate_rds_waste(self, title: str, details: Dict) -> Dict:
        """Calculate RDS-related waste"""
        
        waste = {'monthly': 0.0, 'recommendations': []}
        
        instance_class = details.get('instance_class', 'db.t3.medium')
        cpu_utilization = details.get('cpu_utilization', 50)
        connections = details.get('connections', 10)
        
        if 'underutilized' in title or cpu_utilization < 20:
            current_cost = self.pricing['rds'].get(instance_class, 49.64)
            
            # Suggest downsizing
            if 'xlarge' in instance_class:
                new_instance = instance_class.replace('xlarge', 'large')
            elif 'large' in instance_class:
                new_instance = instance_class.replace('large', 'medium')
            else:
                new_instance = instance_class
            
            new_cost = self.pricing['rds'].get(new_instance, current_cost * 0.5)
            waste['monthly'] = max(current_cost - new_cost, 0)
            waste['recommendations'].append(
                f"Downsize RDS from {instance_class} to {new_instance} "
                f"(Save ${waste['monthly']:.2f}/month)"
            )
        
        return waste
    
    def _calculate_ebs_waste(self, title: str, details: Dict) -> Dict:
        """Calculate EBS-related waste"""
        
        waste = {'monthly': 0.0, 'recommendations': []}
        
        volume_size_gb = details.get('size_gb', 0)
        volume_type = details.get('volume_type', 'gp2')
        utilization = details.get('utilization_pct', 50)
        
        if 'unattached' in title or 'unused' in title:
            # Unattached volume
            waste['monthly'] = volume_size_gb * self.pricing['ebs'].get(volume_type, 0.10)
            waste['recommendations'].append(
                f"Delete unattached {volume_size_gb}GB EBS volume "
                f"(Save ${waste['monthly']:.2f}/month)"
            )
        
        elif 'oversized' in title or utilization < 30:
            # Oversized volume
            current_cost = volume_size_gb * self.pricing['ebs'].get(volume_type, 0.10)
            recommended_size = max(volume_size_gb * 0.6, 20)  # 60% of current or min 20GB
            new_cost = recommended_size * self.pricing['ebs'].get(volume_type, 0.10)
            
            waste['monthly'] = current_cost - new_cost
            waste['recommendations'].append(
                f"Resize EBS volume from {volume_size_gb}GB to {recommended_size:.0f}GB "
                f"(Save ${waste['monthly']:.2f}/month)"
            )
        
        return waste
    
    def _calculate_vpc_waste(self, title: str, details: Dict) -> Dict:
        """Calculate VPC-related waste"""
        
        waste = {'monthly': 0.0, 'recommendations': []}
        
        if 'nat gateway' in title and 'unused' in title:
            waste['monthly'] = self.pricing['nat_gateway']['hourly']
            waste['recommendations'].append(
                f"Remove unused NAT Gateway (Save ${waste['monthly']:.2f}/month)"
            )
        
        elif 'idle load balancer' in title:
            waste['monthly'] = self.pricing['load_balancer']['alb_monthly']
            waste['recommendations'].append(
                f"Remove idle load balancer (Save ${waste['monthly']:.2f}/month)"
            )
        
        return waste
    
    def _calculate_risk_cost(self, finding: Dict, details: Dict) -> Dict:
        """Calculate potential risk cost of security finding"""
        
        severity = finding.get('severity', 'MEDIUM')
        title = finding.get('title', '').lower()
        
        # Base risk from severity
        base_risk = self.risk_multipliers['base_risk'].get(severity, 5000)
        
        risk = {
            'base_risk': base_risk,
            'multipliers': [],
            'total_risk': base_risk
        }
        
        # Apply exposure multiplier
        if 'public' in title or '0.0.0.0/0' in title:
            multiplier = self.risk_multipliers['exposure']['public']
            risk['multipliers'].append(('Public Exposure', multiplier))
            risk['total_risk'] *= multiplier
        elif 'internet' in title:
            multiplier = self.risk_multipliers['exposure']['internet_facing']
            risk['multipliers'].append(('Internet-facing', multiplier))
            risk['total_risk'] *= multiplier
        
        # Apply data sensitivity multiplier
        if 'encryption' in title or 'encrypted' in title:
            multiplier = self.risk_multipliers['data_sensitivity']['confidential']
            risk['multipliers'].append(('Unencrypted Data', multiplier))
            risk['total_risk'] *= multiplier
        
        # Apply compliance multiplier
        compliance_frameworks = finding.get('compliance_frameworks', [])
        if compliance_frameworks:
            max_compliance_mult = 1.0
            for framework in compliance_frameworks:
                framework_name = framework.get('framework', '').lower()
                if 'pci' in framework_name:
                    max_compliance_mult = max(max_compliance_mult, 
                                            self.risk_multipliers['compliance']['pci_dss'])
                elif 'hipaa' in framework_name:
                    max_compliance_mult = max(max_compliance_mult,
                                            self.risk_multipliers['compliance']['hipaa'])
            
            if max_compliance_mult > 1.0:
                risk['multipliers'].append(('Compliance Violation', max_compliance_mult))
                risk['total_risk'] *= max_compliance_mult
        
        return risk
    
    def calculate_portfolio_impact(self, findings: list) -> Dict:
        """Calculate total cost impact across all findings"""
        
        portfolio = {
            'total_monthly_waste': 0.0,
            'total_annual_waste': 0.0,
            'total_risk_exposure': 0.0,
            'total_impact': 0.0,
            'by_service': {},
            'by_severity': {
                'CRITICAL': {'count': 0, 'waste': 0.0, 'risk': 0.0},
                'HIGH': {'count': 0, 'waste': 0.0, 'risk': 0.0},
                'MEDIUM': {'count': 0, 'waste': 0.0, 'risk': 0.0},
                'LOW': {'count': 0, 'waste': 0.0, 'risk': 0.0},
            },
            'top_opportunities': []
        }
        
        finding_impacts = []
        
        for finding in findings:
            impact = self.calculate_finding_impact(finding)
            
            # Accumulate totals
            portfolio['total_monthly_waste'] += impact['monthly_waste']
            portfolio['total_risk_exposure'] += impact['risk_cost']
            
            # By service
            service = finding.get('service', 'Unknown')
            if service not in portfolio['by_service']:
                portfolio['by_service'][service] = {
                    'count': 0,
                    'waste': 0.0,
                    'risk': 0.0
                }
            
            portfolio['by_service'][service]['count'] += 1
            portfolio['by_service'][service]['waste'] += impact['monthly_waste']
            portfolio['by_service'][service]['risk'] += impact['risk_cost']
            
            # By severity
            severity = finding.get('severity', 'MEDIUM')
            if severity in portfolio['by_severity']:
                portfolio['by_severity'][severity]['count'] += 1
                portfolio['by_severity'][severity]['waste'] += impact['monthly_waste']
                portfolio['by_severity'][severity]['risk'] += impact['risk_cost']
            
            # Track for top opportunities
            finding_impacts.append({
                'finding_id': finding.get('id'),
                'title': finding.get('title'),
                'total_impact': impact['total_impact'],
                'monthly_waste': impact['monthly_waste'],
                'risk_cost': impact['risk_cost'],
                'recommendations': impact['recommendations']
            })
        
        # Calculate totals
        portfolio['total_annual_waste'] = portfolio['total_monthly_waste'] * 12
        portfolio['total_impact'] = portfolio['total_annual_waste'] + portfolio['total_risk_exposure']
        
        # Get top 10 opportunities
        finding_impacts.sort(key=lambda x: x['total_impact'], reverse=True)
        portfolio['top_opportunities'] = finding_impacts[:10]
        
        return portfolio
    
    def format_cost_display(self, impact: Dict) -> str:
        """Format cost impact for display"""
        
        output = []
        output.append("💰 Cost Impact Analysis")
        output.append("═" * 60)
        
        if impact['monthly_waste'] > 0:
            output.append(f"\n📊 Waste Costs:")
            output.append(f"  Monthly: ${impact['monthly_waste']:,.2f}")
            output.append(f"  Annual:  ${impact['annual_waste']:,.2f}")
        
        if impact['risk_cost'] > 0:
            output.append(f"\n⚠️  Security Risk Cost:")
            output.append(f"  Potential Incident Cost: ${impact['risk_cost']:,.0f}")
            
            if 'breakdown' in impact and 'risk' in impact['breakdown']:
                risk = impact['breakdown']['risk']
                output.append(f"  Base Risk ({risk.get('base_risk', 0):,.0f}) × Multipliers:")
                for mult_name, mult_value in risk.get('multipliers', []):
                    output.append(f"    • {mult_name}: {mult_value}x")
        
        output.append(f"\n💵 Total Impact: ${impact['total_impact']:,.2f}")
        
        if impact.get('recommendations'):
            output.append(f"\n💡 Recommendations:")
            for rec in impact['recommendations']:
                output.append(f"  • {rec}")
        
        return "\n".join(output)


# Example usage
if __name__ == "__main__":
    calculator = CostImpactCalculator()
    
    # Test finding
    finding = {
        'service': 'EC2',
        'title': 'Underutilized EC2 Instance',
        'severity': 'MEDIUM',
        'resource_details': {
            'instance_type': 't3.xlarge',
            'cpu_utilization': 15
        }
    }
    
    impact = calculator.calculate_finding_impact(finding)
    print(calculator.format_cost_display(impact))
    
    print("\n" + "="*60 + "\n")
    
    # Test security finding
    security_finding = {
        'service': 'S3',
        'title': 'S3 Bucket Without Encryption - Public Access',
        'severity': 'CRITICAL',
        'compliance_frameworks': [
            {'framework': 'PCI-DSS'},
            {'framework': 'HIPAA'}
        ]
    }
    
    security_impact = calculator.calculate_finding_impact(security_finding)
    print(calculator.format_cost_display(security_impact))
