"""
Compliance Framework Mapper
Maps AWS WAF findings to industry compliance frameworks
"""

from typing import List, Dict, Optional
from dataclasses import dataclass
import json


@dataclass
class ComplianceRequirement:
    framework: str
    requirement_id: str
    description: str
    severity_impact: str = "MEDIUM"
    category: str = ""


class ComplianceMapper:
    """Maps WAF findings to compliance requirements"""
    
    def __init__(self):
        self.mappings = self._initialize_mappings()
    
    def _initialize_mappings(self) -> Dict[str, Dict[str, List[ComplianceRequirement]]]:
        """Initialize comprehensive compliance mappings"""
        
        mappings = {
            # S3 Security Findings
            's3_public_access': {
                'CIS_AWS_FOUNDATIONS': [
                    ComplianceRequirement(
                        'CIS AWS Foundations',
                        '2.1.5',
                        'Ensure that S3 Buckets are configured with Block public access',
                        'HIGH'
                    )
                ],
                'PCI_DSS': [
                    ComplianceRequirement(
                        'PCI-DSS v4.0',
                        '1.2.1',
                        'Configuration standards for NSCs are identified and defined',
                        'CRITICAL'
                    ),
                    ComplianceRequirement(
                        'PCI-DSS v4.0',
                        '1.3.1',
                        'Inbound traffic to the CDE is restricted',
                        'CRITICAL'
                    )
                ],
                'HIPAA': [
                    ComplianceRequirement(
                        'HIPAA',
                        '§164.312(a)(1)',
                        'Access Control - Implement technical policies and procedures',
                        'HIGH'
                    ),
                    ComplianceRequirement(
                        'HIPAA',
                        '§164.312(e)(1)',
                        'Transmission Security',
                        'HIGH'
                    )
                ],
                'SOC2': [
                    ComplianceRequirement(
                        'SOC 2',
                        'CC6.6',
                        'Logical and Physical Access Controls - Restrict Access',
                        'HIGH'
                    )
                ],
                'NIST_CSF': [
                    ComplianceRequirement(
                        'NIST CSF',
                        'PR.AC-3',
                        'Remote access is managed',
                        'HIGH'
                    ),
                    ComplianceRequirement(
                        'NIST CSF',
                        'PR.DS-5',
                        'Protections against data leaks are implemented',
                        'HIGH'
                    )
                ]
            },
            
            's3_no_encryption': {
                'CIS_AWS_FOUNDATIONS': [
                    ComplianceRequirement(
                        'CIS AWS Foundations',
                        '2.1.1',
                        'Ensure S3 Bucket encryption is enabled',
                        'HIGH'
                    )
                ],
                'PCI_DSS': [
                    ComplianceRequirement(
                        'PCI-DSS v4.0',
                        '3.4.1',
                        'PAN is masked when displayed',
                        'CRITICAL'
                    ),
                    ComplianceRequirement(
                        'PCI-DSS v4.0',
                        '3.5.1',
                        'Disk encryption and/or data-level encryption is used',
                        'CRITICAL'
                    )
                ],
                'HIPAA': [
                    ComplianceRequirement(
                        'HIPAA',
                        '§164.312(a)(2)(iv)',
                        'Encryption and Decryption',
                        'HIGH'
                    ),
                    ComplianceRequirement(
                        'HIPAA',
                        '§164.312(e)(2)(ii)',
                        'Encryption (Addressable)',
                        'HIGH'
                    )
                ],
                'SOC2': [
                    ComplianceRequirement(
                        'SOC 2',
                        'CC6.7',
                        'Encryption protects data at rest and in transit',
                        'HIGH'
                    )
                ],
                'NIST_CSF': [
                    ComplianceRequirement(
                        'NIST CSF',
                        'PR.DS-1',
                        'Data-at-rest is protected',
                        'HIGH'
                    )
                ]
            },
            
            's3_no_versioning': {
                'CIS_AWS_FOUNDATIONS': [
                    ComplianceRequirement(
                        'CIS AWS Foundations',
                        '2.1.3',
                        'Ensure MFA Delete is enabled on S3 buckets',
                        'MEDIUM'
                    )
                ],
                'SOC2': [
                    ComplianceRequirement(
                        'SOC 2',
                        'CC8.1',
                        'Change Management - Controls provide reasonable assurance',
                        'MEDIUM'
                    )
                ],
                'NIST_CSF': [
                    ComplianceRequirement(
                        'NIST CSF',
                        'PR.IP-4',
                        'Backups are conducted, maintained, and tested',
                        'MEDIUM'
                    )
                ]
            },
            
            's3_no_logging': {
                'CIS_AWS_FOUNDATIONS': [
                    ComplianceRequirement(
                        'CIS AWS Foundations',
                        '2.1.4',
                        'Ensure S3 bucket logging is enabled',
                        'MEDIUM'
                    )
                ],
                'PCI_DSS': [
                    ComplianceRequirement(
                        'PCI-DSS v4.0',
                        '10.2.1',
                        'Audit logs capture all access to system components',
                        'HIGH'
                    )
                ],
                'HIPAA': [
                    ComplianceRequirement(
                        'HIPAA',
                        '§164.312(b)',
                        'Audit Controls',
                        'MEDIUM'
                    )
                ],
                'SOC2': [
                    ComplianceRequirement(
                        'SOC 2',
                        'CC7.2',
                        'System monitoring',
                        'MEDIUM'
                    )
                ],
                'NIST_CSF': [
                    ComplianceRequirement(
                        'NIST CSF',
                        'DE.AE-3',
                        'Event data are collected and correlated',
                        'MEDIUM'
                    )
                ]
            },
            
            # CloudTrail Findings
            'cloudtrail_not_enabled': {
                'CIS_AWS_FOUNDATIONS': [
                    ComplianceRequirement(
                        'CIS AWS Foundations',
                        '3.1',
                        'Ensure CloudTrail is enabled in all regions',
                        'HIGH'
                    ),
                    ComplianceRequirement(
                        'CIS AWS Foundations',
                        '3.2',
                        'Ensure CloudTrail log file validation is enabled',
                        'HIGH'
                    )
                ],
                'PCI_DSS': [
                    ComplianceRequirement(
                        'PCI-DSS v4.0',
                        '10.2',
                        'Audit logs are implemented to support detection',
                        'CRITICAL'
                    )
                ],
                'HIPAA': [
                    ComplianceRequirement(
                        'HIPAA',
                        '§164.312(b)',
                        'Audit Controls - Hardware, software, procedural mechanisms',
                        'HIGH'
                    )
                ],
                'SOC2': [
                    ComplianceRequirement(
                        'SOC 2',
                        'CC7.2',
                        'System monitoring detects anomalies',
                        'HIGH'
                    )
                ],
                'NIST_CSF': [
                    ComplianceRequirement(
                        'NIST CSF',
                        'DE.AE-3',
                        'Event data are collected and correlated from multiple sources',
                        'HIGH'
                    ),
                    ComplianceRequirement(
                        'NIST CSF',
                        'PR.PT-1',
                        'Audit/log records are determined, documented, implemented',
                        'HIGH'
                    )
                ]
            },
            
            # IAM Findings
            'iam_root_no_mfa': {
                'CIS_AWS_FOUNDATIONS': [
                    ComplianceRequirement(
                        'CIS AWS Foundations',
                        '1.13',
                        'Ensure MFA is enabled for the root user account',
                        'CRITICAL'
                    )
                ],
                'PCI_DSS': [
                    ComplianceRequirement(
                        'PCI-DSS v4.0',
                        '8.4.2',
                        'MFA is implemented for all access',
                        'CRITICAL'
                    )
                ],
                'HIPAA': [
                    ComplianceRequirement(
                        'HIPAA',
                        '§164.312(a)(2)(i)',
                        'Unique User Identification (Required)',
                        'CRITICAL'
                    )
                ],
                'SOC2': [
                    ComplianceRequirement(
                        'SOC 2',
                        'CC6.1',
                        'Logical and physical access controls restrict access',
                        'CRITICAL'
                    )
                ],
                'NIST_CSF': [
                    ComplianceRequirement(
                        'NIST CSF',
                        'PR.AC-1',
                        'Identities and credentials are issued, managed, verified',
                        'CRITICAL'
                    )
                ]
            },
            
            'iam_user_no_mfa': {
                'CIS_AWS_FOUNDATIONS': [
                    ComplianceRequirement(
                        'CIS AWS Foundations',
                        '1.14',
                        'Ensure MFA is enabled for all IAM users',
                        'HIGH'
                    )
                ],
                'PCI_DSS': [
                    ComplianceRequirement(
                        'PCI-DSS v4.0',
                        '8.4.2',
                        'MFA is implemented for all access into the CDE',
                        'HIGH'
                    )
                ],
                'SOC2': [
                    ComplianceRequirement(
                        'SOC 2',
                        'CC6.1',
                        'Multi-factor authentication',
                        'HIGH'
                    )
                ]
            },
            
            'iam_inactive_credentials': {
                'CIS_AWS_FOUNDATIONS': [
                    ComplianceRequirement(
                        'CIS AWS Foundations',
                        '1.3',
                        'Ensure credentials unused for 90 days or greater are disabled',
                        'MEDIUM'
                    )
                ],
                'PCI_DSS': [
                    ComplianceRequirement(
                        'PCI-DSS v4.0',
                        '8.2.6',
                        'Inactive user accounts are removed or disabled',
                        'MEDIUM'
                    )
                ],
                'SOC2': [
                    ComplianceRequirement(
                        'SOC 2',
                        'CC6.2',
                        'Credentials are removed when access is no longer required',
                        'MEDIUM'
                    )
                ]
            },
            
            # Security Group Findings
            'security_group_unrestricted_ingress': {
                'CIS_AWS_FOUNDATIONS': [
                    ComplianceRequirement(
                        'CIS AWS Foundations',
                        '5.2',
                        'Ensure no security groups allow ingress from 0.0.0.0/0 to port 22',
                        'CRITICAL'
                    ),
                    ComplianceRequirement(
                        'CIS AWS Foundations',
                        '5.3',
                        'Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389',
                        'CRITICAL'
                    )
                ],
                'PCI_DSS': [
                    ComplianceRequirement(
                        'PCI-DSS v4.0',
                        '1.2.1',
                        'Configuration standards are defined for NSCs',
                        'CRITICAL'
                    ),
                    ComplianceRequirement(
                        'PCI-DSS v4.0',
                        '1.3.1',
                        'Inbound traffic to the CDE is restricted',
                        'CRITICAL'
                    )
                ],
                'HIPAA': [
                    ComplianceRequirement(
                        'HIPAA',
                        '§164.312(a)(1)',
                        'Access Control',
                        'HIGH'
                    )
                ],
                'SOC2': [
                    ComplianceRequirement(
                        'SOC 2',
                        'CC6.6',
                        'Logical and Physical Access Controls',
                        'HIGH'
                    )
                ],
                'NIST_CSF': [
                    ComplianceRequirement(
                        'NIST CSF',
                        'PR.AC-5',
                        'Network integrity is protected',
                        'HIGH'
                    )
                ]
            },
            
            # RDS Findings
            'rds_no_encryption': {
                'CIS_AWS_FOUNDATIONS': [
                    ComplianceRequirement(
                        'CIS AWS Foundations',
                        '2.3.1',
                        'Ensure that encryption is enabled for RDS instances',
                        'HIGH'
                    )
                ],
                'PCI_DSS': [
                    ComplianceRequirement(
                        'PCI-DSS v4.0',
                        '3.5.1',
                        'Disk encryption is used',
                        'CRITICAL'
                    )
                ],
                'HIPAA': [
                    ComplianceRequirement(
                        'HIPAA',
                        '§164.312(a)(2)(iv)',
                        'Encryption and Decryption',
                        'HIGH'
                    )
                ],
                'SOC2': [
                    ComplianceRequirement(
                        'SOC 2',
                        'CC6.7',
                        'Encryption protects data',
                        'HIGH'
                    )
                ],
                'NIST_CSF': [
                    ComplianceRequirement(
                        'NIST CSF',
                        'PR.DS-1',
                        'Data-at-rest is protected',
                        'HIGH'
                    )
                ]
            },
            
            'rds_public_access': {
                'CIS_AWS_FOUNDATIONS': [
                    ComplianceRequirement(
                        'CIS AWS Foundations',
                        '2.3.3',
                        'Ensure that public access is not given to RDS instances',
                        'CRITICAL'
                    )
                ],
                'PCI_DSS': [
                    ComplianceRequirement(
                        'PCI-DSS v4.0',
                        '1.3.1',
                        'Inbound traffic to the CDE is restricted',
                        'CRITICAL'
                    )
                ],
                'HIPAA': [
                    ComplianceRequirement(
                        'HIPAA',
                        '§164.312(a)(1)',
                        'Access Control',
                        'CRITICAL'
                    )
                ]
            },
            
            'rds_no_backup': {
                'CIS_AWS_FOUNDATIONS': [
                    ComplianceRequirement(
                        'CIS AWS Foundations',
                        '2.3.4',
                        'Ensure that automatic backups are enabled for RDS instances',
                        'MEDIUM'
                    )
                ],
                'SOC2': [
                    ComplianceRequirement(
                        'SOC 2',
                        'A1.2',
                        'Backup and disaster recovery',
                        'MEDIUM'
                    )
                ],
                'NIST_CSF': [
                    ComplianceRequirement(
                        'NIST CSF',
                        'PR.IP-4',
                        'Backups are conducted, maintained, and tested',
                        'MEDIUM'
                    )
                ]
            },
            
            # EBS Findings
            'ebs_unencrypted': {
                'CIS_AWS_FOUNDATIONS': [
                    ComplianceRequirement(
                        'CIS AWS Foundations',
                        '2.2.1',
                        'Ensure EBS volume encryption is enabled',
                        'HIGH'
                    )
                ],
                'PCI_DSS': [
                    ComplianceRequirement(
                        'PCI-DSS v4.0',
                        '3.5.1',
                        'Disk encryption is used',
                        'HIGH'
                    )
                ],
                'HIPAA': [
                    ComplianceRequirement(
                        'HIPAA',
                        '§164.312(a)(2)(iv)',
                        'Encryption and Decryption',
                        'HIGH'
                    )
                ],
                'SOC2': [
                    ComplianceRequirement(
                        'SOC 2',
                        'CC6.7',
                        'Encryption protects data',
                        'HIGH'
                    )
                ]
            },
            
            # KMS Findings
            'kms_key_rotation_disabled': {
                'CIS_AWS_FOUNDATIONS': [
                    ComplianceRequirement(
                        'CIS AWS Foundations',
                        '3.8',
                        'Ensure rotation for customer created CMKs is enabled',
                        'MEDIUM'
                    )
                ],
                'PCI_DSS': [
                    ComplianceRequirement(
                        'PCI-DSS v4.0',
                        '3.6.1',
                        'Cryptographic keys are managed',
                        'MEDIUM'
                    )
                ],
                'NIST_CSF': [
                    ComplianceRequirement(
                        'NIST CSF',
                        'PR.AC-1',
                        'Credentials are managed',
                        'MEDIUM'
                    )
                ]
            },
            
            # VPC Findings
            'vpc_flow_logs_disabled': {
                'CIS_AWS_FOUNDATIONS': [
                    ComplianceRequirement(
                        'CIS AWS Foundations',
                        '3.9',
                        'Ensure VPC flow logging is enabled',
                        'MEDIUM'
                    )
                ],
                'PCI_DSS': [
                    ComplianceRequirement(
                        'PCI-DSS v4.0',
                        '10.2.1',
                        'Audit logs capture all access to system components',
                        'MEDIUM'
                    )
                ],
                'SOC2': [
                    ComplianceRequirement(
                        'SOC 2',
                        'CC7.2',
                        'System monitoring',
                        'MEDIUM'
                    )
                ],
                'NIST_CSF': [
                    ComplianceRequirement(
                        'NIST CSF',
                        'DE.AE-3',
                        'Event data are collected',
                        'MEDIUM'
                    )
                ]
            },
            
            # Config Findings
            'config_not_enabled': {
                'CIS_AWS_FOUNDATIONS': [
                    ComplianceRequirement(
                        'CIS AWS Foundations',
                        '3.5',
                        'Ensure AWS Config is enabled',
                        'MEDIUM'
                    )
                ],
                'SOC2': [
                    ComplianceRequirement(
                        'SOC 2',
                        'CC8.1',
                        'Change management controls',
                        'MEDIUM'
                    )
                ],
                'NIST_CSF': [
                    ComplianceRequirement(
                        'NIST CSF',
                        'DE.CM-7',
                        'Monitoring for unauthorized activity',
                        'MEDIUM'
                    )
                ]
            }
        }
        
        return mappings
    
    def get_compliance_mappings(self, finding_title: str) -> List[ComplianceRequirement]:
        """Get all compliance mappings for a finding"""
        
        # Normalize finding title to mapping key
        finding_key = self._normalize_finding_title(finding_title)
        
        all_requirements = []
        
        if finding_key in self.mappings:
            for framework_reqs in self.mappings[finding_key].values():
                all_requirements.extend(framework_reqs)
        
        return all_requirements
    
    def get_compliance_by_framework(self, finding_title: str, framework: str) -> List[ComplianceRequirement]:
        """Get compliance mappings for specific framework"""
        
        finding_key = self._normalize_finding_title(finding_title)
        
        if finding_key in self.mappings and framework in self.mappings[finding_key]:
            return self.mappings[finding_key][framework]
        
        return []
    
    def _normalize_finding_title(self, title: str) -> str:
        """Convert finding title to mapping key"""
        
        title_lower = title.lower()
        
        # S3 mappings
        if 's3' in title_lower:
            if 'public' in title_lower or 'block public access' in title_lower:
                return 's3_public_access'
            elif 'encrypt' in title_lower and 'not enabled' in title_lower:
                return 's3_no_encryption'
            elif 'versioning' in title_lower:
                return 's3_no_versioning'
            elif 'logging' in title_lower or 'access log' in title_lower:
                return 's3_no_logging'
        
        # CloudTrail mappings
        if 'cloudtrail' in title_lower:
            if 'not enabled' in title_lower or 'disabled' in title_lower:
                return 'cloudtrail_not_enabled'
        
        # IAM mappings
        if 'iam' in title_lower or 'root' in title_lower:
            if 'root' in title_lower and 'mfa' in title_lower:
                return 'iam_root_no_mfa'
            elif 'mfa' in title_lower:
                return 'iam_user_no_mfa'
            elif 'inactive' in title_lower or 'unused' in title_lower:
                return 'iam_inactive_credentials'
        
        # Security Group mappings
        if 'security group' in title_lower:
            if '0.0.0.0/0' in title_lower or 'unrestricted' in title_lower:
                return 'security_group_unrestricted_ingress'
        
        # RDS mappings
        if 'rds' in title_lower:
            if 'encrypt' in title_lower:
                return 'rds_no_encryption'
            elif 'public' in title_lower:
                return 'rds_public_access'
            elif 'backup' in title_lower:
                return 'rds_no_backup'
        
        # EBS mappings
        if 'ebs' in title_lower:
            if 'encrypt' in title_lower:
                return 'ebs_unencrypted'
        
        # KMS mappings
        if 'kms' in title_lower:
            if 'rotation' in title_lower:
                return 'kms_key_rotation_disabled'
        
        # VPC mappings
        if 'vpc' in title_lower:
            if 'flow log' in title_lower:
                return 'vpc_flow_logs_disabled'
        
        # Config mappings
        if 'config' in title_lower:
            if 'not enabled' in title_lower:
                return 'config_not_enabled'
        
        return 'unknown'
    
    def get_framework_coverage(self, findings: List[Dict]) -> Dict[str, int]:
        """Get count of findings per compliance framework"""
        
        coverage = {
            'CIS_AWS_FOUNDATIONS': 0,
            'PCI_DSS': 0,
            'HIPAA': 0,
            'SOC2': 0,
            'NIST_CSF': 0
        }
        
        for finding in findings:
            title = finding.get('title', '')
            mappings = self.get_compliance_mappings(title)
            
            frameworks_seen = set()
            for req in mappings:
                if req.framework not in frameworks_seen:
                    framework_key = req.framework.replace(' ', '_').replace('-', '_').replace('.', '').upper()
                    if framework_key in coverage:
                        coverage[framework_key] += 1
                    frameworks_seen.add(req.framework)
        
        return coverage
    
    def generate_compliance_report(self, findings: List[Dict]) -> Dict:
        """Generate comprehensive compliance report"""
        
        report = {
            'total_findings': len(findings),
            'frameworks': {},
            'critical_compliance_gaps': [],
            'coverage_summary': {}
        }
        
        for framework in ['CIS AWS Foundations', 'PCI-DSS v4.0', 'HIPAA', 'SOC 2', 'NIST CSF']:
            report['frameworks'][framework] = {
                'total_violations': 0,
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'requirements': []
            }
        
        for finding in findings:
            title = finding.get('title', '')
            severity = finding.get('severity', 'MEDIUM')
            
            mappings = self.get_compliance_mappings(title)
            
            for req in mappings:
                framework_data = report['frameworks'].get(req.framework, {})
                if framework_data:
                    framework_data['total_violations'] += 1
                    framework_data['requirements'].append({
                        'requirement_id': req.requirement_id,
                        'description': req.description,
                        'finding_title': title,
                        'severity': severity
                    })
                    
                    # Count by severity
                    if severity == 'CRITICAL':
                        framework_data['critical'] += 1
                        report['critical_compliance_gaps'].append({
                            'framework': req.framework,
                            'requirement': req.requirement_id,
                            'finding': title
                        })
                    elif severity == 'HIGH':
                        framework_data['high'] += 1
                    elif severity == 'MEDIUM':
                        framework_data['medium'] += 1
                    else:
                        framework_data['low'] += 1
        
        # Coverage summary
        report['coverage_summary'] = self.get_framework_coverage(findings)
        
        return report
    
    def format_compliance_section(self, finding: Dict) -> str:
        """Format compliance mappings for display"""
        
        title = finding.get('title', '')
        mappings = self.get_compliance_mappings(title)
        
        if not mappings:
            return "No specific compliance mappings identified"
        
        output = []
        output.append("📋 Compliance Framework Mappings:")
        output.append("─" * 60)
        
        # Group by framework
        by_framework = {}
        for req in mappings:
            if req.framework not in by_framework:
                by_framework[req.framework] = []
            by_framework[req.framework].append(req)
        
        for framework, reqs in sorted(by_framework.items()):
            output.append(f"\n🏛️ {framework}")
            for req in reqs:
                output.append(f"  • {req.requirement_id}: {req.description}")
        
        return "\n".join(output)


# Example usage
if __name__ == "__main__":
    mapper = ComplianceMapper()
    
    # Test finding
    finding = {
        'title': 'S3 Bucket Without Encryption Enabled',
        'severity': 'HIGH'
    }
    
    print("Testing compliance mapper...")
    print(f"\nFinding: {finding['title']}")
    print(f"\n{mapper.format_compliance_section(finding)}")
    
    # Test report
    findings = [
        {'title': 'S3 Bucket Without Encryption Enabled', 'severity': 'HIGH'},
        {'title': 'IAM Root Account Without MFA', 'severity': 'CRITICAL'},
        {'title': 'Security Group Allows Unrestricted Ingress', 'severity': 'CRITICAL'}
    ]
    
    report = mapper.generate_compliance_report(findings)
    print(f"\n\nCompliance Report:")
    print(f"Total Findings: {report['total_findings']}")
    print(f"\nFramework Coverage:")
    for framework, count in report['coverage_summary'].items():
        print(f"  {framework}: {count} violations")
