"""
AWS Security & Compliance Integration
Supports Security Hub, GuardDuty, AWS Config, and compliance management
"""

import streamlit as st
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from core_account_manager import get_account_manager

class SecurityManager:
    """AWS Security Hub, GuardDuty, and Config Management"""
    
    def __init__(self, session):
        """Initialize security manager with boto3 session"""
        self.security_hub = session.client('securityhub')
        self.guardduty = session.client('guardduty')
        self.config = session.client('config')
        self.iam = session.client('iam')
    
    # ============= SECURITY HUB =============
    
    def get_security_hub_summary(self) -> Dict[str, Any]:
        """Get Security Hub overview and compliance status"""
        try:
            # Get findings summary
            response = self.security_hub.get_findings(
                Filters={
                    'RecordState': [{'Value': 'ACTIVE', 'Comparison': 'EQUALS'}]
                },
                MaxResults=100
            )
            
            findings = response.get('Findings', [])
            
            # Count by severity
            severity_counts = {
                'CRITICAL': 0,
                'HIGH': 0,
                'MEDIUM': 0,
                'LOW': 0,
                'INFORMATIONAL': 0
            }
            
            for finding in findings:
                severity = finding.get('Severity', {}).get('Label', 'INFORMATIONAL')
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            # Get compliance standards
            standards_response = self.security_hub.get_enabled_standards()
            enabled_standards = standards_response.get('StandardsSubscriptions', [])
            
            return {
                'total_findings': len(findings),
                'severity_counts': severity_counts,
                'enabled_standards': len(enabled_standards),
                'standards': [s['StandardsArn'] for s in enabled_standards]
            }
        except Exception as e:
            st.error(f"Error getting Security Hub summary: {str(e)}")
            return {'total_findings': 0, 'severity_counts': {}, 'enabled_standards': 0}
    
    def list_security_findings(self, severity: Optional[str] = None, 
                              limit: int = 100) -> List[Dict[str, Any]]:
        """List security findings from Security Hub"""
        try:
            filters = {
                'RecordState': [{'Value': 'ACTIVE', 'Comparison': 'EQUALS'}]
            }
            
            if severity:
                filters['SeverityLabel'] = [{'Value': severity, 'Comparison': 'EQUALS'}]
            
            response = self.security_hub.get_findings(
                Filters=filters,
                MaxResults=limit,
                SortCriteria=[
                    {'Field': 'SeverityLabel', 'SortOrder': 'desc'}
                ]
            )
            
            findings = []
            for finding in response.get('Findings', []):
                findings.append({
                    'id': finding.get('Id', ''),
                    'title': finding.get('Title', ''),
                    'description': finding.get('Description', ''),
                    'severity': finding.get('Severity', {}).get('Label', 'INFORMATIONAL'),
                    'resource_type': finding.get('Resources', [{}])[0].get('Type', 'Unknown'),
                    'resource_id': finding.get('Resources', [{}])[0].get('Id', 'Unknown'),
                    'compliance_status': finding.get('Compliance', {}).get('Status', 'NOT_AVAILABLE'),
                    'workflow_status': finding.get('Workflow', {}).get('Status', 'NEW'),
                    'created_at': finding.get('CreatedAt', ''),
                    'updated_at': finding.get('UpdatedAt', ''),
                    'remediation': finding.get('Remediation', {}).get('Recommendation', {}).get('Text', '')
                })
            
            return findings
        except Exception as e:
            st.error(f"Error listing findings: {str(e)}")
            return []
    
    def update_finding_workflow(self, finding_id: str, workflow_status: str) -> Dict[str, Any]:
        """Update the workflow status of a finding"""
        try:
            self.security_hub.batch_update_findings(
                FindingIdentifiers=[
                    {'Id': finding_id, 'ProductArn': finding_id.split('/')[0]}
                ],
                Workflow={'Status': workflow_status}
            )
            
            return {
                'success': True,
                'message': f'Finding workflow updated to {workflow_status}'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def enable_security_hub(self) -> Dict[str, Any]:
        """Enable Security Hub"""
        try:
            self.security_hub.enable_security_hub()
            return {
                'success': True,
                'message': 'Security Hub enabled successfully'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def enable_security_standard(self, standard_arn: str) -> Dict[str, Any]:
        """Enable a security standard (CIS, PCI-DSS, AWS Foundational)"""
        try:
            self.security_hub.batch_enable_standards(
                StandardsSubscriptionRequests=[
                    {'StandardsArn': standard_arn}
                ]
            )
            return {
                'success': True,
                'message': f'Security standard enabled: {standard_arn}'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    # ============= GUARDDUTY =============
    
    def get_guardduty_detector(self) -> Optional[str]:
        """Get GuardDuty detector ID"""
        try:
            response = self.guardduty.list_detectors()
            detectors = response.get('DetectorIds', [])
            return detectors[0] if detectors else None
        except Exception as e:
            st.error(f"Error getting GuardDuty detector: {str(e)}")
            return None
    
    def list_guardduty_findings(self, detector_id: str, 
                               severity: Optional[float] = None) -> List[Dict[str, Any]]:
        """List GuardDuty findings"""
        try:
            # Get finding IDs
            filters = {}
            if severity:
                filters['severity'] = {'Gte': severity}
            
            response = self.guardduty.list_findings(
                DetectorId=detector_id,
                FindingCriteria={'Criterion': filters} if filters else {},
                MaxResults=50,
                SortCriteria={'AttributeName': 'severity', 'OrderBy': 'DESC'}
            )
            
            finding_ids = response.get('FindingIds', [])
            
            if not finding_ids:
                return []
            
            # Get finding details
            details_response = self.guardduty.get_findings(
                DetectorId=detector_id,
                FindingIds=finding_ids
            )
            
            findings = []
            for finding in details_response.get('Findings', []):
                findings.append({
                    'id': finding.get('Id', ''),
                    'type': finding.get('Type', ''),
                    'severity': finding.get('Severity', 0),
                    'title': finding.get('Title', ''),
                    'description': finding.get('Description', ''),
                    'resource_type': finding.get('Resource', {}).get('ResourceType', 'Unknown'),
                    'region': finding.get('Region', ''),
                    'created_at': finding.get('CreatedAt', ''),
                    'updated_at': finding.get('UpdatedAt', ''),
                    'count': finding.get('Service', {}).get('Count', 0)
                })
            
            return findings
        except Exception as e:
            st.error(f"Error listing GuardDuty findings: {str(e)}")
            return []
    
    def enable_guardduty(self) -> Dict[str, Any]:
        """Enable GuardDuty"""
        try:
            response = self.guardduty.create_detector(
                Enable=True,
                FindingPublishingFrequency='FIFTEEN_MINUTES'
            )
            
            return {
                'success': True,
                'detector_id': response['DetectorId'],
                'message': 'GuardDuty enabled successfully'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def archive_guardduty_findings(self, detector_id: str, finding_ids: List[str]) -> Dict[str, Any]:
        """Archive GuardDuty findings"""
        try:
            self.guardduty.archive_findings(
                DetectorId=detector_id,
                FindingIds=finding_ids
            )
            
            return {
                'success': True,
                'message': f'{len(finding_ids)} findings archived'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    # ============= AWS CONFIG =============
    
    def list_config_rules(self) -> List[Dict[str, Any]]:
        """List AWS Config rules"""
        try:
            rules = []
            paginator = self.config.get_paginator('describe_config_rules')
            
            for page in paginator.paginate():
                for rule in page['ConfigRules']:
                    rules.append({
                        'name': rule['ConfigRuleName'],
                        'arn': rule['ConfigRuleArn'],
                        'description': rule.get('Description', ''),
                        'source': rule.get('Source', {}).get('Owner', 'CUSTOM_LAMBDA'),
                        'state': rule.get('ConfigRuleState', 'ACTIVE')
                    })
            
            return rules
        except Exception as e:
            st.error(f"Error listing Config rules: {str(e)}")
            return []
    
    def get_compliance_summary(self) -> Dict[str, Any]:
        """Get Config compliance summary"""
        try:
            response = self.config.describe_compliance_by_config_rule()
            
            compliance_counts = {
                'COMPLIANT': 0,
                'NON_COMPLIANT': 0,
                'NOT_APPLICABLE': 0,
                'INSUFFICIENT_DATA': 0
            }
            
            for rule in response.get('ComplianceByConfigRules', []):
                compliance = rule.get('Compliance', {})
                compliance_type = compliance.get('ComplianceType', 'INSUFFICIENT_DATA')
                compliance_counts[compliance_type] = compliance_counts.get(compliance_type, 0) + 1
            
            return {
                'total_rules': sum(compliance_counts.values()),
                'compliance_counts': compliance_counts,
                'compliance_percentage': (compliance_counts['COMPLIANT'] / sum(compliance_counts.values()) * 100) if sum(compliance_counts.values()) > 0 else 0
            }
        except Exception as e:
            st.error(f"Error getting compliance summary: {str(e)}")
            return {'total_rules': 0, 'compliance_counts': {}}
    
    def get_non_compliant_resources(self, rule_name: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get non-compliant resources"""
        try:
            params = {
                'ComplianceTypes': ['NON_COMPLIANT']
            }
            
            if rule_name:
                params['ConfigRuleName'] = rule_name
            
            response = self.config.describe_compliance_by_resource(**params)
            
            resources = []
            for item in response.get('ComplianceByResources', []):
                resources.append({
                    'resource_type': item.get('ResourceType', ''),
                    'resource_id': item.get('ResourceId', ''),
                    'compliance_type': item.get('Compliance', {}).get('ComplianceType', ''),
                    'compliance_contributor_count': item.get('Compliance', {}).get('ComplianceContributorCount', {}).get('CappedCount', 0)
                })
            
            return resources
        except Exception as e:
            st.error(f"Error getting non-compliant resources: {str(e)}")
            return []
    
    def start_config_recorder(self, recorder_name: str) -> Dict[str, Any]:
        """Start AWS Config recorder"""
        try:
            self.config.start_configuration_recorder(
                ConfigurationRecorderName=recorder_name
            )
            return {
                'success': True,
                'message': f'Config recorder {recorder_name} started'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def put_config_rule(self, rule_name: str, source_identifier: str,
                       resource_types: List[str]) -> Dict[str, Any]:
        """Create or update a Config rule"""
        try:
            self.config.put_config_rule(
                ConfigRule={
                    'ConfigRuleName': rule_name,
                    'Source': {
                        'Owner': 'AWS',
                        'SourceIdentifier': source_identifier
                    },
                    'Scope': {
                        'ComplianceResourceTypes': resource_types
                    }
                }
            )
            
            return {
                'success': True,
                'message': f'Config rule {rule_name} created/updated'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    # ============= IAM ACCESS ANALYZER =============
    
    def list_access_analyzers(self) -> List[Dict[str, Any]]:
        """List IAM Access Analyzers"""
        try:
            # Note: Access Analyzer is region-specific
            access_analyzer = self.session.client('accessanalyzer')
            response = access_analyzer.list_analyzers()
            
            analyzers = []
            for analyzer in response.get('analyzers', []):
                analyzers.append({
                    'name': analyzer['name'],
                    'arn': analyzer['arn'],
                    'status': analyzer['status'],
                    'type': analyzer['type'],
                    'created_at': analyzer['createdAt'].strftime('%Y-%m-%d %H:%M:%S')
                })
            
            return analyzers
        except Exception as e:
            st.error(f"Error listing access analyzers: {str(e)}")
            return []
    
    # ============= COMPLIANCE HELPERS =============
    
    def get_security_score(self) -> Dict[str, Any]:
        """Calculate overall security score"""
        try:
            # Get Security Hub findings
            sh_summary = self.get_security_hub_summary()
            
            # Get Config compliance
            config_summary = self.get_compliance_summary()
            
            # Calculate score (0-100)
            total_findings = sh_summary.get('total_findings', 0)
            critical_findings = sh_summary.get('severity_counts', {}).get('CRITICAL', 0)
            high_findings = sh_summary.get('severity_counts', {}).get('HIGH', 0)
            
            # Deduct points for findings
            score = 100
            score -= critical_findings * 5
            score -= high_findings * 2
            score -= (total_findings - critical_findings - high_findings) * 0.5
            
            # Compliance bonus
            compliance_pct = config_summary.get('compliance_percentage', 0)
            score = (score + compliance_pct) / 2
            
            score = max(0, min(100, score))  # Clamp between 0-100
            
            return {
                'score': round(score, 1),
                'total_findings': total_findings,
                'critical_findings': critical_findings,
                'high_findings': high_findings,
                'compliance_percentage': compliance_pct,
                'grade': self._score_to_grade(score)
            }
        except Exception as e:
            st.error(f"Error calculating security score: {str(e)}")
            return {'score': 0, 'grade': 'F'}
    
    def _score_to_grade(self, score: float) -> str:
        """Convert numeric score to letter grade"""
        if score >= 90:
            return 'A'
        elif score >= 80:
            return 'B'
        elif score >= 70:
            return 'C'
        elif score >= 60:
            return 'D'
        else:
            return 'F'
