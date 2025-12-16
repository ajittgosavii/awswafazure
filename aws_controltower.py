"""
AWS Control Tower Integration
Supports landing zone management, guardrails, and account factory
"""

import streamlit as st
from typing import Dict, List, Optional, Any
from datetime import datetime
from core_account_manager import get_account_manager

class ControlTowerManager:
    """AWS Control Tower Management"""
    
    def __init__(self, session):
        """Initialize Control Tower manager with boto3 session"""
        self.ct = session.client('controltower')
        self.organizations = session.client('organizations')
    
    # ============= LANDING ZONE =============
    
    def get_landing_zone(self) -> Optional[Dict[str, Any]]:
        """Get landing zone information"""
        try:
            # List landing zones
            response = self.ct.list_landing_zones()
            
            landing_zones = response.get('landingZones', [])
            if not landing_zones:
                return None
            
            # Get details of the first landing zone
            lz_arn = landing_zones[0]['arn']
            details = self.ct.get_landing_zone(landingZoneIdentifier=lz_arn)
            
            lz = details['landingZone']
            return {
                'arn': lz['arn'],
                'version': lz.get('version', ''),
                'latest_available_version': lz.get('latestAvailableVersion', ''),
                'status': lz.get('status', ''),
                'drift_status': lz.get('driftStatus', {}).get('status', 'UNKNOWN')
            }
        except Exception as e:
            st.error(f"Error getting landing zone: {str(e)}")
            return None
    
    # ============= ENABLED CONTROLS (GUARDRAILS) =============
    
    def list_enabled_controls(self, target_identifier: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        List enabled controls (guardrails)
        
        Args:
            target_identifier: Optional OU ARN to filter controls
        """
        try:
            params = {}
            if target_identifier:
                params['targetIdentifier'] = target_identifier
            
            controls = []
            paginator = self.ct.get_paginator('list_enabled_controls')
            
            for page in paginator.paginate(**params):
                for control in page['enabledControls']:
                    controls.append({
                        'arn': control.get('arn', ''),
                        'control_identifier': control.get('controlIdentifier', ''),
                        'target_identifier': control.get('targetIdentifier', ''),
                        'status': control.get('statusSummary', {}).get('status', 'UNKNOWN')
                    })
            
            return controls
        except Exception as e:
            st.error(f"Error listing enabled controls: {str(e)}")
            return []
    
    def enable_control(self, control_identifier: str, 
                      target_identifier: str) -> Dict[str, Any]:
        """
        Enable a control (guardrail) on an OU
        
        Args:
            control_identifier: ARN of the control to enable
            target_identifier: ARN of the target OU
        """
        try:
            response = self.ct.enable_control(
                controlIdentifier=control_identifier,
                targetIdentifier=target_identifier
            )
            
            return {
                'success': True,
                'operation_identifier': response.get('operationIdentifier', ''),
                'message': f'Control enablement initiated'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def disable_control(self, control_identifier: str,
                       target_identifier: str) -> Dict[str, Any]:
        """Disable a control (guardrail) from an OU"""
        try:
            response = self.ct.disable_control(
                controlIdentifier=control_identifier,
                targetIdentifier=target_identifier
            )
            
            return {
                'success': True,
                'operation_identifier': response.get('operationIdentifier', ''),
                'message': f'Control disablement initiated'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def get_control_operation(self, operation_identifier: str) -> Optional[Dict[str, Any]]:
        """Get status of a control operation"""
        try:
            response = self.ct.get_control_operation(
                operationIdentifier=operation_identifier
            )
            
            operation = response['controlOperation']
            return {
                'operation_type': operation.get('operationType', ''),
                'start_time': operation.get('startTime', datetime.now()).strftime('%Y-%m-%d %H:%M:%S') if operation.get('startTime') else '',
                'end_time': operation.get('endTime', datetime.now()).strftime('%Y-%m-%d %H:%M:%S') if operation.get('endTime') else '',
                'status': operation.get('status', 'UNKNOWN'),
                'status_message': operation.get('statusMessage', '')
            }
        except Exception as e:
            st.error(f"Error getting control operation: {str(e)}")
            return None
    
    # ============= BASELINES (ENABLED BASELINES) =============
    
    def list_enabled_baselines(self) -> List[Dict[str, Any]]:
        """List enabled baselines"""
        try:
            baselines = []
            paginator = self.ct.get_paginator('list_enabled_baselines')
            
            for page in paginator.paginate():
                for baseline in page['enabledBaselines']:
                    baselines.append({
                        'arn': baseline.get('arn', ''),
                        'baseline_identifier': baseline.get('baselineIdentifier', ''),
                        'baseline_version': baseline.get('baselineVersion', ''),
                        'target_identifier': baseline.get('targetIdentifier', ''),
                        'status': baseline.get('statusSummary', {}).get('status', 'UNKNOWN')
                    })
            
            return baselines
        except Exception as e:
            st.error(f"Error listing enabled baselines: {str(e)}")
            return []
    
    def get_baseline(self, baseline_identifier: str) -> Optional[Dict[str, Any]]:
        """Get baseline details"""
        try:
            response = self.ct.get_baseline(
                baselineIdentifier=baseline_identifier
            )
            
            baseline = response['baseline']
            return {
                'arn': baseline.get('arn', ''),
                'name': baseline.get('name', ''),
                'description': baseline.get('description', '')
            }
        except Exception as e:
            st.error(f"Error getting baseline: {str(e)}")
            return None
    
    def enable_baseline(self, baseline_identifier: str, baseline_version: str,
                       target_identifier: str, parameters: List[Dict] = None) -> Dict[str, Any]:
        """Enable a baseline on an OU"""
        try:
            params = {
                'baselineIdentifier': baseline_identifier,
                'baselineVersion': baseline_version,
                'targetIdentifier': target_identifier
            }
            
            if parameters:
                params['parameters'] = parameters
            
            response = self.ct.enable_baseline(**params)
            
            return {
                'success': True,
                'operation_identifier': response.get('operationIdentifier', ''),
                'message': 'Baseline enablement initiated'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    # ============= ACCOUNT FACTORY =============
    
    def list_governed_resources(self) -> List[Dict[str, Any]]:
        """List resources governed by Control Tower (e.g., accounts)"""
        try:
            # This would list accounts created through Account Factory
            # Note: This is indirect - we use Organizations API
            org_response = self.organizations.list_accounts()
            
            accounts = []
            for account in org_response.get('Accounts', []):
                # Check if account is governed by Control Tower
                # (typically has Control Tower tags or in governed OU)
                accounts.append({
                    'account_id': account['Id'],
                    'account_name': account['Name'],
                    'email': account['Email'],
                    'status': account['Status'],
                    'joined_method': account.get('JoinedMethod', 'UNKNOWN')
                })
            
            return accounts
        except Exception as e:
            st.error(f"Error listing governed resources: {str(e)}")
            return []
    
    # ============= COMPLIANCE & DRIFT =============
    
    def check_landing_zone_drift(self, landing_zone_identifier: str) -> Dict[str, Any]:
        """Check for drift in the landing zone"""
        try:
            # Note: This feature may not be available in all regions/versions
            response = self.ct.get_landing_zone(
                landingZoneIdentifier=landing_zone_identifier
            )
            
            lz = response['landingZone']
            drift_status = lz.get('driftStatus', {})
            
            return {
                'success': True,
                'drift_status': drift_status.get('status', 'UNKNOWN'),
                'message': f"Drift status: {drift_status.get('status', 'UNKNOWN')}"
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    # ============= ORGANIZATIONAL UNITS =============
    
    def list_governed_ous(self) -> List[Dict[str, Any]]:
        """List organizational units governed by Control Tower"""
        try:
            # Get root
            roots = self.organizations.list_roots()['Roots']
            if not roots:
                return []
            
            root_id = roots[0]['Id']
            
            # List OUs under root
            ous = []
            paginator = self.organizations.get_paginator('list_organizational_units_for_parent')
            
            for page in paginator.paginate(ParentId=root_id):
                for ou in page['OrganizationalUnits']:
                    # Check if OU is governed by Control Tower
                    # (Security, Sandbox are typical Control Tower OUs)
                    ous.append({
                        'ou_id': ou['Id'],
                        'ou_arn': ou['Arn'],
                        'ou_name': ou['Name']
                    })
            
            return ous
        except Exception as e:
            st.error(f"Error listing governed OUs: {str(e)}")
            return []
    
    # ============= GUARDRAIL COMPLIANCE =============
    
    def get_guardrail_compliance_status(self) -> Dict[str, Any]:
        """Get overall guardrail compliance status"""
        try:
            enabled_controls = self.list_enabled_controls()
            
            total = len(enabled_controls)
            enabled = sum(1 for c in enabled_controls if c['status'] == 'SUCCEEDED')
            failed = sum(1 for c in enabled_controls if c['status'] == 'FAILED')
            in_progress = sum(1 for c in enabled_controls if c['status'] == 'IN_PROGRESS')
            
            return {
                'total_controls': total,
                'enabled': enabled,
                'failed': failed,
                'in_progress': in_progress,
                'compliance_percentage': (enabled / total * 100) if total > 0 else 0
            }
        except Exception as e:
            st.error(f"Error getting compliance status: {str(e)}")
            return {
                'total_controls': 0,
                'enabled': 0,
                'failed': 0,
                'in_progress': 0,
                'compliance_percentage': 0
            }
