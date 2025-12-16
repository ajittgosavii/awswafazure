"""
AWS CloudFormation Integration - Infrastructure as Code Deployment
Supports stack management, template deployment, change sets, and drift detection
"""

import streamlit as st
import json
import time
from typing import Dict, List, Optional, Any
from datetime import datetime
from core_account_manager import get_account_manager

class CloudFormationManager:
    """AWS CloudFormation Stack Management"""
    
    def __init__(self, session):
        """Initialize CloudFormation manager with boto3 session"""
        self.cfn_client = session.client('cloudformation')
    
    # ============= STACK OPERATIONS =============
    
    def list_stacks(self, status_filter: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        List CloudFormation stacks
        
        Args:
            status_filter: List of statuses to filter (e.g., ['CREATE_COMPLETE', 'UPDATE_COMPLETE'])
        """
        try:
            params = {}
            if status_filter:
                params['StackStatusFilter'] = status_filter
            
            stacks = []
            paginator = self.cfn_client.get_paginator('list_stacks')
            
            for page in paginator.paginate(**params):
                for stack in page['StackSummaries']:
                    if stack['StackStatus'] != 'DELETE_COMPLETE':  # Skip deleted stacks
                        stacks.append({
                            'stack_name': stack['StackName'],
                            'stack_id': stack['StackId'],
                            'status': stack['StackStatus'],
                            'creation_time': stack['CreationTime'].strftime('%Y-%m-%d %H:%M:%S'),
                            'last_updated': stack.get('LastUpdatedTime', stack['CreationTime']).strftime('%Y-%m-%d %H:%M:%S'),
                            'drift_status': stack.get('DriftInformation', {}).get('StackDriftStatus', 'NOT_CHECKED'),
                            'template_description': stack.get('TemplateDescription', '')
                        })
            
            return stacks
        except Exception as e:
            st.error(f"Error listing stacks: {str(e)}")
            return []
    
    def get_stack_info(self, stack_name: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a stack"""
        try:
            response = self.cfn_client.describe_stacks(StackName=stack_name)
            
            if not response['Stacks']:
                return None
            
            stack = response['Stacks'][0]
            
            return {
                'stack_name': stack['StackName'],
                'stack_id': stack['StackId'],
                'status': stack['StackStatus'],
                'status_reason': stack.get('StackStatusReason', ''),
                'creation_time': stack['CreationTime'].strftime('%Y-%m-%d %H:%M:%S'),
                'last_updated': stack.get('LastUpdatedTime', stack['CreationTime']).strftime('%Y-%m-%d %H:%M:%S'),
                'description': stack.get('Description', ''),
                'parameters': stack.get('Parameters', []),
                'outputs': stack.get('Outputs', []),
                'tags': stack.get('Tags', []),
                'capabilities': stack.get('Capabilities', []),
                'drift_status': stack.get('DriftInformation', {}).get('StackDriftStatus', 'NOT_CHECKED')
            }
        except Exception as e:
            st.error(f"Error getting stack info: {str(e)}")
            return None
    
    def create_stack(self, stack_name: str, template_body: str = None,
                    template_url: str = None, parameters: List[Dict] = None,
                    tags: List[Dict] = None, capabilities: List[str] = None) -> Dict[str, Any]:
        """
        Create a new CloudFormation stack
        
        Args:
            stack_name: Name for the stack
            template_body: Template as JSON/YAML string
            template_url: S3 URL to template
            parameters: List of parameter dicts
            tags: List of tag dicts
            capabilities: Required capabilities (e.g., CAPABILITY_IAM)
        """
        try:
            params = {
                'StackName': stack_name,
                'OnFailure': 'ROLLBACK'
            }
            
            if template_body:
                params['TemplateBody'] = template_body
            elif template_url:
                params['TemplateURL'] = template_url
            else:
                return {'success': False, 'error': 'Either template_body or template_url required'}
            
            if parameters:
                params['Parameters'] = parameters
            if tags:
                params['Tags'] = tags
            if capabilities:
                params['Capabilities'] = capabilities
            
            response = self.cfn_client.create_stack(**params)
            
            return {
                'success': True,
                'stack_id': response['StackId'],
                'message': f'Stack {stack_name} creation initiated'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def update_stack(self, stack_name: str, template_body: str = None,
                    template_url: str = None, parameters: List[Dict] = None,
                    capabilities: List[str] = None, use_previous_template: bool = False) -> Dict[str, Any]:
        """Update an existing CloudFormation stack"""
        try:
            params = {
                'StackName': stack_name
            }
            
            if use_previous_template:
                params['UsePreviousTemplate'] = True
            elif template_body:
                params['TemplateBody'] = template_body
            elif template_url:
                params['TemplateURL'] = template_url
            
            if parameters:
                params['Parameters'] = parameters
            if capabilities:
                params['Capabilities'] = capabilities
            
            response = self.cfn_client.update_stack(**params)
            
            return {
                'success': True,
                'stack_id': response['StackId'],
                'message': f'Stack {stack_name} update initiated'
            }
        except Exception as e:
            error_msg = str(e)
            if 'No updates are to be performed' in error_msg:
                return {
                    'success': True,
                    'message': 'No changes detected in stack'
                }
            return {'success': False, 'error': error_msg}
    
    def delete_stack(self, stack_name: str, retain_resources: List[str] = None) -> Dict[str, Any]:
        """Delete a CloudFormation stack"""
        try:
            params = {'StackName': stack_name}
            if retain_resources:
                params['RetainResources'] = retain_resources
            
            self.cfn_client.delete_stack(**params)
            
            return {
                'success': True,
                'message': f'Stack {stack_name} deletion initiated'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    # ============= STACK RESOURCES =============
    
    def list_stack_resources(self, stack_name: str) -> List[Dict[str, Any]]:
        """List resources in a stack"""
        try:
            resources = []
            paginator = self.cfn_client.get_paginator('list_stack_resources')
            
            for page in paginator.paginate(StackName=stack_name):
                for resource in page['StackResourceSummaries']:
                    resources.append({
                        'logical_id': resource['LogicalResourceId'],
                        'physical_id': resource.get('PhysicalResourceId', 'N/A'),
                        'resource_type': resource['ResourceType'],
                        'status': resource['ResourceStatus'],
                        'status_reason': resource.get('ResourceStatusReason', ''),
                        'last_updated': resource['LastUpdatedTimestamp'].strftime('%Y-%m-%d %H:%M:%S')
                    })
            
            return resources
        except Exception as e:
            st.error(f"Error listing stack resources: {str(e)}")
            return []
    
    # ============= CHANGE SETS =============
    
    def create_change_set(self, stack_name: str, change_set_name: str,
                         template_body: str = None, template_url: str = None,
                         parameters: List[Dict] = None, capabilities: List[str] = None,
                         change_set_type: str = 'UPDATE') -> Dict[str, Any]:
        """
        Create a change set to preview changes before executing
        
        Args:
            change_set_type: 'CREATE' or 'UPDATE'
        """
        try:
            params = {
                'StackName': stack_name,
                'ChangeSetName': change_set_name,
                'ChangeSetType': change_set_type
            }
            
            if template_body:
                params['TemplateBody'] = template_body
            elif template_url:
                params['TemplateURL'] = template_url
            
            if parameters:
                params['Parameters'] = parameters
            if capabilities:
                params['Capabilities'] = capabilities
            
            response = self.cfn_client.create_change_set(**params)
            
            return {
                'success': True,
                'change_set_id': response['Id'],
                'message': f'Change set {change_set_name} created'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def describe_change_set(self, change_set_name: str, stack_name: str) -> Optional[Dict[str, Any]]:
        """Get details about a change set"""
        try:
            response = self.cfn_client.describe_change_set(
                ChangeSetName=change_set_name,
                StackName=stack_name
            )
            
            return {
                'change_set_name': response['ChangeSetName'],
                'stack_name': response['StackName'],
                'status': response['Status'],
                'status_reason': response.get('StatusReason', ''),
                'creation_time': response['CreationTime'].strftime('%Y-%m-%d %H:%M:%S'),
                'changes': response.get('Changes', []),
                'parameters': response.get('Parameters', [])
            }
        except Exception as e:
            st.error(f"Error describing change set: {str(e)}")
            return None
    
    def execute_change_set(self, change_set_name: str, stack_name: str) -> Dict[str, Any]:
        """Execute a change set"""
        try:
            self.cfn_client.execute_change_set(
                ChangeSetName=change_set_name,
                StackName=stack_name
            )
            
            return {
                'success': True,
                'message': f'Change set {change_set_name} execution initiated'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def delete_change_set(self, change_set_name: str, stack_name: str) -> Dict[str, Any]:
        """Delete a change set"""
        try:
            self.cfn_client.delete_change_set(
                ChangeSetName=change_set_name,
                StackName=stack_name
            )
            
            return {
                'success': True,
                'message': f'Change set {change_set_name} deleted'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    # ============= DRIFT DETECTION =============
    
    def detect_stack_drift(self, stack_name: str) -> Dict[str, Any]:
        """Initiate drift detection for a stack"""
        try:
            response = self.cfn_client.detect_stack_drift(StackName=stack_name)
            
            return {
                'success': True,
                'drift_detection_id': response['StackDriftDetectionId'],
                'message': 'Drift detection initiated'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def describe_stack_drift(self, drift_detection_id: str) -> Optional[Dict[str, Any]]:
        """Get drift detection results"""
        try:
            response = self.cfn_client.describe_stack_drift_detection_status(
                StackDriftDetectionId=drift_detection_id
            )
            
            return {
                'stack_id': response['StackId'],
                'drift_status': response['StackDriftStatus'],
                'detection_status': response['DetectionStatus'],
                'drifted_stack_resource_count': response.get('DriftedStackResourceCount', 0),
                'timestamp': response['Timestamp'].strftime('%Y-%m-%d %H:%M:%S')
            }
        except Exception as e:
            st.error(f"Error describing drift: {str(e)}")
            return None
    
    def list_stack_resource_drifts(self, stack_name: str) -> List[Dict[str, Any]]:
        """List resource drift information"""
        try:
            drifts = []
            paginator = self.cfn_client.get_paginator('describe_stack_resource_drifts')
            
            for page in paginator.paginate(StackName=stack_name):
                for drift in page['StackResourceDrifts']:
                    drifts.append({
                        'logical_id': drift['LogicalResourceId'],
                        'physical_id': drift.get('PhysicalResourceId', 'N/A'),
                        'resource_type': drift['ResourceType'],
                        'drift_status': drift['StackResourceDriftStatus'],
                        'timestamp': drift['Timestamp'].strftime('%Y-%m-%d %H:%M:%S')
                    })
            
            return drifts
        except Exception as e:
            st.error(f"Error listing resource drifts: {str(e)}")
            return []
    
    # ============= TEMPLATE OPERATIONS =============
    
    def get_template(self, stack_name: str) -> Optional[str]:
        """Get the template body for a stack"""
        try:
            response = self.cfn_client.get_template(
                StackName=stack_name,
                TemplateStage='Original'
            )
            return response['TemplateBody']
        except Exception as e:
            st.error(f"Error getting template: {str(e)}")
            return None
    
    def validate_template(self, template_body: str = None, 
                         template_url: str = None) -> Dict[str, Any]:
        """Validate a CloudFormation template"""
        try:
            params = {}
            if template_body:
                params['TemplateBody'] = template_body
            elif template_url:
                params['TemplateURL'] = template_url
            else:
                return {'success': False, 'error': 'Template required'}
            
            response = self.cfn_client.validate_template(**params)
            
            return {
                'success': True,
                'description': response.get('Description', ''),
                'parameters': response.get('Parameters', []),
                'capabilities': response.get('Capabilities', []),
                'message': 'Template is valid'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    # ============= STACK SETS =============
    
    def list_stack_sets(self) -> List[Dict[str, Any]]:
        """List StackSets"""
        try:
            stack_sets = []
            paginator = self.cfn_client.get_paginator('list_stack_sets')
            
            for page in paginator.paginate():
                for ss in page['Summaries']:
                    stack_sets.append({
                        'stack_set_name': ss['StackSetName'],
                        'stack_set_id': ss.get('StackSetId', ''),
                        'status': ss.get('Status', 'ACTIVE'),
                        'description': ss.get('Description', '')
                    })
            
            return stack_sets
        except Exception as e:
            st.error(f"Error listing stack sets: {str(e)}")
            return []
    
    # ============= STACK EVENTS =============
    
    def get_stack_events(self, stack_name: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent events for a stack"""
        try:
            response = self.cfn_client.describe_stack_events(StackName=stack_name)
            
            events = []
            for event in response['StackEvents'][:limit]:
                events.append({
                    'timestamp': event['Timestamp'].strftime('%Y-%m-%d %H:%M:%S'),
                    'logical_id': event['LogicalResourceId'],
                    'physical_id': event.get('PhysicalResourceId', 'N/A'),
                    'resource_type': event['ResourceType'],
                    'status': event['ResourceStatus'],
                    'reason': event.get('ResourceStatusReason', '')
                })
            
            return events
        except Exception as e:
            st.error(f"Error getting stack events: {str(e)}")
            return []
