"""
AWS Systems Manager Integration
Supports Parameter Store, Automation, Session Manager, and Patch Management
"""

import streamlit as st
from typing import Dict, List, Optional, Any
from datetime import datetime
from core_account_manager import get_account_manager

class SystemsManagerManager:
    """AWS Systems Manager Management"""
    
    def __init__(self, session):
        """Initialize Systems Manager with boto3 session"""
        self.ssm = session.client('ssm')
    
    # ============= PARAMETER STORE =============
    
    def list_parameters(self, path: Optional[str] = None, 
                       recursive: bool = False) -> List[Dict[str, Any]]:
        """List parameters in Parameter Store"""
        try:
            params_list = []
            
            if path:
                # List parameters by path
                paginator = self.ssm.get_paginator('get_parameters_by_path')
                for page in paginator.paginate(
                    Path=path,
                    Recursive=recursive,
                    WithDecryption=False
                ):
                    for param in page['Parameters']:
                        params_list.append({
                            'name': param['Name'],
                            'type': param['Type'],
                            'value': param.get('Value', '***'),
                            'version': param.get('Version', 1),
                            'last_modified': param.get('LastModifiedDate', datetime.now()).strftime('%Y-%m-%d %H:%M:%S')
                        })
            else:
                # List all parameters
                paginator = self.ssm.get_paginator('describe_parameters')
                for page in paginator.paginate():
                    for param in page['Parameters']:
                        params_list.append({
                            'name': param['Name'],
                            'type': param['Type'],
                            'description': param.get('Description', ''),
                            'version': param.get('Version', 1),
                            'last_modified': param.get('LastModifiedDate', datetime.now()).strftime('%Y-%m-%d %H:%M:%S')
                        })
            
            return params_list
        except Exception as e:
            st.error(f"Error listing parameters: {str(e)}")
            return []
    
    def get_parameter(self, name: str, with_decryption: bool = True) -> Optional[Dict[str, Any]]:
        """Get a parameter value"""
        try:
            response = self.ssm.get_parameter(
                Name=name,
                WithDecryption=with_decryption
            )
            
            param = response['Parameter']
            return {
                'name': param['Name'],
                'type': param['Type'],
                'value': param['Value'],
                'version': param['Version'],
                'last_modified': param['LastModifiedDate'].strftime('%Y-%m-%d %H:%M:%S'),
                'arn': param['ARN']
            }
        except Exception as e:
            st.error(f"Error getting parameter: {str(e)}")
            return None
    
    def put_parameter(self, name: str, value: str, 
                     parameter_type: str = 'String',
                     description: str = '',
                     overwrite: bool = False,
                     key_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Create or update a parameter
        
        Args:
            parameter_type: 'String', 'StringList', or 'SecureString'
            key_id: KMS key ID for SecureString (uses default if not specified)
        """
        try:
            params = {
                'Name': name,
                'Value': value,
                'Type': parameter_type,
                'Overwrite': overwrite
            }
            
            if description:
                params['Description'] = description
            
            if parameter_type == 'SecureString' and key_id:
                params['KeyId'] = key_id
            
            response = self.ssm.put_parameter(**params)
            
            return {
                'success': True,
                'version': response.get('Version', 1),
                'message': f'Parameter {name} saved'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def delete_parameter(self, name: str) -> Dict[str, Any]:
        """Delete a parameter"""
        try:
            self.ssm.delete_parameter(Name=name)
            return {
                'success': True,
                'message': f'Parameter {name} deleted'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def delete_parameters(self, names: List[str]) -> Dict[str, Any]:
        """Delete multiple parameters"""
        try:
            response = self.ssm.delete_parameters(Names=names)
            
            deleted = response.get('DeletedParameters', [])
            invalid = response.get('InvalidParameters', [])
            
            return {
                'success': True,
                'deleted_count': len(deleted),
                'invalid_count': len(invalid),
                'message': f'{len(deleted)} parameters deleted'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    # ============= AUTOMATION =============
    
    def list_documents(self, document_filter_list: Optional[List[Dict]] = None) -> List[Dict[str, Any]]:
        """List SSM documents (automation runbooks, command documents, etc.)"""
        try:
            params = {}
            if document_filter_list:
                params['DocumentFilterList'] = document_filter_list
            
            documents = []
            paginator = self.ssm.get_paginator('list_documents')
            
            for page in paginator.paginate(**params):
                for doc in page['DocumentIdentifiers']:
                    documents.append({
                        'name': doc['Name'],
                        'owner': doc.get('Owner', ''),
                        'document_type': doc.get('DocumentType', ''),
                        'document_version': doc.get('DocumentVersion', ''),
                        'platform_types': doc.get('PlatformTypes', []),
                        'tags': doc.get('Tags', [])
                    })
            
            return documents
        except Exception as e:
            st.error(f"Error listing documents: {str(e)}")
            return []
    
    def start_automation_execution(self, document_name: str,
                                   parameters: Optional[Dict[str, List[str]]] = None,
                                   target_parameter_name: Optional[str] = None,
                                   targets: Optional[List[Dict]] = None) -> Dict[str, Any]:
        """Start an automation execution"""
        try:
            params = {
                'DocumentName': document_name
            }
            
            if parameters:
                params['Parameters'] = parameters
            if target_parameter_name:
                params['TargetParameterName'] = target_parameter_name
            if targets:
                params['Targets'] = targets
            
            response = self.ssm.start_automation_execution(**params)
            
            return {
                'success': True,
                'execution_id': response['AutomationExecutionId'],
                'message': f'Automation started: {response["AutomationExecutionId"]}'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def describe_automation_executions(self, max_results: int = 50) -> List[Dict[str, Any]]:
        """List automation executions"""
        try:
            response = self.ssm.describe_automation_executions(
                MaxResults=max_results
            )
            
            executions = []
            for execution in response.get('AutomationExecutionMetadataList', []):
                executions.append({
                    'execution_id': execution['AutomationExecutionId'],
                    'document_name': execution['DocumentName'],
                    'document_version': execution.get('DocumentVersion', ''),
                    'execution_start_time': execution.get('ExecutionStartTime', datetime.now()).strftime('%Y-%m-%d %H:%M:%S'),
                    'execution_end_time': execution.get('ExecutionEndTime', datetime.now()).strftime('%Y-%m-%d %H:%M:%S') if execution.get('ExecutionEndTime') else 'Running',
                    'status': execution.get('AutomationExecutionStatus', 'Unknown')
                })
            
            return executions
        except Exception as e:
            st.error(f"Error listing automation executions: {str(e)}")
            return []
    
    # ============= RUN COMMAND =============
    
    def send_command(self, document_name: str, instance_ids: List[str],
                    parameters: Optional[Dict[str, List[str]]] = None,
                    comment: str = '') -> Dict[str, Any]:
        """Send a command to EC2 instances"""
        try:
            params = {
                'DocumentName': document_name,
                'InstanceIds': instance_ids
            }
            
            if parameters:
                params['Parameters'] = parameters
            if comment:
                params['Comment'] = comment
            
            response = self.ssm.send_command(**params)
            
            return {
                'success': True,
                'command_id': response['Command']['CommandId'],
                'message': f'Command sent: {response["Command"]["CommandId"]}'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def list_commands(self, max_results: int = 25) -> List[Dict[str, Any]]:
        """List Run Command executions"""
        try:
            response = self.ssm.list_commands(MaxResults=max_results)
            
            commands = []
            for cmd in response.get('Commands', []):
                commands.append({
                    'command_id': cmd['CommandId'],
                    'document_name': cmd['DocumentName'],
                    'comment': cmd.get('Comment', ''),
                    'requested_date_time': cmd.get('RequestedDateTime', datetime.now()).strftime('%Y-%m-%d %H:%M:%S'),
                    'status': cmd.get('Status', 'Unknown'),
                    'target_count': cmd.get('TargetCount', 0),
                    'completed_count': cmd.get('CompletedCount', 0)
                })
            
            return commands
        except Exception as e:
            st.error(f"Error listing commands: {str(e)}")
            return []
    
    def get_command_invocation(self, command_id: str, instance_id: str) -> Optional[Dict[str, Any]]:
        """Get command invocation details"""
        try:
            response = self.ssm.get_command_invocation(
                CommandId=command_id,
                InstanceId=instance_id
            )
            
            return {
                'command_id': response['CommandId'],
                'instance_id': response['InstanceId'],
                'status': response['Status'],
                'status_details': response.get('StatusDetails', ''),
                'standard_output': response.get('StandardOutputContent', ''),
                'standard_error': response.get('StandardErrorContent', '')
            }
        except Exception as e:
            st.error(f"Error getting command invocation: {str(e)}")
            return None
    
    # ============= SESSION MANAGER =============
    
    def start_session(self, target: str) -> Dict[str, Any]:
        """Start a Session Manager session (requires AWS CLI)"""
        try:
            response = self.ssm.start_session(Target=target)
            
            return {
                'success': True,
                'session_id': response['SessionId'],
                'token_value': response['TokenValue'],
                'stream_url': response['StreamUrl'],
                'message': f'Session started: {response["SessionId"]}'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def terminate_session(self, session_id: str) -> Dict[str, Any]:
        """Terminate a Session Manager session"""
        try:
            self.ssm.terminate_session(SessionId=session_id)
            return {
                'success': True,
                'message': f'Session {session_id} terminated'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def describe_sessions(self, state: str = 'Active') -> List[Dict[str, Any]]:
        """List Session Manager sessions"""
        try:
            response = self.ssm.describe_sessions(
                State=state
            )
            
            sessions = []
            for session in response.get('Sessions', []):
                sessions.append({
                    'session_id': session['SessionId'],
                    'target': session['Target'],
                    'status': session['Status'],
                    'start_date': session.get('StartDate', datetime.now()).strftime('%Y-%m-%d %H:%M:%S'),
                    'owner': session.get('Owner', '')
                })
            
            return sessions
        except Exception as e:
            st.error(f"Error describing sessions: {str(e)}")
            return []
    
    # ============= PATCH MANAGEMENT =============
    
    def describe_patch_baselines(self) -> List[Dict[str, Any]]:
        """List patch baselines"""
        try:
            response = self.ssm.describe_patch_baselines()
            
            baselines = []
            for baseline in response.get('BaselineIdentities', []):
                baselines.append({
                    'baseline_id': baseline['BaselineId'],
                    'baseline_name': baseline['BaselineName'],
                    'operating_system': baseline.get('OperatingSystem', ''),
                    'baseline_description': baseline.get('BaselineDescription', ''),
                    'default_baseline': baseline.get('DefaultBaseline', False)
                })
            
            return baselines
        except Exception as e:
            st.error(f"Error describing patch baselines: {str(e)}")
            return []
    
    def describe_available_patches(self, max_results: int = 50) -> List[Dict[str, Any]]:
        """List available patches"""
        try:
            response = self.ssm.describe_available_patches(
                MaxResults=max_results
            )
            
            patches = []
            for patch in response.get('Patches', []):
                patches.append({
                    'id': patch.get('Id', ''),
                    'title': patch.get('Title', ''),
                    'description': patch.get('Description', ''),
                    'release_date': patch.get('ReleaseDate', datetime.now()).strftime('%Y-%m-%d'),
                    'classification': patch.get('Classification', ''),
                    'severity': patch.get('Severity', ''),
                    'product': patch.get('Product', '')
                })
            
            return patches
        except Exception as e:
            st.error(f"Error describing available patches: {str(e)}")
            return []
    
    # ============= INVENTORY =============
    
    def get_inventory(self) -> List[Dict[str, Any]]:
        """Get inventory data"""
        try:
            response = self.ssm.get_inventory()
            
            inventory = []
            for entity in response.get('Entities', []):
                inventory.append({
                    'id': entity.get('Id', ''),
                    'data': entity.get('Data', {})
                })
            
            return inventory
        except Exception as e:
            st.error(f"Error getting inventory: {str(e)}")
            return []
    
    def list_resource_data_sync(self) -> List[Dict[str, Any]]:
        """List resource data sync configurations"""
        try:
            response = self.ssm.list_resource_data_sync()
            
            syncs = []
            for sync in response.get('ResourceDataSyncItems', []):
                syncs.append({
                    'sync_name': sync.get('SyncName', ''),
                    'sync_type': sync.get('SyncType', ''),
                    'last_sync_time': sync.get('LastSyncTime', datetime.now()).strftime('%Y-%m-%d %H:%M:%S') if sync.get('LastSyncTime') else 'Never',
                    'last_status': sync.get('LastStatus', ''),
                    's3_destination': sync.get('S3Destination', {})
                })
            
            return syncs
        except Exception as e:
            st.error(f"Error listing resource data sync: {str(e)}")
            return []
