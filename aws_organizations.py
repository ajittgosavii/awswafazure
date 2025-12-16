"""
AWS Organizations Integration - Account Provisioning & Management
Supports account creation, OU management, SCP policies, and organizational governance
"""

import streamlit as st
import time
import json
from typing import Dict, List, Optional, Any
from datetime import datetime
from core_account_manager import get_account_manager

class AWSOrganizationsManager:
    """AWS Organizations Management for Account Provisioning"""
    
    def __init__(self, session):
        """Initialize Organizations manager with boto3 session"""
        self.org_client = session.client('organizations')
        self.sts_client = session.client('sts')
    
    # ============= ORGANIZATION INFO =============
    
    def get_organization(self) -> Optional[Dict[str, Any]]:
        """Get organization details"""
        try:
            response = self.org_client.describe_organization()
            org = response['Organization']
            
            return {
                'id': org['Id'],
                'arn': org['Arn'],
                'master_account_id': org['MasterAccountId'],
                'master_account_email': org['MasterAccountEmail'],
                'feature_set': org.get('FeatureSet', 'CONSOLIDATED_BILLING'),
                'available_policy_types': org.get('AvailablePolicyTypes', [])
            }
        except Exception as e:
            st.error(f"Error getting organization: {str(e)}")
            return None
    
    # ============= ACCOUNT OPERATIONS =============
    
    def list_accounts(self) -> List[Dict[str, Any]]:
        """List all accounts in the organization"""
        try:
            accounts = []
            paginator = self.org_client.get_paginator('list_accounts')
            
            for page in paginator.paginate():
                for account in page['Accounts']:
                    accounts.append({
                        'id': account['Id'],
                        'arn': account['Arn'],
                        'email': account['Email'],
                        'name': account['Name'],
                        'status': account['Status'],
                        'joined_method': account['JoinedMethod'],
                        'joined_timestamp': account['JoinedTimestamp'].strftime('%Y-%m-%d %H:%M:%S')
                    })
            
            return accounts
        except Exception as e:
            st.error(f"Error listing accounts: {str(e)}")
            return []
    
    def create_account(self, account_name: str, email: str, 
                      ou_id: Optional[str] = None,
                      iam_user_access: bool = False,
                      role_name: str = 'OrganizationAccountAccessRole',
                      tags: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """
        Create a new AWS account in the organization
        
        Args:
            account_name: Name for the new account
            email: Unique email address for the account
            ou_id: Optional OU ID to place the account
            iam_user_access: Allow IAM users to access billing
            role_name: Cross-account access role name
            tags: Tags to apply to the account
        """
        try:
            # Create account
            response = self.org_client.create_account(
                Email=email,
                AccountName=account_name,
                RoleName=role_name,
                IamUserAccessToBilling='ALLOW' if iam_user_access else 'DENY'
            )
            
            request_id = response['CreateAccountStatus']['Id']
            
            # Wait for account creation (can take several minutes)
            st.info(f"Account creation initiated. Request ID: {request_id}")
            st.info("This may take 3-5 minutes. Checking status...")
            
            max_attempts = 60
            attempt = 0
            
            while attempt < max_attempts:
                status_response = self.org_client.describe_create_account_status(
                    CreateAccountRequestId=request_id
                )
                status = status_response['CreateAccountStatus']['State']
                
                if status == 'SUCCEEDED':
                    account_id = status_response['CreateAccountStatus']['AccountId']
                    
                    # Move to OU if specified
                    if ou_id:
                        self.move_account(account_id, ou_id)
                    
                    # Tag account if tags provided
                    if tags:
                        self.tag_account(account_id, tags)
                    
                    return {
                        'success': True,
                        'account_id': account_id,
                        'account_name': account_name,
                        'email': email,
                        'request_id': request_id,
                        'message': f'Account {account_id} created successfully'
                    }
                
                elif status == 'FAILED':
                    failure_reason = status_response['CreateAccountStatus'].get('FailureReason', 'Unknown')
                    return {
                        'success': False,
                        'error': f'Account creation failed: {failure_reason}'
                    }
                
                time.sleep(5)
                attempt += 1
            
            return {
                'success': False,
                'error': 'Account creation timeout. Check AWS Console for status.'
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def close_account(self, account_id: str) -> Dict[str, Any]:
        """Close an AWS account (90-day post-closure recovery period)"""
        try:
            self.org_client.close_account(AccountId=account_id)
            return {
                'success': True,
                'message': f'Account {account_id} closure initiated. 90-day recovery period.'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def get_account_info(self, account_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about an account"""
        try:
            response = self.org_client.describe_account(AccountId=account_id)
            account = response['Account']
            
            return {
                'id': account['Id'],
                'arn': account['Arn'],
                'email': account['Email'],
                'name': account['Name'],
                'status': account['Status'],
                'joined_method': account['JoinedMethod'],
                'joined_timestamp': account['JoinedTimestamp'].strftime('%Y-%m-%d %H:%M:%S')
            }
        except Exception as e:
            st.error(f"Error getting account info: {str(e)}")
            return None
    
    # ============= ORGANIZATIONAL UNITS (OUs) =============
    
    def list_ous(self, parent_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """List organizational units"""
        try:
            if parent_id is None:
                # Get root ID
                roots = self.org_client.list_roots()['Roots']
                if not roots:
                    return []
                parent_id = roots[0]['Id']
            
            ous = []
            paginator = self.org_client.get_paginator('list_organizational_units_for_parent')
            
            for page in paginator.paginate(ParentId=parent_id):
                for ou in page['OrganizationalUnits']:
                    ous.append({
                        'id': ou['Id'],
                        'arn': ou['Arn'],
                        'name': ou['Name']
                    })
            
            return ous
        except Exception as e:
            st.error(f"Error listing OUs: {str(e)}")
            return []
    
    def create_ou(self, parent_id: str, name: str) -> Dict[str, Any]:
        """Create an organizational unit"""
        try:
            response = self.org_client.create_organizational_unit(
                ParentId=parent_id,
                Name=name
            )
            
            ou = response['OrganizationalUnit']
            return {
                'success': True,
                'ou_id': ou['Id'],
                'ou_arn': ou['Arn'],
                'message': f'OU "{name}" created'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def delete_ou(self, ou_id: str) -> Dict[str, Any]:
        """Delete an organizational unit (must be empty)"""
        try:
            self.org_client.delete_organizational_unit(
                OrganizationalUnitId=ou_id
            )
            return {
                'success': True,
                'message': f'OU {ou_id} deleted'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def move_account(self, account_id: str, destination_ou_id: str) -> Dict[str, Any]:
        """Move an account to a different OU"""
        try:
            # Get current parent
            parents = self.org_client.list_parents(ChildId=account_id)['Parents']
            if not parents:
                return {'success': False, 'error': 'Cannot find current parent'}
            
            source_parent_id = parents[0]['Id']
            
            # Move account
            self.org_client.move_account(
                AccountId=account_id,
                SourceParentId=source_parent_id,
                DestinationParentId=destination_ou_id
            )
            
            return {
                'success': True,
                'message': f'Account {account_id} moved to {destination_ou_id}'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def list_accounts_for_ou(self, ou_id: str) -> List[Dict[str, Any]]:
        """List accounts in a specific OU"""
        try:
            accounts = []
            paginator = self.org_client.get_paginator('list_accounts_for_parent')
            
            for page in paginator.paginate(ParentId=ou_id):
                for account in page['Accounts']:
                    accounts.append({
                        'id': account['Id'],
                        'name': account['Name'],
                        'email': account['Email'],
                        'status': account['Status']
                    })
            
            return accounts
        except Exception as e:
            st.error(f"Error listing accounts for OU: {str(e)}")
            return []
    
    # ============= SERVICE CONTROL POLICIES (SCPs) =============
    
    def list_policies(self, policy_type: str = 'SERVICE_CONTROL_POLICY') -> List[Dict[str, Any]]:
        """List policies of a specific type"""
        try:
            policies = []
            paginator = self.org_client.get_paginator('list_policies')
            
            for page in paginator.paginate(Filter=policy_type):
                for policy in page['Policies']:
                    policies.append({
                        'id': policy['Id'],
                        'arn': policy['Arn'],
                        'name': policy['Name'],
                        'description': policy.get('Description', ''),
                        'type': policy['Type'],
                        'aws_managed': policy['AwsManaged']
                    })
            
            return policies
        except Exception as e:
            st.error(f"Error listing policies: {str(e)}")
            return []
    
    def create_policy(self, name: str, description: str, 
                     content: Dict[str, Any],
                     policy_type: str = 'SERVICE_CONTROL_POLICY') -> Dict[str, Any]:
        """Create a service control policy"""
        try:
            response = self.org_client.create_policy(
                Content=json.dumps(content),
                Description=description,
                Name=name,
                Type=policy_type
            )
            
            policy = response['Policy']['PolicySummary']
            return {
                'success': True,
                'policy_id': policy['Id'],
                'policy_arn': policy['Arn'],
                'message': f'Policy "{name}" created'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def attach_policy(self, policy_id: str, target_id: str) -> Dict[str, Any]:
        """Attach a policy to an account or OU"""
        try:
            self.org_client.attach_policy(
                PolicyId=policy_id,
                TargetId=target_id
            )
            return {
                'success': True,
                'message': f'Policy {policy_id} attached to {target_id}'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def detach_policy(self, policy_id: str, target_id: str) -> Dict[str, Any]:
        """Detach a policy from an account or OU"""
        try:
            self.org_client.detach_policy(
                PolicyId=policy_id,
                TargetId=target_id
            )
            return {
                'success': True,
                'message': f'Policy {policy_id} detached from {target_id}'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def get_policy_content(self, policy_id: str) -> Optional[Dict[str, Any]]:
        """Get the content of a policy"""
        try:
            response = self.org_client.describe_policy(PolicyId=policy_id)
            content = json.loads(response['Policy']['Content'])
            return content
        except Exception as e:
            st.error(f"Error getting policy content: {str(e)}")
            return None
    
    # ============= TAGS =============
    
    def tag_account(self, account_id: str, tags: Dict[str, str]) -> Dict[str, Any]:
        """Add tags to an account"""
        try:
            tag_list = [{'Key': k, 'Value': v} for k, v in tags.items()]
            self.org_client.tag_resource(
                ResourceId=account_id,
                Tags=tag_list
            )
            return {
                'success': True,
                'message': f'Tags added to account {account_id}'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def list_tags(self, resource_id: str) -> Dict[str, str]:
        """List tags for a resource"""
        try:
            response = self.org_client.list_tags_for_resource(
                ResourceId=resource_id
            )
            return {tag['Key']: tag['Value'] for tag in response.get('Tags', [])}
        except Exception as e:
            st.error(f"Error listing tags: {str(e)}")
            return {}
    
    # ============= DELEGATED ADMINISTRATORS =============
    
    def register_delegated_administrator(self, account_id: str, 
                                        service_principal: str) -> Dict[str, Any]:
        """Register an account as a delegated administrator for a service"""
        try:
            self.org_client.register_delegated_administrator(
                AccountId=account_id,
                ServicePrincipal=service_principal
            )
            return {
                'success': True,
                'message': f'Account {account_id} registered as delegated admin for {service_principal}'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def list_delegated_administrators(self, service_principal: Optional[str] = None) -> List[Dict[str, Any]]:
        """List delegated administrators"""
        try:
            params = {}
            if service_principal:
                params['ServicePrincipal'] = service_principal
            
            response = self.org_client.list_delegated_administrators(**params)
            
            return [{
                'id': admin['Id'],
                'arn': admin['Arn'],
                'email': admin['Email'],
                'name': admin['Name'],
                'status': admin['Status'],
                'delegation_enabled_date': admin.get('DelegationEnabledDate', '').strftime('%Y-%m-%d') if admin.get('DelegationEnabledDate') else ''
            } for admin in response.get('DelegatedAdministrators', [])]
        except Exception as e:
            st.error(f"Error listing delegated administrators: {str(e)}")
            return []
