"""
AWS IAM Identity Center (SSO) Integration
Supports SSO instance management, permission sets, and account assignments
"""

import streamlit as st
from typing import Dict, List, Optional, Any
from core_account_manager import get_account_manager

class IAMIdentityCenterManager:
    """AWS IAM Identity Center (formerly AWS SSO) Management"""
    
    def __init__(self, session):
        """Initialize IAM Identity Center manager with boto3 session"""
        self.sso_admin = session.client('sso-admin')
        self.identitystore = session.client('identitystore')
        self.organizations = session.client('organizations')
    
    # ============= SSO INSTANCE =============
    
    def list_instances(self) -> List[Dict[str, Any]]:
        """List SSO instances"""
        try:
            response = self.sso_admin.list_instances()
            
            instances = []
            for instance in response.get('Instances', []):
                instances.append({
                    'instance_arn': instance['InstanceArn'],
                    'identity_store_id': instance['IdentityStoreId']
                })
            
            return instances
        except Exception as e:
            st.error(f"Error listing SSO instances: {str(e)}")
            return []
    
    # ============= PERMISSION SETS =============
    
    def list_permission_sets(self, instance_arn: str) -> List[Dict[str, Any]]:
        """List permission sets"""
        try:
            permission_sets = []
            paginator = self.sso_admin.get_paginator('list_permission_sets')
            
            for page in paginator.paginate(InstanceArn=instance_arn):
                for ps_arn in page['PermissionSets']:
                    # Get permission set details
                    details = self.sso_admin.describe_permission_set(
                        InstanceArn=instance_arn,
                        PermissionSetArn=ps_arn
                    )
                    
                    ps = details['PermissionSet']
                    permission_sets.append({
                        'arn': ps['PermissionSetArn'],
                        'name': ps['Name'],
                        'description': ps.get('Description', ''),
                        'session_duration': ps.get('SessionDuration', ''),
                        'created_date': ps['CreatedDate'].strftime('%Y-%m-%d %H:%M:%S')
                    })
            
            return permission_sets
        except Exception as e:
            st.error(f"Error listing permission sets: {str(e)}")
            return []
    
    def create_permission_set(self, instance_arn: str, name: str,
                             description: str = '',
                             session_duration: str = 'PT1H') -> Dict[str, Any]:
        """
        Create a permission set
        
        Args:
            session_duration: ISO-8601 format (e.g., PT1H for 1 hour, PT12H for 12 hours)
        """
        try:
            response = self.sso_admin.create_permission_set(
                InstanceArn=instance_arn,
                Name=name,
                Description=description,
                SessionDuration=session_duration
            )
            
            return {
                'success': True,
                'permission_set_arn': response['PermissionSet']['PermissionSetArn'],
                'message': f'Permission set {name} created'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def delete_permission_set(self, instance_arn: str, 
                             permission_set_arn: str) -> Dict[str, Any]:
        """Delete a permission set"""
        try:
            self.sso_admin.delete_permission_set(
                InstanceArn=instance_arn,
                PermissionSetArn=permission_set_arn
            )
            
            return {
                'success': True,
                'message': 'Permission set deleted'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def attach_managed_policy_to_permission_set(self, instance_arn: str,
                                               permission_set_arn: str,
                                               managed_policy_arn: str) -> Dict[str, Any]:
        """Attach AWS managed policy to permission set"""
        try:
            self.sso_admin.attach_managed_policy_to_permission_set(
                InstanceArn=instance_arn,
                PermissionSetArn=permission_set_arn,
                ManagedPolicyArn=managed_policy_arn
            )
            
            return {
                'success': True,
                'message': f'Policy {managed_policy_arn} attached'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def put_inline_policy_to_permission_set(self, instance_arn: str,
                                           permission_set_arn: str,
                                           inline_policy: str) -> Dict[str, Any]:
        """Add inline policy to permission set"""
        try:
            self.sso_admin.put_inline_policy_to_permission_set(
                InstanceArn=instance_arn,
                PermissionSetArn=permission_set_arn,
                InlinePolicy=inline_policy
            )
            
            return {
                'success': True,
                'message': 'Inline policy attached'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def list_managed_policies_in_permission_set(self, instance_arn: str,
                                                permission_set_arn: str) -> List[str]:
        """List managed policies attached to a permission set"""
        try:
            response = self.sso_admin.list_managed_policies_in_permission_set(
                InstanceArn=instance_arn,
                PermissionSetArn=permission_set_arn
            )
            
            return [p['Arn'] for p in response.get('AttachedManagedPolicies', [])]
        except Exception as e:
            st.error(f"Error listing managed policies: {str(e)}")
            return []
    
    # ============= ACCOUNT ASSIGNMENTS =============
    
    def list_account_assignments(self, instance_arn: str, account_id: str,
                                permission_set_arn: str) -> List[Dict[str, Any]]:
        """List account assignments for a permission set"""
        try:
            assignments = []
            paginator = self.sso_admin.get_paginator('list_account_assignments')
            
            for page in paginator.paginate(
                InstanceArn=instance_arn,
                AccountId=account_id,
                PermissionSetArn=permission_set_arn
            ):
                for assignment in page['AccountAssignments']:
                    assignments.append({
                        'principal_type': assignment['PrincipalType'],
                        'principal_id': assignment['PrincipalId'],
                        'permission_set_arn': assignment['PermissionSetArn'],
                        'account_id': assignment['AccountId']
                    })
            
            return assignments
        except Exception as e:
            st.error(f"Error listing account assignments: {str(e)}")
            return []
    
    def create_account_assignment(self, instance_arn: str, account_id: str,
                                 permission_set_arn: str, principal_type: str,
                                 principal_id: str) -> Dict[str, Any]:
        """
        Create account assignment
        
        Args:
            principal_type: 'USER' or 'GROUP'
            principal_id: User or group ID from Identity Store
        """
        try:
            response = self.sso_admin.create_account_assignment(
                InstanceArn=instance_arn,
                TargetId=account_id,
                TargetType='AWS_ACCOUNT',
                PermissionSetArn=permission_set_arn,
                PrincipalType=principal_type,
                PrincipalId=principal_id
            )
            
            return {
                'success': True,
                'request_id': response['AccountAssignmentCreationStatus']['RequestId'],
                'message': 'Account assignment created'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def delete_account_assignment(self, instance_arn: str, account_id: str,
                                 permission_set_arn: str, principal_type: str,
                                 principal_id: str) -> Dict[str, Any]:
        """Delete account assignment"""
        try:
            response = self.sso_admin.delete_account_assignment(
                InstanceArn=instance_arn,
                TargetId=account_id,
                TargetType='AWS_ACCOUNT',
                PermissionSetArn=permission_set_arn,
                PrincipalType=principal_type,
                PrincipalId=principal_id
            )
            
            return {
                'success': True,
                'request_id': response['AccountAssignmentDeletionStatus']['RequestId'],
                'message': 'Account assignment deleted'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    # ============= IDENTITY STORE =============
    
    def list_users(self, identity_store_id: str) -> List[Dict[str, Any]]:
        """List users in the identity store"""
        try:
            users = []
            paginator = self.identitystore.get_paginator('list_users')
            
            for page in paginator.paginate(IdentityStoreId=identity_store_id):
                for user in page['Users']:
                    users.append({
                        'user_id': user['UserId'],
                        'user_name': user['UserName'],
                        'display_name': user.get('DisplayName', ''),
                        'emails': [e['Value'] for e in user.get('Emails', [])]
                    })
            
            return users
        except Exception as e:
            st.error(f"Error listing users: {str(e)}")
            return []
    
    def list_groups(self, identity_store_id: str) -> List[Dict[str, Any]]:
        """List groups in the identity store"""
        try:
            groups = []
            paginator = self.identitystore.get_paginator('list_groups')
            
            for page in paginator.paginate(IdentityStoreId=identity_store_id):
                for group in page['Groups']:
                    groups.append({
                        'group_id': group['GroupId'],
                        'display_name': group['DisplayName'],
                        'description': group.get('Description', '')
                    })
            
            return groups
        except Exception as e:
            st.error(f"Error listing groups: {str(e)}")
            return []
    
    def create_user(self, identity_store_id: str, user_name: str,
                   display_name: str, email: str,
                   given_name: str, family_name: str) -> Dict[str, Any]:
        """Create a user in the identity store"""
        try:
            response = self.identitystore.create_user(
                IdentityStoreId=identity_store_id,
                UserName=user_name,
                DisplayName=display_name,
                Name={
                    'GivenName': given_name,
                    'FamilyName': family_name
                },
                Emails=[
                    {
                        'Value': email,
                        'Type': 'work',
                        'Primary': True
                    }
                ]
            )
            
            return {
                'success': True,
                'user_id': response['UserId'],
                'message': f'User {user_name} created'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def create_group(self, identity_store_id: str, display_name: str,
                    description: str = '') -> Dict[str, Any]:
        """Create a group in the identity store"""
        try:
            response = self.identitystore.create_group(
                IdentityStoreId=identity_store_id,
                DisplayName=display_name,
                Description=description
            )
            
            return {
                'success': True,
                'group_id': response['GroupId'],
                'message': f'Group {display_name} created'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def add_user_to_group(self, identity_store_id: str, group_id: str,
                         user_id: str) -> Dict[str, Any]:
        """Add a user to a group"""
        try:
            response = self.identitystore.create_group_membership(
                IdentityStoreId=identity_store_id,
                GroupId=group_id,
                MemberId={'UserId': user_id}
            )
            
            return {
                'success': True,
                'membership_id': response['MembershipId'],
                'message': 'User added to group'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    # ============= PROVISIONING =============
    
    def provision_permission_set(self, instance_arn: str,
                                permission_set_arn: str,
                                target_type: str = 'ALL_PROVISIONED_ACCOUNTS') -> Dict[str, Any]:
        """Provision permission set to accounts"""
        try:
            response = self.sso_admin.provision_permission_set(
                InstanceArn=instance_arn,
                PermissionSetArn=permission_set_arn,
                TargetType=target_type
            )
            
            return {
                'success': True,
                'request_id': response['PermissionSetProvisioningStatus']['RequestId'],
                'message': 'Permission set provisioning initiated'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
