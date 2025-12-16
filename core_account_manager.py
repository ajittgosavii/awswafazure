"""
AWS Account Manager - Multi-Account Management with IAM Role Assumption
"""

import boto3
from botocore.exceptions import ClientError, BotoCoreError
import streamlit as st
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json

@dataclass
class AssumedRoleSession:
    """Represents an assumed role session"""
    account_id: str
    account_name: str
    credentials: Dict[str, str]
    expiration: datetime
    session: boto3.Session

class AWSAccountManager:
    """Manages multi-account AWS access via IAM role assumption"""
    
    def __init__(self, management_credentials: Dict[str, str]):
        """
        Initialize account manager
        
        Args:
            management_credentials: Dict with access_key_id, secret_access_key, region
        """
        self.management_credentials = management_credentials
        self._session_cache = {}
        self._sts_client = boto3.client(
            'sts',
            aws_access_key_id=management_credentials['access_key_id'],
            aws_secret_access_key=management_credentials['secret_access_key'],
            region_name=management_credentials.get('region', 'us-east-1')
        )
    
    def assume_role(
        self, 
        account_id: str,
        account_name: str,
        role_arn: str,
        session_name: Optional[str] = None,
        duration: int = 3600
    ) -> Optional[AssumedRoleSession]:
        """
        Assume role in target account, or use direct credentials if role_arn is empty
        
        Args:
            account_id: Target AWS account ID
            account_name: Friendly name for the account
            role_arn: ARN of role to assume (empty string = use management credentials directly)
            session_name: Optional session name
            duration: Session duration in seconds (default: 1 hour)
        
        Returns:
            AssumedRoleSession if successful, None otherwise
        """
        # Handle empty role_arn - use management credentials directly
        if not role_arn or role_arn.strip() == "":
            return self._create_direct_session(account_id, account_name)
        
        # Check cache first
        cache_key = f"{account_id}:{role_arn}"
        if cache_key in self._session_cache:
            cached_session = self._session_cache[cache_key]
            # Check if session is still valid (with 5 min buffer)
            if cached_session.expiration > datetime.now(timezone.utc) + timedelta(minutes=5):
                return cached_session
        
        try:
            # Generate session name
            if not session_name:
                session_name = f"CloudIDP-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
            
            # Assume role
            response = self._sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName=session_name,
                DurationSeconds=duration
            )
            
            credentials = response['Credentials']
            
            # Create boto3 session with assumed role credentials
            assumed_session = boto3.Session(
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken']
            )
            
            # Create session object
            role_session = AssumedRoleSession(
                account_id=account_id,
                account_name=account_name,
                credentials={
                    'AccessKeyId': credentials['AccessKeyId'],
                    'SecretAccessKey': credentials['SecretAccessKey'],
                    'SessionToken': credentials['SessionToken']
                },
                expiration=credentials['Expiration'],
                session=assumed_session
            )
            
            # Cache the session
            self._session_cache[cache_key] = role_session
            
            return role_session
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_msg = e.response['Error']['Message']
            st.error(f"❌ Failed to assume role in {account_name} ({account_id}): {error_code} - {error_msg}")
            return None
        except Exception as e:
            st.error(f"❌ Unexpected error assuming role in {account_name}: {str(e)}")
            return None
    
    def _create_direct_session(self, account_id: str, account_name: str) -> Optional[AssumedRoleSession]:
        """
        Create a session using management credentials directly (no role assumption)
        
        Args:
            account_id: Target AWS account ID
            account_name: Friendly name for the account
        
        Returns:
            AssumedRoleSession using management credentials
        """
        try:
            # Create session with management credentials
            direct_session = boto3.Session(
                aws_access_key_id=self.management_credentials['access_key_id'],
                aws_secret_access_key=self.management_credentials['secret_access_key'],
                region_name=self.management_credentials.get('region', 'us-east-1')
            )
            
            # Verify credentials work by getting caller identity
            sts = direct_session.client('sts')
            identity = sts.get_caller_identity()
            
            # Create a pseudo session object (long-lived, no expiration for direct creds)
            role_session = AssumedRoleSession(
                account_id=account_id,
                account_name=account_name,
                credentials={
                    'AccessKeyId': self.management_credentials['access_key_id'],
                    'SecretAccessKey': self.management_credentials['secret_access_key'],
                    'SessionToken': None  # No session token for direct credentials
                },
                expiration=datetime.now(timezone.utc) + timedelta(hours=24),  # Set far future expiration
                session=direct_session
            )
            
            st.success(f"✅ Connected to {account_name} using direct credentials (User: {identity['Arn'].split('/')[-1]})")
            
            return role_session
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_msg = e.response['Error']['Message']
            st.error(f"❌ Failed to connect to {account_name} with direct credentials: {error_code} - {error_msg}")
            return None
        except Exception as e:
            st.error(f"❌ Unexpected error connecting to {account_name}: {str(e)}")
            return None
    
    def get_account_identity(self, session: AssumedRoleSession) -> Optional[Dict]:
        """
        Get account identity information
        
        Args:
            session: Assumed role session
        
        Returns:
            Dict with account, arn, user_id
        """
        try:
            sts = session.session.client('sts')
            identity = sts.get_caller_identity()
            return {
                'account': identity['Account'],
                'arn': identity['Arn'],
                'user_id': identity['UserId']
            }
        except Exception as e:
            st.error(f"Error getting account identity: {e}")
            return None
    
    def test_account_connection(
        self, 
        account_id: str,
        account_name: str,
        role_arn: str
    ) -> Tuple[bool, Optional[str]]:
        """
        Test if we can successfully connect to an account
        
        Args:
            account_id: AWS account ID
            account_name: Account friendly name
            role_arn: Role ARN to assume
        
        Returns:
            Tuple of (success: bool, error_message: Optional[str])
        """
        try:
            session = self.assume_role(account_id, account_name, role_arn)
            if session:
                identity = self.get_account_identity(session)
                if identity:
                    return True, None
                else:
                    return False, "Could not verify account identity"
            else:
                return False, "Failed to assume role"
        except Exception as e:
            return False, str(e)
    
    def list_available_accounts(self) -> List[Dict]:
        """
        List all accounts available via AWS Organizations (if configured)
        
        Returns:
            List of account dictionaries
        """
        try:
            org_client = boto3.client(
                'organizations',
                aws_access_key_id=self.management_credentials['access_key_id'],
                aws_secret_access_key=self.management_credentials['secret_access_key'],
                region_name='us-east-1'  # Organizations is global
            )
            
            accounts = []
            paginator = org_client.get_paginator('list_accounts')
            
            for page in paginator.paginate():
                for account in page['Accounts']:
                    if account['Status'] == 'ACTIVE':
                        accounts.append({
                            'Id': account['Id'],
                            'Name': account['Name'],
                            'Email': account['Email'],
                            'Status': account['Status'],
                            'JoinedMethod': account.get('JoinedMethod', 'N/A')
                        })
            
            return accounts
            
        except ClientError as e:
            # Organizations might not be available
            if e.response['Error']['Code'] == 'AccessDeniedException':
                return []
            raise
        except Exception:
            return []
    
    def clear_session_cache(self):
        """Clear all cached sessions (useful for debugging or force refresh)"""
        self._session_cache = {}
    
    def get_cached_session_count(self) -> int:
        """Get number of cached sessions"""
        return len(self._session_cache)
    
    @staticmethod
    def get_configured_account_names() -> List[str]:
        """Get list of configured account names from settings"""
        from config_settings import AppConfig
        accounts = AppConfig.load_aws_accounts()
        return [acc.account_name for acc in accounts]
    
    def get_session(self, account_name: str) -> Optional[boto3.Session]:
        """
        Get boto3 session for an account by name
        
        Args:
            account_name: Name of the account
            
        Returns:
            boto3.Session or None
        """
        from config_settings import AppConfig
        accounts = AppConfig.load_aws_accounts()
        
        for account in accounts:
            if account.account_name == account_name:
                assumed_session = self.assume_role(
                    account_id=account.account_id,
                    account_name=account.account_name,
                    role_arn=account.role_arn
                )
                if assumed_session:
                    return assumed_session.session
        
        return None
    
    def get_session_with_region(self, account_name: str, region: str) -> Optional[boto3.Session]:
        """
        Get boto3 session for an account with specific region
        
        Args:
            account_name: Name of the account
            region: AWS region (e.g., 'us-east-2')
            
        Returns:
            boto3.Session configured for the specified region, or None
        """
        from config_settings import AppConfig
        accounts = AppConfig.load_aws_accounts()
        
        for account in accounts:
            if account.account_name == account_name:
                assumed_session = self.assume_role(
                    account_id=account.account_id,
                    account_name=account.account_name,
                    role_arn=account.role_arn
                )
                if assumed_session:
                    # Create a new session with the specified region
                    return boto3.Session(
                        aws_access_key_id=assumed_session.credentials['AccessKeyId'],
                        aws_secret_access_key=assumed_session.credentials['SecretAccessKey'],
                        aws_session_token=assumed_session.credentials['SessionToken'],
                        region_name=region
                    )
        
        return None

@st.cache_resource(ttl=300)
def get_account_manager() -> Optional[AWSAccountManager]:
    """
    Get cached account manager instance
    
    Returns:
        AWSAccountManager instance or None if not configured
    """
    from config_settings import AppConfig
    
    credentials = AppConfig.get_management_credentials()
    if not credentials:
        return None
    
    return AWSAccountManager(credentials)

def get_account_names() -> List[str]:
    """
    Get list of configured AWS account names
    
    Returns:
        List of account names
    """
    from config_settings import AppConfig
    accounts = AppConfig.load_aws_accounts()
    return [acc.account_name for acc in accounts]