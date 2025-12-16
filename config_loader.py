"""
Configuration Loader for Streamlit Cloud
Loads accounts from Streamlit secrets for zero-infrastructure deployment
"""

import streamlit as st
from typing import List, Optional
import logging

# Import from multi_account_manager
from multi_account_manager import AccountConfig

logger = logging.getLogger(__name__)

def load_accounts_from_streamlit_secrets() -> List[AccountConfig]:
    """
    Load account configurations from Streamlit secrets
    
    Expected format in Streamlit secrets:
    [accounts]
    [[accounts.list]]
    account_id = "123456789012"
    account_name = "Production"
    environment = "production"
    role_arn = "arn:aws:iam::123456789012:role/WAFAdvisorCrossAccountRole"
    external_id = "your-secure-random-string"
    regions = ["us-east-1", "us-west-2"]
    priority = "high"
    
    Returns:
        List of AccountConfig objects
    """
    accounts = []
    
    try:
        if not hasattr(st, 'secrets'):
            logger.warning("Streamlit secrets not available")
            return accounts
        
        if 'accounts' not in st.secrets:
            logger.info("No [accounts] section in secrets - multi-account disabled")
            return accounts
        
        accounts_config = st.secrets['accounts']
        
        # Handle both TOML formats
        if 'list' in accounts_config:
            accounts_list = accounts_config['list']
            # Convert single dict to list
            if isinstance(accounts_list, dict):
                accounts_list = [accounts_list]
        else:
            accounts_list = [accounts_config]
        
        # Parse each account
        for idx, acc in enumerate(accounts_list):
            try:
                account_id = acc.get('account_id', '')
                role_arn = acc.get('role_arn', '')
                
                if not account_id or not role_arn:
                    logger.warning(f"Skipping account {idx}: missing required fields")
                    continue
                
                # Handle regions (can be list or comma-separated string)
                regions_value = acc.get('regions', ['us-east-1'])
                if isinstance(regions_value, str):
                    regions = [r.strip() for r in regions_value.split(',')]
                else:
                    regions = list(regions_value)
                
                # Create account config
                account_config = AccountConfig(
                    account_id=account_id,
                    account_name=acc.get('account_name', f'Account-{account_id}'),
                    environment=acc.get('environment', 'production'),
                    role_arn=role_arn,
                    external_id=acc.get('external_id', ''),
                    regions=regions,
                    scan_schedule={'frequency': acc.get('scan_frequency', 'weekly')},
                    priority=acc.get('priority', 'medium'),
                    notification_email=acc.get('notification_email', ''),
                    tags={},
                    enabled=acc.get('enabled', True)
                )
                
                accounts.append(account_config)
                logger.info(f"Loaded: {account_config.account_name} ({account_config.account_id})")
                
            except Exception as e:
                logger.error(f"Failed to parse account {idx}: {e}")
                continue
        
        logger.info(f"Successfully loaded {len(accounts)} account(s)")
        return accounts
        
    except Exception as e:
        logger.error(f"Failed to load accounts: {e}")
        return accounts

def validate_secrets_configuration() -> tuple:
    """
    Validate Streamlit secrets configuration
    
    Returns:
        Tuple of (is_valid: bool, message: str)
    """
    try:
        missing = []
        
        # Check Anthropic API key
        if 'ANTHROPIC_API_KEY' not in st.secrets:
            missing.append('ANTHROPIC_API_KEY')
        
        # Check AWS credentials
        if 'aws' not in st.secrets:
            missing.append('[aws] section')
        else:
            aws = st.secrets['aws']
            if 'access_key_id' not in aws:
                missing.append('aws.access_key_id')
            if 'secret_access_key' not in aws:
                missing.append('aws.secret_access_key')
        
        # Check accounts (optional)
        if 'accounts' in st.secrets:
            accounts = load_accounts_from_streamlit_secrets()
            account_count = len(accounts)
        else:
            account_count = 0
        
        if missing:
            return False, f"Missing: {', '.join(missing)}"
        
        if account_count == 0:
            return True, "Single account mode (no multi-account configured)"
        else:
            return True, f"Multi-account mode: {account_count} account(s) configured"
            
    except Exception as e:
        return False, f"Configuration error: {str(e)}"

__all__ = [
    'load_accounts_from_streamlit_secrets',
    'validate_secrets_configuration'
]
