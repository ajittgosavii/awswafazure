"""
Multi-Account Manager Module
Handles cross-account role assumption, account registry, and parallel scanning orchestration
"""

import boto3
import yaml
import json
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging

# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class AccountConfig:
    """Configuration for a single AWS account"""
    account_id: str
    account_name: str
    environment: str
    role_arn: str
    external_id: str
    regions: List[str]
    scan_schedule: Dict
    priority: str
    notification_email: str
    tags: Dict[str, str] = field(default_factory=dict)
    enabled: bool = True

@dataclass
class AccountSession:
    """Represents an active session for an account"""
    account_id: str
    account_name: str
    session: boto3.Session
    credentials: Dict
    assumed_at: datetime
    regions: List[str]
    
@dataclass
class MultiAccountScanResult:
    """Results from multi-account scanning"""
    total_accounts: int
    successful_accounts: List[str]
    failed_accounts: Dict[str, str]  # account_id -> error
    scan_results: Dict[str, any]  # account_id -> LandscapeAssessment
    total_duration_seconds: float
    aggregated_findings: List[any]
    aggregated_inventory: Dict

# ============================================================================
# MULTI-ACCOUNT MANAGER CLASS
# ============================================================================

class MultiAccountManager:
    """
    Manages multi-account AWS scanning operations
    - Cross-account role assumption
    - Account registry management
    - Parallel account scanning
    - Result aggregation
    """
    
    def __init__(self, hub_session: boto3.Session, config_path: Optional[str] = None):
        """
        Initialize multi-account manager
        
        Args:
            hub_session: Boto3 session in the hub account
            config_path: Path to accounts configuration YAML
        """
        self.hub_session = hub_session
        self.accounts: List[AccountConfig] = []
        self.active_sessions: Dict[str, AccountSession] = {}
        self.logger = logging.getLogger(__name__)
        
        # Get hub account ID
        try:
            sts = hub_session.client('sts')
            self.hub_account_id = sts.get_caller_identity()['Account']
        except Exception as e:
            self.logger.error(f"Failed to get hub account ID: {e}")
            self.hub_account_id = None
        
        # Load accounts from config if provided
        if config_path:
            self.load_accounts_from_config(config_path)
    
    def load_accounts_from_config(self, config_path: str) -> int:
        """
        Load account configurations from YAML file
        
        Args:
            config_path: Path to accounts.yaml file
            
        Returns:
            Number of accounts loaded
        """
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            
            self.accounts = []
            for acc in config.get('accounts', []):
                # Get external ID from Secrets Manager if it's a secret reference
                external_id = acc.get('external_id', '')
                if acc.get('external_id_secret'):
                    external_id = self._get_secret(acc['external_id_secret'])
                
                account_config = AccountConfig(
                    account_id=acc['account_id'],
                    account_name=acc['account_name'],
                    environment=acc['environment'],
                    role_arn=acc['role_arn'],
                    external_id=external_id,
                    regions=acc.get('regions', ['us-east-1']),
                    scan_schedule=acc.get('scan_schedule', {}),
                    priority=acc.get('priority', 'medium'),
                    notification_email=acc.get('notification_email', ''),
                    tags=acc.get('tags', {}),
                    enabled=acc.get('enabled', True)
                )
                self.accounts.append(account_config)
            
            self.logger.info(f"Loaded {len(self.accounts)} accounts from configuration")
            return len(self.accounts)
            
        except Exception as e:
            self.logger.error(f"Failed to load accounts from config: {e}")
            return 0
    
    def _get_secret(self, secret_name: str) -> str:
        """Get secret value from AWS Secrets Manager"""
        try:
            secretsmanager = self.hub_session.client('secretsmanager')
            response = secretsmanager.get_secret_value(SecretId=secret_name)
            
            if 'SecretString' in response:
                return response['SecretString']
            else:
                return response['SecretBinary'].decode('utf-8')
                
        except Exception as e:
            self.logger.error(f"Failed to get secret {secret_name}: {e}")
            return ""
    
    def assume_role(self, account_config: AccountConfig, 
                   session_name: Optional[str] = None) -> Optional[AccountSession]:
        """
        Assume cross-account role and create session
        
        Args:
            account_config: Account configuration
            session_name: Optional session name (default: WAFAdvisor-{timestamp})
            
        Returns:
            AccountSession if successful, None otherwise
        """
        if not session_name:
            session_name = f"WAFAdvisor-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        
        try:
            sts = self.hub_session.client('sts')
            
            # Prepare assume role parameters
            assume_params = {
                'RoleArn': account_config.role_arn,
                'RoleSessionName': session_name,
                'DurationSeconds': 3600  # 1 hour
            }
            
            # Add external ID if provided
            if account_config.external_id:
                assume_params['ExternalId'] = account_config.external_id
            
            # Assume the role
            response = sts.assume_role(**assume_params)
            credentials = response['Credentials']
            
            # Create boto3 session with assumed role credentials
            assumed_session = boto3.Session(
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken']
            )
            
            # Verify the session by getting caller identity
            assumed_sts = assumed_session.client('sts')
            identity = assumed_sts.get_caller_identity()
            
            self.logger.info(
                f"Successfully assumed role in account {account_config.account_id} "
                f"({account_config.account_name})"
            )
            
            # Create and store account session
            account_session = AccountSession(
                account_id=account_config.account_id,
                account_name=account_config.account_name,
                session=assumed_session,
                credentials={
                    'AccessKeyId': credentials['AccessKeyId'],
                    'SecretAccessKey': credentials['SecretAccessKey'],
                    'SessionToken': credentials['SessionToken'],
                    'Expiration': credentials['Expiration']
                },
                assumed_at=datetime.now(),
                regions=account_config.regions
            )
            
            self.active_sessions[account_config.account_id] = account_session
            return account_session
            
        except Exception as e:
            self.logger.error(
                f"Failed to assume role for account {account_config.account_id}: {e}"
            )
            return None
    
    def get_enabled_accounts(self, environments: Optional[List[str]] = None,
                           priorities: Optional[List[str]] = None) -> List[AccountConfig]:
        """
        Get list of enabled accounts, optionally filtered
        
        Args:
            environments: Filter by environments (e.g., ['production', 'staging'])
            priorities: Filter by priorities (e.g., ['high', 'critical'])
            
        Returns:
            List of filtered AccountConfig objects
        """
        filtered = [acc for acc in self.accounts if acc.enabled]
        
        if environments:
            filtered = [acc for acc in filtered if acc.environment in environments]
        
        if priorities:
            filtered = [acc for acc in filtered if acc.priority in priorities]
        
        return filtered
    
    def scan_single_account(self, account_config: AccountConfig,
                          scanner_class, progress_callback=None) -> Tuple[str, any, Optional[str]]:
        """
        Scan a single account across all its configured regions
        
        Args:
            account_config: Account configuration
            scanner_class: Scanner class to use (e.g., AWSLandscapeScanner)
            progress_callback: Optional callback for progress updates
            
        Returns:
            Tuple of (account_id, assessment_result, error_message)
        """
        try:
            # Assume role
            account_session = self.assume_role(account_config)
            if not account_session:
                return (account_config.account_id, None, "Failed to assume role")
            
            # Create scanner with assumed session
            scanner = scanner_class(account_session.session)
            
            # Create progress callback for this account
            def account_progress(progress, message):
                if progress_callback:
                    progress_callback(
                        account_config.account_id,
                        account_config.account_name,
                        progress,
                        message
                    )
            
            # Run scan
            assessment = scanner.run_scan(
                regions=account_config.regions,
                progress_callback=account_progress
            )
            
            # Add account metadata to assessment
            assessment.account_name = account_config.account_name
            assessment.environment = account_config.environment
            
            self.logger.info(
                f"Successfully scanned account {account_config.account_id} "
                f"({account_config.account_name})"
            )
            
            return (account_config.account_id, assessment, None)
            
        except Exception as e:
            error_msg = str(e)
            self.logger.error(
                f"Failed to scan account {account_config.account_id}: {error_msg}"
            )
            return (account_config.account_id, None, error_msg)
    
    def scan_all_accounts(self, scanner_class, 
                        max_workers: int = 5,
                        environments: Optional[List[str]] = None,
                        priorities: Optional[List[str]] = None,
                        progress_callback=None) -> MultiAccountScanResult:
        """
        Scan all enabled accounts in parallel
        
        Args:
            scanner_class: Scanner class to use (e.g., AWSLandscapeScanner)
            max_workers: Maximum number of accounts to scan in parallel
            environments: Filter by environments
            priorities: Filter by priorities
            progress_callback: Optional callback for progress updates
            
        Returns:
            MultiAccountScanResult with aggregated results
        """
        start_time = datetime.now()
        
        # Get accounts to scan
        accounts_to_scan = self.get_enabled_accounts(environments, priorities)
        
        if not accounts_to_scan:
            self.logger.warning("No accounts to scan")
            return MultiAccountScanResult(
                total_accounts=0,
                successful_accounts=[],
                failed_accounts={},
                scan_results={},
                total_duration_seconds=0,
                aggregated_findings=[],
                aggregated_inventory={}
            )
        
        self.logger.info(f"Starting parallel scan of {len(accounts_to_scan)} accounts")
        
        successful_accounts = []
        failed_accounts = {}
        scan_results = {}
        
        # Parallel scanning with ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all scan tasks
            future_to_account = {
                executor.submit(
                    self.scan_single_account,
                    account,
                    scanner_class,
                    progress_callback
                ): account for account in accounts_to_scan
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_account):
                account = future_to_account[future]
                try:
                    account_id, assessment, error = future.result(timeout=1800)  # 30 min timeout
                    
                    if error:
                        failed_accounts[account_id] = error
                    else:
                        successful_accounts.append(account_id)
                        scan_results[account_id] = assessment
                        
                except Exception as e:
                    failed_accounts[account.account_id] = str(e)
        
        # Aggregate results
        aggregated_findings = []
        aggregated_inventory = {}
        
        for account_id, assessment in scan_results.items():
            # Aggregate findings
            for finding in assessment.findings:
                finding.account_id = account_id
                aggregated_findings.append(finding)
            
            # Aggregate inventory (sum up resources)
            if not aggregated_inventory:
                aggregated_inventory = vars(assessment.inventory).copy()
            else:
                for key, value in vars(assessment.inventory).items():
                    if isinstance(value, (int, float)):
                        aggregated_inventory[key] = aggregated_inventory.get(key, 0) + value
        
        duration = (datetime.now() - start_time).total_seconds()
        
        self.logger.info(
            f"Multi-account scan completed: "
            f"{len(successful_accounts)} successful, "
            f"{len(failed_accounts)} failed, "
            f"Duration: {duration:.1f}s"
        )
        
        return MultiAccountScanResult(
            total_accounts=len(accounts_to_scan),
            successful_accounts=successful_accounts,
            failed_accounts=failed_accounts,
            scan_results=scan_results,
            total_duration_seconds=duration,
            aggregated_findings=aggregated_findings,
            aggregated_inventory=aggregated_inventory
        )
    
    def get_account_summary(self) -> Dict:
        """Get summary of all configured accounts"""
        summary = {
            'total_accounts': len(self.accounts),
            'enabled_accounts': len([a for a in self.accounts if a.enabled]),
            'by_environment': {},
            'by_priority': {},
            'total_regions': sum(len(a.regions) for a in self.accounts)
        }
        
        # Count by environment
        for acc in self.accounts:
            env = acc.environment
            summary['by_environment'][env] = summary['by_environment'].get(env, 0) + 1
        
        # Count by priority
        for acc in self.accounts:
            pri = acc.priority
            summary['by_priority'][pri] = summary['by_priority'].get(pri, 0) + 1
        
        return summary
    
    def validate_account_access(self, account_config: AccountConfig) -> Tuple[bool, str]:
        """
        Validate that we can assume role and access the account
        
        Args:
            account_config: Account configuration to validate
            
        Returns:
            Tuple of (success, message)
        """
        try:
            account_session = self.assume_role(account_config)
            if not account_session:
                return (False, "Failed to assume role")
            
            # Try to make a simple API call
            sts = account_session.session.client('sts')
            identity = sts.get_caller_identity()
            
            # Verify account ID matches
            if identity['Account'] != account_config.account_id:
                return (False, f"Account ID mismatch: expected {account_config.account_id}, "
                              f"got {identity['Account']}")
            
            return (True, f"Successfully validated access to {account_config.account_name}")
            
        except Exception as e:
            return (False, f"Validation failed: {str(e)}")
    
    def add_account_manually(self, account_id: str, account_name: str,
                           role_arn: str, external_id: str,
                           regions: List[str], environment: str = "production",
                           priority: str = "medium") -> AccountConfig:
        """
        Manually add an account to the registry
        
        Args:
            account_id: AWS account ID
            account_name: Friendly name for the account
            role_arn: ARN of the cross-account role
            external_id: External ID for role assumption
            regions: List of regions to scan
            environment: Environment tag
            priority: Priority level
            
        Returns:
            Created AccountConfig
        """
        account_config = AccountConfig(
            account_id=account_id,
            account_name=account_name,
            environment=environment,
            role_arn=role_arn,
            external_id=external_id,
            regions=regions,
            scan_schedule={'frequency': 'weekly'},
            priority=priority,
            notification_email='',
            tags={'Environment': environment},
            enabled=True
        )
        
        self.accounts.append(account_config)
        self.logger.info(f"Added account {account_name} ({account_id})")
        
        return account_config

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def discover_all_regions(session: boto3.Session) -> List[str]:
    """
    Discover all enabled AWS regions for the account
    
    Args:
        session: Boto3 session
        
    Returns:
        List of region names
    """
    try:
        ec2 = session.client('ec2', region_name='us-east-1')
        response = ec2.describe_regions(AllRegions=False)
        regions = [r['RegionName'] for r in response['Regions']]
        return sorted(regions)
    except Exception as e:
        logging.error(f"Failed to discover regions: {e}")
        # Return common regions as fallback
        return [
            'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
            'eu-west-1', 'eu-west-2', 'eu-central-1',
            'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1'
        ]

def get_region_groups() -> Dict[str, List[str]]:
    """Get predefined region groups"""
    return {
        'US': ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2'],
        'EU': ['eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1', 'eu-north-1'],
        'APAC': ['ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1', 
                 'ap-northeast-2', 'ap-south-1'],
        'Other': ['ca-central-1', 'sa-east-1', 'me-south-1', 'af-south-1']
    }

# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    'MultiAccountManager',
    'AccountConfig',
    'AccountSession',
    'MultiAccountScanResult',
    'discover_all_regions',
    'get_region_groups'
]
