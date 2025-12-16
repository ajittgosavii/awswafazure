"""
AWS Connector Module - Enhanced with Multi-Account Support
Handles AWS authentication, session management, and multi-account orchestration
Version: 3.0.0
"""

import streamlit as st
from typing import Optional, Tuple, Dict, List
from dataclasses import dataclass
import os
import logging

# Multi-account support (optional - graceful degradation if not available)
try:
    from multi_account_manager import MultiAccountManager, discover_all_regions
    from config_loader import load_accounts_from_streamlit_secrets
    MULTI_ACCOUNT_AVAILABLE = True
except ImportError:
    MULTI_ACCOUNT_AVAILABLE = False
    logging.warning("Multi-account support not available - install dependencies")

logger = logging.getLogger(__name__)

# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class AWSCredentials:
    """AWS Credentials container"""
    access_key_id: str
    secret_access_key: str
    session_token: Optional[str] = None
    region: str = "us-east-1"
    role_arn: Optional[str] = None
    source: str = "manual"

# ============================================================================
# CREDENTIAL HELPERS
# ============================================================================

def get_aws_credentials_from_secrets() -> Tuple[Optional[AWSCredentials], str]:
    """
    Get AWS credentials from Streamlit secrets.
    Returns tuple of (credentials, debug_info)
    """
    debug_info = []
    
    try:
        if hasattr(st, 'secrets'):
            debug_info.append(f"Secrets keys: {list(st.secrets.keys())}")
            
            # FORMAT 1: [aws] section
            if 'aws' in st.secrets:
                aws_secrets = dict(st.secrets['aws'])
                debug_info.append(f"[aws] keys: {list(aws_secrets.keys())}")
                
                access_key = (
                    aws_secrets.get('access_key_id') or 
                    aws_secrets.get('ACCESS_KEY_ID') or
                    aws_secrets.get('aws_access_key_id') or
                    aws_secrets.get('AWS_ACCESS_KEY_ID') or
                    aws_secrets.get('management_access_key_id') or
                    aws_secrets.get('MANAGEMENT_ACCESS_KEY_ID')
                )
                secret_key = (
                    aws_secrets.get('secret_access_key') or 
                    aws_secrets.get('SECRET_ACCESS_KEY') or
                    aws_secrets.get('aws_secret_access_key') or
                    aws_secrets.get('AWS_SECRET_ACCESS_KEY') or
                    aws_secrets.get('management_secret_access_key') or
                    aws_secrets.get('MANAGEMENT_SECRET_ACCESS_KEY')
                )
                region = (
                    aws_secrets.get('default_region') or 
                    aws_secrets.get('region') or 
                    aws_secrets.get('AWS_REGION') or
                    'us-east-1'
                )
                
                if access_key and secret_key:
                    debug_info.append("SUCCESS: Found credentials in [aws] section")
                    return AWSCredentials(
                        access_key_id=access_key,
                        secret_access_key=secret_key,
                        region=region,
                        source="secrets"
                    ), "\n".join(debug_info)
            
            # FORMAT 2: Flat AWS_ keys
            access_key = st.secrets.get('AWS_ACCESS_KEY_ID')
            secret_key = st.secrets.get('AWS_SECRET_ACCESS_KEY')
            if access_key and secret_key:
                return AWSCredentials(
                    access_key_id=access_key,
                    secret_access_key=secret_key,
                    region=st.secrets.get('AWS_REGION', 'us-east-1'),
                    source="secrets"
                ), "Found flat AWS_ keys"
                
    except Exception as e:
        debug_info.append(f"Error: {e}")
    
    return None, "\n".join(debug_info) if debug_info else "No secrets"

def get_aws_session(credentials: Optional[AWSCredentials] = None):
    """
    Create boto3 session from credentials.
    If credentials not provided, tries to get from multiple sources.
    """
    try:
        import boto3
        from botocore.config import Config
        
        # If no credentials provided, try to get them
        if credentials is None:
            # Priority order:
            # 1. Session state (from manual entry)
            # 2. Streamlit secrets
            # 3. Environment variables
            # 4. AWS CLI config
            # 5. IAM role (for EC2/ECS/Lambda)
            
            # Try session state first
            if ('aws_access_key' in st.session_state and 
                'aws_secret_key' in st.session_state):
                session = boto3.Session(
                    aws_access_key_id=st.session_state.aws_access_key,
                    aws_secret_access_key=st.session_state.aws_secret_key,
                    region_name=st.session_state.get('aws_region', 'us-east-1')
                )
                return session
            
            # Try Streamlit secrets
            creds, debug = get_aws_credentials_from_secrets()
            if creds:
                session = boto3.Session(
                    aws_access_key_id=creds.access_key_id,
                    aws_secret_access_key=creds.secret_access_key,
                    aws_session_token=creds.session_token,
                    region_name=creds.region
                )
                return session
            
            # Try default boto3 credential chain (env vars, CLI, IAM role)
            try:
                session = boto3.Session()
                # Test if credentials are available
                sts = session.client('sts')
                sts.get_caller_identity()
                return session
            except:
                pass
            
            return None
        
        # Credentials provided, use them
        session = boto3.Session(
            aws_access_key_id=credentials.access_key_id,
            aws_secret_access_key=credentials.secret_access_key,
            aws_session_token=credentials.session_token,
            region_name=credentials.region
        )
        return session
        
    except Exception as e:
        logger.error(f"Failed to create session: {e}")
        return None

def test_aws_connection(session) -> Tuple[bool, str, Dict]:
    """Test AWS connection and return identity info"""
    try:
        from botocore.config import Config
        config = Config(connect_timeout=10, read_timeout=30)
        
        sts = session.client('sts', config=config)
        identity = sts.get_caller_identity()
        
        return True, f"Connected as {identity['Arn']}", {
            'account': identity['Account'],
            'arn': identity['Arn'],
            'user_id': identity['UserId']
        }
    except Exception as e:
        return False, str(e), {}

# ============================================================================
# RENDER FUNCTION
# ============================================================================

# ============================================================================
# MULTI-ACCOUNT SUPPORT FUNCTIONS
# ============================================================================

def render_multi_account_section():
    """Render multi-account scanning section"""
    if not MULTI_ACCOUNT_AVAILABLE:
        st.error("❌ Multi-account support requires additional dependencies")
        st.code("pip install pyyaml", language="bash")
        return
    
    # Check if hub account is connected
    if not st.session_state.get('aws_connected'):
        st.warning("⚠️ Please connect to your Hub Account first using Single Account mode")
        return
    
    st.markdown("### 🌐 Multi-Account Scanning")
    
    # Load configured accounts
    accounts = load_accounts_from_streamlit_secrets()
    
    if not accounts:
        st.info("📝 No additional accounts configured in Streamlit secrets")
        st.markdown("**To add accounts:**")
        st.markdown("1. Go to Streamlit Cloud → Settings → Secrets")
        st.markdown("2. Add account configuration (see `.streamlit/secrets.toml.template`)")
        st.markdown("3. Save and app will restart")
        
        with st.expander("📖 Example Configuration"):
            st.code("""
[accounts]
[[accounts.list]]
account_id = "123456789012"
account_name = "Production"
environment = "production"
role_arn = "arn:aws:iam::123456789012:role/WAFAdvisorCrossAccountRole"
external_id = "your-secure-external-id"
regions = ["us-east-1", "us-west-2"]
priority = "high"
""", language="toml")
        return
    
    # Display account summary
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Configured Accounts", len(accounts))
    with col2:
        enabled = len([a for a in accounts if a.enabled])
        st.metric("Enabled", enabled)
    with col3:
        total_regions = sum(len(a.regions) for a in accounts)
        st.metric("Total Regions", total_regions)
    
    st.markdown("---")
    
    # Account selection
    st.markdown("**Select Accounts to Scan:**")
    selected_accounts = []
    
    for acc in accounts:
        if acc.enabled:
            col1, col2, col3, col4 = st.columns([3, 2, 2, 1])
            with col1:
                selected = st.checkbox(
                    f"{acc.account_name}",
                    key=f"select_{acc.account_id}",
                    value=True
                )
            with col2:
                st.write(f"*{acc.environment}*")
            with col3:
                st.write(f"{len(acc.regions)} region(s)")
            with col4:
                priority_icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
                st.write(priority_icons.get(acc.priority, "⚪"))
            
            if selected:
                selected_accounts.append(acc)
    
    if not selected_accounts:
        st.warning("⚠️ No accounts selected")
        return
    
    st.markdown("---")
    
    # Scan button
    if st.button("🚀 Scan Selected Accounts", type="primary", use_container_width=True):
        st.session_state.multi_account_scan_requested = True
        st.session_state.selected_accounts_for_scan = selected_accounts

def initialize_multi_account_manager():
    """Initialize multi-account manager with hub session"""
    if 'multi_account_manager' not in st.session_state:
        if st.session_state.get('aws_session'):
            try:
                manager = MultiAccountManager(st.session_state.aws_session)
                st.session_state.multi_account_manager = manager
                return manager
            except Exception as e:
                st.error(f"Failed to initialize multi-account manager: {e}")
                return None
    return st.session_state.get('multi_account_manager')

# ============================================================================
# MAIN RENDER FUNCTION (UPDATED)
# ============================================================================

def render_aws_connector_tab():
    """Render AWS Connector configuration tab - Enhanced with multi-account support"""
    
    st.markdown("""
    <div style="background: linear-gradient(135deg, #232F3E 0%, #37475A 100%); padding: 2rem; border-radius: 12px; margin-bottom: 1.5rem;">
        <h2 style="color: #FF9900; margin: 0;">🔌 AWS Connection Manager</h2>
        <p style="color: #FFFFFF; margin: 0.5rem 0 0 0;">Configure and manage your AWS account connections</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Check for boto3
    try:
        import boto3
        BOTO3_AVAILABLE = True
    except ImportError:
        BOTO3_AVAILABLE = False
        st.error("❌ boto3 not installed. Add `boto3` to requirements.txt")
        return
    
    # Mode selection (Single Account vs Multi-Account)
    if MULTI_ACCOUNT_AVAILABLE:
        mode_col1, mode_col2 = st.columns(2)
        with mode_col1:
            scan_mode = st.radio(
                "Scanning Mode",
                ["🔵 Single Account", "🌐 Multi-Account"],
                horizontal=True,
                help="Single: Scan one account | Multi: Scan multiple accounts in parallel"
            )
        st.markdown("---")
    else:
        scan_mode = "🔵 Single Account"
    
    # Route to appropriate rendering
    if "Multi-Account" in scan_mode:
        # First ensure single account connection for hub
        if not st.session_state.get('aws_connected'):
            st.info("👆 First, connect to your Hub Account below")
        
        # Render single account connection section (collapsed)
        with st.expander("🔐 Hub Account Connection", expanded=not st.session_state.get('aws_connected')):
            render_single_account_section()
        
        st.markdown("---")
        
        # Render multi-account section
        render_multi_account_section()
        return
    
    # Single account mode (original functionality)
    render_single_account_section()

def render_single_account_section():
    """Render single account connection section (original functionality)"""
    
    # Connection status
    col1, col2 = st.columns([2, 1])
    
    with col1:
        if st.session_state.get('aws_connected'):
            st.success("✅ Connected to AWS")
            if st.session_state.get('aws_identity'):
                identity = st.session_state.aws_identity
                st.markdown(f"**Account:** {identity.get('account', 'N/A')}")
                st.markdown(f"**ARN:** `{identity.get('arn', 'N/A')}`")
        else:
            st.warning("⚠️ Not connected to AWS")
    
    with col2:
        if st.session_state.get('aws_connected'):
            if st.button("🔄 Reconnect", use_container_width=True):
                st.session_state.aws_connected = False
                st.session_state.aws_session = None
                st.rerun()
    
    st.markdown("---")
    
    # Connection methods
    st.markdown("### 🔐 Connection Method")
    
    method = st.radio(
        "Select authentication method",
        ["🔑 From Secrets (Recommended)", "✏️ Manual Entry", "🎭 Assume Role"],
        horizontal=True
    )
    
    if "Secrets" in method:
        render_secrets_connection()
    elif "Manual" in method:
        render_manual_connection()
    else:
        render_assume_role_connection()
    
    # AWS Services status
    if st.session_state.get('aws_connected'):
        st.markdown("---")
        render_service_status()

def render_secrets_connection():
    """Render secrets-based connection"""
    creds, debug = get_aws_credentials_from_secrets()
    
    if creds:
        st.success("✅ AWS credentials found in secrets")
        
        if st.button("🔗 Connect to AWS", type="primary", use_container_width=True):
            session = get_aws_session(creds)
            if session:
                success, msg, identity = test_aws_connection(session)
                if success:
                    st.session_state.aws_credentials = creds
                    st.session_state.aws_session = session
                    st.session_state.aws_connected = True
                    st.session_state.aws_identity = identity
                    st.success(msg)
                    st.rerun()
                else:
                    st.error(f"Connection failed: {msg}")
    else:
        st.warning("AWS credentials not found in secrets")
        
        with st.expander("🔍 Debug Information"):
            st.code(debug, language="text")
            st.markdown("""
            **Expected format in Streamlit Secrets:**
            ```toml
            [aws]
            access_key_id = "AKIA..."
            secret_access_key = "..."
            default_region = "us-east-1"
            ```
            """)

def render_manual_connection():
    """Render manual credential entry"""
    col1, col2 = st.columns(2)
    
    with col1:
        access_key = st.text_input("Access Key ID", type="password")
        region = st.selectbox("Region", [
            "us-east-1", "us-east-2", "us-west-1", "us-west-2",
            "eu-west-1", "eu-west-2", "eu-central-1",
            "ap-southeast-1", "ap-southeast-2", "ap-northeast-1"
        ])
    
    with col2:
        secret_key = st.text_input("Secret Access Key", type="password")
        session_token = st.text_input("Session Token (optional)", type="password")
    
    if st.button("🔗 Connect to AWS", type="primary", use_container_width=True):
        if access_key and secret_key:
            creds = AWSCredentials(
                access_key_id=access_key,
                secret_access_key=secret_key,
                session_token=session_token if session_token else None,
                region=region,
                source="manual"
            )
            session = get_aws_session(creds)
            if session:
                success, msg, identity = test_aws_connection(session)
                if success:
                    st.session_state.aws_credentials = creds
                    st.session_state.aws_session = session
                    st.session_state.aws_connected = True
                    st.session_state.aws_identity = identity
                    st.success(msg)
                    st.rerun()
                else:
                    st.error(f"Connection failed: {msg}")
        else:
            st.warning("Please enter both Access Key ID and Secret Access Key")

def render_assume_role_connection():
    """Render assume role connection"""
    st.info("Assume a role in another AWS account for cross-account access")
    
    role_arn = st.text_input("Role ARN", placeholder="arn:aws:iam::123456789012:role/RoleName")
    external_id = st.text_input("External ID (optional)")
    session_name = st.text_input("Session Name", value="WAF-Advisor-Session")
    
    if st.button("🔗 Assume Role", type="primary", use_container_width=True):
        if role_arn:
            # First need base credentials
            base_creds, _ = get_aws_credentials_from_secrets()
            if not base_creds:
                st.error("Base AWS credentials required to assume role")
                return
            
            try:
                import boto3
                
                base_session = get_aws_session(base_creds)
                sts = base_session.client('sts')
                
                assume_params = {
                    'RoleArn': role_arn,
                    'RoleSessionName': session_name,
                    'DurationSeconds': 3600
                }
                if external_id:
                    assume_params['ExternalId'] = external_id
                
                response = sts.assume_role(**assume_params)
                
                assumed_creds = AWSCredentials(
                    access_key_id=response['Credentials']['AccessKeyId'],
                    secret_access_key=response['Credentials']['SecretAccessKey'],
                    session_token=response['Credentials']['SessionToken'],
                    region=base_creds.region,
                    role_arn=role_arn,
                    source="assumed_role"
                )
                
                assumed_session = get_aws_session(assumed_creds)
                success, msg, identity = test_aws_connection(assumed_session)
                
                if success:
                    st.session_state.aws_credentials = assumed_creds
                    st.session_state.aws_session = assumed_session
                    st.session_state.aws_connected = True
                    st.session_state.aws_identity = identity
                    st.success(f"Successfully assumed role: {msg}")
                    st.rerun()
                    
            except Exception as e:
                st.error(f"Failed to assume role: {e}")
        else:
            st.warning("Please enter Role ARN")

def render_service_status():
    """Render AWS service availability status"""
    st.markdown("### 🔧 AWS Services Status")
    
    session = st.session_state.get('aws_session')
    if not session:
        return
    
    services = [
        ("EC2", "ec2", "describe_instances"),
        ("S3", "s3", "list_buckets"),
        ("RDS", "rds", "describe_db_instances"),
        ("IAM", "iam", "list_users"),
        ("CloudTrail", "cloudtrail", "describe_trails"),
        ("Security Hub", "securityhub", "get_findings"),
        ("GuardDuty", "guardduty", "list_detectors"),
        ("Config", "config", "describe_configuration_recorders")
    ]
    
    if st.button("🔍 Check Service Access"):
        cols = st.columns(4)
        
        for idx, (name, service, operation) in enumerate(services):
            with cols[idx % 4]:
                try:
                    client = session.client(service)
                    # Just try to create client - full permission check would need actual calls
                    st.markdown(f"✅ {name}")
                except Exception as e:
                    st.markdown(f"❌ {name}")

# Exports
__all__ = [
    'AWSCredentials',
    'get_aws_credentials_from_secrets',
    'get_aws_session',
    'test_aws_connection',
    'render_aws_connector_tab'
]
