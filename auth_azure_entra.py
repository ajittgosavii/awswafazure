"""
Azure AD / Entra ID Enterprise SSO Authentication Module
=========================================================
Complete authentication solution using Microsoft Entra ID (formerly Azure AD)

Features:
- Microsoft OAuth 2.0 / OpenID Connect
- Enterprise SSO with Microsoft accounts
- Azure AD Group-based Role Mapping
- Token refresh and session management
- MFA support (via Azure AD policies)
- Guest user support (B2B)
- Local authentication fallback
- Audit logging

Requirements:
    pip install msal requests PyJWT

Configuration (in .streamlit/secrets.toml):
    [azure_ad]
    tenant_id = "your-tenant-id"
    client_id = "your-client-id"
    client_secret = "your-client-secret"
    redirect_uri = "https://your-app.streamlit.app"

Version: 2.0.0
Author: Infosys Cloud Team
"""

import streamlit as st
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
import json
import hashlib
import uuid
import os
import base64
import time

# Microsoft Authentication Library
try:
    import msal
    MSAL_AVAILABLE = True
except ImportError:
    MSAL_AVAILABLE = False

# HTTP requests
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


# =============================================================================
# CONFIGURATION
# =============================================================================

class AzureADConfig:
    """Azure AD Configuration"""
    
    GRAPH_API_BASE = "https://graph.microsoft.com/v1.0"
    AUTHORITY_BASE = "https://login.microsoftonline.com"
    
    DEFAULT_SCOPES = [
        "User.Read",
        "User.ReadBasic.All",
        "GroupMember.Read.All"
    ]
    
    TOKEN_CACHE_KEY = "azure_ad_token_cache"
    SESSION_TIMEOUT_HOURS = 8
    
    @classmethod
    def get_authority(cls, tenant_id: str) -> str:
        return f"{cls.AUTHORITY_BASE}/{tenant_id}"
    
    @classmethod
    def get_config(cls) -> Dict[str, str]:
        """Get Azure AD configuration from Streamlit secrets"""
        try:
            config = st.secrets.get("azure_ad", {})
            return {
                "tenant_id": config.get("tenant_id", ""),
                "client_id": config.get("client_id", ""),
                "client_secret": config.get("client_secret", ""),
                "redirect_uri": config.get("redirect_uri", "http://localhost:8501"),
                "scopes": config.get("scopes", cls.DEFAULT_SCOPES),
            }
        except Exception:
            return {}


# =============================================================================
# ROLE DEFINITIONS
# =============================================================================

class UserRole(Enum):
    """User role hierarchy"""
    GUEST = 0
    VIEWER = 1
    USER = 2
    MANAGER = 3
    ADMIN = 4
    SUPER_ADMIN = 5
    
    @classmethod
    def from_string(cls, role_str: str) -> 'UserRole':
        mapping = {
            'guest': cls.GUEST,
            'viewer': cls.VIEWER,
            'user': cls.USER,
            'manager': cls.MANAGER,
            'admin': cls.ADMIN,
            'super_admin': cls.SUPER_ADMIN,
            'superadmin': cls.SUPER_ADMIN,
        }
        return mapping.get(role_str.lower(), cls.USER)
    
    def __str__(self):
        return self.name.lower()


# Azure AD Group to Role Mapping - Configure with your Group Object IDs
AZURE_AD_GROUP_ROLE_MAPPING = {
    # "group-object-id": UserRole.ADMIN,
}

# Role permissions
ROLE_PERMISSIONS = {
    UserRole.SUPER_ADMIN: {
        "manage_all_users": True, "manage_organizations": True, "manage_system_settings": True,
        "view_audit_logs": True, "manage_api_keys": True, "delete_any_data": True,
        "run_scans": True, "view_all_scans": True, "export_data": True,
        "manage_integrations": True, "access_all_tabs": True,
        "use_demo_mode": True, "use_live_mode": True,
    },
    UserRole.ADMIN: {
        "view_audit_logs": True, "manage_api_keys": True, "run_scans": True,
        "view_all_scans": True, "export_data": True, "manage_integrations": True,
        "access_all_tabs": True, "manage_org_users": True,
        "use_demo_mode": True, "use_live_mode": True,
    },
    UserRole.MANAGER: {
        "run_scans": True, "view_all_scans": True, "export_data": True,
        "access_all_tabs": True, "view_team_data": True,
        "use_demo_mode": True, "use_live_mode": True,
    },
    UserRole.USER: {
        "run_scans": True, "export_data": True, "access_all_tabs": True,
        "use_demo_mode": True, "use_live_mode": True,
    },
    UserRole.VIEWER: {
        "access_all_tabs": True, "use_demo_mode": True,
    },
    UserRole.GUEST: {
        "use_demo_mode": True,
    },
}

TAB_ACCESS = {
    "WAF Scanner": [UserRole.USER, UserRole.MANAGER, UserRole.ADMIN, UserRole.SUPER_ADMIN],
    "AWS Connector": [UserRole.USER, UserRole.MANAGER, UserRole.ADMIN, UserRole.SUPER_ADMIN],
    "WAF Assessment": [UserRole.VIEWER, UserRole.USER, UserRole.MANAGER, UserRole.ADMIN, UserRole.SUPER_ADMIN],
    "Architecture Designer": [UserRole.USER, UserRole.MANAGER, UserRole.ADMIN, UserRole.SUPER_ADMIN],
    "Cost Optimization": [UserRole.MANAGER, UserRole.ADMIN, UserRole.SUPER_ADMIN],
    "EKS Modernization": [UserRole.USER, UserRole.MANAGER, UserRole.ADMIN, UserRole.SUPER_ADMIN],
    "Compliance": [UserRole.VIEWER, UserRole.USER, UserRole.MANAGER, UserRole.ADMIN, UserRole.SUPER_ADMIN],
    "AI Assistant": [UserRole.USER, UserRole.MANAGER, UserRole.ADMIN, UserRole.SUPER_ADMIN],
    "Admin Panel": [UserRole.ADMIN, UserRole.SUPER_ADMIN],
}


# =============================================================================
# USER MODEL
# =============================================================================

@dataclass
class User:
    """User model compatible with existing codebase"""
    id: str
    email: str
    display_name: str
    role: UserRole = UserRole.USER
    organization_id: str = "default-org"
    given_name: Optional[str] = None
    surname: Optional[str] = None
    job_title: Optional[str] = None
    department: Optional[str] = None
    groups: List[str] = field(default_factory=list)
    login_time: Optional[datetime] = None
    photo_url: Optional[str] = None
    is_guest: bool = False
    tenant_id: Optional[str] = None
    active: bool = True
    created_at: Optional[datetime] = None
    created_by: str = "system"
    
    # Aliases for compatibility
    @property
    def uid(self) -> str:
        return self.id
    
    @property
    def name(self) -> str:
        return self.display_name
    
    def to_dict(self) -> Dict:
        return {
            'id': self.id, 'uid': self.id, 'email': self.email,
            'display_name': self.display_name, 'name': self.display_name,
            'role': str(self.role), 'organization_id': self.organization_id,
            'given_name': self.given_name, 'surname': self.surname,
            'job_title': self.job_title, 'department': self.department,
            'groups': self.groups,
            'login_time': self.login_time.isoformat() if self.login_time else None,
            'photo_url': self.photo_url, 'is_guest': self.is_guest,
            'tenant_id': self.tenant_id, 'active': self.active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'created_by': self.created_by,
        }
    
    @staticmethod
    def from_dict(data: Dict) -> 'User':
        return User(
            id=data.get('id') or data.get('uid', ''),
            email=data.get('email', ''),
            display_name=data.get('display_name') or data.get('name', ''),
            role=UserRole.from_string(data.get('role', 'user')),
            organization_id=data.get('organization_id', 'default-org'),
            given_name=data.get('given_name'),
            surname=data.get('surname'),
            job_title=data.get('job_title'),
            department=data.get('department'),
            groups=data.get('groups', []),
            login_time=datetime.fromisoformat(data['login_time']) if data.get('login_time') else None,
            photo_url=data.get('photo_url'),
            is_guest=data.get('is_guest', False),
            tenant_id=data.get('tenant_id'),
            active=data.get('active', True),
            created_at=datetime.fromisoformat(data['created_at']) if data.get('created_at') else None,
            created_by=data.get('created_by', 'system'),
        )
    
    @staticmethod
    def from_graph_api(data: Dict) -> 'User':
        """Create user from Microsoft Graph API response"""
        email = data.get('mail') or data.get('userPrincipalName', '')
        return User(
            id=data.get('id', ''),
            email=email,
            display_name=data.get('displayName', email.split('@')[0]),
            given_name=data.get('givenName'),
            surname=data.get('surname'),
            job_title=data.get('jobTitle'),
            department=data.get('department'),
            is_guest='#EXT#' in data.get('userPrincipalName', ''),
            created_at=datetime.now(),
        )
    
    def has_permission(self, permission: str) -> bool:
        return ROLE_PERMISSIONS.get(self.role, {}).get(permission, False)
    
    def can_access_tab(self, tab_name: str) -> bool:
        return self.role in TAB_ACCESS.get(tab_name, [])


# Alias for backward compatibility
AzureADUser = User


# =============================================================================
# AZURE AD AUTH MANAGER
# =============================================================================

class AzureADAuthManager:
    """Azure AD / Entra ID Authentication Manager"""
    
    def __init__(self):
        self.config = AzureADConfig.get_config()
        self.msal_app = None
        self._initialized = False
        self.db = None
        self._init_msal_app()
        self._init_local_store()
    
    def _init_msal_app(self):
        """Initialize MSAL application"""
        if not MSAL_AVAILABLE or not self.config.get('client_id'):
            return
        
        try:
            self.msal_app = msal.ConfidentialClientApplication(
                client_id=self.config['client_id'],
                client_credential=self.config['client_secret'],
                authority=AzureADConfig.get_authority(self.config['tenant_id']),
                token_cache=self._get_token_cache()
            )
            self._initialized = True
        except Exception as e:
            print(f"Azure AD init error: {e}")
    
    def _init_local_store(self):
        """Initialize local user store"""
        if 'local_users' not in st.session_state:
            st.session_state.local_users = {}
        if 'audit_logs' not in st.session_state:
            st.session_state.audit_logs = []
    
    def _get_token_cache(self):
        """Get or create token cache"""
        cache = msal.SerializableTokenCache()
        if AzureADConfig.TOKEN_CACHE_KEY in st.session_state:
            cache.deserialize(st.session_state[AzureADConfig.TOKEN_CACHE_KEY])
        return cache
    
    def _save_token_cache(self):
        """Save token cache"""
        if self.msal_app and self.msal_app.token_cache.has_state_changed:
            st.session_state[AzureADConfig.TOKEN_CACHE_KEY] = self.msal_app.token_cache.serialize()
    
    @property
    def firebase_available(self) -> bool:
        """Compatibility property"""
        return self._initialized or True  # Always allow local auth
    
    def is_configured(self) -> bool:
        """Check if Azure AD is configured"""
        return bool(self.config.get('tenant_id') and self.config.get('client_id') and self.config.get('client_secret'))
    
    def get_auth_url(self, state: str = None) -> str:
        """Get Azure AD authorization URL"""
        if not self._initialized:
            return ""
        
        if not state:
            state = hashlib.sha256(os.urandom(32)).hexdigest()
        st.session_state['oauth_state'] = state
        
        return self.msal_app.get_authorization_request_url(
            scopes=self.config.get('scopes', AzureADConfig.DEFAULT_SCOPES),
            state=state,
            redirect_uri=self.config['redirect_uri'],
            prompt="select_account"
        )
    
    def handle_callback(self, code: str, state: str = None) -> Tuple[bool, str, Optional[User]]:
        """Handle OAuth callback"""
        # Initialize session state FIRST before any other operations
        if 'local_users' not in st.session_state:
            st.session_state.local_users = {}
        if 'audit_logs' not in st.session_state:
            st.session_state.audit_logs = []
        if 'authenticated' not in st.session_state:
            st.session_state.authenticated = False
            
        if not self._initialized:
            return False, "Azure AD not initialized", None
        
        stored_state = st.session_state.get('oauth_state')
        if state and stored_state and state != stored_state:
            return False, "Invalid state token", None
        
        try:
            result = self.msal_app.acquire_token_by_authorization_code(
                code=code,
                scopes=self.config.get('scopes', AzureADConfig.DEFAULT_SCOPES),
                redirect_uri=self.config['redirect_uri']
            )
            
            if 'error' in result:
                return False, f"Auth failed: {result.get('error_description', result.get('error'))}", None
            
            self._save_token_cache()
            
            access_token = result.get('access_token')
            user = self._get_user_info(access_token)
            
            if not user:
                return False, "Failed to get user info", None
            
            user.groups = self._get_user_groups(access_token)
            user.role = self._determine_role_from_groups(user.groups)
            user.login_time = datetime.now()
            user.tenant_id = result.get('id_token_claims', {}).get('tid')
            user.photo_url = self._get_user_photo(access_token)
            
            st.session_state['azure_ad_access_token'] = access_token
            self._save_user_to_store(user)
            self._log_action(user.id, user.email, "login", {"method": "azure_ad_sso"})
            
            return True, "Login successful", user
            
        except Exception as e:
            return False, f"Auth error: {str(e)}", None
    
    def _get_user_info(self, access_token: str) -> Optional[User]:
        """Get user info from Graph API"""
        if not REQUESTS_AVAILABLE:
            return None
        try:
            response = requests.get(
                f"{AzureADConfig.GRAPH_API_BASE}/me",
                headers={'Authorization': f'Bearer {access_token}'},
                params={'$select': 'id,displayName,givenName,surname,mail,userPrincipalName,jobTitle,department'},
                timeout=10
            )
            if response.status_code == 200:
                return User.from_graph_api(response.json())
        except Exception:
            pass
        return None
    
    def _get_user_groups(self, access_token: str) -> List[str]:
        """Get user's group memberships"""
        if not REQUESTS_AVAILABLE:
            return []
        try:
            response = requests.get(
                f"{AzureADConfig.GRAPH_API_BASE}/me/memberOf",
                headers={'Authorization': f'Bearer {access_token}'},
                params={'$select': 'id,displayName'},
                timeout=10
            )
            if response.status_code == 200:
                return [g['id'] for g in response.json().get('value', []) 
                       if g.get('@odata.type') == '#microsoft.graph.group']
        except Exception:
            pass
        return []
    
    def _get_user_photo(self, access_token: str) -> Optional[str]:
        """Get user's profile photo"""
        if not REQUESTS_AVAILABLE:
            return None
        try:
            response = requests.get(
                f"{AzureADConfig.GRAPH_API_BASE}/me/photo/$value",
                headers={'Authorization': f'Bearer {access_token}'},
                timeout=10
            )
            if response.status_code == 200:
                photo_data = base64.b64encode(response.content).decode()
                return f"data:{response.headers.get('Content-Type', 'image/jpeg')};base64,{photo_data}"
        except Exception:
            pass
        return None
    
    def _determine_role_from_groups(self, groups: List[str]) -> UserRole:
        """Determine role from Azure AD groups"""
        for group_id, role in AZURE_AD_GROUP_ROLE_MAPPING.items():
            if group_id in groups:
                return role
        return UserRole.USER
    
    def _save_user_to_store(self, user: User):
        """Save user to local store"""
        # Ensure session state is initialized
        if 'local_users' not in st.session_state:
            st.session_state.local_users = {}
        st.session_state.local_users[user.email] = user.to_dict()
    
    def _log_action(self, user_id: str, user_email: str, action: str, details: Dict):
        """Log action"""
        # Ensure session state is initialized
        if 'audit_logs' not in st.session_state:
            st.session_state.audit_logs = []
        st.session_state.audit_logs.append({
            'id': str(uuid.uuid4()),
            'timestamp': datetime.now().isoformat(),
            'user_id': user_id,
            'user_email': user_email,
            'action': action,
            'details': details
        })
        if len(st.session_state.audit_logs) > 1000:
            st.session_state.audit_logs = st.session_state.audit_logs[-1000:]
    
    # =========================================================================
    # USER MANAGEMENT (Admin Panel)
    # =========================================================================
    
    def _ensure_session_state(self):
        """Ensure session state is initialized"""
        if 'local_users' not in st.session_state:
            st.session_state.local_users = {}
        if 'audit_logs' not in st.session_state:
            st.session_state.audit_logs = []
    
    def create_user(self, email: str, password: str, display_name: str,
                   role: str, organization_id: str) -> Tuple[bool, str, Optional[User]]:
        """Create a new user"""
        self._ensure_session_state()
        start_time = time.time()
        current_user = SessionManager.get_current_user()
        created_by = current_user.email if current_user else "system"
        
        if email in st.session_state.local_users:
            return False, f"User '{email}' already exists", None
        
        uid = f"local-{uuid.uuid4().hex[:8]}"
        user = User(
            id=uid, email=email, display_name=display_name,
            role=UserRole.from_string(role), organization_id=organization_id,
            created_at=datetime.now(), created_by=created_by, active=True,
        )
        
        user_data = user.to_dict()
        user_data['password_hash'] = hashlib.sha256(password.encode()).hexdigest()
        st.session_state.local_users[email] = user_data
        
        self._log_action(created_by, created_by, "create_user", {"email": email, "role": role})
        
        return True, f"User created ({time.time() - start_time:.1f}s)", user
    
    def authenticate(self, email: str, password: str) -> Tuple[bool, str, Optional[User]]:
        """Authenticate with email/password"""
        self._ensure_session_state()
        user_data = st.session_state.local_users.get(email)
        
        if not user_data:
            return False, "User not found", None
        if not user_data.get('active', True):
            return False, "Account disabled", None
        
        if user_data.get('password_hash') != hashlib.sha256(password.encode()).hexdigest():
            return False, "Invalid password", None
        
        user = User.from_dict(user_data)
        user.login_time = datetime.now()
        
        self._log_action(user.id, email, "login", {"method": "email_password"})
        return True, "Login successful", user
    
    def update_user(self, uid: str, updates: Dict) -> Tuple[bool, str]:
        """Update user"""
        self._ensure_session_state()
        for email, user_data in st.session_state.local_users.items():
            if user_data.get('id') == uid or user_data.get('uid') == uid:
                for key, value in updates.items():
                    if key == 'password':
                        user_data['password_hash'] = hashlib.sha256(value.encode()).hexdigest()
                    elif key != 'password_hash':
                        user_data[key] = value
                
                current_user = SessionManager.get_current_user()
                self._log_action(current_user.id if current_user else "system", 
                               current_user.email if current_user else "system",
                               "update_user", {"uid": uid})
                return True, "User updated"
        return False, "User not found"
    
    def delete_user(self, uid: str) -> Tuple[bool, str]:
        """Deactivate user"""
        self._ensure_session_state()
        for email, user_data in st.session_state.local_users.items():
            if user_data.get('id') == uid or user_data.get('uid') == uid:
                user_data['active'] = False
                current_user = SessionManager.get_current_user()
                self._log_action(current_user.id if current_user else "system",
                               current_user.email if current_user else "system",
                               "delete_user", {"uid": uid, "email": email})
                return True, "User deactivated"
        return False, "User not found"
    
    def get_all_users(self, force_refresh: bool = False) -> List[User]:
        """Get all users"""
        self._ensure_session_state()
        users = []
        for email, user_data in st.session_state.local_users.items():
            try:
                users.append(User.from_dict(user_data))
            except Exception:
                pass
        return users
    
    def invalidate_user_cache(self):
        """Invalidate user cache"""
        if 'cached_users_list' in st.session_state:
            del st.session_state['cached_users_list']
    
    def get_audit_logs(self, limit: int = 100) -> List[Dict]:
        """Get audit logs"""
        logs = st.session_state.get('audit_logs', [])
        return sorted(logs, key=lambda x: x.get('timestamp', ''), reverse=True)[:limit]
    
    def logout(self) -> str:
        """Logout and return Azure AD logout URL"""
        for key in ['azure_ad_access_token', 'azure_ad_refresh_token', 'oauth_state', 
                   'authenticated', 'current_user', 'user_role', AzureADConfig.TOKEN_CACHE_KEY]:
            if key in st.session_state:
                del st.session_state[key]
        
        if self.is_configured():
            return f"{AzureADConfig.AUTHORITY_BASE}/{self.config['tenant_id']}/oauth2/v2.0/logout?post_logout_redirect_uri={self.config['redirect_uri']}"
        return ""


# =============================================================================
# SESSION MANAGER
# =============================================================================

class SessionManager:
    """Manage user sessions"""
    
    @staticmethod
    def login(user: User):
        """Set up user session"""
        st.session_state.authenticated = True
        st.session_state.current_user = user.to_dict()
        st.session_state.user_role = user.role
        st.session_state.user_email = user.email
        st.session_state.user_id = user.id
        st.session_state.user_name = user.display_name
        st.session_state.login_time = datetime.now().isoformat()
    
    @staticmethod
    def logout():
        """Clear user session"""
        for key in ['authenticated', 'current_user', 'user_role', 'user_email', 
                   'user_id', 'user_name', 'login_time', 'azure_ad_access_token']:
            if key in st.session_state:
                del st.session_state[key]
    
    @staticmethod
    def is_authenticated() -> bool:
        """Check if authenticated"""
        if not st.session_state.get('authenticated', False):
            return False
        
        login_time_str = st.session_state.get('login_time')
        if login_time_str:
            login_time = datetime.fromisoformat(login_time_str)
            if datetime.now() - login_time > timedelta(hours=AzureADConfig.SESSION_TIMEOUT_HOURS):
                SessionManager.logout()
                return False
        return True
    
    @staticmethod
    def get_current_user() -> Optional[User]:
        """Get current user"""
        if not SessionManager.is_authenticated():
            return None
        user_data = st.session_state.get('current_user')
        return User.from_dict(user_data) if user_data else None
    
    @staticmethod
    def has_permission(permission: str) -> bool:
        """Check permission"""
        user = SessionManager.get_current_user()
        return user.has_permission(permission) if user else False
    
    @staticmethod
    def can_access_tab(tab_name: str) -> bool:
        """Check tab access"""
        user = SessionManager.get_current_user()
        return user.can_access_tab(tab_name) if user else False


# =============================================================================
# DECORATORS
# =============================================================================

def require_auth(func):
    """Require authentication"""
    def wrapper(*args, **kwargs):
        if not SessionManager.is_authenticated():
            st.error("🔒 Please sign in")
            render_login_page()
            return None
        return func(*args, **kwargs)
    return wrapper


def require_permission(permission: str):
    """Require permission"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            if not SessionManager.is_authenticated():
                render_login_page()
                return None
            if not SessionManager.has_permission(permission):
                st.error(f"⛔ Access denied: {permission}")
                return None
            return func(*args, **kwargs)
        return wrapper
    return decorator


def require_role(min_role: UserRole):
    """Require minimum role"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            user = SessionManager.get_current_user()
            if not user:
                render_login_page()
                return None
            if user.role.value < min_role.value:
                st.error(f"⛔ Required role: {min_role.name}")
                return None
            return func(*args, **kwargs)
        return wrapper
    return decorator


def check_tab_access(tab_name: str) -> bool:
    """Check tab access"""
    return SessionManager.can_access_tab(tab_name)


# =============================================================================
# UI COMPONENTS
# =============================================================================

def render_login_page():
    """Render Infosys-branded login page with Azure AD / Microsoft SSO"""
    # Initialize session state FIRST
    _init_session_state()
    
    auth_manager = get_auth_manager()
    
    # OAuth callback handling
    query_params = st.query_params
    if 'code' in query_params:
        with st.spinner("🔐 Signing in with Microsoft..."):
            success, message, user = auth_manager.handle_callback(
                query_params.get('code'), query_params.get('state'))
        
        if success and user:
            SessionManager.login(user)
            st.query_params.clear()
            st.success(f"✅ Welcome, {user.display_name}!")
            st.balloons()
            st.rerun()
        else:
            st.error(f"❌ {message}")
            st.query_params.clear()
            return
    
    # Infosys-branded CSS
    st.markdown("""
    <style>
    /* Hide Streamlit default elements */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    
    /* Login container */
    .login-container {
        max-width: 500px;
        margin: 20px auto;
        padding: 40px;
        background: white;
        border-radius: 8px;
        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    }
    
    /* Infosys logo styling */
    .infosys-logo {
        text-align: center;
        margin-bottom: 20px;
    }
    .infosys-logo img {
        height: 50px;
    }
    .infosys-text {
        font-family: 'Arial', sans-serif;
        font-size: 36px;
        font-weight: bold;
        color: #007CC3;
        text-align: center;
    }
    
    /* Title styling */
    .app-title {
        text-align: center;
        font-size: 24px;
        font-weight: 600;
        color: #333;
        margin: 20px 0 5px 0;
    }
    .app-subtitle {
        text-align: center;
        font-size: 20px;
        color: #007CC3;
        margin-bottom: 5px;
    }
    .app-edition {
        text-align: center;
        font-size: 14px;
        color: #666;
        margin-bottom: 30px;
    }
    
    /* Sign in header */
    .signin-header {
        font-size: 16px;
        font-weight: 500;
        color: #333;
        margin-bottom: 20px;
        padding-bottom: 10px;
        border-bottom: 1px solid #eee;
    }
    
    /* Microsoft button */
    .ms-signin-btn {
        display: flex;
        align-items: center;
        justify-content: center;
        background: #2F2F2F;
        color: white !important;
        padding: 12px 24px;
        border-radius: 4px;
        text-decoration: none !important;
        font-weight: 500;
        font-size: 15px;
        width: 100%;
        margin: 15px 0;
        transition: background 0.2s;
    }
    .ms-signin-btn:hover {
        background: #1a1a1a;
        text-decoration: none !important;
        color: white !important;
    }
    .ms-signin-btn img {
        width: 21px;
        height: 21px;
        margin-right: 12px;
    }
    
    /* Divider */
    .divider {
        display: flex;
        align-items: center;
        text-align: center;
        margin: 20px 0;
        color: #999;
        font-size: 13px;
    }
    .divider::before, .divider::after {
        content: '';
        flex: 1;
        border-bottom: 1px solid #ddd;
    }
    .divider::before { margin-right: 15px; }
    .divider::after { margin-left: 15px; }
    
    /* Form styling */
    .form-label {
        font-size: 14px;
        color: #333;
        margin-bottom: 5px;
        display: flex;
        align-items: center;
    }
    .form-label .help-icon {
        margin-left: auto;
        color: #999;
        cursor: help;
    }
    
    /* Remember me */
    .remember-row {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin: 15px 0;
    }
    .forgot-link {
        color: #007CC3;
        font-size: 13px;
        text-decoration: none;
    }
    .forgot-link:hover {
        text-decoration: underline;
    }
    
    /* Footer */
    .login-footer {
        text-align: center;
        margin-top: 30px;
        padding-top: 20px;
        border-top: 1px solid #eee;
        color: #999;
        font-size: 12px;
    }
    </style>
    """, unsafe_allow_html=True)
    
    # Main layout
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        # Infosys Logo
        st.markdown("""
        <div class="infosys-logo">
            <span class="infosys-text">Infosys</span>
        </div>
        """, unsafe_allow_html=True)
        
        # App Title
        st.markdown("""
        <div class="app-title">AI-Based AWS Well-Architected</div>
        <div class="app-subtitle">Framework Advisor</div>
        <div class="app-edition">Enterprise Edition</div>
        """, unsafe_allow_html=True)
        
        # Microsoft Sign-In Button (always show, but works when configured)
        if auth_manager.is_configured():
            auth_url = auth_manager.get_auth_url()
            st.markdown(f"""
            <a href="{auth_url}" class="ms-signin-btn">
                <img src="https://upload.wikimedia.org/wikipedia/commons/4/44/Microsoft_logo.svg" alt="Microsoft">
                Sign in with Microsoft
            </a>
            """, unsafe_allow_html=True)
            
            st.markdown('<div class="divider">or sign in with email</div>', unsafe_allow_html=True)
        else:
            # Show disabled Microsoft button with setup hint
            st.markdown("""
            <div style="background: #f5f5f5; border: 1px dashed #ccc; border-radius: 4px; padding: 15px; margin: 15px 0; text-align: center;">
                <span style="color: #666;">🔒 Microsoft SSO available when configured</span>
            </div>
            """, unsafe_allow_html=True)
        
        # Sign In Header
        st.markdown('<div class="signin-header">Sign In to Continue</div>', unsafe_allow_html=True)
        
        # Login Form
        with st.form("login_form", clear_on_submit=False):
            # Email field
            email = st.text_input(
                "Email Address",
                placeholder="Enter your email",
                help="Your company email address"
            )
            
            # Password field
            password = st.text_input(
                "Password",
                type="password",
                placeholder="Enter your password",
                help="Your account password"
            )
            
            # Remember me and forgot password row
            col_rem, col_forgot = st.columns([1, 1])
            with col_rem:
                remember = st.checkbox("Remember me", value=True)
            with col_forgot:
                st.markdown('<div style="text-align: right; padding-top: 5px;"><a href="#" class="forgot-link">Forgot password?</a></div>', unsafe_allow_html=True)
            
            # Submit buttons
            col_signin, col_demo = st.columns([2, 1])
            with col_signin:
                signin_clicked = st.form_submit_button("Sign In", type="primary", use_container_width=True)
            with col_demo:
                demo_clicked = st.form_submit_button("Demo", use_container_width=True)
            
            # Handle sign in
            if signin_clicked:
                if email and password:
                    success, msg, user = auth_manager.authenticate(email, password)
                    if success and user:
                        SessionManager.login(user)
                        st.success(f"✅ Welcome, {user.display_name}!")
                        st.rerun()
                    else:
                        st.error(f"❌ {msg}")
                else:
                    st.warning("Please enter email and password")
            
            # Handle demo mode
            if demo_clicked:
                demo_user = User(
                    id=f"demo-{uuid.uuid4().hex[:8]}",
                    email="demo@infosys.com",
                    display_name="Demo User",
                    role=UserRole.USER,
                    organization_id="Infosys",
                    login_time=datetime.now()
                )
                SessionManager.login(demo_user)
                st.success("✅ Logged in as Demo User")
                st.rerun()
        
        # Development/Admin quick access
        with st.expander("🔧 Quick Access (Development)"):
            st.caption("For development and testing purposes")
            
            quick_col1, quick_col2 = st.columns(2)
            with quick_col1:
                if st.button("👤 Login as Admin", use_container_width=True):
                    admin_user = User(
                        id=f"admin-{uuid.uuid4().hex[:8]}",
                        email="admin@infosys.com",
                        display_name="Admin User",
                        role=UserRole.ADMIN,
                        organization_id="Infosys",
                        login_time=datetime.now()
                    )
                    SessionManager.login(admin_user)
                    st.rerun()
            
            with quick_col2:
                if st.button("🔴 Login as Super Admin", use_container_width=True):
                    super_admin = User(
                        id=f"super-{uuid.uuid4().hex[:8]}",
                        email="superadmin@infosys.com",
                        display_name="Super Admin",
                        role=UserRole.SUPER_ADMIN,
                        organization_id="Infosys",
                        login_time=datetime.now()
                    )
                    SessionManager.login(super_admin)
                    st.rerun()
        
        # Azure AD Setup (if not configured)
        if not auth_manager.is_configured():
            with st.expander("📋 Enable Microsoft SSO"):
                st.info("""
                **To enable Microsoft Entra ID (Azure AD) SSO:**
                
                1. Register app in [Azure Portal](https://portal.azure.com) → Azure AD → App registrations
                2. Create a client secret
                3. Add to `.streamlit/secrets.toml`:
                
                ```toml
                [azure_ad]
                tenant_id = "your-tenant-id"
                client_id = "your-client-id"
                client_secret = "your-secret"
                redirect_uri = "https://your-app.streamlit.app"
                ```
                
                See `docs/AZURE_AD_SETUP_GUIDE.md` for detailed instructions.
                """)
        
        # Footer
        st.markdown("""
        <div class="login-footer">
            Powered by Infosys | AWS Well-Architected Framework<br>
            © 2024 All Rights Reserved
        </div>
        """, unsafe_allow_html=True)


def render_user_menu():
    """Render user menu in sidebar"""
    user = SessionManager.get_current_user()
    if not user:
        return
    
    with st.sidebar:
        st.markdown("---")
        
        col1, col2 = st.columns([1, 3])
        with col1:
            if user.photo_url:
                st.image(user.photo_url, width=50)
            else:
                st.markdown("### 👤")
        with col2:
            st.markdown(f"**{user.display_name}**")
            role_badges = {
                UserRole.SUPER_ADMIN: "🔴 Super Admin", UserRole.ADMIN: "🟠 Admin",
                UserRole.MANAGER: "🟡 Manager", UserRole.USER: "🟢 User",
                UserRole.VIEWER: "🔵 Viewer", UserRole.GUEST: "⚪ Guest",
            }
            st.caption(role_badges.get(user.role, "⚪ Guest"))
        
        st.caption(f"📧 {user.email}")
        if user.department:
            st.caption(f"🏢 {user.department}")
        
        st.markdown("---")
        
        if user.role in [UserRole.ADMIN, UserRole.SUPER_ADMIN]:
            if st.button("⚙️ Admin Panel", use_container_width=True):
                st.session_state.show_admin_panel = True
                st.rerun()
        
        if st.button("🚪 Sign Out", use_container_width=True):
            SessionManager.logout()
            st.rerun()


def render_admin_panel():
    """Render admin panel"""
    user = SessionManager.get_current_user()
    if not user or user.role not in [UserRole.ADMIN, UserRole.SUPER_ADMIN]:
        st.error("Access denied")
        return
    
    st.markdown("## ⚙️ Admin Panel")
    st.caption(f"Logged in as: **{user.display_name}** ({user.role.name})")
    
    if st.button("← Back to Application"):
        st.session_state.show_admin_panel = False
        st.rerun()
    
    tabs = st.tabs(["👥 Users", "📊 Analytics", "📜 Audit Logs"])
    auth_mgr = get_auth_manager()
    
    with tabs[0]:
        _render_user_management(auth_mgr, user)
    with tabs[1]:
        _render_analytics(auth_mgr)
    with tabs[2]:
        _render_audit_logs(auth_mgr)


def _render_user_management(auth_mgr, current_user):
    """User management section"""
    st.markdown("### 👥 User Management")
    
    if st.button("➕ Add New User", type="primary"):
        st.session_state.show_add_user_form = True
    
    if st.session_state.get('show_add_user_form'):
        with st.form("add_user_form"):
            col1, col2 = st.columns(2)
            with col1:
                new_email = st.text_input("Email *")
                new_name = st.text_input("Display Name *")
            with col2:
                new_password = st.text_input("Password *", type="password")
                new_password_confirm = st.text_input("Confirm Password *", type="password")
            
            roles = ["viewer", "user", "manager"]
            if current_user.role == UserRole.SUPER_ADMIN:
                roles.append("admin")
            new_role = st.selectbox("Role", roles)
            new_org = st.text_input("Organization", value="Infosys Limited")
            
            col_a, col_b = st.columns(2)
            with col_a:
                if st.form_submit_button("✅ Create", type="primary"):
                    if not all([new_email, new_name, new_password]):
                        st.error("All fields required")
                    elif new_password != new_password_confirm:
                        st.error("Passwords don't match")
                    elif len(new_password) < 6:
                        st.error("Password too short")
                    else:
                        success, msg, _ = auth_mgr.create_user(new_email, new_password, new_name, new_role, new_org)
                        if success:
                            st.success(msg)
                            st.session_state.show_add_user_form = False
                            st.rerun()
                        else:
                            st.error(msg)
            with col_b:
                if st.form_submit_button("❌ Cancel"):
                    st.session_state.show_add_user_form = False
                    st.rerun()
    
    st.markdown("### 📋 All Users")
    users = auth_mgr.get_all_users()
    st.caption(f"Total: {len(users)}")
    
    for u in users:
        status = "🟢" if u.active else "🔴"
        with st.expander(f"{status} {u.display_name} ({u.email})"):
            st.markdown(f"**Role:** {u.role.name} | **Status:** {'Active' if u.active else 'Inactive'}")
            if u.id != current_user.id:
                new_role = st.selectbox("Change Role", ["viewer", "user", "manager", "admin"], key=f"role_{u.id}")
                col1, col2 = st.columns(2)
                with col1:
                    if st.button("Update", key=f"upd_{u.id}"):
                        auth_mgr.update_user(u.id, {"role": new_role})
                        st.rerun()
                with col2:
                    if u.active and st.button("Disable", key=f"del_{u.id}"):
                        auth_mgr.delete_user(u.id)
                        st.rerun()


def _render_analytics(auth_mgr):
    """Analytics section"""
    users = auth_mgr.get_all_users()
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Total Users", len(users))
    with col2:
        st.metric("Active", sum(1 for u in users if u.active))
    with col3:
        st.metric("Admins", sum(1 for u in users if u.role in [UserRole.ADMIN, UserRole.SUPER_ADMIN]))


def _render_audit_logs(auth_mgr):
    """Audit logs section"""
    logs = auth_mgr.get_audit_logs(50)
    if not logs:
        st.info("No logs")
        return
    
    for log in logs:
        icon = {'login': '🔐', 'create_user': '➕', 'update_user': '✏️', 'delete_user': '🗑️'}.get(log.get('action'), '📋')
        st.markdown(f"{icon} **{log.get('timestamp', '')[:19]}** - `{log.get('action')}` by {log.get('user_email')}")


# =============================================================================
# SINGLETON
# =============================================================================

_auth_manager_instance = None

def _init_session_state():
    """Initialize session state for authentication"""
    if 'local_users' not in st.session_state:
        st.session_state.local_users = {}
    if 'audit_logs' not in st.session_state:
        st.session_state.audit_logs = []
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False

def get_auth_manager() -> AzureADAuthManager:
    """Get singleton instance"""
    global _auth_manager_instance
    _init_session_state()  # Always ensure session state is initialized
    if _auth_manager_instance is None:
        _auth_manager_instance = AzureADAuthManager()
    return _auth_manager_instance


def init_authentication():
    """Initialize authentication"""
    _init_session_state()
    get_auth_manager()


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    'AzureADAuthManager', 'User', 'AzureADUser', 'UserRole', 'SessionManager',
    'get_auth_manager', 'init_authentication', 'render_login_page', 
    'render_user_menu', 'render_admin_panel', 'require_auth', 'require_permission',
    'require_role', 'check_tab_access', 'ROLE_PERMISSIONS', 'TAB_ACCESS',
]
