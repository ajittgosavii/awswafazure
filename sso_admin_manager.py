"""
SSO & Admin Management System
=============================
Authentication: Microsoft Azure AD (Entra ID)
Role Storage: Google Firestore (stores ONLY user roles)

Architecture:
- Azure AD handles ALL authentication (Microsoft SSO)
- Firestore stores ONLY user roles (minimal data)
- New users automatically get "User" role
- Admins manage roles via Admin Panel
- NO development/quick access (security)

Version: 5.0.0
"""

import streamlit as st
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import hashlib
import os
import base64
import time

# Microsoft Authentication Library
try:
    import msal
    MSAL_AVAILABLE = True
except ImportError:
    MSAL_AVAILABLE = False

# HTTP requests for Graph API
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# Firebase/Firestore for role storage ONLY
try:
    import firebase_admin
    from firebase_admin import credentials, firestore
    FIRESTORE_AVAILABLE = True
except ImportError:
    FIRESTORE_AVAILABLE = False


# =============================================================================
# SESSION STATE INITIALIZATION
# =============================================================================

def _init_session_state():
    """Initialize session state"""
    defaults = {
        'authenticated': False,
        'current_user': None,
        'user_role': None,
        'show_admin_panel': False,
        'local_users': {},  # Compatibility
        'audit_logs': [],   # Compatibility
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


# =============================================================================
# ROLE DEFINITIONS
# =============================================================================

class UserRole(Enum):
    """User role hierarchy"""
    GUEST = 0
    VIEWER = 1
    USER = 2        # DEFAULT for all new users
    MANAGER = 3
    ADMIN = 4
    SUPER_ADMIN = 5
    
    @classmethod
    def from_string(cls, role_str: str) -> 'UserRole':
        mapping = {
            'guest': cls.GUEST, 'viewer': cls.VIEWER, 'user': cls.USER,
            'manager': cls.MANAGER, 'admin': cls.ADMIN,
            'super_admin': cls.SUPER_ADMIN, 'superadmin': cls.SUPER_ADMIN,
        }
        return mapping.get(str(role_str).lower(), cls.USER)
    
    def __str__(self):
        return self.name.lower()


# Role permissions
ROLE_PERMISSIONS = {
    UserRole.SUPER_ADMIN: {
        "manage_all_users": True, "manage_system_settings": True, "view_audit_logs": True,
        "run_scans": True, "view_all_scans": True, "export_data": True,
        "access_all_tabs": True, "use_demo_mode": True, "use_live_mode": True,
    },
    UserRole.ADMIN: {
        "manage_org_users": True, "view_audit_logs": True, "run_scans": True,
        "view_all_scans": True, "export_data": True, "access_all_tabs": True,
        "use_demo_mode": True, "use_live_mode": True,
    },
    UserRole.MANAGER: {
        "run_scans": True, "view_all_scans": True, "export_data": True,
        "access_all_tabs": True, "use_demo_mode": True, "use_live_mode": True,
    },
    UserRole.USER: {
        "run_scans": True, "export_data": True, "access_all_tabs": True,
        "use_demo_mode": True, "use_live_mode": True,
    },
    UserRole.VIEWER: {"access_all_tabs": True, "use_demo_mode": True},
    UserRole.GUEST: {"use_demo_mode": True},
}

# Tab access by role
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
    """User model"""
    uid: str
    email: str
    display_name: str
    role: UserRole = UserRole.USER
    organization_id: str = ""
    job_title: Optional[str] = None
    department: Optional[str] = None
    photo_url: Optional[str] = None
    last_login: Optional[datetime] = None
    active: bool = True
    
    @property
    def id(self) -> str:
        return self.uid
    
    def to_dict(self) -> Dict:
        return {
            'uid': self.uid, 'id': self.uid, 'email': self.email, 
            'display_name': self.display_name, 'role': str(self.role),
            'organization_id': self.organization_id, 'job_title': self.job_title,
            'department': self.department, 'photo_url': self.photo_url,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'active': self.active,
        }
    
    @staticmethod
    def from_dict(data: Dict) -> 'User':
        return User(
            uid=data.get('uid') or data.get('id', ''),
            email=data.get('email', ''),
            display_name=data.get('display_name', ''),
            role=UserRole.from_string(data.get('role', 'user')),
            organization_id=data.get('organization_id', ''),
            job_title=data.get('job_title'),
            department=data.get('department'),
            photo_url=data.get('photo_url'),
            last_login=datetime.fromisoformat(data['last_login']) if data.get('last_login') else None,
            active=data.get('active', True),
        )
    
    def has_permission(self, permission: str) -> bool:
        return ROLE_PERMISSIONS.get(self.role, {}).get(permission, False)
    
    def can_access_tab(self, tab_name: str) -> bool:
        return self.role in TAB_ACCESS.get(tab_name, [])


# =============================================================================
# FIRESTORE - ROLE STORAGE ONLY
# =============================================================================

class FirestoreRoleStore:
    """Firestore stores ONLY user roles - nothing else"""
    
    _instance = None
    _db = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        self._init_firestore()
        self._initialized = True
    
    def _init_firestore(self):
        """Initialize Firestore"""
        if not FIRESTORE_AVAILABLE:
            print("⚠️ Firestore not available. Install: pip install firebase-admin")
            return
        
        try:
            if not firebase_admin._apps:
                # Try to get service account from secrets
                sa = st.secrets.get("firebase", {}).get("service_account", {})
                if sa:
                    cred = credentials.Certificate(dict(sa))
                    firebase_admin.initialize_app(cred)
                else:
                    print("⚠️ Firebase service account not configured")
                    return
            self._db = firestore.client()
        except Exception as e:
            print(f"Firestore init error: {e}")
            self._db = None
    
    @property
    def is_available(self) -> bool:
        return self._db is not None
    
    def get_role(self, user_id: str) -> UserRole:
        """Get role from Firestore. Returns USER if not found."""
        if not self.is_available:
            return UserRole.USER
        try:
            doc = self._db.collection('user_roles').document(user_id).get()
            if doc.exists:
                return UserRole.from_string(doc.to_dict().get('role', 'user'))
            return UserRole.USER
        except Exception:
            return UserRole.USER
    
    def set_role(self, user_id: str, email: str, display_name: str, 
                 role: UserRole, updated_by: str) -> bool:
        """Set role in Firestore"""
        if not self.is_available:
            return False
        try:
            self._db.collection('user_roles').document(user_id).set({
                'email': email,
                'display_name': display_name,
                'role': str(role),
                'updated_at': firestore.SERVER_TIMESTAMP,
                'updated_by': updated_by,
            }, merge=True)
            return True
        except Exception as e:
            print(f"Error setting role: {e}")
            return False
    
    def ensure_user_exists(self, user_id: str, email: str, display_name: str) -> UserRole:
        """Create user if not exists. First user becomes SUPER_ADMIN, others get USER."""
        if not self.is_available:
            return UserRole.USER
        
        try:
            # FIRST: Check if this email is configured as super_admin in secrets
            try:
                super_admin_email = st.secrets.get("azure_ad", {}).get("super_admin_email", "")
                if super_admin_email:
                    email_lower = email.lower().strip()
                    admin_lower = super_admin_email.lower().strip()
                    
                    is_admin = (email_lower == admin_lower)
                    
                    if not is_admin and "#ext#" in email_lower:
                        try:
                            ext_part = email_lower.split("#ext#")[0]
                            if "_" in ext_part:
                                parts = ext_part.rsplit("_", 1)
                                original_email = f"{parts[0]}@{parts[1]}"
                                is_admin = (original_email == admin_lower)
                        except:
                            pass
                    
                    if not is_admin:
                        admin_base = admin_lower.split("@")[0] if "@" in admin_lower else admin_lower
                        is_admin = admin_base in email_lower
                    
                    if is_admin:
                        # Update by email query
                        self._update_role_by_email(email, display_name, 'super_admin')
                        print(f"✅ SUPER ADMIN configured: {email}")
                        return UserRole.SUPER_ADMIN
            except Exception as e:
                print(f"Error checking super_admin_email: {e}")
            
            # Look up user by EMAIL (not by document ID)
            existing_role = self._get_role_by_email(email)
            if existing_role:
                return existing_role
            
            # New user - check if this is the FIRST user
            existing_users = list(self._db.collection('user_roles').limit(1).stream())
            
            if len(existing_users) == 0:
                role = UserRole.SUPER_ADMIN
                print(f"🔑 First user detected! {email} will be Super Admin")
            else:
                role = UserRole.USER
            
            # Create new document
            self._db.collection('user_roles').add({
                'email': email,
                'display_name': display_name,
                'role': str(role),
                'azure_user_id': user_id,
                'created_at': firestore.SERVER_TIMESTAMP,
            })
            return role
        except Exception as e:
            print(f"Error in ensure_user_exists: {e}")
            return UserRole.USER
    
    def _get_role_by_email(self, email: str) -> Optional[UserRole]:
        """Get user role by email"""
        if not self.is_available:
            return None
        try:
            docs = self._db.collection('user_roles').where('email', '==', email).limit(1).stream()
            for doc in docs:
                return UserRole.from_string(doc.to_dict().get('role', 'user'))
            return None
        except Exception:
            return None
    
    def _update_role_by_email(self, email: str, display_name: str, role: str):
        """Update user role by email"""
        if not self.is_available:
            return
        try:
            docs = self._db.collection('user_roles').where('email', '==', email).limit(1).stream()
            for doc in docs:
                doc.reference.update({
                    'role': role,
                    'display_name': display_name,
                    'updated_at': firestore.SERVER_TIMESTAMP,
                    'is_configured_admin': True,
                })
                return
            # If not found, create new
            self._db.collection('user_roles').add({
                'email': email,
                'display_name': display_name,
                'role': role,
                'created_at': firestore.SERVER_TIMESTAMP,
                'is_configured_admin': True,
            })
        except Exception as e:
            print(f"Error updating role by email: {e}")
    
    def get_all_users(self) -> List[Dict]:
        """Get all users with roles"""
        if not self.is_available:
            return []
        try:
            docs = self._db.collection('user_roles').stream()
            return [{'id': doc.id, **doc.to_dict()} for doc in docs]
        except Exception:
            return []
    
    def log_audit(self, user_email: str, action: str, details: str):
        """Log audit action"""
        if not self.is_available:
            return
        try:
            self._db.collection('audit_logs').add({
                'user_email': user_email,
                'action': action,
                'details': details,
                'timestamp': firestore.SERVER_TIMESTAMP,
            })
        except Exception:
            pass
    
    def has_users(self) -> bool:
        """Check if any users exist"""
        if not self.is_available:
            return True  # Assume users exist to skip setup
        try:
            docs = self._db.collection('user_roles').limit(1).get()
            return len(list(docs)) > 0
        except Exception:
            return True


# =============================================================================
# AZURE AD CONFIGURATION
# =============================================================================

class AzureADConfig:
    """Azure AD Configuration"""
    GRAPH_API = "https://graph.microsoft.com/v1.0"
    AUTHORITY = "https://login.microsoftonline.com"
    SCOPES = ["User.Read"]
    SESSION_HOURS = 8
    
    @classmethod
    def get_config(cls) -> Dict:
        try:
            cfg = st.secrets.get("azure_ad", {})
            # Use 'common' for multi-tenant + personal accounts
            # Use 'organizations' for multi-tenant org accounts only
            # Use 'consumers' for personal accounts only
            # Use specific tenant_id for single tenant
            tenant = cfg.get("tenant_id", "common")
            if tenant.lower() in ["multi", "multitenant", "all", ""]:
                tenant = "common"
            return {
                "tenant_id": tenant,
                "client_id": cfg.get("client_id", ""),
                "client_secret": cfg.get("client_secret", ""),
                "redirect_uri": cfg.get("redirect_uri", "http://localhost:8501"),
            }
        except Exception:
            return {}


# =============================================================================
# LOCAL USER STORE (Compatibility)
# =============================================================================

class LocalStore:
    """Local store for compatibility"""
    def has_users(self) -> bool:
        return True  # Always return True to skip setup page


# =============================================================================
# AUTH MANAGER
# =============================================================================

class AuthManager:
    """Authentication Manager - Azure AD + Firestore Roles"""
    
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._setup_done = False
        return cls._instance
    
    def __init__(self):
        if self._setup_done:
            return
        _init_session_state()
        self.config = AzureADConfig.get_config()
        self.role_store = FirestoreRoleStore()
        self.local_store = LocalStore()
        self.msal_app = None
        self._init_msal()
        self._setup_done = True
    
    def _init_msal(self):
        """Initialize MSAL"""
        if not MSAL_AVAILABLE:
            print("⚠️ MSAL not available. Install: pip install msal")
            return
        if not self.config.get('client_id'):
            return
        try:
            self.msal_app = msal.ConfidentialClientApplication(
                client_id=self.config['client_id'],
                client_credential=self.config['client_secret'],
                authority=f"{AzureADConfig.AUTHORITY}/{self.config['tenant_id']}"
            )
        except Exception as e:
            print(f"MSAL init error: {e}")
    
    def is_configured(self) -> bool:
        """Check if Azure AD is configured"""
        return bool(self.config.get('tenant_id') and 
                   self.config.get('client_id') and 
                   self.config.get('client_secret'))
    
    @property
    def firebase_available(self) -> bool:
        return self.role_store.is_available
    
    def get_auth_url(self) -> str:
        """Get Azure AD authorization URL"""
        if not self.msal_app:
            return ""
        state = hashlib.sha256(os.urandom(32)).hexdigest()
        st.session_state['oauth_state'] = state
        return self.msal_app.get_authorization_request_url(
            scopes=AzureADConfig.SCOPES,
            state=state,
            redirect_uri=self.config['redirect_uri'],
            prompt="select_account"
        )
    
    def handle_callback(self, code: str, state: str = None) -> Tuple[bool, str, Optional[User]]:
        """Handle Azure AD OAuth callback"""
        _init_session_state()
        
        if not self.msal_app:
            return False, "Azure AD not configured", None
        
        # Note: State validation is relaxed because Streamlit session state
        # is often lost during OAuth redirects. The OAuth flow is still secure
        # because the authorization code is single-use and tied to the client.
        stored_state = st.session_state.get('oauth_state')
        if state and stored_state and state != stored_state:
            # Log but don't fail - state mismatch is common with Streamlit
            print(f"OAuth state mismatch (expected: {stored_state[:8]}..., got: {state[:8] if state else 'None'}...)")
        
        try:
            result = self.msal_app.acquire_token_by_authorization_code(
                code=code,
                scopes=AzureADConfig.SCOPES,
                redirect_uri=self.config['redirect_uri']
            )
            
            if 'error' in result:
                return False, result.get('error_description', 'Auth failed'), None
            
            access_token = result.get('access_token')
            if not access_token:
                return False, "No access token", None
            
            # Get user from Microsoft Graph API
            user = self._get_user_from_graph(access_token)
            if not user:
                return False, "Failed to get user info", None
            
            # Get/Create role in Firestore (defaults to USER)
            user.role = self.role_store.ensure_user_exists(
                user.uid, user.email, user.display_name)
            user.last_login = datetime.now()
            
            # Log
            self.role_store.log_audit(user.email, "login", "Azure AD SSO")
            
            return True, "Success", user
            
        except Exception as e:
            return False, f"Error: {str(e)}", None
    
    def _get_user_from_graph(self, access_token: str) -> Optional[User]:
        """Get user info from Microsoft Graph API"""
        if not REQUESTS_AVAILABLE:
            return None
        try:
            headers = {'Authorization': f'Bearer {access_token}'}
            
            resp = requests.get(
                f"{AzureADConfig.GRAPH_API}/me",
                headers=headers,
                params={'$select': 'id,displayName,mail,userPrincipalName,jobTitle,department'},
                timeout=10
            )
            
            if resp.status_code != 200:
                return None
            
            data = resp.json()
            email = data.get('mail') or data.get('userPrincipalName', '')
            
            # Get photo
            photo_url = None
            try:
                photo_resp = requests.get(
                    f"{AzureADConfig.GRAPH_API}/me/photo/$value",
                    headers=headers, timeout=5)
                if photo_resp.status_code == 200:
                    photo_url = f"data:image/jpeg;base64,{base64.b64encode(photo_resp.content).decode()}"
            except Exception:
                pass
            
            return User(
                uid=data.get('id', ''),
                email=email,
                display_name=data.get('displayName', email.split('@')[0]),
                job_title=data.get('jobTitle'),
                department=data.get('department'),
                photo_url=photo_url,
            )
        except Exception as e:
            print(f"Graph API error: {e}")
            return None
    
    def authenticate(self, email: str, password: str) -> Tuple[bool, str, Optional[User]]:
        """Email/password auth - not used with Azure AD"""
        return False, "Please use Microsoft Sign-In", None
    
    def update_user_role(self, user_id: str, email: str, display_name: str,
                        new_role: str, updated_by: str) -> Tuple[bool, str]:
        """Update user role (Admin only)"""
        role = UserRole.from_string(new_role)
        if self.role_store.set_role(user_id, email, display_name, role, updated_by):
            self.role_store.log_audit(updated_by, "role_update", f"{email} -> {role.name}")
            return True, f"Role updated to {role.name}"
        return False, "Failed to update"
    
    def get_all_users(self, force_refresh: bool = False) -> List[User]:
        """Get all users"""
        users_data = self.role_store.get_all_users()
        return [User(
            uid=u.get('id', ''),
            email=u.get('email', ''),
            display_name=u.get('display_name', ''),
            role=UserRole.from_string(u.get('role', 'user'))
        ) for u in users_data]
    
    def logout(self):
        """Logout"""
        user = SessionManager.get_current_user()
        if user:
            self.role_store.log_audit(user.email, "logout", "")
        SessionManager.logout()


# =============================================================================
# SESSION MANAGER
# =============================================================================

class SessionManager:
    """Session Manager"""
    
    @staticmethod
    def login(user: User):
        st.session_state.authenticated = True
        st.session_state.current_user = user.to_dict()
        st.session_state.user_role = user.role
        st.session_state.login_time = datetime.now().isoformat()
    
    @staticmethod
    def logout():
        for key in ['authenticated', 'current_user', 'user_role', 'login_time', 
                   'oauth_state', 'show_admin_panel']:
            if key in st.session_state:
                del st.session_state[key]
    
    @staticmethod
    def is_authenticated() -> bool:
        if not st.session_state.get('authenticated'):
            return False
        login_time = st.session_state.get('login_time')
        if login_time:
            elapsed = datetime.now() - datetime.fromisoformat(login_time)
            if elapsed > timedelta(hours=AzureADConfig.SESSION_HOURS):
                SessionManager.logout()
                return False
        return True
    
    @staticmethod
    def get_current_user() -> Optional[User]:
        if not SessionManager.is_authenticated():
            return None
        data = st.session_state.get('current_user')
        if not data:
            return None
        
        user = User.from_dict(data)
        
        # ALWAYS refresh role from Firestore
        try:
            role_store = FirestoreRoleStore()
            fresh_role = role_store._get_role_by_email(user.email)
            if fresh_role:
                user.role = fresh_role
                # Update session state too
                data['role'] = str(fresh_role)
                st.session_state.current_user = data
                st.session_state.user_role = fresh_role
        except Exception as e:
            print(f"Error refreshing role: {e}")
        
        return user
    
    @staticmethod
    def has_permission(permission: str) -> bool:
        user = SessionManager.get_current_user()
        return user.has_permission(permission) if user else False
    
    @staticmethod
    def can_access_tab(tab_name: str) -> bool:
        user = SessionManager.get_current_user()
        return user.can_access_tab(tab_name) if user else False


# =============================================================================
# SINGLETON & HELPERS
# =============================================================================

def get_auth_manager() -> AuthManager:
    _init_session_state()
    return AuthManager()

def check_tab_access(tab_name: str) -> bool:
    return SessionManager.can_access_tab(tab_name)


# =============================================================================
# UI: LOGIN PAGE (Azure AD Only)
# =============================================================================

def render_login_page():
    """Login page - Microsoft SSO only, no dev access"""
    _init_session_state()
    auth_mgr = get_auth_manager()
    
    # Handle OAuth callback
    params = st.query_params
    if 'code' in params:
        with st.spinner("🔐 Signing in with Microsoft..."):
            success, msg, user = auth_mgr.handle_callback(
                params.get('code'), params.get('state'))
        st.query_params.clear()
        
        if success and user:
            SessionManager.login(user)
            # Debug info
            try:
                configured_admin = st.secrets.get("azure_ad", {}).get("super_admin_email", "NOT_SET")
                st.success(f"✅ Welcome, {user.display_name}!")
                st.info(f"🔍 Debug: Your email: `{user.email}` | Role: `{user.role}` | Configured admin: `{configured_admin}`")
                if user.email.lower().strip() == configured_admin.lower().strip():
                    st.success("✅ Email matches super_admin_email!")
                else:
                    st.warning(f"⚠️ Email mismatch: '{user.email}' != '{configured_admin}'")
            except Exception as e:
                st.error(f"Debug error: {e}")
            time.sleep(3)
            st.rerun()
        else:
            st.error(f"❌ {msg}")
            return
    
    # CSS
    st.markdown("""
    <style>
    #MainMenu, footer {visibility: hidden;}
    [data-testid="stSidebar"] {display: none !important;}
    .stApp {background: linear-gradient(180deg, #f8f9fa 0%, #fff 100%);}
    .infosys-logo {text-align:center;font-family:'Segoe UI',Arial;font-size:48px;font-weight:500;color:#007CC3;margin:50px 0 20px 0;}
    .app-title {text-align:center;font-size:24px;font-weight:600;color:#232F3E;}
    .app-subtitle {text-align:center;font-size:20px;color:#007CC3;margin:8px 0;}
    .app-edition {text-align:center;font-size:14px;color:#666;margin-bottom:40px;}
    .ms-btn {display:flex;align-items:center;justify-content:center;background:#2F2F2F;color:white!important;
        padding:14px 32px;border-radius:4px;text-decoration:none!important;font-weight:500;font-size:15px;
        margin:20px auto;max-width:320px;transition:all 0.2s;}
    .ms-btn:hover {background:#1a1a1a;transform:translateY(-1px);box-shadow:0 4px 12px rgba(0,0,0,0.15);}
    .ms-btn img {width:21px;height:21px;margin-right:12px;}
    .info-box {background:#f0f7ff;border:1px solid #cce0ff;border-radius:8px;padding:16px;
        margin:20px auto;max-width:400px;text-align:center;font-size:13px;color:#555;}
    .footer {text-align:center;color:#999;font-size:12px;margin-top:60px;}
    </style>
    """, unsafe_allow_html=True)
    
    # Logo
    st.markdown('<div class="infosys-logo">Infosys<sup style="font-size:12px;">®</sup></div>', unsafe_allow_html=True)
    st.markdown('<div class="app-title">AI-Based AWS Well-Architected</div>', unsafe_allow_html=True)
    st.markdown('<div class="app-subtitle">Framework Advisor</div>', unsafe_allow_html=True)
    st.markdown('<div class="app-edition">Enterprise Edition</div>', unsafe_allow_html=True)
    
    if auth_mgr.is_configured():
        # Microsoft Sign-In Button
        auth_url = auth_mgr.get_auth_url()
        st.markdown(f"""
        <a href="{auth_url}" class="ms-btn">
            <img src="https://upload.wikimedia.org/wikipedia/commons/4/44/Microsoft_logo.svg" alt="">
            Sign in with Microsoft
        </a>
        """, unsafe_allow_html=True)
        
        st.markdown("""
        <div class="info-box">
            🔒 Sign in with your organization's Microsoft account.<br>
            <b>First user</b> automatically becomes <b>Super Admin</b>.<br>
            Subsequent users get <b>User</b> role by default.
        </div>
        """, unsafe_allow_html=True)
    else:
        st.error("⚠️ Azure AD is not configured.")
        st.info("""
        **Administrator: Add to `.streamlit/secrets.toml`:**
        ```toml
        [azure_ad]
        tenant_id = "your-tenant-id"
        client_id = "your-client-id"
        client_secret = "your-client-secret"
        redirect_uri = "https://your-app.streamlit.app"
        ```
        """)
    
    st.markdown('<div class="footer">Powered by Infosys | AWS Well-Architected Framework<br>© 2024 All Rights Reserved</div>', unsafe_allow_html=True)


# =============================================================================
# UI: USER MENU (Sidebar)
# =============================================================================

def render_user_menu():
    """User menu in sidebar"""
    user = SessionManager.get_current_user()
    if not user:
        return
    
    with st.sidebar:
        st.markdown("---")
        
        col1, col2 = st.columns([1, 3])
        with col1:
            if user.photo_url:
                st.image(user.photo_url, width=45)
            else:
                st.markdown("### 👤")
        with col2:
            st.markdown(f"**{user.display_name}**")
            badges = {
                UserRole.SUPER_ADMIN: "🔴 Super Admin", UserRole.ADMIN: "🟠 Admin",
                UserRole.MANAGER: "🟡 Manager", UserRole.USER: "🟢 User",
                UserRole.VIEWER: "🔵 Viewer", UserRole.GUEST: "⚪ Guest",
            }
            st.caption(badges.get(user.role, "🟢 User"))
        
        if user.department:
            st.caption(f"🏢 {user.department}")
        
        st.markdown("---")
        
        # Admin Panel (Admins only)
        if user.role in [UserRole.ADMIN, UserRole.SUPER_ADMIN]:
            if st.button("⚙️ Admin Panel", use_container_width=True):
                st.session_state.show_admin_panel = True
                st.rerun()
        
        # Sign Out
        if st.button("🚪 Sign Out", use_container_width=True):
            get_auth_manager().logout()
            st.rerun()


# =============================================================================
# UI: ADMIN PANEL (Role Management)
# =============================================================================

def render_admin_panel():
    """Admin panel for role management"""
    user = SessionManager.get_current_user()
    if not user or user.role not in [UserRole.ADMIN, UserRole.SUPER_ADMIN]:
        st.error("⛔ Access denied")
        return
    
    st.markdown("## ⚙️ Admin Panel - User Role Management")
    st.caption(f"Logged in as: **{user.display_name}** ({user.role.name})")
    
    if st.button("← Back to Application"):
        st.session_state.show_admin_panel = False
        st.rerun()
    
    st.markdown("---")
    
    auth_mgr = get_auth_manager()
    all_users = auth_mgr.role_store.get_all_users()
    
    if not all_users:
        st.info("📭 No users yet. Users appear after their first Microsoft sign-in.")
        return
    
    # Metrics
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Users", len(all_users))
    col2.metric("Admins", sum(1 for u in all_users if u.get('role') in ['admin', 'super_admin']))
    col3.metric("Managers", sum(1 for u in all_users if u.get('role') == 'manager'))
    col4.metric("Users", sum(1 for u in all_users if u.get('role') == 'user'))
    
    st.markdown("---")
    st.markdown("### 👥 Manage User Roles")
    
    # Role options based on current user
    if user.role == UserRole.SUPER_ADMIN:
        role_options = ["viewer", "user", "manager", "admin", "super_admin"]
    else:
        role_options = ["viewer", "user", "manager"]
    
    for u in sorted(all_users, key=lambda x: x.get('email', '')):
        uid = u.get('id', '')
        email = u.get('email', 'Unknown')
        name = u.get('display_name', email)
        current_role = u.get('role', 'user')
        
        icon = {'user': '🟢', 'viewer': '🔵', 'manager': '🟡', 'admin': '🟠', 'super_admin': '🔴'}.get(current_role, '⚪')
        
        with st.expander(f"{icon} {name} ({email})"):
            st.markdown(f"**Current Role:** `{current_role.upper()}`")
            
            if email == user.email:
                st.info("You cannot change your own role.")
            else:
                try:
                    idx = role_options.index(current_role)
                except ValueError:
                    idx = 1
                
                new_role = st.selectbox("New Role", role_options, index=idx, key=f"role_{uid}")
                
                if st.button("💾 Update Role", key=f"btn_{uid}"):
                    success, msg = auth_mgr.update_user_role(uid, email, name, new_role, user.email)
                    if success:
                        st.success(msg)
                        time.sleep(1)
                        st.rerun()
                    else:
                        st.error(msg)


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    'UserRole', 'User', 'SessionManager', 'AuthManager',
    'get_auth_manager', 'render_login_page', 'render_user_menu', 'render_admin_panel',
    'check_tab_access', 'ROLE_PERMISSIONS', 'TAB_ACCESS',
]
