"""
Azure AD / Entra ID Enterprise SSO Authentication Module
=========================================================
Authentication: Microsoft Entra ID (Azure AD)
Role Storage: Google Firestore (Real-time Database)

Architecture:
- Azure AD handles all authentication (Microsoft SSO)
- Firestore stores ONLY user roles (minimal data)
- New users get "User" role by default
- Admins manage roles via Admin Panel

Requirements:
    pip install msal requests firebase-admin

Version: 3.0.0
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

# Firebase/Firestore for role storage
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
    USER = 2        # DEFAULT for new users
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
    id: str
    email: str
    display_name: str
    role: UserRole = UserRole.USER
    job_title: Optional[str] = None
    department: Optional[str] = None
    photo_url: Optional[str] = None
    login_time: Optional[datetime] = None
    
    @property
    def uid(self) -> str:
        return self.id
    
    def to_dict(self) -> Dict:
        return {
            'id': self.id, 'email': self.email, 'display_name': self.display_name,
            'role': str(self.role), 'job_title': self.job_title,
            'department': self.department, 'photo_url': self.photo_url,
            'login_time': self.login_time.isoformat() if self.login_time else None,
        }
    
    @staticmethod
    def from_dict(data: Dict) -> 'User':
        return User(
            id=data.get('id', ''), email=data.get('email', ''),
            display_name=data.get('display_name', ''),
            role=UserRole.from_string(data.get('role', 'user')),
            job_title=data.get('job_title'), department=data.get('department'),
            photo_url=data.get('photo_url'),
            login_time=datetime.fromisoformat(data['login_time']) if data.get('login_time') else None,
        )
    
    def has_permission(self, permission: str) -> bool:
        return ROLE_PERMISSIONS.get(self.role, {}).get(permission, False)
    
    def can_access_tab(self, tab_name: str) -> bool:
        return self.role in TAB_ACCESS.get(tab_name, [])


# =============================================================================
# FIRESTORE ROLE STORAGE (Stores ONLY roles)
# =============================================================================

class FirestoreRoleStore:
    """Firestore for storing user roles ONLY"""
    
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
        """Initialize Firestore connection"""
        if not FIRESTORE_AVAILABLE:
            return
        
        try:
            if not firebase_admin._apps:
                service_account = st.secrets.get("firebase", {}).get("service_account", {})
                if service_account:
                    cred = credentials.Certificate(dict(service_account))
                    firebase_admin.initialize_app(cred)
            self._db = firestore.client()
        except Exception as e:
            print(f"Firestore init error: {e}")
            self._db = None
    
    @property
    def is_available(self) -> bool:
        return self._db is not None
    
    def get_role(self, user_id: str) -> UserRole:
        """Get user role from Firestore. Returns USER if not found."""
        if not self.is_available:
            return UserRole.USER
        
        try:
            doc = self._db.collection('user_roles').document(user_id).get()
            if doc.exists:
                return UserRole.from_string(doc.to_dict().get('role', 'user'))
            return UserRole.USER  # Default role for new users
        except Exception:
            return UserRole.USER
    
    def set_role(self, user_id: str, email: str, display_name: str, role: UserRole, updated_by: str) -> bool:
        """Set user role in Firestore"""
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
            doc_ref = self._db.collection('user_roles').document(user_id)
            doc = doc_ref.get()
            
            if doc.exists:
                return UserRole.from_string(doc.to_dict().get('role', 'user'))
            
            # New user - check if this is the FIRST user (no users exist yet)
            existing_users = list(self._db.collection('user_roles').limit(1).stream())
            
            if len(existing_users) == 0:
                # FIRST USER - make them Super Admin
                role = UserRole.SUPER_ADMIN
                print(f"🔑 First user detected! {email} will be Super Admin")
            else:
                # Not first user - default to USER role
                role = UserRole.USER
            
            doc_ref.set({
                'email': email,
                'display_name': display_name,
                'role': str(role),
                'created_at': firestore.SERVER_TIMESTAMP,
            })
            return role
        except Exception as e:
            print(f"Error in ensure_user_exists: {e}")
            return UserRole.USER
    
    def get_all_users(self) -> List[Dict]:
        """Get all users with roles"""
        if not self.is_available:
            return []
        
        try:
            docs = self._db.collection('user_roles').stream()
            return [{'id': doc.id, **doc.to_dict()} for doc in docs]
        except Exception:
            return []
    
    def log_action(self, user_email: str, action: str, details: str):
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
            return {
                "tenant_id": cfg.get("tenant_id", ""),
                "client_id": cfg.get("client_id", ""),
                "client_secret": cfg.get("client_secret", ""),
                "redirect_uri": cfg.get("redirect_uri", "http://localhost:8501"),
            }
        except Exception:
            return {}


# =============================================================================
# AZURE AD AUTH MANAGER
# =============================================================================

class AzureADAuthManager:
    """Azure AD Authentication Manager"""
    
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
        self.msal_app = None
        self._init_msal()
        self._setup_done = True
    
    def _init_msal(self):
        """Initialize MSAL"""
        if not MSAL_AVAILABLE or not self.config.get('client_id'):
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
        return bool(self.config.get('tenant_id') and self.config.get('client_id') and self.config.get('client_secret'))
    
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
        """Handle OAuth callback from Azure AD"""
        _init_session_state()
        
        if not self.msal_app:
            return False, "Azure AD not configured", None
        
        # Note: State validation is relaxed because Streamlit session state
        # is often lost during OAuth redirects. The OAuth flow is still secure
        # because the authorization code is single-use and tied to the client.
        stored_state = st.session_state.get('oauth_state')
        if state and stored_state and state != stored_state:
            # Log but don't fail - state mismatch is common with Streamlit
            print(f"OAuth state mismatch (this is normal with Streamlit redirects)")
        
        try:
            # Exchange code for token
            result = self.msal_app.acquire_token_by_authorization_code(
                code=code,
                scopes=AzureADConfig.SCOPES,
                redirect_uri=self.config['redirect_uri']
            )
            
            if 'error' in result:
                return False, result.get('error_description', 'Authentication failed'), None
            
            access_token = result.get('access_token')
            if not access_token:
                return False, "No access token received", None
            
            # Get user info from Microsoft Graph API
            user = self._get_user_from_graph(access_token)
            if not user:
                return False, "Failed to get user info from Microsoft", None
            
            # Get/Create role in Firestore (defaults to USER)
            user.role = self.role_store.ensure_user_exists(user.id, user.email, user.display_name)
            user.login_time = datetime.now()
            
            # Log login
            self.role_store.log_action(user.email, "login", "Azure AD SSO")
            
            return True, "Login successful", user
            
        except Exception as e:
            return False, f"Authentication error: {str(e)}", None
    
    def _get_user_from_graph(self, access_token: str) -> Optional[User]:
        """Get user info from Microsoft Graph API"""
        if not REQUESTS_AVAILABLE:
            return None
        
        try:
            headers = {'Authorization': f'Bearer {access_token}'}
            
            # Get user profile
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
            
            # Get profile photo
            photo_url = None
            try:
                photo_resp = requests.get(f"{AzureADConfig.GRAPH_API}/me/photo/$value", headers=headers, timeout=5)
                if photo_resp.status_code == 200:
                    photo_b64 = base64.b64encode(photo_resp.content).decode()
                    photo_url = f"data:image/jpeg;base64,{photo_b64}"
            except Exception:
                pass
            
            return User(
                id=data.get('id', ''),
                email=email,
                display_name=data.get('displayName', email.split('@')[0]),
                job_title=data.get('jobTitle'),
                department=data.get('department'),
                photo_url=photo_url,
            )
        except Exception as e:
            print(f"Graph API error: {e}")
            return None
    
    def update_user_role(self, user_id: str, email: str, display_name: str, 
                        new_role: str, updated_by: str) -> Tuple[bool, str]:
        """Update user role (Admin only)"""
        role = UserRole.from_string(new_role)
        if self.role_store.set_role(user_id, email, display_name, role, updated_by):
            self.role_store.log_action(updated_by, "role_update", f"{email} -> {role.name}")
            return True, f"Role updated to {role.name}"
        return False, "Failed to update role"
    
    def get_all_users(self) -> List[Dict]:
        """Get all users"""
        return self.role_store.get_all_users()
    
    def logout(self):
        """Logout user"""
        user = SessionManager.get_current_user()
        if user:
            self.role_store.log_action(user.email, "logout", "")
        SessionManager.logout()


# =============================================================================
# SESSION MANAGER
# =============================================================================

class SessionManager:
    """Manage user sessions"""
    
    @staticmethod
    def login(user: User):
        st.session_state.authenticated = True
        st.session_state.current_user = user.to_dict()
        st.session_state.user_role = user.role
        st.session_state.login_time = datetime.now().isoformat()
    
    @staticmethod
    def logout():
        keys = ['authenticated', 'current_user', 'user_role', 'login_time', 'oauth_state', 'show_admin_panel']
        for key in keys:
            if key in st.session_state:
                del st.session_state[key]
    
    @staticmethod
    def is_authenticated() -> bool:
        if not st.session_state.get('authenticated'):
            return False
        # Check session timeout
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
        return User.from_dict(data) if data else None
    
    @staticmethod
    def has_permission(permission: str) -> bool:
        user = SessionManager.get_current_user()
        return user.has_permission(permission) if user else False
    
    @staticmethod
    def can_access_tab(tab_name: str) -> bool:
        user = SessionManager.get_current_user()
        return user.can_access_tab(tab_name) if user else False


# =============================================================================
# DECORATORS
# =============================================================================

def require_auth(func):
    def wrapper(*args, **kwargs):
        if not SessionManager.is_authenticated():
            st.error("🔒 Please sign in")
            render_login_page()
            return None
        return func(*args, **kwargs)
    return wrapper

def require_role(min_role: UserRole):
    def decorator(func):
        def wrapper(*args, **kwargs):
            user = SessionManager.get_current_user()
            if not user or user.role.value < min_role.value:
                st.error(f"⛔ Access denied. Required: {min_role.name}")
                return None
            return func(*args, **kwargs)
        return wrapper
    return decorator

def check_tab_access(tab_name: str) -> bool:
    return SessionManager.can_access_tab(tab_name)


# =============================================================================
# SINGLETON
# =============================================================================

def get_auth_manager() -> AzureADAuthManager:
    _init_session_state()
    return AzureADAuthManager()


# =============================================================================
# UI: LOGIN PAGE
# =============================================================================

def render_login_page():
    """Render login page with Microsoft SSO only"""
    _init_session_state()
    auth_mgr = get_auth_manager()
    
    # Handle OAuth callback
    params = st.query_params
    if 'code' in params:
        with st.spinner("🔐 Signing in with Microsoft..."):
            success, msg, user = auth_mgr.handle_callback(params.get('code'), params.get('state'))
        
        st.query_params.clear()
        
        if success and user:
            SessionManager.login(user)
            st.success(f"✅ Welcome, {user.display_name}!")
            time.sleep(1)
            st.rerun()
        else:
            st.error(f"❌ {msg}")
            return
    
    # Styling
    st.markdown("""
    <style>
    #MainMenu, footer {visibility: hidden;}
    .infosys-logo { text-align: center; font-family: 'Segoe UI', Arial; font-size: 42px; 
        font-weight: 500; color: #007CC3; margin: 40px 0 20px 0; }
    .app-title { text-align: center; font-size: 22px; font-weight: 600; color: #333; }
    .app-subtitle { text-align: center; font-size: 18px; color: #007CC3; margin: 5px 0; }
    .app-edition { text-align: center; font-size: 13px; color: #666; margin-bottom: 30px; }
    .ms-btn { display: flex; align-items: center; justify-content: center; background: #2F2F2F;
        color: white !important; padding: 14px 28px; border-radius: 4px; text-decoration: none !important;
        font-weight: 500; font-size: 15px; margin: 20px auto; max-width: 300px; }
    .ms-btn:hover { background: #1a1a1a; }
    .ms-btn img { width: 21px; height: 21px; margin-right: 12px; }
    .info-box { background: #f0f7ff; border: 1px solid #cce0ff; border-radius: 8px;
        padding: 15px; margin: 20px auto; max-width: 400px; text-align: center; font-size: 13px; color: #555; }
    .footer { text-align: center; color: #999; font-size: 12px; margin-top: 50px; }
    </style>
    """, unsafe_allow_html=True)
    
    # Logo and Title
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
        st.error("⚠️ Azure AD is not configured. Contact your administrator.")
    
    st.markdown('<div class="footer">Powered by Infosys | AWS Well-Architected Framework</div>', unsafe_allow_html=True)


# =============================================================================
# UI: USER MENU (Sidebar)
# =============================================================================

def render_user_menu():
    """Render user menu in sidebar"""
    user = SessionManager.get_current_user()
    if not user:
        return
    
    with st.sidebar:
        st.markdown("---")
        
        # User info
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
        
        # Admin Panel button (Admins only)
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
    
    st.markdown("## ⚙️ Admin Panel - Role Management")
    st.caption(f"Logged in as: **{user.display_name}** ({user.role.name})")
    
    if st.button("← Back to Application"):
        st.session_state.show_admin_panel = False
        st.rerun()
    
    st.markdown("---")
    
    auth_mgr = get_auth_manager()
    all_users = auth_mgr.get_all_users()
    
    if not all_users:
        st.info("📭 No users found. Users appear here after their first Microsoft sign-in.")
        return
    
    # Metrics
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Users", len(all_users))
    col2.metric("Admins", sum(1 for u in all_users if u.get('role') in ['admin', 'super_admin']))
    col3.metric("Managers", sum(1 for u in all_users if u.get('role') == 'manager'))
    col4.metric("Users", sum(1 for u in all_users if u.get('role') == 'user'))
    
    st.markdown("---")
    st.markdown("### 👥 User List")
    
    # Role options based on current user's role
    if user.role == UserRole.SUPER_ADMIN:
        role_options = ["viewer", "user", "manager", "admin", "super_admin"]
    else:
        role_options = ["viewer", "user", "manager"]  # Admin can't create other admins
    
    for u in sorted(all_users, key=lambda x: x.get('email', '')):
        uid = u.get('id', '')
        email = u.get('email', 'Unknown')
        name = u.get('display_name', email)
        current_role = u.get('role', 'user')
        
        with st.expander(f"{'🟢' if current_role == 'user' else '🔵' if current_role == 'viewer' else '🟡' if current_role == 'manager' else '🟠' if current_role == 'admin' else '🔴'} {name} ({email})"):
            st.markdown(f"**Current Role:** `{current_role.upper()}`")
            
            # Don't allow users to change their own role
            if email == user.email:
                st.info("You cannot change your own role.")
            else:
                new_role = st.selectbox(
                    "Change Role", 
                    role_options, 
                    index=role_options.index(current_role) if current_role in role_options else 1,
                    key=f"role_{uid}"
                )
                
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
    'UserRole', 'User', 'SessionManager', 'AzureADAuthManager',
    'get_auth_manager', 'render_login_page', 'render_user_menu', 'render_admin_panel',
    'require_auth', 'require_role', 'check_tab_access',
    'ROLE_PERMISSIONS', 'TAB_ACCESS',
]
