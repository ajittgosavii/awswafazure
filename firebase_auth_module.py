"""
Firebase Authentication Module for AWS WAF Advisor
Provides SSO with Google Firebase and Admin User Management

Features:
- Google Sign-In via Firebase
- Email/Password authentication
- Admin user management (create, disable, delete users)
- Role-based access control (Admin, User, Viewer)
- User profile management
- Session management
"""

import streamlit as st
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import json
import hashlib
import uuid
import requests  # For Firebase REST API calls

# Firebase Admin SDK (install: pip install firebase-admin)
try:
    import firebase_admin
    from firebase_admin import credentials, auth, firestore
    FIREBASE_ADMIN_AVAILABLE = True
except ImportError:
    FIREBASE_ADMIN_AVAILABLE = False

# PyrebaseX for client-side (install: pip install pyrebasex)
try:
    import pyrebasex
    PYREBASE_AVAILABLE = True
except ImportError:
    PYREBASE_AVAILABLE = False

class UserRole:
    """User role definitions"""
    ADMIN = "admin"
    USER = "user"
    VIEWER = "viewer"
    
    @staticmethod
    def get_all_roles():
        return [UserRole.ADMIN, UserRole.USER, UserRole.VIEWER]
    
    @staticmethod
    def get_permissions(role: str) -> Dict[str, bool]:
        """Get permissions for each role"""
        permissions = {
            UserRole.ADMIN: {
                "create_users": True,
                "delete_users": True,
                "modify_users": True,
                "view_all_assessments": True,
                "delete_assessments": True,
                "manage_settings": True,
                "run_aws_scans": True,
                "export_data": True
            },
            UserRole.USER: {
                "create_users": False,
                "delete_users": False,
                "modify_users": False,
                "view_all_assessments": False,
                "delete_assessments": False,
                "manage_settings": False,
                "run_aws_scans": True,
                "export_data": True
            },
            UserRole.VIEWER: {
                "create_users": False,
                "delete_users": False,
                "modify_users": False,
                "view_all_assessments": False,
                "delete_assessments": False,
                "manage_settings": False,
                "run_aws_scans": False,
                "export_data": False
            }
        }
        return permissions.get(role, permissions[UserRole.VIEWER])

class FirebaseAuthManager:
    """Manage Firebase authentication and user operations"""
    
    def __init__(self):
        self.initialized = False
        self.firebase_app = None
        self.db = None
        self.auth_client = None
        
    def initialize_firebase(self, config: Dict) -> Tuple[bool, str]:
        """
        Initialize Firebase with service account credentials
        
        Args:
            config: Firebase configuration with service_account_key and optional web_config
            
        Returns:
            (success, message)
        """
        if self.initialized:
            return True, "Already initialized"
        
        try:
            # Initialize Firebase Admin SDK (required)
            if FIREBASE_ADMIN_AVAILABLE:
                if not firebase_admin._apps:
                    cred = credentials.Certificate(config['service_account_key'])
                    self.firebase_app = firebase_admin.initialize_app(cred)
                else:
                    self.firebase_app = firebase_admin.get_app()
                
                self.db = firestore.client()
                self.initialized = True
            
            # Initialize Pyrebase for client-side operations (optional)
            # Only needed if you want Google Sign-In or client-side auth
            if PYREBASE_AVAILABLE and 'web_config' in config:
                firebase_config = config.get('web_config', {})
                if firebase_config:  # Only initialize if web_config provided
                    firebase = pyrebasex.initialize_app(firebase_config)
                    self.auth_client = firebase.auth()
            
            return True, "Firebase initialized successfully"
            
        except Exception as e:
            return False, f"Firebase initialization failed: {str(e)}"
    
    def create_user(self, email: str, password: str, display_name: str, 
                   role: str = UserRole.USER) -> Tuple[bool, str, Optional[Dict]]:
        """
        Create a new user (Admin only)
        
        Returns:
            (success, message, user_data)
        """
        if not FIREBASE_ADMIN_AVAILABLE:
            return False, "Firebase Admin SDK not available", None
        
        if not self.initialized or self.db is None:
            return False, "Firebase not initialized. Please configure Firebase in settings.", None
        
        try:
            # Create user in Firebase Auth
            user = auth.create_user(
                email=email,
                password=password,
                display_name=display_name,
                email_verified=False
            )
            
            # Create user profile in Firestore
            user_data = {
                'uid': user.uid,
                'email': email,
                'display_name': display_name,
                'role': role,
                'created_at': datetime.now().isoformat(),
                'created_by': st.session_state.get('user_email', 'system'),
                'last_login': None,
                'active': True,
                'metadata': {
                    'assessments_count': 0,
                    'last_activity': None
                }
            }
            
            self.db.collection('users').document(user.uid).set(user_data)
            
            return True, f"User {email} created successfully", user_data
            
        except auth.EmailAlreadyExistsError:
            return False, f"User with email {email} already exists", None
        except Exception as e:
            return False, f"Error creating user: {str(e)}", None
    
    def sign_in_with_email(self, email: str, password: str) -> Tuple[bool, str, Optional[Dict]]:
        """
        Sign in user with email and password (server-side authentication)
        Requires Firebase Web API Key for password verification
        
        Returns:
            (success, message, user_info)
        """
        if not FIREBASE_ADMIN_AVAILABLE:
            return False, "Firebase Admin SDK not available", None
        
        if not self.initialized or self.db is None:
            return False, "Firebase not initialized. Please configure Firebase in settings.", None
        
        try:
            # For password verification, we need the Web API Key
            # You can get this from Firebase Console > Project Settings > General
            api_key = None
            
            # Try to get API key from secrets
            try:
                import streamlit as st
                if hasattr(st, 'secrets') and 'firebase' in st.secrets:
                    # Check for api_key in firebase section
                    if 'api_key' in st.secrets['firebase']:
                        api_key = st.secrets['firebase']['api_key']
                    # Or in web_config if provided
                    elif 'web_config' in st.secrets['firebase'] and 'apiKey' in st.secrets['firebase']['web_config']:
                        api_key = st.secrets['firebase']['web_config']['apiKey']
            except:
                pass
            
            if not api_key:
                return False, "Firebase API key not configured. Add 'api_key' to secrets.toml", None
            
            # Verify password using Firebase REST API
            import requests
            url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={api_key}"
            payload = {
                "email": email,
                "password": password,
                "returnSecureToken": True
            }
            
            response = requests.post(url, json=payload)
            
            if response.status_code != 200:
                error_data = response.json()
                error_message = error_data.get('error', {}).get('message', '')
                
                if 'INVALID_PASSWORD' in error_message or 'INVALID_EMAIL' in error_message:
                    return False, "Invalid email or password", None
                elif 'EMAIL_NOT_FOUND' in error_message:
                    return False, "User not found", None
                else:
                    return False, f"Login failed: {error_message}", None
            
            result = response.json()
            uid = result['localId']
            
            # Get user profile from Firestore
            user_doc = self.db.collection('users').document(uid).get()
            
            if not user_doc.exists:
                return False, "User profile not found", None
            
            user_data = user_doc.to_dict()
            
            if not user_data.get('active', True):
                return False, "User account is disabled", None
            
            # Update last login
            self.db.collection('users').document(uid).update({
                'last_login': datetime.now().isoformat()
            })
            
            # Prepare session data
            session_data = {
                'uid': uid,
                'email': user_data['email'],
                'display_name': user_data['display_name'],
                'role': user_data['role'],
                'token': result['idToken'],
                'refresh_token': result.get('refreshToken')
            }
            
            return True, "Login successful", session_data
            
        except Exception as e:
            return False, f"Login failed: {str(e)}", None
    
    def sign_in_with_google(self) -> Tuple[bool, str, Optional[Dict]]:
        """
        Sign in with Google (requires client-side implementation)
        This is a placeholder - actual Google Sign-In requires JavaScript
        """
        return False, "Google Sign-In requires client-side implementation", None
    
    def get_all_users(self) -> List[Dict]:
        """Get all users (Admin only)"""
        if not FIREBASE_ADMIN_AVAILABLE:
            return []
        
        if not self.initialized or self.db is None:
            st.warning("⚠️ Firebase not initialized. Please configure Firebase in settings.")
            return []
        
        try:
            users_ref = self.db.collection('users')
            users = []
            
            for doc in users_ref.stream():
                user_data = doc.to_dict()
                users.append(user_data)
            
            return users
        except Exception as e:
            st.error(f"Error fetching users: {str(e)}")
            return []
    
    def update_user_role(self, uid: str, new_role: str) -> Tuple[bool, str]:
        """Update user role (Admin only)"""
        if not FIREBASE_ADMIN_AVAILABLE:
            return False, "Firebase Admin SDK not available"
        
        if not self.initialized or self.db is None:
            return False, "Firebase not initialized. Please configure Firebase in settings."
        
        try:
            self.db.collection('users').document(uid).update({
                'role': new_role,
                'updated_at': datetime.now().isoformat(),
                'updated_by': st.session_state.get('user_email', 'system')
            })
            return True, f"User role updated to {new_role}"
        except Exception as e:
            return False, f"Error updating role: {str(e)}"
    
    def disable_user(self, uid: str) -> Tuple[bool, str]:
        """Disable user account (Admin only)"""
        if not FIREBASE_ADMIN_AVAILABLE:
            return False, "Firebase Admin SDK not available"
        
        if not self.initialized or self.db is None:
            return False, "Firebase not initialized. Please configure Firebase in settings."
        
        try:
            # Disable in Firebase Auth
            auth.update_user(uid, disabled=True)
            
            # Update in Firestore
            self.db.collection('users').document(uid).update({
                'active': False,
                'disabled_at': datetime.now().isoformat(),
                'disabled_by': st.session_state.get('user_email', 'system')
            })
            
            return True, "User disabled successfully"
        except Exception as e:
            return False, f"Error disabling user: {str(e)}"
    
    def enable_user(self, uid: str) -> Tuple[bool, str]:
        """Enable user account (Admin only)"""
        if not FIREBASE_ADMIN_AVAILABLE:
            return False, "Firebase Admin SDK not available"
        
        if not self.initialized or self.db is None:
            return False, "Firebase not initialized. Please configure Firebase in settings."
        
        try:
            # Enable in Firebase Auth
            auth.update_user(uid, disabled=False)
            
            # Update in Firestore
            self.db.collection('users').document(uid).update({
                'active': True,
                'enabled_at': datetime.now().isoformat(),
                'enabled_by': st.session_state.get('user_email', 'system')
            })
            
            return True, "User enabled successfully"
        except Exception as e:
            return False, f"Error enabling user: {str(e)}"
    
    def delete_user(self, uid: str) -> Tuple[bool, str]:
        """Delete user permanently (Admin only)"""
        if not FIREBASE_ADMIN_AVAILABLE:
            return False, "Firebase Admin SDK not available"
        
        if not self.initialized or self.db is None:
            return False, "Firebase not initialized. Please configure Firebase in settings."
        
        try:
            # Delete from Firebase Auth
            auth.delete_user(uid)
            
            # Delete from Firestore
            self.db.collection('users').document(uid).delete()
            
            return True, "User deleted successfully"
        except Exception as e:
            return False, f"Error deleting user: {str(e)}"
    
    def reset_password(self, email: str) -> Tuple[bool, str]:
        """Send password reset email using Firebase Admin SDK"""
        if not FIREBASE_ADMIN_AVAILABLE:
            return False, "Firebase Admin SDK not available"
        
        try:
            # Get API key for password reset
            import streamlit as st
            api_key = None
            
            try:
                if hasattr(st, 'secrets') and 'firebase' in st.secrets:
                    if 'api_key' in st.secrets['firebase']:
                        api_key = st.secrets['firebase']['api_key']
                    elif 'web_config' in st.secrets['firebase'] and 'apiKey' in st.secrets['firebase']['web_config']:
                        api_key = st.secrets['firebase']['web_config']['apiKey']
            except:
                pass
            
            if not api_key:
                return False, "Firebase API key not configured for password reset"
            
            # Use Firebase REST API to send password reset email
            import requests
            url = f"https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key={api_key}"
            payload = {
                "requestType": "PASSWORD_RESET",
                "email": email
            }
            
            response = requests.post(url, json=payload)
            
            if response.status_code == 200:
                return True, f"Password reset email sent to {email}"
            else:
                error_data = response.json()
                error_message = error_data.get('error', {}).get('message', 'Unknown error')
                return False, f"Error sending reset email: {error_message}"
            
        except Exception as e:
            return False, f"Error sending reset email: {str(e)}"
    
    def verify_token(self, token: str) -> Tuple[bool, Optional[Dict]]:
        """Verify Firebase ID token"""
        if not FIREBASE_ADMIN_AVAILABLE:
            return False, None
        
        try:
            decoded_token = auth.verify_id_token(token)
            return True, decoded_token
        except Exception as e:
            return False, None
    
    def sign_out(self):
        """Sign out current user"""
        # Clear session state
        keys_to_clear = ['authenticated', 'user_uid', 'user_email', 'user_role', 
                        'user_name', 'firebase_token']
        for key in keys_to_clear:
            if key in st.session_state:
                del st.session_state[key]

# Global instance
firebase_manager = FirebaseAuthManager()

# ============================================================================
# STREAMLIT UI COMPONENTS
# ============================================================================

def render_login_page():
    """Render login page"""
    st.markdown("""
    <div style="background: #FFFFFF; 
                padding: 3rem; border-radius: 12px; margin-bottom: 2rem; text-align: center;
                border: 3px solid #FF9900;
                box-shadow: 0 4px 12px rgba(0,0,0,0.1);">
        <h1 style="color: #232F3E; margin: 0; font-size: 2.2rem; font-weight: 700;">🔐 AWS Well-Architected Advisor</h1>
        <p style="color: #FF9900; margin: 0.5rem 0 0 0; font-size: 1.2rem; font-weight: 600;">
            Enterprise Edition v2.2 - Secure Login
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        st.markdown("### 📧 Sign In")
        
        with st.form("login_form"):
            email = st.text_input("Email", placeholder="your.email@company.com")
            password = st.text_input("Password", type="password")
            
            col_btn1, col_btn2 = st.columns(2)
            
            with col_btn1:
                submit = st.form_submit_button("🔓 Sign In", use_container_width=True, type="primary")
            
            with col_btn2:
                forgot = st.form_submit_button("🔄 Forgot Password", use_container_width=True)
            
            if submit:
                if not email or not password:
                    st.error("Please enter both email and password")
                else:
                    with st.spinner("Signing in..."):
                        success, message, user_data = firebase_manager.sign_in_with_email(email, password)
                        
                        if success:
                            # Store in session state
                            st.session_state.authenticated = True
                            st.session_state.user_uid = user_data['uid']
                            st.session_state.user_email = user_data['email']
                            st.session_state.user_name = user_data['display_name']
                            st.session_state.user_role = user_data['role']
                            st.session_state.firebase_token = user_data['token']
                            
                            st.success(f"✅ Welcome back, {user_data['display_name']}!")
                            st.rerun()
                        else:
                            st.error(f"❌ {message}")
            
            if forgot:
                if email:
                    success, message = firebase_manager.reset_password(email)
                    if success:
                        st.success(message)
                    else:
                        st.error(message)
                else:
                    st.warning("Please enter your email address")
        
        st.markdown("---")
        st.markdown("""
        <div style="text-align: center; color: #666; font-size: 0.9rem;">
            <p>Need access? Contact your administrator</p>
            <p>Protected by Firebase Authentication 🔒</p>
        </div>
        """, unsafe_allow_html=True)

def render_admin_user_management():
    """Render admin user management interface"""
    st.markdown("""
    <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                padding: 2rem; border-radius: 12px; margin-bottom: 2rem;">
        <h2 style="color: white; margin: 0;">👥 User Management</h2>
        <p style="color: white; opacity: 0.9; margin: 0.5rem 0 0 0;">
            Create and manage user accounts
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # Check admin permission
    if st.session_state.get('user_role') != UserRole.ADMIN:
        st.error("⛔ Admin access required")
        return
    
    tabs = st.tabs(["➕ Create User", "📋 Manage Users", "📊 User Statistics"])
    
    # Tab 1: Create User
    with tabs[0]:
        render_create_user_form()
    
    # Tab 2: Manage Users
    with tabs[1]:
        render_user_list()
    
    # Tab 3: Statistics
    with tabs[2]:
        render_user_statistics()

def render_create_user_form():
    """Render user creation form"""
    st.markdown("### ➕ Create New User")
    
    with st.form("create_user_form"):
        col1, col2 = st.columns(2)
        
        with col1:
            display_name = st.text_input("Full Name *", placeholder="John Doe")
            email = st.text_input("Email *", placeholder="john.doe@company.com")
        
        with col2:
            password = st.text_input("Initial Password *", type="password", 
                                    help="User can change this after first login")
            role = st.selectbox("Role *", UserRole.get_all_roles())
        
        # Show permissions for selected role
        st.markdown("**Permissions for this role:**")
        permissions = UserRole.get_permissions(role)
        
        perm_cols = st.columns(4)
        perm_list = list(permissions.items())
        for idx, (perm, enabled) in enumerate(perm_list):
            with perm_cols[idx % 4]:
                icon = "✅" if enabled else "❌"
                st.markdown(f"{icon} {perm.replace('_', ' ').title()}")
        
        submitted = st.form_submit_button("👤 Create User", type="primary", use_container_width=True)
        
        if submitted:
            if not all([display_name, email, password]):
                st.error("Please fill in all required fields")
            elif len(password) < 6:
                st.error("Password must be at least 6 characters")
            else:
                with st.spinner("Creating user..."):
                    success, message, user_data = firebase_manager.create_user(
                        email=email,
                        password=password,
                        display_name=display_name,
                        role=role
                    )
                    
                    if success:
                        st.success(f"✅ {message}")
                        st.info(f"""
                        **User Details:**
                        - **Name:** {display_name}
                        - **Email:** {email}
                        - **Role:** {role}
                        - **Status:** Active
                        
                        📧 User will receive login credentials at: {email}
                        """)
                    else:
                        st.error(f"❌ {message}")

def render_user_list():
    """Render list of all users with management options"""
    st.markdown("### 📋 All Users")
    
    users = firebase_manager.get_all_users()
    
    if not users:
        st.info("No users found")
        return
    
    # Sort by creation date (handle None and missing values)
    # Convert all values to comparable timestamps
    def get_sort_datetime(user):
        try:
            created_at = user.get('created_at')
            if created_at is None:
                return 0  # Use timestamp 0 for missing dates
            if isinstance(created_at, str):
                try:
                    dt = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                    return dt.timestamp()
                except:
                    return 0
            # Handle Firebase DatetimeWithNanoseconds or datetime objects
            # Convert to timestamp for consistent comparison
            if hasattr(created_at, 'timestamp'):
                return created_at.timestamp()
            # If it has a method to convert to datetime
            if hasattr(created_at, 'astimezone'):
                return created_at.timestamp()
            return 0
        except Exception as e:
            return 0  # Fallback to 0 if any error occurs
    
    try:
        users.sort(key=get_sort_datetime, reverse=True)
    except Exception as e:
        st.warning(f"Could not sort users by date: {str(e)}")
        # Users will remain in original order
    
    # Add search/filter
    col_search, col_filter = st.columns([3, 1])
    with col_search:
        search = st.text_input("🔍 Search users", placeholder="Name or email...")
    with col_filter:
        role_filter = st.selectbox("Filter by role", ["All"] + UserRole.get_all_roles())
    
    # Filter users
    filtered_users = users
    if search:
        filtered_users = [u for u in filtered_users if 
                         search.lower() in u.get('email', '').lower() or 
                         search.lower() in u.get('display_name', '').lower()]
    if role_filter != "All":
        filtered_users = [u for u in filtered_users if u.get('role') == role_filter]
    
    st.markdown(f"**Total Users:** {len(filtered_users)}")
    
    # Display users
    for user in filtered_users:
        with st.expander(f"👤 {user.get('display_name', 'Unknown')} ({user.get('email', 'N/A')})"):
            col1, col2 = st.columns([2, 1])
            
            # Helper function to format dates
            def format_date(date_value):
                if date_value is None or date_value == 'Never':
                    return 'N/A'
                if isinstance(date_value, str):
                    return date_value[:10] if len(date_value) >= 10 else date_value
                # Handle datetime objects (including Firebase DatetimeWithNanoseconds)
                try:
                    if hasattr(date_value, 'strftime'):
                        return date_value.strftime('%Y-%m-%d')
                    elif hasattr(date_value, 'isoformat'):
                        return date_value.isoformat()[:10]
                    else:
                        return str(date_value)[:10]
                except:
                    return 'N/A'
            
            with col1:
                created_date = format_date(user.get('created_at', 'N/A'))
                last_login = format_date(user.get('last_login')) if user.get('last_login') else 'Never'
                
                st.markdown(f"""
                **Role:** {user.get('role', 'N/A').title()}  
                **Status:** {"🟢 Active" if user.get('active', True) else "🔴 Disabled"}  
                **Created:** {created_date}  
                **Last Login:** {last_login}  
                **Assessments:** {user.get('metadata', {}).get('assessments_count', 0)}
                """)
            
            with col2:
                # Don't allow admin to modify themselves
                if user.get('uid') == st.session_state.get('user_uid'):
                    st.info("👤 You (cannot modify)")
                else:
                    # Change role
                    new_role = st.selectbox(
                        "Change Role",
                        UserRole.get_all_roles(),
                        index=UserRole.get_all_roles().index(user.get('role', UserRole.USER)),
                        key=f"role_{user.get('uid')}"
                    )
                    
                    if st.button("💾 Update Role", key=f"update_{user.get('uid')}", use_container_width=True):
                        success, message = firebase_manager.update_user_role(user.get('uid'), new_role)
                        if success:
                            st.success(message)
                            st.rerun()
                        else:
                            st.error(message)
                    
                    # Enable/Disable
                    if user.get('active', True):
                        if st.button("🚫 Disable User", key=f"disable_{user.get('uid')}", use_container_width=True):
                            success, message = firebase_manager.disable_user(user.get('uid'))
                            if success:
                                st.success(message)
                                st.rerun()
                            else:
                                st.error(message)
                    else:
                        if st.button("✅ Enable User", key=f"enable_{user.get('uid')}", use_container_width=True):
                            success, message = firebase_manager.enable_user(user.get('uid'))
                            if success:
                                st.success(message)
                                st.rerun()
                            else:
                                st.error(message)
                    
                    # Delete (with confirmation)
                    if st.button("🗑️ Delete User", key=f"delete_{user.get('uid')}", use_container_width=True):
                        st.warning("⚠️ This action cannot be undone!")
                        if st.button("✔️ Confirm Delete", key=f"confirm_delete_{user.get('uid')}"):
                            success, message = firebase_manager.delete_user(user.get('uid'))
                            if success:
                                st.success(message)
                                st.rerun()
                            else:
                                st.error(message)

def render_user_statistics():
    """Render user statistics dashboard"""
    st.markdown("### 📊 User Statistics")
    
    users = firebase_manager.get_all_users()
    
    if not users:
        st.info("No data available")
        return
    
    # Calculate statistics
    total_users = len(users)
    active_users = sum(1 for u in users if u.get('active', True))
    
    role_counts = {}
    for role in UserRole.get_all_roles():
        role_counts[role] = sum(1 for u in users if u.get('role') == role)
    
    # Display metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Users", total_users)
    with col2:
        st.metric("Active Users", active_users)
    with col3:
        st.metric("Disabled", total_users - active_users)
    with col4:
        st.metric("Admins", role_counts.get(UserRole.ADMIN, 0))
    
    # Role distribution
    st.markdown("#### Role Distribution")
    for role, count in role_counts.items():
        percentage = (count / total_users * 100) if total_users > 0 else 0
        st.progress(percentage / 100, text=f"{role.title()}: {count} ({percentage:.1f}%)")
    
    # Recent logins
    st.markdown("#### Recent Activity")
    
    # Helper function to get sortable timestamp
    def get_timestamp(user):
        last_login = user.get('last_login')
        if not last_login:
            return 0
        # Handle DatetimeWithNanoseconds from Firestore
        if hasattr(last_login, 'timestamp'):
            return last_login.timestamp()
        # Handle string datetime
        if isinstance(last_login, str):
            try:
                from datetime import datetime
                return datetime.fromisoformat(last_login.replace('Z', '+00:00')).timestamp()
            except:
                return 0
        return 0
    
    recent_users = sorted(
        [u for u in users if u.get('last_login')],
        key=get_timestamp,
        reverse=True
    )[:5]
    
    if recent_users:
        for user in recent_users:
            display_name = user.get('display_name') or 'Unknown User'
            last_login = user.get('last_login')
            
            # Format last_login for display
            if last_login:
                if hasattr(last_login, 'strftime'):
                    # DatetimeWithNanoseconds or datetime object
                    last_login_display = last_login.strftime('%Y-%m-%d %H:%M')
                elif isinstance(last_login, str):
                    # String datetime
                    last_login_display = last_login[:16] if len(last_login) >= 16 else last_login
                else:
                    last_login_display = 'N/A'
            else:
                last_login_display = 'N/A'
            
            st.markdown(f"- **{display_name}** - {last_login_display}")
    else:
        st.info("No recent activity")

def render_user_profile_sidebar():
    """Render user profile in sidebar"""
    if not st.session_state.get('authenticated'):
        return
    
    with st.sidebar:
        st.markdown("---")
        st.markdown("### 👤 Profile")
        
        role_icon = {
            UserRole.ADMIN: "👑",
            UserRole.USER: "👤",
            UserRole.VIEWER: "👁️"
        }
        
        role = st.session_state.get('user_role', UserRole.VIEWER)
        
        st.markdown(f"""
        **{st.session_state.get('user_name', 'User')}** {role_icon.get(role, '')}  
        {st.session_state.get('user_email', '')}  
        Role: {role.title()}
        """)
        
        if st.button("🚪 Sign Out", use_container_width=True):
            firebase_manager.sign_out()
            st.rerun()

def check_authentication() -> bool:
    """Check if user is authenticated"""
    return st.session_state.get('authenticated', False)

def require_admin():
    """Decorator to require admin access"""
    if st.session_state.get('user_role') != UserRole.ADMIN:
        st.error("⛔ Admin access required")
        st.stop()

def has_permission(permission: str) -> bool:
    """Check if current user has specific permission"""
    role = st.session_state.get('user_role', UserRole.VIEWER)
    permissions = UserRole.get_permissions(role)
    return permissions.get(permission, False)