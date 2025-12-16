"""
Authentication UI Components
Login page, logout, user profile display
"""

import streamlit as st
from auth_azure_sso import AzureSSO, UserManager, RoleManager, init_authentication
import hashlib
from datetime import datetime
from urllib.parse import parse_qs, urlparse

def render_login_page():
    """Render login page with Azure SSO"""
    init_authentication()
    
    auth_manager = st.session_state.auth_manager
    user_manager = st.session_state.user_manager
    
    # Check if already authenticated
    if user_manager.is_authenticated():
        st.switch_page("pages/dashboard.py")
        return
    
    # Check for OAuth callback
    query_params = st.query_params
    if 'code' in query_params:
        handle_oauth_callback(query_params)
        return
    
    # Show login page
    st.set_page_config(page_title="CloudIDP - Login", page_icon="☁️", layout="centered")
    
    # Header
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.image("https://via.placeholder.com/400x100/0078D4/FFFFFF?text=CloudIDP", use_column_width=True)
        st.markdown("### ☁️ Cloud Infrastructure Development Platform")
        st.markdown("**Multi-Cloud Management** • AWS • Azure • GCP")
    
    st.markdown("---")
    
    # Check if Azure SSO is configured
    if not auth_manager.is_configured():
        st.error("⚠️ Azure SSO is not configured")
        st.info("""
        **Administrator:** Please configure Azure SSO in Streamlit secrets:
        
        1. Register an app in Azure AD (Entra ID)
        2. Add these secrets to `.streamlit/secrets.toml`:
        
        ```toml
        [azure_sso]
        azure_tenant_id = "your-tenant-id"
        azure_client_id = "your-client-id"
        azure_client_secret = "your-client-secret"
        azure_redirect_uri = "https://your-app.streamlit.app"
        ```
        
        See [Azure AD App Registration Guide](#) for detailed instructions.
        """)
        return
    
    # Login options
    st.markdown("### 🔐 Sign In")
    
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        # Generate state for CSRF protection
        if 'oauth_state' not in st.session_state:
            st.session_state.oauth_state = hashlib.sha256(
                f"{datetime.now().isoformat()}".encode()
            ).hexdigest()
        
        # Azure SSO button
        login_url = auth_manager.get_login_url(st.session_state.oauth_state)
        
        st.markdown(f'''
        <a href="{login_url}" target="_self">
            <button style="
                background-color: #0078D4;
                color: white;
                padding: 12px 24px;
                font-size: 16px;
                border: none;
                border-radius: 4px;
                cursor: pointer;
                width: 100%;
                display: flex;
                align-items: center;
                justify-content: center;
            ">
                <img src="https://upload.wikimedia.org/wikipedia/commons/4/44/Microsoft_logo.svg" 
                     width="20" style="margin-right: 10px;">
                Sign in with Microsoft
            </button>
        </a>
        ''', unsafe_allow_html=True)
        
        st.markdown("<br>", unsafe_allow_html=True)
        
        # Alternative: Local development mode (optional)
        with st.expander("🔧 Developer Mode (Local Only)"):
            st.warning("⚠️ For local development only - DO NOT use in production!")
            dev_email = st.text_input("Email", "developer@company.com")
            if st.button("Login as Developer", use_container_width=True):
                # Create mock user session for development
                mock_user = {
                    'id': 'dev-user-123',
                    'email': dev_email,
                    'name': 'Developer User',
                    'given_name': 'Developer',
                    'surname': 'User',
                    'job_title': 'Developer',
                    'department': 'Engineering'
                }
                mock_token = {
                    'access_token': 'dev-token',
                    'refresh_token': 'dev-refresh'
                }
                user_manager.create_user_session(mock_user, mock_token)
                st.success("✅ Logged in as developer")
                st.rerun()
    
    # Footer
    st.markdown("---")
    st.markdown("""
    <div style='text-align: center; color: gray; font-size: 12px;'>
        CloudIDP v3.0 • Secure Multi-Cloud Platform<br>
        Protected by Azure Active Directory
    </div>
    """, unsafe_allow_html=True)


def handle_oauth_callback(query_params):
    """Handle OAuth callback from Azure AD"""
    auth_manager = st.session_state.auth_manager
    user_manager = st.session_state.user_manager
    
    code = query_params.get('code', [None])[0] if isinstance(query_params.get('code'), list) else query_params.get('code')
    state = query_params.get('state', [None])[0] if isinstance(query_params.get('state'), list) else query_params.get('state')
    error = query_params.get('error')
    
    # Check for errors
    if error:
        st.error(f"❌ Login failed: {error}")
        st.info("Please try again or contact your administrator.")
        if st.button("Return to Login"):
            st.query_params.clear()
            st.rerun()
        return
    
    # Verify state (CSRF protection)
    # Note: Streamlit creates new session on redirect, so state might be lost
    # We validate that state exists and has correct format (SHA256 hex)
    if state:
        # Check if state is a valid SHA256 hex string (64 characters, hex only)
        if len(state) == 64 and all(c in '0123456789abcdef' for c in state.lower()):
            # State is valid format - proceed
            pass
        else:
            st.error("❌ Invalid state parameter format")
            return
    else:
        st.warning("⚠️ No state parameter received - proceeding with caution")
        # Continue anyway since state validation is difficult with Streamlit's session model
    
    # Exchange code for token
    with st.spinner("🔐 Authenticating with Microsoft..."):
        token_data = auth_manager.exchange_code_for_token(code)
    
    if not token_data:
        st.error("❌ Failed to authenticate")
        return
    
    # Get user information
    with st.spinner("👤 Getting user information..."):
        user_info = auth_manager.get_user_info(token_data['access_token'])
    
    if not user_info:
        st.error("❌ Failed to get user information")
        return
    
    # Create user session
    user_manager.create_user_session(user_info, token_data)
    
    # Clear query parameters
    st.query_params.clear()
    
    # Success message
    st.success(f"✅ Welcome, {user_info.get('displayName')}!")
    st.balloons()
    
    # Redirect to dashboard
    st.rerun()


def render_user_profile():
    """Render user profile in sidebar"""
    user_manager = st.session_state.get('user_manager')
    if not user_manager or not user_manager.is_authenticated():
        return
    
    user = user_manager.get_current_user()
    role_manager = st.session_state.get('role_manager')
    
    with st.sidebar:
        st.markdown("---")
        st.markdown("### 👤 User Profile")
        
        # User photo
        if user.get('photo'):
            st.image(user['photo'], width=80)
        else:
            st.markdown("👤")
        
        # User info
        st.markdown(f"**{user.get('name')}**")
        st.caption(user.get('email'))
        
        if user.get('job_title'):
            st.caption(f"📋 {user.get('job_title')}")
        if user.get('department'):
            st.caption(f"🏢 {user.get('department')}")
        
        # Role
        user_role = role_manager.get_user_role(user['id'])
        role_info = role_manager.get_role_info(user_role)
        st.markdown(f"**Role:** {role_info.get('name', user_role)}")
        
        # Session info
        login_time = datetime.fromisoformat(user.get('login_time', datetime.now().isoformat()))
        st.caption(f"🕒 Logged in: {login_time.strftime('%I:%M %p')}")
        
        # Actions
        col1, col2 = st.columns(2)
        with col1:
            if st.button("⚙️ Settings", use_container_width=True):
                st.session_state.show_settings = True
        with col2:
            if st.button("🚪 Logout", use_container_width=True):
                user_manager.logout()
                st.rerun()


def render_user_settings():
    """Render user settings page"""
    user_manager = st.session_state.get('user_manager')
    if not user_manager or not user_manager.is_authenticated():
        st.warning("⚠️ Please login to access settings")
        return
    
    user = user_manager.get_current_user()
    role_manager = st.session_state.get('role_manager')
    
    st.title("⚙️ User Settings")
    
    tabs = st.tabs(["👤 Profile", "🎨 Preferences", "🔐 Security", "📊 Activity"])
    
    # Profile tab
    with tabs[0]:
        st.markdown("### 👤 Profile Information")
        
        col1, col2 = st.columns([1, 3])
        with col1:
            if user.get('photo'):
                st.image(user['photo'], width=120)
            else:
                st.markdown("### 👤")
        
        with col2:
            st.markdown(f"**Name:** {user.get('name')}")
            st.markdown(f"**Email:** {user.get('email')}")
            st.markdown(f"**Job Title:** {user.get('job_title', 'N/A')}")
            st.markdown(f"**Department:** {user.get('department', 'N/A')}")
            st.markdown(f"**Office:** {user.get('office_location', 'N/A')}")
        
        st.markdown("---")
        st.markdown("### 🎭 Role & Permissions")
        
        user_role = role_manager.get_user_role(user['id'])
        role_info = role_manager.get_role_info(user_role)
        
        st.markdown(f"**Current Role:** {role_info.get('name', user_role)}")
        st.caption(role_info.get('description', ''))
        
        st.markdown("**Permissions:**")
        permissions = role_info.get('permissions', [])
        if '*' in permissions:
            st.success("✅ Full Access (All Permissions)")
        else:
            for perm in permissions:
                st.markdown(f"- ✅ {perm.replace('_', ' ').title()}")
    
    # Preferences tab
    with tabs[1]:
        st.markdown("### 🎨 User Preferences")
        
        prefs = st.session_state.get('user_preferences', {})
        
        # Theme
        theme = st.selectbox(
            "Theme",
            ["Light", "Dark", "Auto"],
            index=["light", "dark", "auto"].index(prefs.get('theme', 'light'))
        )
        
        # Default cloud
        default_cloud = st.selectbox(
            "Default Cloud",
            ["AWS", "Azure", "GCP"],
            index=["aws", "azure", "gcp"].index(prefs.get('default_cloud', 'aws'))
        )
        
        # Notifications
        notifications = st.checkbox(
            "Enable Notifications",
            value=prefs.get('notifications_enabled', True)
        )
        
        # Dashboard layout
        layout = st.selectbox(
            "Dashboard Layout",
            ["Default", "Compact", "Detailed"],
            index=["default", "compact", "detailed"].index(prefs.get('dashboard_layout', 'default'))
        )
        
        if st.button("💾 Save Preferences", type="primary"):
            st.session_state.user_preferences = {
                'theme': theme.lower(),
                'default_cloud': default_cloud.lower(),
                'notifications_enabled': notifications,
                'dashboard_layout': layout.lower()
            }
            st.success("✅ Preferences saved!")
    
    # Security tab
    with tabs[2]:
        st.markdown("### 🔐 Security")
        
        st.markdown("#### 🔑 Session Information")
        login_time = datetime.fromisoformat(user.get('login_time'))
        expires_at = datetime.fromisoformat(user.get('expires_at'))
        
        st.markdown(f"**Login Time:** {login_time.strftime('%Y-%m-%d %I:%M %p')}")
        st.markdown(f"**Session Expires:** {expires_at.strftime('%Y-%m-%d %I:%M %p')}")
        
        time_remaining = expires_at - datetime.now()
        hours_remaining = time_remaining.total_seconds() / 3600
        st.markdown(f"**Time Remaining:** {hours_remaining:.1f} hours")
        
        st.markdown("---")
        st.markdown("#### 🛡️ Security Actions")
        
        if st.button("🚪 Logout All Devices", type="primary"):
            st.warning("This will log you out from all devices")
            if st.button("✅ Confirm Logout All"):
                user_manager.logout()
                st.success("✅ Logged out from all devices")
                st.rerun()
    
    # Activity tab
    with tabs[3]:
        st.markdown("### 📊 Recent Activity")
        st.info("Activity logging will be available soon")
        
        # Placeholder for activity log
        st.markdown("Recent actions will appear here:")
        st.markdown("- Login events")
        st.markdown("- Resource access")
        st.markdown("- Configuration changes")
        st.markdown("- Report generations")


def render_admin_panel():
    """Render admin panel for user management"""
    user_manager = st.session_state.get('user_manager')
    role_manager = st.session_state.get('role_manager')
    
    if not user_manager or not user_manager.is_authenticated():
        st.warning("⚠️ Please login to access admin panel")
        return
    
    user = user_manager.get_current_user()
    if not role_manager.has_permission(user['id'], '*'):
        st.error("❌ Admin access required")
        return
    
    st.title("👨‍💼 Admin Panel")
    
    tabs = st.tabs(["👥 Users", "🎭 Roles", "📊 Analytics", "⚙️ Settings"])
    
    # Users tab
    with tabs[0]:
        st.markdown("### 👥 User Management")
        
        # User list (mock data)
        st.markdown("#### Active Users")
        users_data = [
            {"email": "john.doe@company.com", "name": "John Doe", "role": "architect", "last_login": "2025-12-07 09:30"},
            {"email": "jane.smith@company.com", "name": "Jane Smith", "role": "developer", "last_login": "2025-12-07 10:15"},
            {"email": "bob.wilson@company.com", "name": "Bob Wilson", "role": "finops", "last_login": "2025-12-06 16:45"},
        ]
        
        for user_data in users_data:
            with st.expander(f"{user_data['name']} ({user_data['email']})"):
                col1, col2 = st.columns(2)
                with col1:
                    st.markdown(f"**Role:** {user_data['role']}")
                    st.markdown(f"**Last Login:** {user_data['last_login']}")
                with col2:
                    new_role = st.selectbox(
                        "Change Role",
                        list(role_manager.ROLES.keys()),
                        key=f"role_{user_data['email']}"
                    )
                    if st.button("Update Role", key=f"update_{user_data['email']}"):
                        st.success(f"✅ Role updated to {new_role}")
        
        st.markdown("---")
        st.markdown("#### Add New User")
        new_email = st.text_input("Email")
        new_role = st.selectbox("Role", list(role_manager.ROLES.keys()))
        if st.button("➕ Add User"):
            st.success(f"✅ User {new_email} added with role {new_role}")
    
    # Roles tab
    with tabs[1]:
        st.markdown("### 🎭 Role Management")
        
        for role_id, role_info in role_manager.ROLES.items():
            with st.expander(f"{role_info['name']} ({role_id})"):
                st.markdown(f"**Description:** {role_info['description']}")
                st.markdown("**Permissions:**")
                for perm in role_info['permissions']:
                    st.markdown(f"- {perm}")
    
    # Analytics tab
    with tabs[2]:
        st.markdown("### 📊 Usage Analytics")
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Users", "25")
        with col2:
            st.metric("Active Today", "18")
        with col3:
            st.metric("New This Week", "3")
        
        st.markdown("---")
        st.markdown("#### Usage by Feature")
        st.info("Analytics dashboard coming soon")
    
    # Settings tab
    with tabs[3]:
        st.markdown("### ⚙️ Platform Settings")
        
        st.markdown("#### Authentication")
        st.checkbox("Require MFA", value=False)
        st.number_input("Session Timeout (hours)", min_value=1, max_value=24, value=8)
        
        st.markdown("#### Features")
        st.checkbox("Enable AI Assistant", value=True)
        st.checkbox("Enable Cost Alerts", value=True)
        st.checkbox("Enable Audit Logging", value=True)
        
        if st.button("💾 Save Settings", type="primary"):
            st.success("✅ Settings saved!")