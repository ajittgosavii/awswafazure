"""
Example: How to Integrate Firebase Authentication with Your Streamlit App
This shows the key changes needed in streamlit_app.py
"""

import streamlit as st
from firebase_auth_module import (
    firebase_manager,
    check_authentication,
    render_login_page,
    render_admin_user_management,
    render_user_profile_sidebar,
    has_permission,
    UserRole
)

# ============================================================================
# STEP 1: PAGE CONFIGURATION (Keep your existing config)
# ============================================================================

st.set_page_config(
    page_title="AWS Well-Architected Advisor | Enterprise",
    page_icon="🏗️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================================================================
# STEP 2: INITIALIZE FIREBASE (Add this at the very beginning)
# ============================================================================

def initialize_firebase():
    """Initialize Firebase on first run"""
    if 'firebase_initialized' not in st.session_state:
        try:
            # Get Firebase config from Streamlit secrets
            config = {
                'service_account_key': dict(st.secrets['firebase']['service_account_key']),
                'web_config': dict(st.secrets['firebase']['web_config'])
            }
            
            success, message = firebase_manager.initialize_firebase(config)
            
            if success:
                st.session_state.firebase_initialized = True
            else:
                st.error(f"🔥 Firebase initialization failed: {message}")
                st.info("""
                **Setup Required:**
                1. Complete Firebase setup (see FIREBASE_SETUP_GUIDE.md)
                2. Add Firebase credentials to .streamlit/secrets.toml
                3. Restart the app
                """)
                st.stop()
                
        except Exception as e:
            st.error(f"❌ Firebase configuration error: {str(e)}")
            st.info("Please check your .streamlit/secrets.toml file")
            st.stop()

# Initialize Firebase
initialize_firebase()

# ============================================================================
# STEP 3: CHECK AUTHENTICATION (Add before main content)
# ============================================================================

# If not authenticated, show login page and stop
if not check_authentication():
    render_login_page()
    st.stop()

# ============================================================================
# STEP 4: RENDER USER PROFILE IN SIDEBAR
# ============================================================================

render_user_profile_sidebar()

# ============================================================================
# STEP 5: UPDATE YOUR MAIN APP WITH ROLE-BASED ACCESS
# ============================================================================

def main():
    """Main application with authentication"""
    
    # Welcome message
    st.title("🏗️ AWS Well-Architected Framework Advisor")
    st.markdown(f"Welcome back, **{st.session_state.get('user_name')}**! 👋")
    
    # Create tabs based on user role
    user_role = st.session_state.get('user_role', UserRole.VIEWER)
    
    if user_role == UserRole.ADMIN:
        # Admin sees all tabs including User Management
        tabs = st.tabs([
            "📊 Dashboard",
            "🏗️ WAF Assessment Hub",
            "📤 Architecture & Migration",
            "🎯 Architecture Patterns",
            "🚀 EKS & Modernization",
            "👥 User Management"  # Admin only
        ])
        
        # Tab 0: Dashboard
        with tabs[0]:
            render_dashboard()
        
        # Tab 1: WAF Assessment Hub
        with tabs[1]:
            if has_permission("run_aws_scans"):
                render_waf_assessment_hub()
            else:
                st.warning("⚠️ You don't have permission to run AWS scans")
        
        # Tab 2: Architecture & Migration
        with tabs[2]:
            render_architecture_migration()
        
        # Tab 3: Architecture Patterns
        with tabs[3]:
            render_architecture_patterns()
        
        # Tab 4: EKS & Modernization
        with tabs[4]:
            render_eks_modernization()
        
        # Tab 5: User Management (Admin Only)
        with tabs[5]:
            render_admin_user_management()
    
    elif user_role == UserRole.USER:
        # Regular users see standard tabs
        tabs = st.tabs([
            "📊 Dashboard",
            "🏗️ WAF Assessment Hub",
            "📤 Architecture & Migration",
            "🎯 Architecture Patterns",
            "🚀 EKS & Modernization"
        ])
        
        with tabs[0]:
            render_dashboard()
        
        with tabs[1]:
            if has_permission("run_aws_scans"):
                render_waf_assessment_hub()
            else:
                st.warning("⚠️ You don't have permission to run AWS scans")
        
        with tabs[2]:
            render_architecture_migration()
        
        with tabs[3]:
            render_architecture_patterns()
        
        with tabs[4]:
            render_eks_modernization()
    
    else:  # VIEWER
        # Viewers see limited tabs
        tabs = st.tabs([
            "📊 Dashboard",
            "🎯 Architecture Patterns"
        ])
        
        with tabs[0]:
            render_dashboard()
            st.info("👁️ You have viewer access. Contact admin for additional permissions.")
        
        with tabs[1]:
            render_architecture_patterns()

# ============================================================================
# STEP 6: YOUR EXISTING RENDER FUNCTIONS (Keep as-is, add permission checks)
# ============================================================================

def render_dashboard():
    """Dashboard with user-specific content"""
    st.markdown("### 📊 Dashboard")
    
    # Show different content based on role
    if st.session_state.get('user_role') == UserRole.ADMIN:
        st.info("👑 Admin Dashboard - You have full access to all features")
    elif st.session_state.get('user_role') == UserRole.USER:
        st.info("👤 User Dashboard - You can run assessments and view reports")
    else:
        st.info("👁️ Viewer Dashboard - Read-only access")
    
    # Show user's recent activity
    st.markdown("#### Your Recent Activity")
    st.markdown("- Last login: " + st.session_state.get('last_login', 'N/A'))
    st.markdown("- Assessments: 0")  # TODO: Get from Firestore

def render_waf_assessment_hub():
    """WAF Assessment with permission checks"""
    # Check if user can run scans
    if not has_permission("run_aws_scans"):
        st.warning("⚠️ You don't have permission to run AWS scans")
        return
    
    # Import your existing WAF module
    try:
        from waf_review_module import render_waf_review_tab
        render_waf_review_tab()
    except ImportError:
        st.error("WAF module not found")

def render_architecture_migration():
    """Architecture & Migration - accessible to User and Admin"""
    st.markdown("### 📤 Architecture & Migration")
    # Your existing code here

def render_architecture_patterns():
    """Architecture Patterns - accessible to all"""
    try:
        from architecture_patterns import render_architecture_patterns_tab
        render_architecture_patterns_tab()
    except ImportError:
        st.error("Architecture Patterns module not found")

def render_eks_modernization():
    """EKS & Modernization - accessible to User and Admin"""
    if not has_permission("run_aws_scans"):
        st.warning("⚠️ You don't have permission to access this feature")
        return
    
    try:
        from eks_modernization_module import render_eks_modernization_tab
        render_eks_modernization_tab()
    except ImportError:
        st.error("EKS Modernization module not found")

# ============================================================================
# STEP 7: RUN THE APP
# ============================================================================

if __name__ == "__main__":
    main()

# ============================================================================
# EXAMPLE: SAVING ASSESSMENTS WITH USER INFO
# ============================================================================

def save_assessment_example(assessment_data: dict):
    """Example: How to save assessments with user information"""
    
    if not FIREBASE_ADMIN_AVAILABLE:
        st.warning("Firebase not configured - cannot save assessment")
        return
    
    try:
        from firebase_admin import firestore
        db = firestore.client()
        
        # Add user info to assessment
        assessment_data.update({
            'created_by': st.session_state.get('user_uid'),
            'created_by_email': st.session_state.get('user_email'),
            'created_by_name': st.session_state.get('user_name'),
            'created_at': datetime.now().isoformat(),
            'organization': st.session_state.get('user_email', '').split('@')[1]
        })
        
        # Save to Firestore
        doc_ref = db.collection('assessments').add(assessment_data)
        
        st.success(f"✅ Assessment saved! ID: {doc_ref[1].id}")
        
    except Exception as e:
        st.error(f"Error saving assessment: {str(e)}")

# ============================================================================
# EXAMPLE: LOADING USER'S ASSESSMENTS
# ============================================================================

def load_user_assessments():
    """Example: Load assessments for current user"""
    
    if not FIREBASE_ADMIN_AVAILABLE:
        return []
    
    try:
        from firebase_admin import firestore
        db = firestore.client()
        
        user_uid = st.session_state.get('user_uid')
        user_role = st.session_state.get('user_role')
        
        # Admins can see all assessments
        if user_role == UserRole.ADMIN and has_permission("view_all_assessments"):
            assessments_ref = db.collection('assessments')
        else:
            # Regular users see only their own
            assessments_ref = db.collection('assessments').where('created_by', '==', user_uid)
        
        assessments = []
        for doc in assessments_ref.stream():
            assessment = doc.to_dict()
            assessment['id'] = doc.id
            assessments.append(assessment)
        
        return assessments
        
    except Exception as e:
        st.error(f"Error loading assessments: {str(e)}")
        return []

# ============================================================================
# SUMMARY OF CHANGES
# ============================================================================

"""
CHANGES NEEDED IN YOUR streamlit_app.py:

1. Add imports at top:
   from firebase_auth_module import (
       firebase_manager, check_authentication, render_login_page,
       render_admin_user_management, render_user_profile_sidebar,
       has_permission, UserRole
   )

2. Add after st.set_page_config():
   initialize_firebase()

3. Add before main content:
   if not check_authentication():
       render_login_page()
       st.stop()
   render_user_profile_sidebar()

4. Update tabs to include User Management for admins

5. Add permission checks using has_permission() where needed

6. Save/load data with user context (examples above)

That's it! Your app now has:
✅ Secure authentication
✅ Role-based access control  
✅ Admin user management
✅ User session tracking
"""
