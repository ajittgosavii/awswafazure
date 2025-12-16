"""
Complete Main App Integration Example
Shows how to integrate portfolio functionality into your existing WAF Advisor app

This file demonstrates how to modify your existing app.py or main assessment page
to support both single-account and multi-account portfolio assessments.
"""

import streamlit as st
from datetime import datetime

# Your existing imports
# from waf_review_module import ...

# NEW: Portfolio imports
from waf_portfolio_integration import (
    render_assessment_type_selector,
    render_portfolio_workflow,
    is_portfolio_assessment,
    save_assessment_or_portfolio,
    get_assessment_or_portfolio,
    export_portfolio_pdf
)


def main():
    """
    Main application entry point
    Modified to support both single-account and portfolio assessments
    """
    
    st.set_page_config(
        page_title="AWS WAF Advisor",
        page_icon="🏗️",
        layout="wide"
    )
    
    # Initialize session state
    if 'waf_assessments' not in st.session_state:
        st.session_state.waf_assessments = {}
    
    # Sidebar
    render_sidebar()
    
    # Main content
    render_main_content()


def render_sidebar():
    """Render sidebar with navigation"""
    
    with st.sidebar:
        st.title("🏗️ AWS WAF Advisor")
        st.markdown("---")
        
        # Navigation
        page = st.radio(
            "Navigation",
            ["🏠 Home", "📋 Assessments", "📊 Dashboard", "⚙️ Settings"],
            label_visibility="collapsed"
        )
        
        st.session_state.current_page = page
        
        st.markdown("---")
        
        # Assessment list
        if st.session_state.waf_assessments:
            st.subheader("Your Assessments")
            
            for assessment_id, assessment in st.session_state.waf_assessments.items():
                assessment_name = assessment.get('name', 'Unnamed')
                is_portfolio = is_portfolio_assessment(assessment)
                
                icon = "🏢" if is_portfolio else "📄"
                
                if st.button(f"{icon} {assessment_name}", key=f"nav_{assessment_id}"):
                    st.session_state.current_assessment_id = assessment_id
                    st.rerun()


def render_main_content():
    """Render main content area"""
    
    page = st.session_state.get('current_page', '🏠 Home')
    
    if page == "🏠 Home":
        render_home_page()
    elif page == "📋 Assessments":
        render_assessments_page()
    elif page == "📊 Dashboard":
        render_dashboard_page()
    elif page == "⚙️ Settings":
        render_settings_page()


def render_home_page():
    """Render home page"""
    
    st.title("🏗️ AWS Well-Architected Framework Advisor")
    
    st.markdown("""
    Welcome to the AWS WAF Advisor! This tool helps you assess your AWS workloads 
    against the Well-Architected Framework's best practices.
    
    ### Features:
    - ✅ Single-account assessments
    - ✅ Multi-account portfolio assessments
    - ✅ Automated AWS infrastructure scanning
    - ✅ AI-powered insights and recommendations
    - ✅ Comprehensive PDF reports
    """)
    
    st.markdown("---")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("🚀 Get Started")
        if st.button("Create New Assessment", type="primary", use_container_width=True):
            st.session_state.current_page = "📋 Assessments"
            st.rerun()
    
    with col2:
        st.subheader("📚 Resources")
        st.markdown("""
        - [AWS Well-Architected Framework](https://aws.amazon.com/architecture/well-architected/)
        - [Documentation](#)
        - [Support](#)
        """)


def render_assessments_page():
    """
    Main assessments page
    THIS IS WHERE THE PORTFOLIO INTEGRATION HAPPENS
    """
    
    st.title("📋 Assessments")
    
    # Check if editing an existing assessment
    if 'current_assessment_id' in st.session_state:
        render_assessment_editor()
        return
    
    # Otherwise, show assessment type selector
    st.markdown("---")
    
    # ⭐ KEY INTEGRATION POINT: Assessment type selector
    assessment_type = render_assessment_type_selector()
    
    st.markdown("---")
    
    if assessment_type == "Multi-Account Portfolio":
        # ⭐ KEY INTEGRATION POINT: Portfolio workflow
        render_portfolio_workflow()
    
    else:
        # ⭐ EXISTING: Single-account workflow
        render_single_account_workflow()


def render_single_account_workflow():
    """
    Your existing single-account assessment creation
    This should be your current code for creating assessments
    """
    
    st.header("📄 Create Single-Account Assessment")
    
    with st.form("create_single_assessment"):
        col1, col2 = st.columns(2)
        
        with col1:
            name = st.text_input("Assessment Name *", placeholder="Q4 2024 Production Review")
            workload_name = st.text_input("Workload Name *", placeholder="Production Environment")
        
        with col2:
            environment = st.selectbox("Environment", ["Production", "Staging", "Development", "Test"])
            assessment_type = st.selectbox("Type", ["Comprehensive", "Targeted", "Compliance-Focused"])
        
        account_id = st.text_input("AWS Account ID", placeholder="123456789012", max_chars=12)
        
        if st.form_submit_button("Create Assessment", type="primary"):
            if not name or not workload_name:
                st.error("❌ Name and workload are required")
            else:
                # Create single-account assessment (your existing logic)
                assessment = {
                    'id': f"assessment_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                    'name': name,
                    'workload_name': workload_name,
                    'type': assessment_type,
                    'environment': environment,
                    'account_id': account_id if account_id else None,
                    'created_at': datetime.now().isoformat(),
                    'updated_at': datetime.now().isoformat(),
                    'overall_score': 0,
                    'progress': 0,
                    'scores': {},
                    'responses': {},
                    'action_items': [],
                    'is_portfolio': False,  # ⭐ Explicit flag
                }
                
                # Save
                save_assessment_or_portfolio(assessment)
                st.session_state.current_assessment_id = assessment['id']
                
                st.success(f"✅ Assessment '{name}' created!")
                st.rerun()


def render_assessment_editor():
    """
    Edit existing assessment (single or portfolio)
    This works for BOTH types automatically
    """
    
    assessment_id = st.session_state.current_assessment_id
    assessment = get_assessment_or_portfolio(assessment_id)
    
    if not assessment:
        st.error("❌ Assessment not found")
        if st.button("Back to Assessments"):
            del st.session_state.current_assessment_id
            st.rerun()
        return
    
    # Show assessment name
    is_portfolio = is_portfolio_assessment(assessment)
    icon = "🏢" if is_portfolio else "📄"
    
    st.title(f"{icon} {assessment.get('name', 'Assessment')}")
    
    # Back button
    if st.button("← Back to Assessments"):
        del st.session_state.current_assessment_id
        st.rerun()
    
    st.markdown("---")
    
    # Different tabs based on type
    if is_portfolio:
        # Portfolio tabs (handled by portfolio workflow)
        from waf_portfolio_integration import (
            render_portfolio_dashboard,
            render_portfolio_management,
            handle_portfolio_scan
        )
        
        tab1, tab2, tab3, tab4, tab5 = st.tabs([
            "📊 Dashboard",
            "⚙️ Manage Accounts",
            "🔍 AWS Scan",
            "📝 Assessment",
            "📄 Export"
        ])
        
        with tab1:
            render_portfolio_dashboard(assessment)
        
        with tab2:
            render_portfolio_management(assessment)
        
        with tab3:
            handle_portfolio_scan(assessment)
        
        with tab4:
            render_waf_questions(assessment)  # Your existing questions UI
        
        with tab5:
            export_portfolio_pdf(assessment)
    
    else:
        # Single-account tabs (your existing UI)
        tab1, tab2, tab3, tab4 = st.tabs([
            "📝 Assessment",
            "🔍 AWS Scan",
            "📊 Scores",
            "📄 Export"
        ])
        
        with tab1:
            render_waf_questions(assessment)  # Your existing function
        
        with tab2:
            render_aws_scan(assessment)  # Your existing function
        
        with tab3:
            render_scores_dashboard(assessment)  # Your existing function
        
        with tab4:
            export_portfolio_pdf(assessment)  # Works for both!


def render_waf_questions(assessment: Dict):
    """
    Your existing WAF questions UI
    This should work the same for both single and portfolio assessments
    """
    
    st.header("📝 WAF Assessment Questions")
    
    # Your existing question rendering logic
    st.info("⚡ This is your existing questions UI - it works for both types!")
    
    # Example structure:
    pillar = st.selectbox("Select Pillar", [
        "Operational Excellence",
        "Security",
        "Reliability",
        "Performance Efficiency",
        "Cost Optimization",
        "Sustainability"
    ])
    
    st.markdown(f"### {pillar}")
    st.markdown("Answer the questions below...")
    
    # Your existing question loop
    # for question in questions:
    #     render_question(question, assessment)


def render_aws_scan(assessment: Dict):
    """
    Your existing AWS scan UI
    Modified to handle portfolios
    """
    
    st.header("🔍 AWS Infrastructure Scan")
    
    # Check if portfolio
    if is_portfolio_assessment(assessment):
        from waf_portfolio_integration import handle_portfolio_scan
        handle_portfolio_scan(assessment)
    else:
        # Your existing single-account scan logic
        st.info("⚡ Single-account scan")
        
        if st.button("🔍 Scan AWS Account", type="primary"):
            st.info("Running AWS scan...")
            # Your existing scan code
            # run_aws_scan(assessment)


def render_scores_dashboard(assessment: Dict):
    """Your existing scores dashboard"""
    
    st.header("📊 Scores & Metrics")
    
    overall_score = assessment.get('overall_score', 0)
    progress = assessment.get('progress', 0)
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("Overall Score", f"{overall_score:.0f}/100")
    
    with col2:
        st.metric("Progress", f"{progress:.0f}%")
    
    with col3:
        action_items = assessment.get('action_items', [])
        st.metric("Action Items", len(action_items))


def render_dashboard_page():
    """Dashboard overview page"""
    
    st.title("📊 Dashboard")
    
    st.info("Dashboard showing all assessments and their status")
    
    # List all assessments
    if not st.session_state.waf_assessments:
        st.warning("No assessments yet. Create one to get started!")
        return
    
    for assessment_id, assessment in st.session_state.waf_assessments.items():
        is_portfolio = is_portfolio_assessment(assessment)
        icon = "🏢" if is_portfolio else "📄"
        
        with st.expander(f"{icon} {assessment.get('name', 'Unnamed')}"):
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.metric("Score", f"{assessment.get('overall_score', 0):.0f}/100")
            
            with col2:
                st.metric("Progress", f"{assessment.get('progress', 0):.0f}%")
            
            with col3:
                if is_portfolio:
                    accounts = assessment.get('accounts', [])
                    st.metric("Accounts", len(accounts))
                else:
                    st.metric("Type", "Single")
            
            if st.button(f"Open {assessment.get('name')}", key=f"open_{assessment_id}"):
                st.session_state.current_assessment_id = assessment_id
                st.session_state.current_page = "📋 Assessments"
                st.rerun()


def render_settings_page():
    """Settings page"""
    
    st.title("⚙️ Settings")
    
    st.subheader("AWS Configuration")
    st.text_input("Default Region", value="us-east-1")
    
    st.subheader("API Keys")
    st.text_input("Anthropic API Key", type="password", value="sk-ant-***")


# =============================================================================
# EXAMPLE USAGE
# =============================================================================

if __name__ == "__main__":
    main()


# =============================================================================
# MIGRATION NOTES
# =============================================================================

"""
TO INTEGRATE INTO YOUR EXISTING APP:

1. Copy these files to your project:
   - portfolio_data_model.py
   - multi_account_scanner.py
   - waf_portfolio_integration.py
   - pdf_report_generator.py (replace with MULTI_ACCOUNT version)

2. In your main app.py or assessment page:
   
   ADD THIS IMPORT:
   from waf_portfolio_integration import (
       render_assessment_type_selector,
       render_portfolio_workflow,
       is_portfolio_assessment
   )
   
   REPLACE YOUR ASSESSMENT CREATION SECTION:
   
   # Before:
   st.header("Create Assessment")
   # ... your single-account form
   
   # After:
   assessment_type = render_assessment_type_selector()
   
   if assessment_type == "Multi-Account Portfolio":
       render_portfolio_workflow()
   else:
       # Your existing single-account form
       pass

3. In your PDF export button:
   
   # Before:
   from pdf_report_generator import generate_waf_pdf_report
   pdf = generate_waf_pdf_report(assessment)
   
   # After: (same code! Auto-detects portfolio)
   from pdf_report_generator import generate_waf_pdf_report
   pdf = generate_waf_pdf_report(assessment)

4. In your AWS scan handler:
   
   # Before:
   if st.button("Scan AWS"):
       run_single_account_scan(assessment)
   
   # After:
   if st.button("Scan AWS"):
       if is_portfolio_assessment(assessment):
           from waf_portfolio_integration import handle_portfolio_scan
           handle_portfolio_scan(assessment)
       else:
           run_single_account_scan(assessment)

That's it! Your existing code continues to work, plus you get portfolio support!
"""
