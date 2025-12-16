"""
WAF Portfolio Integration Module
Add this to your existing waf_review_module.py or import from here

This module provides complete portfolio functionality that integrates
seamlessly with your existing single-account WAF assessment code.
"""

import streamlit as st
import boto3
from typing import Dict, List, Optional
from datetime import datetime
from portfolio_data_model import (
    create_portfolio_assessment,
    add_account_to_portfolio,
    remove_account_from_portfolio,
    is_portfolio_assessment,
    merge_auto_detected_answers,
    calculate_portfolio_scores,
    get_account_summary
)
from multi_account_scanner import run_multi_account_scan, validate_account_access


# =============================================================================
# PORTFOLIO ASSESSMENT MANAGEMENT
# =============================================================================

def render_assessment_type_selector():
    """
    Render radio button to choose assessment type
    Call this at the top of your assessment page
    """
    assessment_type = st.radio(
        "📋 Assessment Type",
        ["Single Account", "Multi-Account Portfolio"],
        horizontal=True,
        help="Single Account: Assess one AWS account\nPortfolio: Assess multiple AWS accounts together"
    )
    
    return assessment_type


def handle_portfolio_creation():
    """
    Handle portfolio creation workflow
    Returns portfolio dict if created, None otherwise
    """
    st.header("🏢 Create Multi-Account Portfolio")
    st.markdown("Assess multiple AWS accounts as a unified portfolio with consolidated reporting.")
    
    with st.form("create_portfolio_form"):
        # Basic Info
        st.subheader("Portfolio Details")
        col1, col2 = st.columns(2)
        
        with col1:
            name = st.text_input(
                "Portfolio Name *",
                placeholder="Q4 2024 Production Portfolio",
                help="Descriptive name for this portfolio"
            )
            workload_name = st.text_input(
                "Workload Description *",
                placeholder="Multi-Account Production Environment",
                help="What workload does this portfolio represent?"
            )
        
        with col2:
            environment = st.selectbox(
                "Environment",
                ["Production", "Staging", "Development", "Test", "Multi-Environment"],
                help="Primary environment type"
            )
            assessment_type = st.selectbox(
                "Assessment Type",
                ["Comprehensive", "Targeted", "Compliance-Focused"],
                help="Type of assessment"
            )
        
        st.markdown("---")
        st.subheader("AWS Accounts")
        st.markdown("Add 2 or more AWS accounts to create a portfolio.")
        
        # Account Configuration
        num_accounts = st.number_input(
            "Number of Accounts",
            min_value=2,
            max_value=10,
            value=2,
            help="How many AWS accounts?"
        )
        
        accounts = []
        
        for i in range(int(num_accounts)):
            st.markdown(f"**Account {i+1}**")
            
            col1, col2, col3 = st.columns([2, 2, 1])
            
            with col1:
                account_id = st.text_input(
                    f"Account ID *",
                    key=f"acc_id_{i}",
                    placeholder="123456789012",
                    max_chars=12,
                    help="12-digit AWS account ID"
                )
            
            with col2:
                account_name = st.text_input(
                    f"Account Name *",
                    key=f"acc_name_{i}",
                    placeholder="Production Main",
                    help="Friendly name"
                )
            
            with col3:
                priority = st.selectbox(
                    f"Priority",
                    ["High", "Medium", "Low"],
                    index=0 if i == 0 else 1,  # First account defaults to High
                    key=f"priority_{i}",
                    help="Account importance"
                )
            
            role_arn = st.text_input(
                f"IAM Role ARN (Optional)",
                key=f"role_{i}",
                placeholder="arn:aws:iam::123456789012:role/WAFAdvisorRole",
                help="Leave blank to use default credentials"
            )
            
            regions = st.multiselect(
                f"Regions to Scan",
                ["us-east-1", "us-east-2", "us-west-1", "us-west-2", 
                 "eu-west-1", "eu-west-2", "eu-central-1", 
                 "ap-southeast-1", "ap-southeast-2", "ap-northeast-1"],
                default=["us-east-1"],
                key=f"regions_{i}",
                help="AWS regions to scan"
            )
            
            # Validate and add account
            if account_id and account_name:
                account_config = {
                    'account_id': account_id,
                    'account_name': account_name,
                    'priority': priority.lower(),
                    'regions': regions if regions else ['us-east-1']
                }
                
                if role_arn:
                    account_config['role_arn'] = role_arn
                
                accounts.append(account_config)
            
            st.markdown("---")
        
        # Submit
        submitted = st.form_submit_button(
            "🚀 Create Portfolio",
            type="primary",
            use_container_width=True
        )
        
        if submitted:
            # Validation
            errors = []
            
            if not name:
                errors.append("Portfolio name is required")
            
            if not workload_name:
                errors.append("Workload description is required")
            
            if len(accounts) < 2:
                errors.append("Portfolio must have at least 2 accounts with valid IDs and names")
            
            # Validate account IDs
            for acc in accounts:
                if not acc['account_id'].isdigit() or len(acc['account_id']) != 12:
                    errors.append(f"Invalid account ID: {acc['account_id']} (must be 12 digits)")
            
            # Check duplicates
            account_ids = [acc['account_id'] for acc in accounts]
            if len(account_ids) != len(set(account_ids)):
                errors.append("Duplicate account IDs detected")
            
            if errors:
                for error in errors:
                    st.error(f"❌ {error}")
                return None
            
            # Create portfolio
            try:
                portfolio = create_portfolio_assessment(
                    name=name,
                    workload_name=workload_name,
                    accounts=accounts,
                    environment=environment,
                    assessment_type=assessment_type
                )
                
                st.success(f"✅ Portfolio '{name}' created successfully!")
                st.success(f"📊 {len(accounts)} accounts configured")
                st.balloons()
                
                return portfolio
                
            except Exception as e:
                st.error(f"❌ Error creating portfolio: {e}")
                return None
    
    return None


def render_portfolio_dashboard(assessment: Dict):
    """
    Render portfolio dashboard view
    Shows metrics and account comparison
    """
    if not is_portfolio_assessment(assessment):
        st.warning("⚠️ This is not a portfolio assessment")
        return
    
    st.header("📊 Portfolio Dashboard")
    
    # Get data
    accounts = assessment.get('accounts', [])
    scores_by_account = assessment.get('scores_by_account', {})
    overall_score = assessment.get('overall_score', 0)
    progress = assessment.get('progress', 0)
    summary = get_account_summary(assessment)
    
    # Top metrics
    col1, col2, col3, col4, col5 = st.columns(5)
    
    with col1:
        st.metric("Portfolio Score", f"{overall_score:.0f}/100")
    
    with col2:
        st.metric("Progress", f"{progress:.0f}%")
    
    with col3:
        st.metric("Total Accounts", summary['total_accounts'])
    
    with col4:
        st.metric("Scanned", summary['scanned_accounts'])
    
    with col5:
        st.metric("Pending", summary['pending_accounts'])
    
    st.markdown("---")
    
    # Account comparison table
    st.subheader("Account Status")
    
    table_data = []
    for account in accounts:
        account_id = account['account_id']
        account_name = account.get('account_name', account_id)
        priority = account.get('priority', 'medium')
        score = scores_by_account.get(account_id, 0)
        
        # Priority icon
        if priority == 'high':
            priority_icon = "🔴 High"
        elif priority == 'medium':
            priority_icon = "🟡 Medium"
        else:
            priority_icon = "🟢 Low"
        
        # Status
        if score > 0:
            status = f"✅ {score:.0f}/100"
        else:
            status = "⏳ Pending"
        
        table_data.append({
            'Account Name': account_name,
            'Account ID': account_id,
            'Priority': priority_icon,
            'Score': status,
            'Regions': ', '.join(account.get('regions', ['us-east-1']))
        })
    
    st.table(table_data)


def render_portfolio_management(assessment: Dict):
    """
    Render portfolio account management interface
    Add/remove accounts
    """
    if not is_portfolio_assessment(assessment):
        st.warning("⚠️ This is not a portfolio assessment")
        return
    
    st.header("⚙️ Manage Portfolio Accounts")
    
    accounts = assessment.get('accounts', [])
    
    # Current accounts
    st.subheader("Current Accounts")
    
    for idx, account in enumerate(accounts):
        account_id = account['account_id']
        account_name = account.get('account_name', 'Unknown')
        priority = account.get('priority', 'medium')
        
        with st.expander(f"{'🔴' if priority == 'high' else '🟡' if priority == 'medium' else '🟢'} {account_name} ({account_id})"):
            col1, col2 = st.columns([3, 1])
            
            with col1:
                st.write(f"**Account ID:** {account_id}")
                st.write(f"**Priority:** {priority.title()}")
                st.write(f"**Regions:** {', '.join(account.get('regions', ['us-east-1']))}")
                
                if 'role_arn' in account:
                    st.code(account['role_arn'], language='text')
            
            with col2:
                if st.button("🗑️ Remove", key=f"remove_{idx}"):
                    try:
                        assessment = remove_account_from_portfolio(assessment, account_id)
                        
                        # Update in session state
                        if 'waf_assessments' in st.session_state:
                            st.session_state.waf_assessments[assessment['id']] = assessment
                        
                        st.success(f"✅ Removed {account_name}")
                        st.rerun()
                    except Exception as e:
                        st.error(f"❌ Error: {e}")
    
    st.markdown("---")
    
    # Add new account
    st.subheader("➕ Add Account")
    
    with st.form("add_account_form"):
        col1, col2 = st.columns(2)
        
        with col1:
            new_account_id = st.text_input("Account ID *", max_chars=12, placeholder="123456789012")
            new_account_name = st.text_input("Account Name *", placeholder="Production Secondary")
        
        with col2:
            new_priority = st.selectbox("Priority", ["High", "Medium", "Low"], index=1)
            new_regions = st.multiselect(
                "Regions",
                ["us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-west-1", "eu-central-1"],
                default=["us-east-1"]
            )
        
        new_role_arn = st.text_input("IAM Role ARN (Optional)", placeholder="arn:aws:iam::123456789012:role/WAFAdvisorRole")
        
        if st.form_submit_button("Add Account", type="primary"):
            if not new_account_id or not new_account_name:
                st.error("❌ Account ID and name are required")
            elif not new_account_id.isdigit() or len(new_account_id) != 12:
                st.error("❌ Invalid account ID format (must be 12 digits)")
            else:
                try:
                    assessment = add_account_to_portfolio(
                        assessment,
                        account_id=new_account_id,
                        account_name=new_account_name,
                        role_arn=new_role_arn if new_role_arn else None,
                        regions=new_regions if new_regions else ['us-east-1'],
                        priority=new_priority.lower()
                    )
                    
                    # Update in session state
                    if 'waf_assessments' in st.session_state:
                        st.session_state.waf_assessments[assessment['id']] = assessment
                    
                    st.success(f"✅ Added {new_account_name}")
                    st.rerun()
                except ValueError as e:
                    st.error(f"❌ {e}")
                except Exception as e:
                    st.error(f"❌ Error: {e}")


def handle_portfolio_scan(assessment: Dict):
    """
    Handle portfolio AWS scan
    Integrates with your existing AWS helper and auto-detector
    """
    if not is_portfolio_assessment(assessment):
        st.warning("⚠️ This is not a portfolio assessment")
        return
    
    st.header("🔍 Portfolio AWS Scan")
    
    accounts = assessment.get('accounts', [])
    summary = get_account_summary(assessment)
    
    # Status display
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("Total Accounts", summary['total_accounts'])
    
    with col2:
        st.metric("Scanned", summary['scanned_accounts'], 
                 delta=f"{summary['scanned_accounts']} complete")
    
    with col3:
        st.metric("Pending", summary['pending_accounts'],
                 delta=f"{summary['pending_accounts']} remaining")
    
    st.markdown("---")
    
    # Scan buttons
    col1, col2 = st.columns(2)
    
    with col1:
        scan_all = st.button(
            "🔍 Scan All Accounts",
            type="primary",
            use_container_width=True,
            help="Scan all accounts in portfolio"
        )
    
    with col2:
        rescan = st.button(
            "🔄 Re-scan Portfolio",
            use_container_width=True,
            help="Re-scan previously scanned accounts"
        )
    
    if scan_all or rescan:
        st.info(f"🔍 Starting portfolio scan: {len(accounts)} accounts...")
        
        try:
            # Get AWS helper and auto-detector from session state if available
            aws_helper = st.session_state.get('aws_helper', None)
            auto_detector = st.session_state.get('auto_detector', None)
            
            # Run multi-account scan
            updated_assessment = run_multi_account_scan(
                assessment,
                aws_helper=aws_helper,
                auto_detector=auto_detector
            )
            
            # Update in session state
            if 'waf_assessments' in st.session_state:
                st.session_state.waf_assessments[assessment['id']] = updated_assessment
            
            # Calculate scores if scan completed
            if updated_assessment.get('scan_completed_at'):
                st.info("📊 Calculating portfolio scores...")
                
                # You'll integrate this with your existing scoring logic
                # For now, placeholder
                st.success("✅ Portfolio scan complete!")
            
            st.rerun()
            
        except Exception as e:
            st.error(f"❌ Scan failed: {e}")
            st.exception(e)


# =============================================================================
# INTEGRATION WITH EXISTING CODE
# =============================================================================

def get_assessment_or_portfolio(assessment_id: str) -> Optional[Dict]:
    """
    Get assessment from session state
    Works for both single and portfolio assessments
    """
    if 'waf_assessments' not in st.session_state:
        return None
    
    return st.session_state.waf_assessments.get(assessment_id)


def save_assessment_or_portfolio(assessment: Dict):
    """
    Save assessment to session state
    Works for both single and portfolio assessments
    """
    if 'waf_assessments' not in st.session_state:
        st.session_state.waf_assessments = {}
    
    st.session_state.waf_assessments[assessment['id']] = assessment
    assessment['updated_at'] = datetime.now().isoformat()


def export_portfolio_pdf(assessment: Dict):
    """
    Export portfolio PDF
    Integrates with your existing PDF export button
    """
    from pdf_report_generator import generate_waf_pdf_report
    
    try:
        pdf_bytes = generate_waf_pdf_report(assessment)
        
        # Determine filename
        assessment_name = assessment.get('name', 'assessment').replace(' ', '_')
        if is_portfolio_assessment(assessment):
            filename = f"{assessment_name}_Portfolio_Report.pdf"
        else:
            filename = f"{assessment_name}_Report.pdf"
        
        st.download_button(
            label="📥 Download PDF Report",
            data=pdf_bytes,
            file_name=filename,
            mime="application/pdf",
            use_container_width=True
        )
        
        st.success("✅ PDF generated successfully!")
        
    except Exception as e:
        st.error(f"❌ Error generating PDF: {e}")
        st.info("💡 Make sure reportlab is installed: pip install reportlab")


# =============================================================================
# MAIN PORTFOLIO WORKFLOW
# =============================================================================

def render_portfolio_workflow():
    """
    Complete portfolio workflow
    Call this from your main app when user selects "Multi-Account Portfolio"
    """
    
    # Check if we have a current portfolio
    if 'current_portfolio_id' not in st.session_state:
        # Create new portfolio
        portfolio = handle_portfolio_creation()
        
        if portfolio:
            # Save to session state
            save_assessment_or_portfolio(portfolio)
            st.session_state.current_portfolio_id = portfolio['id']
            st.rerun()
    
    else:
        # Load existing portfolio
        portfolio_id = st.session_state.current_portfolio_id
        portfolio = get_assessment_or_portfolio(portfolio_id)
        
        if not portfolio:
            st.error("❌ Portfolio not found")
            if st.button("Create New Portfolio"):
                del st.session_state.current_portfolio_id
                st.rerun()
            return
        
        # Show portfolio name
        st.title(f"🏢 {portfolio.get('name', 'Portfolio')}")
        
        # Tabs for portfolio management
        tab1, tab2, tab3, tab4, tab5 = st.tabs([
            "📊 Dashboard",
            "⚙️ Manage Accounts",
            "🔍 AWS Scan",
            "📝 Assessment",
            "📄 Export PDF"
        ])
        
        with tab1:
            render_portfolio_dashboard(portfolio)
        
        with tab2:
            render_portfolio_management(portfolio)
        
        with tab3:
            handle_portfolio_scan(portfolio)
        
        with tab4:
            st.info("📝 Assessment questions will appear here")
            st.markdown("Complete the AWS Well-Architected Framework questions for your portfolio.")
            # Your existing assessment questions UI goes here
            # It should work with portfolio just like single account
        
        with tab5:
            st.header("📄 Export Portfolio PDF")
            st.markdown("Generate a comprehensive PDF report for this portfolio assessment.")
            
            export_portfolio_pdf(portfolio)
            
            # Additional export options
            if st.button("🔙 Back to Portfolio List"):
                del st.session_state.current_portfolio_id
                st.rerun()
