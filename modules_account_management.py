"""
Module 1: Account & Region Management
Complete account lifecycle management UI
"""

import streamlit as st
import pandas as pd
from typing import Dict, List, Optional
from datetime import datetime
from config_settings import AppConfig
from core_account_manager import get_account_manager
from utils_helpers import Helpers

class AccountManagementModule:
    """Account and region management interface"""
    
    @staticmethod
    def render():
        """Render account management module"""
        
        st.markdown("## 🏢 AWS Account & Region Management")
        st.caption("Manage AWS accounts, regions, and connections")
        
        # Load account manager
        account_mgr = get_account_manager()
        if not account_mgr:
            st.error("❌ AWS account manager not configured")
            return
        
        # Sub-tabs
        tabs = st.tabs([
            "📋 Account Overview",
            "🔌 Connection Status",
            "➕ Add Account",
            "⚙️ Account Settings",
            "🌍 Region Configuration"
        ])
        
        with tabs[0]:
            AccountManagementModule._render_account_overview(account_mgr)
        
        with tabs[1]:
            AccountManagementModule._render_connection_status(account_mgr)
        
        with tabs[2]:
            AccountManagementModule._render_add_account()
        
        with tabs[3]:
            AccountManagementModule._render_account_settings(account_mgr)
        
        with tabs[4]:
            AccountManagementModule._render_region_config()
    
    @staticmethod
    def _render_account_overview(account_mgr):
        """Render account overview"""
        
        st.markdown("### 📊 Connected Accounts Overview")
        
        accounts = AppConfig.load_aws_accounts()
        
        if not accounts:
            st.warning("⚠️ No AWS accounts configured")
            st.info("👉 Go to **Add Account** tab to add your first account")
            return
        
        # Summary metrics
        col1, col2, col3, col4 = st.columns(4)
        
        active_count = len([a for a in accounts if a.status == 'active'])
        suspended_count = len([a for a in accounts if a.status == 'suspended'])
        
        with col1:
            st.metric("Total Accounts", len(accounts))
        with col2:
            st.metric("Active", active_count)
        with col3:
            st.metric("Suspended", suspended_count)
        with col4:
            total_regions = sum(len(a.regions) for a in accounts)
            st.metric("Total Regions", total_regions)
        
        st.markdown("---")
        
        # Account cards
        for idx, acc in enumerate(accounts):
            with st.expander(
                f"{'✅' if acc.status == 'active' else '❌'} **{acc.account_name}** ({acc.account_id})",
                expanded=False
            ):
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown(f"""
                    **Account Details:**
                    - **Account ID:** `{acc.account_id}`
                    - **Environment:** {Helpers.get_environment_badge(acc.environment)}
                    - **Status:** {acc.status.upper()}
                    - **Cost Center:** {acc.cost_center or 'Not set'}
                    """, unsafe_allow_html=True)
                
                with col2:
                    st.markdown(f"""
                    **Configuration:**
                    - **Role ARN:** `{acc.role_arn}`
                    - **Regions:** {', '.join(acc.regions)}
                    - **Owner:** {acc.owner_email or 'Not set'}
                    """)
                
                # Test connection, resources, costs, and DELETE buttons
                col1, col2, col3, col4 = st.columns(4)
                with col1:
                    if st.button("🔄 Test Connection", key=f"test_{acc.account_name}_{acc.account_id}_{idx}"):
                        with st.spinner("Testing connection..."):
                            success, error = account_mgr.test_account_connection(
                                acc.account_id,
                                acc.account_name,
                                acc.role_arn
                            )
                            if success:
                                st.success("✅ Connection successful!")
                            else:
                                st.error(f"❌ Connection failed: {error}")
                
                with col2:
                    if st.button("📊 View Resources", key=f"resources_{acc.account_name}_{acc.account_id}_{idx}"):
                        st.info("Navigate to Resource Inventory tab")
                
                with col3:
                    if st.button("💰 View Costs", key=f"costs_{acc.account_name}_{acc.account_id}_{idx}"):
                        st.info("Navigate to FinOps tab")
                
                with col4:
                    if st.button("🗑️ Delete", key=f"delete_{acc.account_name}_{acc.account_id}_{idx}", type="secondary"):
                        AccountManagementModule._show_delete_instructions(acc)
    
    @staticmethod
    def _show_delete_instructions(account):
        """Show instructions for deleting an account"""
        st.markdown("---")
        st.warning(f"⚠️ **Delete Account: {account.account_name} ({account.account_id})**")
        
        st.markdown("""
        To remove this account from CloudIDP:
        
        **Step 1: Locate the account section in secrets.toml**
        """)
        
        # Generate the section name
        section_name = account.account_name.lower().replace(' ', '_').replace('-', '_')
        
        st.code(f"""
# Find and DELETE this entire section from .streamlit/secrets.toml:

[aws_accounts.{section_name}]
account_id = "{account.account_id}"
account_name = "{account.account_name}"
role_arn = "{account.role_arn}"
regions = {list(account.regions)}
environment = "{account.environment}"
cost_center = "{account.cost_center or ''}"
owner_email = "{account.owner_email or ''}"
status = "{account.status}"
        """, language="toml")
        
        st.markdown("""
        **Step 2: Save the file**
        
        **Step 3: Restart CloudIDP**
        ```bash
        # Stop current process (Ctrl+C)
        # Restart:
        streamlit run streamlit_app.py
        ```
        
        **Step 4: Verify removal**
        - The account should no longer appear in the account list
        - All references to this account will be removed
        """)
        
        st.error("""
        ⚠️ **Warning:**
        - This action cannot be undone from the UI
        - You must manually edit secrets.toml
        - Make a backup of secrets.toml before deleting
        - Deleting the account will not affect your actual AWS account
        """)
        
        st.info("""
        💡 **Alternative:** Instead of deleting, you can set `status = "suspended"` to temporarily disable the account without removing it.
        """)
    
    @staticmethod
    def _render_connection_status(account_mgr):
        """Render connection status for all accounts"""
        
        st.markdown("### 🔌 Connection Health Check")
        st.caption("Test connectivity to all configured accounts")
        
        if st.button("🔄 Test All Connections", type="primary"):
            accounts = AppConfig.load_aws_accounts()
            
            results = []
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            for idx, acc in enumerate(accounts):
                status_text.text(f"Testing {acc.account_name}...")
                
                success, error = account_mgr.test_account_connection(
                    acc.account_id,
                    acc.account_name,
                    acc.role_arn
                )
                
                results.append({
                    'Account Name': acc.account_name,
                    'Account ID': acc.account_id,
                    'Environment': acc.environment.upper(),
                    'Status': '✅ Connected' if success else '❌ Failed',
                    'Role ARN': acc.role_arn,
                    'Error': error if not success else 'None',
                    'Last Tested': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                })
                
                progress_bar.progress((idx + 1) / len(accounts))
            
            status_text.text("✅ All tests complete!")
            
            # Display results
            df = pd.DataFrame(results)
            st.dataframe(df, use_container_width=True, hide_index=True)
            
            # Summary
            successful = len([r for r in results if '✅' in r['Status']])
            st.success(f"✅ {successful}/{len(accounts)} accounts connected successfully")
            
            if successful < len(accounts):
                st.warning(f"⚠️ {len(accounts) - successful} account(s) failed connection test")
    
    @staticmethod
    def _render_add_account():
        """Render add account form"""
        
        st.markdown("### ➕ Add New AWS Account")
        st.caption("Manually register a new AWS account")
        
        st.info("""
        **Two Options to Add Accounts:**
        
        1. **Automated Onboarding** (Recommended)
           - Go to **Account Lifecycle** tab
           - CloudIDP automatically creates IAM roles and configures services
        
        2. **Manual Registration** (Below)
           - Requires pre-configured CloudIDP-Access IAM role in target account
           - Update secrets.toml with account details
        """)
        
        st.markdown("---")
        
        with st.form("add_account_form"):
            st.markdown("#### Account Information")
            
            col1, col2 = st.columns(2)
            
            with col1:
                account_id = st.text_input(
                    "AWS Account ID *",
                    placeholder="123456789012",
                    help="12-digit AWS account ID"
                )
                
                account_name = st.text_input(
                    "Account Name *",
                    placeholder="Production",
                    help="Friendly name for this account"
                )
                
                environment = st.selectbox(
                    "Environment *",
                    options=['production', 'development', 'staging', 'sandbox']
                )
            
            with col2:
                role_arn = st.text_input(
                    "CloudIDP Role ARN *",
                    placeholder="arn:aws:iam::123456789012:role/CloudIDP-Access",
                    help="ARN of the CloudIDP-Access role"
                )
                
                cost_center = st.text_input(
                    "Cost Center",
                    placeholder="Engineering"
                )
                
                owner_email = st.text_input(
                    "Owner Email",
                    placeholder="platform@company.com"
                )
            
            st.markdown("#### Region Configuration")
            
            regions = st.multiselect(
                "Active Regions *",
                options=AppConfig.DEFAULT_REGIONS,
                default=['us-east-1'],
                help="Select regions to monitor"
            )
            
            submitted = st.form_submit_button("➕ Add Account", type="primary")
            
            if submitted:
                if not account_id or not account_name or not role_arn or not regions:
                    st.error("❌ Please fill in all required fields (marked with *)")
                else:
                    st.success("✅ Account configuration validated!")
                    
                    st.code(f"""
# Add this to your .streamlit/secrets.toml:

[aws.accounts.{account_name.lower().replace(' ', '_')}]
account_id = "{account_id}"
account_name = "{account_name}"
role_arn = "{role_arn}"
regions = {regions}
environment = "{environment}"
cost_center = "{cost_center}"
owner_email = "{owner_email}"
status = "active"
                    """, language="toml")
                    
                    st.info("""
                    **Next Steps:**
                    1. Copy the configuration above
                    2. Add it to your `.streamlit/secrets.toml` file
                    3. Restart the application
                    4. Test the connection in **Connection Status** tab
                    """)
    
    @staticmethod
    def _render_account_settings(account_mgr):
        """Render account settings"""
        
        st.markdown("### ⚙️ Account Settings")
        
        accounts = AppConfig.load_aws_accounts()
        
        if not accounts:
            st.info("No accounts to configure")
            return
        
        selected_account = st.selectbox(
            "Select Account",
            options=[f"{a.account_name} ({a.account_id})" for a in accounts]
        )
        
        if not selected_account:
            st.warning("Please select an account")
            return
        
        # Find selected account
        account_id = selected_account.split('(')[1].split(')')[0]
        account = next((a for a in accounts if a.account_id == account_id), None)
        
        if account:
            st.markdown(f"#### Settings for {account.account_name}")
            
            with st.form("account_settings"):
                col1, col2 = st.columns(2)
                
                with col1:
                    new_status = st.selectbox(
                        "Account Status",
                        options=['active', 'suspended', 'offboarding'],
                        index=['active', 'suspended', 'offboarding'].index(account.status)
                    )
                    
                    new_regions = st.multiselect(
                        "Active Regions",
                        options=AppConfig.DEFAULT_REGIONS,
                        default=account.regions
                    )
                
                with col2:
                    new_cost_center = st.text_input(
                        "Cost Center",
                        value=account.cost_center or ""
                    )
                    
                    new_owner = st.text_input(
                        "Owner Email",
                        value=account.owner_email or ""
                    )
                
                # Role ARN editing (full width)
                st.markdown("#### IAM Role Configuration")
                new_role_arn = st.text_input(
                    "CloudIDP Role ARN",
                    value=account.role_arn,
                    help="The ARN of the IAM role that CloudIDP will assume in this account",
                    placeholder="arn:aws:iam::123456789012:role/CloudIDP-ExecutionRole"
                )
                
                if st.form_submit_button("💾 Save Settings", type="primary"):
                    st.success("✅ Settings updated!")
                    
                    # Display updated configuration
                    st.markdown("#### Updated Configuration")
                    st.code(f"""
# Update this in your .streamlit/secrets.toml:

[aws_accounts.{account.account_name.lower().replace(' ', '_').replace('-', '_')}]
account_id = "{account.account_id}"
account_name = "{account.account_name}"
role_arn = "{new_role_arn}"
regions = {list(new_regions)}
environment = "{account.environment}"
cost_center = "{new_cost_center}"
owner_email = "{new_owner}"
status = "{new_status}"
                    """, language="toml")
                    
                    st.info("""
                    **Next Steps:**
                    1. Copy the configuration above
                    2. Update your `.streamlit/secrets.toml` file
                    3. Restart the application to apply changes
                    """)
                    
                    # Show what changed
                    changes = []
                    if new_role_arn != account.role_arn:
                        changes.append(f"**Role ARN:** `{account.role_arn}` → `{new_role_arn}`")
                    if new_status != account.status:
                        changes.append(f"**Status:** {account.status} → {new_status}")
                    if set(new_regions) != set(account.regions):
                        changes.append(f"**Regions:** {account.regions} → {list(new_regions)}")
                    if new_cost_center != (account.cost_center or ""):
                        changes.append(f"**Cost Center:** {account.cost_center or 'None'} → {new_cost_center}")
                    if new_owner != (account.owner_email or ""):
                        changes.append(f"**Owner:** {account.owner_email or 'None'} → {new_owner}")
                    
                    if changes:
                        st.markdown("##### Changes Summary:")
                        for change in changes:
                            st.markdown(f"- {change}", unsafe_allow_html=True)
    
    @staticmethod
    def _render_region_config():
        """Render region configuration"""
        
        st.markdown("### 🌍 AWS Region Configuration")
        
        st.markdown("#### Supported Regions")
        
        regions_data = [
            {'Region Code': 'us-east-1', 'Name': 'US East (N. Virginia)', 'Location': '🇺🇸 USA'},
            {'Region Code': 'us-east-2', 'Name': 'US East (Ohio)', 'Location': '🇺🇸 USA'},
            {'Region Code': 'us-west-1', 'Name': 'US West (California)', 'Location': '🇺🇸 USA'},
            {'Region Code': 'us-west-2', 'Name': 'US West (Oregon)', 'Location': '🇺🇸 USA'},
            {'Region Code': 'eu-west-1', 'Name': 'EU (Ireland)', 'Location': '🇮🇪 Europe'},
            {'Region Code': 'eu-central-1', 'Name': 'EU (Frankfurt)', 'Location': '🇩🇪 Europe'},
            {'Region Code': 'ap-southeast-1', 'Name': 'Asia Pacific (Singapore)', 'Location': '🇸🇬 APAC'},
            {'Region Code': 'ap-northeast-1', 'Name': 'Asia Pacific (Tokyo)', 'Location': '🇯🇵 APAC'}
        ]
        
        df = pd.DataFrame(regions_data)
        st.dataframe(df, use_container_width=True, hide_index=True)
        
        st.markdown("#### Region Usage Across Accounts")
        
        accounts = AppConfig.load_aws_accounts()
        region_usage = {}
        
        for acc in accounts:
            for region in acc.regions:
                region_usage[region] = region_usage.get(region, 0) + 1
        
        if region_usage:
            usage_df = pd.DataFrame(
                list(region_usage.items()),
                columns=['Region', 'Accounts']
            ).sort_values('Accounts', ascending=False)
            
            st.bar_chart(usage_df.set_index('Region'))
