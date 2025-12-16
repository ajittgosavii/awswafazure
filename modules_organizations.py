"""
Organizations Management Module - Account Provisioning & Governance
UI for AWS Organizations, OUs, SCPs, and account lifecycle
"""

import streamlit as st
import pandas as pd
from typing import Optional
from core_account_manager import get_account_manager, get_account_names
from aws_organizations import AWSOrganizationsManager

class OrganizationsManagementUI:
    """UI for AWS Organizations Management"""
    
    @staticmethod
    def render():
        """Main render method for Organizations module"""
        st.title("🏢 AWS Organizations Management")
        
        # Get account manager
        account_mgr = get_account_manager()
        
        if not account_mgr:
            st.warning("⚠️ Please configure AWS credentials in Account Management")
            st.info("👉 Go to the 'Account Management' tab to add your AWS accounts first.")
            return
        
        # This should be the management account
        st.info("📌 This module requires management account credentials")
        
        # Get account names
        account_names = get_account_names()
        
        if not account_names:
            st.warning("⚠️ No AWS accounts configured")
            st.info("👉 Go to the 'Account Management' tab to add your AWS accounts first.")
            return
        
        selected_account = st.selectbox(
            "Select Management Account",
            options=account_names,
            key="org_account_selector"
        )
        
        if not selected_account:
            st.info("Please select an account")
            return
        
        # Get session
        session = account_mgr.get_session(selected_account)
        if not session:
            st.error(f"Failed to get session for {selected_account}")
            return
        
        # Initialize Organizations Manager
        org_mgr = AWSOrganizationsManager(session)
        
        # Main tabs
        tabs = st.tabs([
            "🏢 Organization",
            "👥 Accounts",
            "📁 Organizational Units",
            "📜 Policies (SCPs)",
            "🏗️ Create Account",
            "🏷️ Tags"
        ])
        
        # Organization Tab
        with tabs[0]:
            OrganizationsManagementUI._render_organization(org_mgr)
        
        # Accounts Tab
        with tabs[1]:
            OrganizationsManagementUI._render_accounts(org_mgr)
        
        # OUs Tab
        with tabs[2]:
            OrganizationsManagementUI._render_ous(org_mgr)
        
        # Policies Tab
        with tabs[3]:
            OrganizationsManagementUI._render_policies(org_mgr)
        
        # Create Account Tab
        with tabs[4]:
            OrganizationsManagementUI._render_create_account(org_mgr)
        
        # Tags Tab
        with tabs[5]:
            OrganizationsManagementUI._render_tags(org_mgr)
    
    @staticmethod
    def _render_organization(org_mgr: AWSOrganizationsManager):
        """Render organization overview"""
        st.subheader("🏢 Organization Overview")
        
        org = org_mgr.get_organization()
        
        if not org:
            st.error("Could not retrieve organization information. Ensure this is the management account.")
            return
        
        # Display organization details
        col1, col2 = st.columns(2)
        with col1:
            st.metric("Organization ID", org['id'])
            st.metric("Master Account ID", org['master_account_id'])
        with col2:
            st.metric("Feature Set", org['feature_set'])
            st.metric("Master Account Email", org['master_account_email'])
        
        # Available policy types
        if org.get('available_policy_types'):
            st.markdown("### Available Policy Types")
            policy_types = pd.DataFrame(org['available_policy_types'])
            st.dataframe(policy_types, use_container_width=True)
    
    @staticmethod
    def _render_accounts(org_mgr: AWSOrganizationsManager):
        """Render accounts list"""
        st.subheader("👥 AWS Accounts")
        
        accounts = org_mgr.list_accounts()
        
        if not accounts:
            st.info("No accounts found")
            return
        
        # Metrics
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Accounts", len(accounts))
        with col2:
            active_accounts = sum(1 for a in accounts if a['status'] == 'ACTIVE')
            st.metric("Active Accounts", active_accounts)
        with col3:
            invited_accounts = sum(1 for a in accounts if a['joined_method'] == 'INVITED')
            st.metric("Invited Accounts", invited_accounts)
        
        # Accounts table
        accounts_df = pd.DataFrame(accounts)
        st.dataframe(
            accounts_df[['id', 'name', 'email', 'status', 'joined_method', 'joined_timestamp']],
            use_container_width=True
        )
        
        # Account details
        if accounts:
            st.markdown("### Account Details")
            selected_account_id = st.selectbox(
                "Select account to view details",
                options=[a['id'] for a in accounts],
                format_func=lambda x: f"{x} - {next((a['name'] for a in accounts if a['id'] == x), '')}"
            )
            
            if selected_account_id:
                account_info = org_mgr.get_account_info(selected_account_id)
                if account_info:
                    col1, col2 = st.columns(2)
                    with col1:
                        st.write("**Account ID:**", account_info['id'])
                        st.write("**Account Name:**", account_info['name'])
                        st.write("**Email:**", account_info['email'])
                    with col2:
                        st.write("**Status:**", account_info['status'])
                        st.write("**Joined Method:**", account_info['joined_method'])
                        st.write("**Joined:**", account_info['joined_timestamp'])
    
    @staticmethod
    def _render_ous(org_mgr: AWSOrganizationsManager):
        """Render Organizational Units"""
        st.subheader("📁 Organizational Units (OUs)")
        
        ous = org_mgr.list_ous()
        
        if ous:
            st.metric("Total OUs", len(ous))
            
            # OU table
            ou_df = pd.DataFrame(ous)
            st.dataframe(ou_df, use_container_width=True)
            
            # OU details
            st.markdown("### OU Details & Accounts")
            selected_ou = st.selectbox(
                "Select OU",
                options=[ou['id'] for ou in ous],
                format_func=lambda x: next((ou['name'] for ou in ous if ou['id'] == x), x)
            )
            
            if selected_ou:
                accounts = org_mgr.list_accounts_for_ou(selected_ou)
                if accounts:
                    st.write(f"**Accounts in this OU:** {len(accounts)}")
                    accounts_df = pd.DataFrame(accounts)
                    st.dataframe(accounts_df, use_container_width=True)
                else:
                    st.info("No accounts in this OU")
        else:
            st.info("No OUs found")
        
        # Create OU
        st.markdown("### Create Organizational Unit")
        with st.expander("Create New OU"):
            ou_name = st.text_input("OU Name", placeholder="Production")
            parent_id = st.text_input("Parent ID (Root or OU ID)", 
                                     help="Get this from the Root or parent OU ARN")
            
            if st.button("Create OU"):
                if ou_name and parent_id:
                    result = org_mgr.create_ou(parent_id, ou_name)
                    if result.get('success'):
                        st.success(f"✅ {result.get('message')}")
                        st.info(f"OU ID: {result.get('ou_id')}")
                        st.rerun()
                    else:
                        st.error(f"❌ {result.get('error')}")
                else:
                    st.warning("Please provide OU name and parent ID")
    
    @staticmethod
    def _render_policies(org_mgr: AWSOrganizationsManager):
        """Render Service Control Policies"""
        st.subheader("📜 Service Control Policies (SCPs)")
        
        policies = org_mgr.list_policies()
        
        if not policies:
            st.info("No policies found")
            return
        
        # Metrics
        col1, col2 = st.columns(2)
        with col1:
            st.metric("Total Policies", len(policies))
        with col2:
            aws_managed = sum(1 for p in policies if p.get('aws_managed'))
            st.metric("AWS Managed", aws_managed)
        
        # Policies table
        policies_df = pd.DataFrame(policies)
        st.dataframe(policies_df[['name', 'type', 'aws_managed', 'description']], 
                    use_container_width=True)
        
        # Policy details
        if policies:
            st.markdown("### Policy Details")
            selected_policy = st.selectbox(
                "Select policy to view content",
                options=[p['id'] for p in policies],
                format_func=lambda x: next((p['name'] for p in policies if p['id'] == x), x)
            )
            
            if selected_policy:
                content = org_mgr.get_policy_content(selected_policy)
                if content:
                    st.json(content)
        
        # Attach/Detach policy
        st.markdown("### Attach/Detach Policy")
        col1, col2 = st.columns(2)
        
        with col1:
            st.write("**Attach Policy**")
            policy_to_attach = st.selectbox(
                "Select Policy",
                options=[p['id'] for p in policies],
                format_func=lambda x: next((p['name'] for p in policies if p['id'] == x), x),
                key="attach_policy"
            )
            target_attach = st.text_input("Target ID (Account or OU)", key="attach_target")
            if st.button("Attach"):
                if policy_to_attach and target_attach:
                    result = org_mgr.attach_policy(policy_to_attach, target_attach)
                    if result.get('success'):
                        st.success(f"✅ {result.get('message')}")
                    else:
                        st.error(f"❌ {result.get('error')}")
        
        with col2:
            st.write("**Detach Policy**")
            policy_to_detach = st.selectbox(
                "Select Policy",
                options=[p['id'] for p in policies],
                format_func=lambda x: next((p['name'] for p in policies if p['id'] == x), x),
                key="detach_policy"
            )
            target_detach = st.text_input("Target ID (Account or OU)", key="detach_target")
            if st.button("Detach"):
                if policy_to_detach and target_detach:
                    result = org_mgr.detach_policy(policy_to_detach, target_detach)
                    if result.get('success'):
                        st.success(f"✅ {result.get('message')}")
                    else:
                        st.error(f"❌ {result.get('error')}")
    
    @staticmethod
    def _render_create_account(org_mgr: AWSOrganizationsManager):
        """Render account creation form"""
        st.subheader("🏗️ Create New AWS Account")
        
        st.info("⏱️ Account creation takes 3-5 minutes. You'll receive an email when complete.")
        
        with st.form("create_account_form"):
            account_name = st.text_input(
                "Account Name",
                placeholder="production-account",
                help="Friendly name for the account"
            )
            
            email = st.text_input(
                "Email Address",
                placeholder="aws+production@company.com",
                help="Must be unique across all AWS accounts"
            )
            
            role_name = st.text_input(
                "Cross-Account Role Name",
                value="OrganizationAccountAccessRole",
                help="This role will be created in the new account"
            )
            
            iam_billing_access = st.checkbox(
                "Allow IAM users to access billing",
                value=False
            )
            
            # Optional: OU selection
            ous = org_mgr.list_ous()
            ou_options = ["None (place in Root)"] + [f"{ou['name']} ({ou['id']})" for ou in ous]
            ou_selection = st.selectbox("Place in Organizational Unit", options=ou_options)
            
            ou_id = None
            if ou_selection != "None (place in Root)":
                ou_id = ou_selection.split('(')[1].rstrip(')')
            
            # Tags
            st.markdown("**Tags (Optional)**")
            col1, col2 = st.columns(2)
            with col1:
                tag_keys = st.text_area("Tag Keys (one per line)", 
                                       placeholder="Environment\nCostCenter\nOwner")
            with col2:
                tag_values = st.text_area("Tag Values (one per line)", 
                                         placeholder="Production\nEngineering\nplatform-team")
            
            submit = st.form_submit_button("Create Account", type="primary")
            
            if submit:
                if not account_name or not email:
                    st.error("Account name and email are required")
                else:
                    # Parse tags
                    tags = None
                    if tag_keys and tag_values:
                        keys = [k.strip() for k in tag_keys.split('\n') if k.strip()]
                        values = [v.strip() for v in tag_values.split('\n') if v.strip()]
                        if len(keys) == len(values):
                            tags = dict(zip(keys, values))
                    
                    with st.spinner("Creating account... This may take 3-5 minutes..."):
                        result = org_mgr.create_account(
                            account_name=account_name,
                            email=email,
                            ou_id=ou_id,
                            iam_user_access=iam_billing_access,
                            role_name=role_name,
                            tags=tags
                        )
                        
                        if result.get('success'):
                            st.success(f"✅ Account created successfully!")
                            st.balloons()
                            st.info(f"**Account ID:** {result.get('account_id')}")
                            st.info(f"**Account Name:** {result.get('account_name')}")
                            st.info(f"**Email:** {result.get('email')}")
                            st.info(f"**Request ID:** {result.get('request_id')}")
                        else:
                            st.error(f"❌ {result.get('error')}")
    
    @staticmethod
    def _render_tags(org_mgr: AWSOrganizationsManager):
        """Render tags management"""
        st.subheader("🏷️ Account Tags")
        
        # Get accounts
        accounts = org_mgr.list_accounts()
        
        if not accounts:
            st.info("No accounts found")
            return
        
        # Select account
        selected_account_id = st.selectbox(
            "Select Account",
            options=[a['id'] for a in accounts],
            format_func=lambda x: f"{x} - {next((a['name'] for a in accounts if a['id'] == x), '')}"
        )
        
        if selected_account_id:
            # Display current tags
            tags = org_mgr.list_tags(selected_account_id)
            
            if tags:
                st.markdown("### Current Tags")
                tags_df = pd.DataFrame([{'Key': k, 'Value': v} for k, v in tags.items()])
                st.dataframe(tags_df, use_container_width=True)
            else:
                st.info("No tags on this account")
            
            # Add tags
            st.markdown("### Add Tags")
            with st.expander("Add New Tags"):
                tag_key = st.text_input("Tag Key", key="new_tag_key")
                tag_value = st.text_input("Tag Value", key="new_tag_value")
                
                if st.button("Add Tag"):
                    if tag_key and tag_value:
                        result = org_mgr.tag_account(selected_account_id, {tag_key: tag_value})
                        if result.get('success'):
                            st.success(f"✅ Tag added")
                            st.rerun()
                        else:
                            st.error(f"❌ {result.get('error')}")
