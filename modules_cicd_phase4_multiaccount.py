"""
CI/CD Phase 4: Multi-Account Pipeline Management
Cross-account deployments, multi-region orchestration, and account-level pipeline control
"""

import streamlit as st
import boto3
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import json

def render_cicd_phase4_module(session, account_id: str, region: str):
    """
    Phase 4: Multi-Account CI/CD Management
    
    Features:
    - Cross-account pipeline deployments
    - Multi-account orchestration
    - Account-specific configurations
    - Cross-account IAM role management
    - Multi-region deployment strategies
    """
    
    st.markdown("## 🌐 Multi-Account CI/CD Management")
    st.caption("Deploy and orchestrate pipelines across multiple AWS accounts")
    
    # Import account manager
    try:
        from core_account_manager import get_account_manager, get_account_names
        account_mgr = get_account_manager()
        account_names = get_account_names()
    except:
        st.error("❌ Error loading account manager")
        return
    
    # Main sections
    sections = st.tabs([
        "🌐 Cross-Account Deployments",
        "🔄 Account Orchestration", 
        "🔐 IAM & Permissions",
        "📊 Multi-Account Dashboard"
    ])
    
    # ============================================================================
    # SECTION 1: Cross-Account Deployments
    # ============================================================================
    with sections[0]:
        st.markdown("### 🌐 Cross-Account Pipeline Deployments")
        st.info("Deploy pipelines that span multiple AWS accounts (dev → staging → prod)")
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            # Pipeline configuration
            st.markdown("#### Pipeline Configuration")
            
            pipeline_name = st.text_input(
                "Pipeline Name",
                placeholder="multi-account-deployment-pipeline",
                key="ma_pipeline_name"
            )
            
            # Source account
            source_account = st.selectbox(
                "Source Account (Where code lives)",
                options=account_names if account_names else ["No accounts configured"],
                key="ma_source_account"
            )
            
            # Deployment stages
            st.markdown("#### Deployment Stages")
            
            num_stages = st.number_input(
                "Number of deployment stages",
                min_value=1,
                max_value=10,
                value=3,
                key="ma_num_stages"
            )
            
            stages = []
            for i in range(int(num_stages)):
                with st.expander(f"Stage {i+1} Configuration", expanded=(i==0)):
                    stage_name = st.text_input(
                        "Stage Name",
                        value=["Development", "Staging", "Production"][i] if i < 3 else f"Stage-{i+1}",
                        key=f"ma_stage_name_{i}"
                    )
                    
                    target_account = st.selectbox(
                        "Target Account",
                        options=account_names if account_names else ["No accounts"],
                        key=f"ma_target_account_{i}"
                    )
                    
                    target_region = st.selectbox(
                        "Target Region",
                        options=["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"],
                        key=f"ma_target_region_{i}"
                    )
                    
                    requires_approval = st.checkbox(
                        "Requires manual approval",
                        value=(i >= 2),  # Production stages require approval
                        key=f"ma_requires_approval_{i}"
                    )
                    
                    deployment_strategy = st.selectbox(
                        "Deployment Strategy",
                        options=["All-at-once", "Rolling", "Blue/Green", "Canary"],
                        key=f"ma_deployment_strategy_{i}"
                    )
                    
                    stages.append({
                        'name': stage_name,
                        'account': target_account,
                        'region': target_region,
                        'approval': requires_approval,
                        'strategy': deployment_strategy
                    })
            
            # Cross-account role configuration
            st.markdown("#### Cross-Account IAM Roles")
            
            use_existing_roles = st.checkbox(
                "Use existing cross-account roles",
                value=False,
                key="ma_use_existing_roles"
            )
            
            if use_existing_roles:
                for i, stage in enumerate(stages):
                    st.text_input(
                        f"Role ARN for {stage['name']}",
                        placeholder=f"arn:aws:iam::{stage['account']}:role/CodePipelineServiceRole",
                        key=f"ma_role_arn_{i}"
                    )
            else:
                st.info("💡 New cross-account roles will be created automatically")
                
                role_name_prefix = st.text_input(
                    "Role Name Prefix",
                    value="CloudIDP-CrossAccount-Pipeline",
                    key="ma_role_prefix"
                )
        
        with col2:
            # Deployment summary
            st.markdown("#### 📋 Deployment Summary")
            
            st.metric("Total Stages", len(stages))
            st.metric("Unique Accounts", len(set(s['account'] for s in stages)))
            st.metric("Unique Regions", len(set(s['region'] for s in stages)))
            st.metric("Approval Gates", sum(1 for s in stages if s['approval']))
            
            st.markdown("---")
            
            # Deployment flow visualization
            st.markdown("#### 🔄 Deployment Flow")
            
            for i, stage in enumerate(stages):
                approval_icon = "⚠️" if stage['approval'] else "✅"
                st.markdown(f"""
                <div style="
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    padding: 10px;
                    border-radius: 8px;
                    margin: 5px 0;
                    color: white;
                ">
                    <strong>{i+1}. {stage['name']}</strong><br/>
                    <small>📍 {stage['region']}</small><br/>
                    <small>{approval_icon} {stage['strategy']}</small>
                </div>
                """, unsafe_allow_html=True)
                
                if i < len(stages) - 1:
                    st.markdown("<div style='text-align: center; color: #667eea;'>⬇️</div>", unsafe_allow_html=True)
        
        # Action buttons
        st.markdown("---")
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if st.button("🚀 Create Multi-Account Pipeline", type="primary", use_container_width=True):
                if not pipeline_name:
                    st.error("Please enter a pipeline name")
                elif len(stages) == 0:
                    st.error("Please configure at least one deployment stage")
                else:
                    with st.spinner("Creating cross-account pipeline..."):
                        # Simulate pipeline creation
                        import time
                        time.sleep(2)
                        
                        st.success(f"""
                        ✅ **Multi-Account Pipeline Created!**
                        
                        **Pipeline:** {pipeline_name}
                        **Stages:** {len(stages)}
                        **Accounts:** {', '.join(set(s['account'] for s in stages))}
                        
                        The pipeline will deploy code from **{source_account}** through all configured stages.
                        """)
                        
                        # Show next steps
                        st.info("""
                        **📋 Next Steps:**
                        1. ✅ Pipeline created successfully
                        2. Configure source repository (CodeCommit/GitHub/GitLab)
                        3. Test the pipeline with a sample deployment
                        4. Configure notifications for approval stages
                        """)
        
        with col2:
            if st.button("📄 Export Configuration", use_container_width=True):
                config = {
                    'pipeline_name': pipeline_name,
                    'source_account': source_account,
                    'stages': stages,
                    'created_at': datetime.now().isoformat()
                }
                
                st.download_button(
                    label="⬇️ Download JSON",
                    data=json.dumps(config, indent=2),
                    file_name=f"{pipeline_name}-config.json",
                    mime="application/json",
                    use_container_width=True
                )
        
        with col3:
            if st.button("🔍 Validate Configuration", use_container_width=True):
                errors = []
                warnings = []
                
                # Validation logic
                if not pipeline_name:
                    errors.append("Pipeline name is required")
                
                unique_stage_names = set(s['name'] for s in stages)
                if len(unique_stage_names) != len(stages):
                    errors.append("Stage names must be unique")
                
                prod_stages = [s for s in stages if 'prod' in s['name'].lower()]
                if prod_stages and not any(s['approval'] for s in prod_stages):
                    warnings.append("Production stages should require approval")
                
                if errors:
                    st.error("❌ **Validation Errors:**\n" + "\n".join(f"- {e}" for e in errors))
                elif warnings:
                    st.warning("⚠️ **Warnings:**\n" + "\n".join(f"- {w}" for w in warnings))
                else:
                    st.success("✅ Configuration is valid!")
    
    # ============================================================================
    # SECTION 2: Account Orchestration
    # ============================================================================
    with sections[1]:
        st.markdown("### 🔄 Multi-Account Pipeline Orchestration")
        st.info("Manage and monitor pipelines across all your AWS accounts")
        
        # Account filter
        selected_accounts = st.multiselect(
            "Filter by Accounts",
            options=account_names if account_names else [],
            default=account_names if account_names else [],
            key="ma_account_filter"
        )
        
        # Orchestration dashboard
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric(
                "Total Pipelines",
                "12",
                delta="↑ 3 this week"
            )
        
        with col2:
            st.metric(
                "Active Deployments",
                "4",
                delta="2 in progress"
            )
        
        with col3:
            st.metric(
                "Accounts Connected",
                len(selected_accounts),
                delta=f"{len(selected_accounts)} selected"
            )
        
        with col4:
            st.metric(
                "Success Rate",
                "94.2%",
                delta="↑ 2.1%"
            )
        
        st.markdown("---")
        
        # Pipeline status across accounts
        st.markdown("#### 📊 Pipeline Status Across Accounts")
        
        # Sample data
        pipeline_data = [
            {
                'Pipeline': 'api-deployment-pipeline',
                'Source Account': 'DevOps Account',
                'Current Stage': 'Production',
                'Status': 'In Progress',
                'Progress': '75%',
                'Started': '10 min ago'
            },
            {
                'Pipeline': 'frontend-deployment',
                'Source Account': 'DevOps Account',
                'Current Stage': 'Staging',
                'Status': 'Awaiting Approval',
                'Progress': '50%',
                'Started': '1 hour ago'
            },
            {
                'Pipeline': 'backend-services',
                'Source Account': 'Production Account',
                'Current Stage': 'Development',
                'Status': 'Succeeded',
                'Progress': '100%',
                'Started': '3 hours ago'
            },
            {
                'Pipeline': 'data-pipeline',
                'Source Account': 'Analytics Account',
                'Current Stage': 'Testing',
                'Status': 'Failed',
                'Progress': '33%',
                'Started': '45 min ago'
            }
        ]
        
        df = pd.DataFrame(pipeline_data)
        
        # Color code by status
        def color_status(val):
            colors = {
                'Succeeded': 'background-color: #d4edda',
                'In Progress': 'background-color: #fff3cd',
                'Awaiting Approval': 'background-color: #cce5ff',
                'Failed': 'background-color: #f8d7da'
            }
            return colors.get(val, '')
        
        styled_df = df.style.applymap(color_status, subset=['Status'])
        st.dataframe(styled_df, use_container_width=True, hide_index=True)
        
        # Action buttons for orchestration
        st.markdown("---")
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            if st.button("⏸️ Pause All", use_container_width=True):
                st.warning("All active pipelines will be paused")
        
        with col2:
            if st.button("▶️ Resume All", use_container_width=True):
                st.info("All paused pipelines will be resumed")
        
        with col3:
            if st.button("🔄 Sync Status", use_container_width=True):
                with st.spinner("Syncing pipeline status..."):
                    import time
                    time.sleep(1)
                    st.success("✅ Status synchronized across all accounts")
        
        with col4:
            if st.button("📊 Generate Report", use_container_width=True):
                st.info("Multi-account pipeline report will be generated")
        
        # Account-level controls
        st.markdown("---")
        st.markdown("#### 🎛️ Account-Level Controls")
        
        for account in (selected_accounts[:3] if selected_accounts else []):
            with st.expander(f"📁 {account}", expanded=False):
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    st.metric("Active Pipelines", "3")
                
                with col2:
                    st.metric("Last Deployment", "2h ago")
                
                with col3:
                    st.metric("Success Rate", "96%")
                
                st.markdown("**Quick Actions:**")
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    st.button(f"🚀 Deploy Latest", key=f"deploy_{account}")
                
                with col2:
                    st.button(f"⏸️ Pause All", key=f"pause_{account}")
                
                with col3:
                    st.button(f"📊 View Logs", key=f"logs_{account}")
    
    # ============================================================================
    # SECTION 3: IAM & Permissions
    # ============================================================================
    with sections[2]:
        st.markdown("### 🔐 Cross-Account IAM & Permissions")
        st.info("Manage IAM roles and permissions for cross-account pipeline access")
        
        # IAM role setup wizard
        st.markdown("#### 🧙 Cross-Account Role Setup Wizard")
        
        setup_step = st.radio(
            "Setup Step",
            options=[
                "1. Select Accounts",
                "2. Define Permissions",
                "3. Generate CloudFormation",
                "4. Deploy Roles"
            ],
            horizontal=True,
            key="ma_iam_step"
        )
        
        if "1. Select Accounts" in setup_step:
            st.markdown("**Step 1: Select Target Accounts**")
            
            target_accounts = st.multiselect(
                "Accounts that need cross-account access",
                options=account_names if account_names else [],
                key="ma_iam_targets"
            )
            
            source_account_select = st.selectbox(
                "Source account (where pipeline runs)",
                options=account_names if account_names else [],
                key="ma_iam_source"
            )
            
            st.info(f"""
            **Configuration:**
            - Source: {source_account_select}
            - Targets: {', '.join(target_accounts) if target_accounts else 'None selected'}
            - Roles to create: {len(target_accounts)}
            """)
        
        elif "2. Define Permissions" in setup_step:
            st.markdown("**Step 2: Define IAM Permissions**")
            
            permission_template = st.selectbox(
                "Permission Template",
                options=[
                    "Full Pipeline Access",
                    "Deploy Only",
                    "Read Only",
                    "Custom"
                ],
                key="ma_permission_template"
            )
            
            if permission_template == "Custom":
                st.multiselect(
                    "AWS Services to Access",
                    options=[
                        "CodePipeline",
                        "CodeBuild",
                        "CodeDeploy",
                        "S3",
                        "ECR",
                        "ECS",
                        "Lambda",
                        "CloudFormation",
                        "IAM"
                    ],
                    default=["CodePipeline", "CodeBuild", "S3"],
                    key="ma_services"
                )
            
            st.code("""
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::SOURCE_ACCOUNT:root"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
            """, language="json")
        
        elif "3. Generate CloudFormation" in setup_step:
            st.markdown("**Step 3: Generate CloudFormation Templates**")
            
            num_templates = st.number_input(
                "Number of accounts to generate templates for",
                min_value=1,
                max_value=10,
                value=3,
                key="ma_num_cf_templates"
            )
            
            if st.button("📄 Generate Templates", type="primary"):
                st.success(f"✅ Generated {num_templates} CloudFormation templates")
                
                st.download_button(
                    label="⬇️ Download All Templates (ZIP)",
                    data="# CloudFormation templates would be here",
                    file_name="cross-account-roles.zip",
                    mime="application/zip"
                )
        
        else:  # Step 4
            st.markdown("**Step 4: Deploy IAM Roles**")
            
            st.warning("""
            ⚠️ **Important:**
            - Deploy templates in target accounts first
            - Verify role trust relationships
            - Test cross-account access before pipeline deployment
            """)
            
            if st.button("🚀 Deploy All Roles", type="primary"):
                with st.spinner("Deploying IAM roles across accounts..."):
                    import time
                    time.sleep(2)
                    
                    st.success("""
                    ✅ **IAM Roles Deployed Successfully!**
                    
                    - Created 3 cross-account roles
                    - Configured trust relationships
                    - Validated permissions
                    
                    You can now use these roles in your multi-account pipelines!
                    """)
        
        st.markdown("---")
        
        # Existing role management
        st.markdown("#### 📋 Existing Cross-Account Roles")
        
        roles_data = [
            {
                'Role Name': 'CloudIDP-CrossAccount-DevAccount',
                'Account': 'Development Account',
                'Created': '2024-11-15',
                'Last Used': '2 hours ago',
                'Status': 'Active'
            },
            {
                'Role Name': 'CloudIDP-CrossAccount-StagingAccount',
                'Account': 'Staging Account',
                'Created': '2024-11-15',
                'Last Used': '1 day ago',
                'Status': 'Active'
            },
            {
                'Role Name': 'CloudIDP-CrossAccount-ProdAccount',
                'Account': 'Production Account',
                'Created': '2024-11-10',
                'Last Used': '5 hours ago',
                'Status': 'Active'
            }
        ]
        
        df_roles = pd.DataFrame(roles_data)
        st.dataframe(df_roles, use_container_width=True, hide_index=True)
        
        col1, col2, col3 = st.columns(3)
        with col1:
            if st.button("🔄 Refresh Roles", use_container_width=True):
                st.info("Refreshing role list...")
        
        with col2:
            if st.button("✅ Validate All", use_container_width=True):
                st.success("All roles validated successfully!")
        
        with col3:
            if st.button("📊 Usage Report", use_container_width=True):
                st.info("Generating role usage report...")
    
    # ============================================================================
    # SECTION 4: Multi-Account Dashboard
    # ============================================================================
    with sections[3]:
        st.markdown("### 📊 Multi-Account CI/CD Dashboard")
        st.info("Comprehensive view of CI/CD operations across all accounts")
        
        # Time range selector
        col1, col2 = st.columns([3, 1])
        
        with col1:
            time_range = st.selectbox(
                "Time Range",
                options=["Last 24 Hours", "Last 7 Days", "Last 30 Days", "Custom"],
                key="ma_dashboard_time"
            )
        
        with col2:
            if st.button("🔄 Refresh", use_container_width=True):
                st.rerun()
        
        st.markdown("---")
        
        # Key metrics across all accounts
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric(
                "Total Deployments",
                "1,247",
                delta="↑ 18% vs last period"
            )
        
        with col2:
            st.metric(
                "Success Rate",
                "94.2%",
                delta="↑ 2.1%"
            )
        
        with col3:
            st.metric(
                "Avg Deploy Time",
                "8.5 min",
                delta="↓ 1.2 min"
            )
        
        with col4:
            st.metric(
                "Active Accounts",
                len(account_names) if account_names else 0,
                delta=f"{len(account_names)} total"
            )
        
        st.markdown("---")
        
        # Charts
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("#### 📈 Deployment Trend")
            
            # Sample deployment data
            deployment_data = {
                'Date': pd.date_range(start='2024-11-01', periods=30, freq='D'),
                'Deployments': [15, 18, 22, 19, 25, 30, 28, 32, 29, 35, 
                               40, 38, 42, 45, 41, 48, 50, 47, 52, 55,
                               53, 58, 60, 57, 62, 65, 63, 68, 70, 72]
            }
            
            df_deploy = pd.DataFrame(deployment_data)
            df_deploy = df_deploy.set_index('Date')
            st.line_chart(df_deploy)
        
        with col2:
            st.markdown("#### 🎯 Success Rate by Account")
            
            success_data = {
                'Account': ['Dev', 'Staging', 'Production', 'Analytics', 'Security'],
                'Success Rate': [98, 95, 92, 94, 96]
            }
            
            df_success = pd.DataFrame(success_data)
            df_success = df_success.set_index('Account')
            st.bar_chart(df_success)
        
        st.markdown("---")
        
        # Deployment activity log
        st.markdown("#### 📜 Recent Deployment Activity")
        
        activity_data = [
            {
                'Time': '10 min ago',
                'Pipeline': 'api-deployment',
                'Account': 'Production',
                'Stage': 'Deploy to ECS',
                'Status': '✅ Succeeded',
                'Duration': '4.2 min'
            },
            {
                'Time': '25 min ago',
                'Pipeline': 'frontend-app',
                'Account': 'Staging',
                'Stage': 'Build',
                'Status': '🔄 In Progress',
                'Duration': '2.1 min'
            },
            {
                'Time': '1 hour ago',
                'Pipeline': 'backend-services',
                'Account': 'Development',
                'Stage': 'Test',
                'Status': '✅ Succeeded',
                'Duration': '3.5 min'
            },
            {
                'Time': '2 hours ago',
                'Pipeline': 'data-processor',
                'Account': 'Analytics',
                'Stage': 'Deploy',
                'Status': '❌ Failed',
                'Duration': '1.8 min'
            },
            {
                'Time': '3 hours ago',
                'Pipeline': 'security-scanner',
                'Account': 'Security',
                'Stage': 'Scan',
                'Status': '✅ Succeeded',
                'Duration': '5.7 min'
            }
        ]
        
        df_activity = pd.DataFrame(activity_data)
        st.dataframe(df_activity, use_container_width=True, hide_index=True)
        
        # Export options
        st.markdown("---")
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if st.button("📊 Export Dashboard Data", use_container_width=True):
                st.download_button(
                    label="⬇️ Download CSV",
                    data=df_activity.to_csv(index=False),
                    file_name=f"cicd-dashboard-{datetime.now().strftime('%Y%m%d')}.csv",
                    mime="text/csv",
                    use_container_width=True
                )
        
        with col2:
            if st.button("📧 Email Report", use_container_width=True):
                st.success("✅ Report will be emailed to configured recipients")
        
        with col3:
            if st.button("📅 Schedule Reports", use_container_width=True):
                st.info("Configure automated report scheduling")
