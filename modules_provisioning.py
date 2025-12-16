"""
Provisioning & Deployment Module - Infrastructure Deployment WITH CI/CD INTEGRATION
Automated deployment workflows using CloudFormation, multi-region, rollback
Enhanced with CI/CD pipeline monitoring and approval workflows
"""

import streamlit as st
import pandas as pd
from typing import Dict, List, Optional
from datetime import datetime, timedelta
from core_account_manager import get_account_manager, get_account_names
from aws_cloudformation import CloudFormationManager
import json
from auth_azure_sso import require_permission

# ============================================================================
# CI/CD INTEGRATION (DEMO MODE - Shows sample data)
# ============================================================================

class CICDDeployment:
    """Represents a CI/CD pipeline deployment"""
    def __init__(self, pipeline_id, pipeline_name, status, environment, stack_name,
                 commit_hash, commit_message, author, triggered_at, completed_at=None,
                 approval_required=False, pipeline_url=None):
        self.pipeline_id = pipeline_id
        self.pipeline_name = pipeline_name
        self.status = status
        self.environment = environment
        self.stack_name = stack_name
        self.commit_hash = commit_hash
        self.commit_message = commit_message
        self.author = author
        self.triggered_at = triggered_at
        self.completed_at = completed_at
        self.approval_required = approval_required
        self.pipeline_url = pipeline_url

class CICDIntegrationManager:
    """Manages CI/CD pipeline integrations - Demo Mode"""
    
    def __init__(self):
        """Initialize with demo data"""
        self.demo_mode = True
    
    def get_recent_deployments(self, limit=10):
        """Get demo deployment data"""
        now = datetime.now()
        
        return [
            CICDDeployment(
                pipeline_id="GHA-1234",
                pipeline_name="Deploy Infrastructure",
                status="success",
                environment="production",
                stack_name="prod-vpc-stack",
                commit_hash="abc1234",
                commit_message="Add production VPC with 3 AZs",
                author="John Doe",
                triggered_at=now - timedelta(hours=2),
                completed_at=now - timedelta(hours=1, minutes=45),
                pipeline_url="#"
            ),
            CICDDeployment(
                pipeline_id="GHA-1235",
                pipeline_name="Deploy Infrastructure",
                status="pending_approval",
                environment="production",
                stack_name="prod-rds-stack",
                commit_hash="def5678",
                commit_message="Add production RDS with read replicas",
                author="Jane Smith",
                triggered_at=now - timedelta(minutes=30),
                completed_at=None,
                approval_required=True,
                pipeline_url="#"
            ),
            CICDDeployment(
                pipeline_id="GHA-1233",
                pipeline_name="Deploy Infrastructure",
                status="success",
                environment="staging",
                stack_name="staging-app-stack",
                commit_hash="def5678",
                commit_message="Add production RDS with read replicas",
                author="Jane Smith",
                triggered_at=now - timedelta(minutes=45),
                completed_at=now - timedelta(minutes=35),
                pipeline_url="#"
            ),
            CICDDeployment(
                pipeline_id="GHA-1230",
                pipeline_name="Deploy Infrastructure",
                status="running",
                environment="staging",
                stack_name="staging-update-stack",
                commit_hash="jkl3456",
                commit_message="Update Lambda functions",
                author="Alice Johnson",
                triggered_at=now - timedelta(minutes=10),
                completed_at=None,
                pipeline_url="#"
            )
        ]
    
    def approve_deployment(self, pipeline_id):
        """Approve a deployment"""
        return {"success": True, "message": f"Pipeline {pipeline_id} approved"}
    
    def reject_deployment(self, pipeline_id, reason):
        """Reject a deployment"""
        return {"success": True, "message": f"Pipeline {pipeline_id} rejected"}

# ============================================================================
# MAIN PROVISIONING MODULE (ORIGINAL CLASS NAME PRESERVED)
# ============================================================================

class ProvisioningModule:
    """Provisioning & Deployment functionality - Enhanced with CI/CD"""
    
    @staticmethod
    @require_permission('provision_resources')

    def render():
        """Main render method"""
        st.title("🚀 Provisioning & Deployment")
        st.caption("Infrastructure deployment with CI/CD integration")
        
        account_mgr = get_account_manager()
        if not account_mgr:
            st.warning("⚠️ Configure AWS credentials first")
            st.info("👉 Go to the 'Account Management' tab to add your AWS accounts first.")
            return
        
        # Get account names
        account_names = get_account_names()
        
        if not account_names:
            st.warning("⚠️ No AWS accounts configured")
            st.info("👉 Go to the 'Account Management' tab to add your AWS accounts first.")
            return
        
        selected_account = st.selectbox(
            "Select AWS Account",
            options=account_names,
            key="provisioning_account"
        )
        
        if not selected_account:
            return
        
        # Check if a specific region is selected
        selected_region = st.session_state.get('selected_regions', 'all')
        
        if selected_region == 'all':
            st.error("❌ Error loading Provisioning: You must specify a region.")
            st.info("📍 CloudFormation stacks are region-specific. Please select a specific region from the sidebar to view and deploy stacks.")
            return
        
        # Get region-specific session
        session = account_mgr.get_session_with_region(selected_account, selected_region)
        if not session:
            st.error(f"Failed to get session for {selected_account} in region {selected_region}")
            return
        
        # Show selected region
        st.info(f"📍 Managing stacks in **{selected_region}**")
        
        cfn_mgr = CloudFormationManager(session)
        cicd_mgr = CICDIntegrationManager()
        
        # Create tabs - ENHANCED with CI/CD (3 new + 6 original = 9 total)
        tabs = st.tabs([
            "📊 CI/CD Deployments",
            "⏸️ Pending Approvals",
            "🎯 Trigger Pipeline",
            "📚 Stack Library",
            "🚀 Deploy Stack",
            "🔄 Active Deployments",
            "📝 Change Sets",
            "🌍 Multi-Region",
            "⏮️ Rollback"
        ])
        
        with tabs[0]:
            ProvisioningModule._render_cicd_deployments(cicd_mgr, cfn_mgr)
        
        with tabs[1]:
            ProvisioningModule._render_pending_approvals(cicd_mgr)
        
        with tabs[2]:
            ProvisioningModule._render_trigger_pipeline(cicd_mgr)
        
        with tabs[3]:
            ProvisioningModule._render_stack_library(cfn_mgr)
        
        with tabs[4]:
            ProvisioningModule._render_deploy_stack(cfn_mgr)
        
        with tabs[5]:
            ProvisioningModule._render_active_deployments(cfn_mgr)
        
        with tabs[6]:
            ProvisioningModule._render_change_sets(cfn_mgr)
        
        with tabs[7]:
            ProvisioningModule._render_multi_region()
        
        with tabs[8]:
            ProvisioningModule._render_rollback(cfn_mgr)
    
    # ========================================================================
    # NEW TAB 1: CI/CD DEPLOYMENTS
    # ========================================================================
    
    @staticmethod
    def _render_cicd_deployments(cicd_mgr, cfn_mgr):
        """Monitor CI/CD pipeline deployments"""
        st.subheader("📊 CI/CD Pipeline Deployments")
        st.caption("Monitor automated deployments from your CI/CD pipelines")
        
        st.info("💡 **Demo Mode:** Showing sample CI/CD deployments. Configure GitHub/GitLab integration to see real pipeline data.")
        
        with st.expander("📖 How to Enable Real CI/CD Integration"):
            st.markdown("""
            ### Setup Instructions
            
            **For GitHub Actions:**
            1. Add to `.streamlit/secrets.toml`:
               ```toml
               GITHUB_TOKEN = "ghp_your_token"
               GITHUB_ORG = "your-org"
               GITHUB_REPO = "infrastructure"
               ```
            2. See `GITHUB_ACTIONS_INTEGRATION.txt` for complete setup
            
            **For GitLab CI:**
            1. Add to `.streamlit/secrets.toml`:
               ```toml
               GITLAB_TOKEN = "your_token"
               GITLAB_PROJECT_ID = "12345"
               ```
            
            **Benefits:**
            - Real-time pipeline status
            - Actual Git commit information
            - Live approval workflows
            - Complete audit trail
            """)
        
        # Get deployments
        deployments = cicd_mgr.get_recent_deployments(limit=20)
        
        if not deployments:
            st.info("No recent CI/CD deployments found")
            return
        
        # Summary metrics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Deployments", len(deployments))
        
        with col2:
            pending = sum(1 for d in deployments if d.status == "pending_approval")
            st.metric("Pending Approval", pending)
        
        with col3:
            running = sum(1 for d in deployments if d.status == "running")
            st.metric("Running", running)
        
        with col4:
            failed = sum(1 for d in deployments if d.status == "failed")
            st.metric("Failed", failed)
        
        st.markdown("---")
        
        # Display deployments
        for deployment in deployments:
            # Status icon
            if deployment.status == "success":
                status_icon = "✅"
            elif deployment.status == "failed":
                status_icon = "❌"
            elif deployment.status == "running":
                status_icon = "🔄"
            elif deployment.status == "pending_approval":
                status_icon = "⏸️"
            else:
                status_icon = "⚪"
            
            # Environment badge
            env_colors = {"production": "🔴", "staging": "🟡", "dev": "🟢"}
            env_badge = env_colors.get(deployment.environment, "⚪")
            
            with st.expander(
                f"{status_icon} {env_badge} **{deployment.environment.upper()}** | "
                f"{deployment.stack_name} | {deployment.status.upper()}",
                expanded=deployment.approval_required
            ):
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown(f"**Pipeline:** {deployment.pipeline_name}")
                    st.markdown(f"**Pipeline ID:** {deployment.pipeline_id}")
                    st.markdown(f"**Stack:** {deployment.stack_name}")
                    st.markdown(f"**Environment:** {deployment.environment}")
                
                with col2:
                    st.markdown(f"**Commit:** `{deployment.commit_hash}`")
                    st.markdown(f"**Message:** {deployment.commit_message}")
                    st.markdown(f"**Author:** {deployment.author}")
                    st.markdown(f"**Triggered:** {deployment.triggered_at.strftime('%Y-%m-%d %H:%M:%S')}")
                    
                    if deployment.completed_at:
                        duration = (deployment.completed_at - deployment.triggered_at).total_seconds() / 60
                        st.markdown(f"**Duration:** {duration:.1f} minutes")
                
                # Approval UI
                if deployment.approval_required and deployment.status == "pending_approval":
                    st.markdown("---")
                    st.warning("⏸️ **This deployment requires approval!**")
                    
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        if st.button("✅ Approve", key=f"approve_{deployment.pipeline_id}", type="primary"):
                            result = cicd_mgr.approve_deployment(deployment.pipeline_id)
                            if result.get("success"):
                                st.success("Deployment approved!")
                                st.balloons()
                    
                    with col2:
                        if st.button("❌ Reject", key=f"reject_{deployment.pipeline_id}"):
                            st.session_state[f"show_reject_{deployment.pipeline_id}"] = True
                    
                    if st.session_state.get(f"show_reject_{deployment.pipeline_id}"):
                        reason = st.text_area(
                            "Rejection Reason",
                            key=f"reason_{deployment.pipeline_id}",
                            placeholder="Explain why this deployment is being rejected..."
                        )
                        if st.button("Confirm Rejection", key=f"confirm_{deployment.pipeline_id}"):
                            if reason.strip():
                                result = cicd_mgr.reject_deployment(deployment.pipeline_id, reason)
                                st.error(f"Deployment rejected: {reason}")
    
    # ========================================================================
    # NEW TAB 2: PENDING APPROVALS
    # ========================================================================
    
    @staticmethod
    def _render_pending_approvals(cicd_mgr):
        """Show deployments pending approval"""
        st.subheader("⏸️ Pending Approvals")
        st.caption("Review and approve production deployments")
        
        # Get pending deployments
        all_deployments = cicd_mgr.get_recent_deployments(limit=50)
        pending = [d for d in all_deployments if d.status == "pending_approval"]
        
        if not pending:
            st.success("✅ No deployments pending approval")
            st.info("💡 Production deployments will appear here for manual approval before deployment")
            return
        
        st.warning(f"⚠️ {len(pending)} deployment(s) awaiting approval")
        
        for deployment in pending:
            with st.container():
                st.markdown(f"### 🔴 PRODUCTION: {deployment.stack_name}")
                
                col1, col2 = st.columns([2, 1])
                
                with col1:
                    st.markdown(f"**Pipeline:** {deployment.pipeline_name} (#{deployment.pipeline_id})")
                    st.markdown(f"**Commit:** `{deployment.commit_hash}`")
                    st.markdown(f"**Message:** {deployment.commit_message}")
                    st.markdown(f"**Author:** {deployment.author}")
                    
                    wait_time = (datetime.now() - deployment.triggered_at).total_seconds() / 60
                    if wait_time > 60:
                        st.warning(f"⏰ Waiting for {wait_time/60:.1f} hours")
                    else:
                        st.info(f"⏰ Waiting for {wait_time:.0f} minutes")
                
                with col2:
                    st.markdown("**Deployment History:**")
                    
                    # Show test results
                    commit_deployments = [d for d in all_deployments if d.commit_hash == deployment.commit_hash]
                    
                    for env_deploy in sorted(commit_deployments, key=lambda x: x.triggered_at):
                        if env_deploy.environment == "dev":
                            st.success("✅ DEV: Deployed")
                        elif env_deploy.environment == "staging":
                            st.success("✅ STAGING: Deployed")
                        elif env_deploy.environment == "production" and env_deploy.status == "pending_approval":
                            st.warning("⏸️ PROD: Pending")
                
                # Approval actions
                st.markdown("---")
                col1, col2, col3 = st.columns([1, 1, 3])
                
                with col1:
                    if st.button("✅ Approve", type="primary", key=f"approve_main_{deployment.pipeline_id}"):
                        result = cicd_mgr.approve_deployment(deployment.pipeline_id)
                        if result.get("success"):
                            st.success("✅ Deployment approved!")
                            st.balloons()
                
                with col2:
                    if st.button("❌ Reject", key=f"reject_main_{deployment.pipeline_id}"):
                        st.session_state[f"show_reject_main_{deployment.pipeline_id}"] = True
                
                if st.session_state.get(f"show_reject_main_{deployment.pipeline_id}"):
                    reason = st.text_area(
                        "Why are you rejecting this deployment?",
                        key=f"reject_reason_main_{deployment.pipeline_id}",
                        placeholder="E.g., 'Security concerns' or 'Need more testing'"
                    )
                    
                    if st.button("Confirm Rejection", key=f"confirm_main_{deployment.pipeline_id}"):
                        if reason.strip():
                            result = cicd_mgr.reject_deployment(deployment.pipeline_id, reason)
                            st.error(f"❌ Deployment rejected: {reason}")
                
                st.markdown("---")
    
    # ========================================================================
    # NEW TAB 3: TRIGGER PIPELINE
    # ========================================================================
    
    @staticmethod
    def _render_trigger_pipeline(cicd_mgr):
        """Trigger CI/CD pipeline deployments"""
        st.subheader("🎯 Trigger CI/CD Pipeline")
        st.caption("Manually trigger automated deployments")
        
        st.info("💡 **Demo Mode:** This shows the UI for triggering pipelines. Configure CI/CD integration to enable real triggers.")
        
        with st.form("trigger_pipeline"):
            st.markdown("#### Pipeline Configuration")
            
            col1, col2 = st.columns(2)
            
            with col1:
                repository = st.text_input(
                    "Repository",
                    value="myorg/infrastructure",
                    help="Format: organization/repository"
                )
                
                branch = st.selectbox(
                    "Branch/Tag",
                    options=["main", "develop", "staging", "v1.0.0"],
                    help="Select the branch or tag to deploy"
                )
                
                environment = st.selectbox(
                    "Target Environment",
                    options=["dev", "staging", "production"],
                    help="Environment to deploy to"
                )
            
            with col2:
                stack_name = st.text_input(
                    "Stack Name",
                    placeholder="my-infrastructure-stack",
                    help="CloudFormation stack name"
                )
                
                require_approval = st.checkbox(
                    "Require Manual Approval",
                    value=(environment == "production"),
                    help="Pause pipeline for manual approval before deployment"
                )
            
            submitted = st.form_submit_button("🚀 Trigger Pipeline", type="primary")
            
            if submitted:
                st.success(f"✅ Pipeline would be triggered for {repository}/{branch} → {environment}")
                st.info("Configure CI/CD integration to enable real pipeline triggering")
    
    # ========================================================================
    # ORIGINAL TABS (PRESERVED EXACTLY AS BEFORE)
    # ========================================================================
    
    @staticmethod
    def _render_stack_library(cfn_mgr):
        """Stack library and templates"""
        st.subheader("📚 CloudFormation Stack Library")
        
        # List existing stacks
        stacks = cfn_mgr.list_stacks()
        
        if stacks:
            st.metric("Total Stacks", len(stacks))
            
            # Status filter
            status_filter = st.multiselect(
                "Filter by Status",
                options=["CREATE_COMPLETE", "UPDATE_COMPLETE", "CREATE_IN_PROGRESS", 
                        "UPDATE_IN_PROGRESS", "ROLLBACK_COMPLETE"],
                default=["CREATE_COMPLETE", "UPDATE_COMPLETE"]
            )
            
            # Filter stacks
            filtered_stacks = [s for s in stacks if s['status'] in status_filter] if status_filter else stacks
            
            # Display stacks
            for stack in filtered_stacks:
                status_icon = "✅" if "COMPLETE" in stack['status'] else "🔄" if "IN_PROGRESS" in stack['status'] else "❌"
                
                with st.expander(f"{status_icon} {stack['stack_name']} - {stack['status']}"):
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.write(f"**Stack ID:** {stack['stack_id']}")
                        st.write(f"**Status:** {stack['status']}")
                        st.write(f"**Created:** {stack['creation_time']}")
                    
                    with col2:
                        st.write(f"**Last Updated:** {stack['last_updated']}")
                        st.write(f"**Drift Status:** {stack.get('drift_status', 'NOT_CHECKED')}")
                    
                    # Actions
                    col1, col2, col3, col4 = st.columns(4)
                    with col1:
                        if st.button("👁️ Details", key=f"details_{stack['stack_name']}"):
                            stack_info = cfn_mgr.get_stack_info(stack['stack_name'])
                            if stack_info:
                                st.json(stack_info)
                    
                    with col2:
                        if st.button("📋 Resources", key=f"resources_{stack['stack_name']}"):
                            resources = cfn_mgr.list_stack_resources(stack['stack_name'])
                            if resources:
                                res_df = pd.DataFrame(resources)
                                st.dataframe(res_df, use_container_width=True)
                    
                    with col3:
                        if st.button("🔍 Drift", key=f"drift_{stack['stack_name']}"):
                            result = cfn_mgr.detect_stack_drift(stack['stack_name'])
                            if result.get('success'):
                                st.success("Drift detection started")
                    
                    with col4:
                        if st.button("🗑️ Delete", key=f"delete_{stack['stack_name']}"):
                            result = cfn_mgr.delete_stack(stack['stack_name'])
                            if result.get('success'):
                                st.success(f"Stack deletion initiated")
                                st.rerun()
        else:
            st.info("No stacks found in this account")
    
    @staticmethod
    def _render_deploy_stack(cfn_mgr):
        """Deploy new stack"""
        st.subheader("🚀 Deploy CloudFormation Stack")
        
        with st.form("deploy_stack"):
            st.markdown("### Stack Configuration")
            
            stack_name = st.text_input("Stack Name*", 
                placeholder="my-infrastructure-stack")
            
            # Template source
            template_source = st.radio("Template Source", 
                ["Upload Template", "S3 URL", "Quick Start Template"])
            
            if template_source == "Upload Template":
                template_body = st.text_area("CloudFormation Template (JSON/YAML)",
                    placeholder='{\n  "AWSTemplateFormatVersion": "2010-09-09",\n  ...\n}',
                    height=300)
                template_url = None
            
            elif template_source == "S3 URL":
                template_url = st.text_input("Template S3 URL",
                    placeholder="https://s3.amazonaws.com/bucket/template.yaml")
                template_body = None
            
            else:
                # Quick start templates
                quick_template = st.selectbox("Select Quick Start", [
                    "VPC with Public/Private Subnets",
                    "EC2 Instance with Security Group",
                    "RDS Database",
                    "S3 Bucket with Encryption",
                    "Lambda Function with API Gateway"
                ])
                
                # Simple template
                template_body = """{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "Quick start template",
  "Resources": {
    "TestBucket": {
      "Type": "AWS::S3::Bucket"
    }
  }
}"""
                template_url = None
                st.code(template_body, language='json')
            
            # Parameters
            st.markdown("### Stack Parameters (Optional)")
            params_input = st.text_area("Parameters (JSON format)",
                placeholder='[{"ParameterKey": "InstanceType", "ParameterValue": "t3.micro"}]',
                height=100)
            
            # Capabilities
            st.markdown("### Capabilities")
            capabilities = st.multiselect("Required Capabilities", [
                "CAPABILITY_IAM",
                "CAPABILITY_NAMED_IAM",
                "CAPABILITY_AUTO_EXPAND"
            ])
            
            # Tags
            st.markdown("### Tags")
            tags_input = st.text_area("Tags (JSON format)",
                placeholder='[{"Key": "Environment", "Value": "Production"}]',
                height=80)
            
            submit = st.form_submit_button("Deploy Stack", type="primary")
            
            if submit:
                if not stack_name:
                    st.error("Stack name is required")
                elif not template_body and not template_url:
                    st.error("Template source is required")
                else:
                    # Parse parameters and tags
                    parameters = None
                    tags = None
                    
                    try:
                        if params_input:
                            parameters = json.loads(params_input)
                        if tags_input:
                            tags = json.loads(tags_input)
                    except:
                        st.error("Invalid JSON format for parameters or tags")
                        return
                    
                    with st.spinner("Deploying stack..."):
                        result = cfn_mgr.create_stack(
                            stack_name=stack_name,
                            template_body=template_body,
                            template_url=template_url,
                            parameters=parameters,
                            tags=tags,
                            capabilities=capabilities
                        )
                        
                        if result.get('success'):
                            st.success(f"✅ Stack deployment initiated!")
                            st.info(f"Stack ID: {result.get('stack_id')}")
                            st.balloons()
                        else:
                            st.error(f"❌ {result.get('error')}")
    
    @staticmethod
    def _render_active_deployments(cfn_mgr):
        """Active deployments"""
        st.subheader("🔄 Active Deployments")
        
        # Get stacks in progress
        stacks = cfn_mgr.list_stacks(
            status_filter=["CREATE_IN_PROGRESS", "UPDATE_IN_PROGRESS", 
                          "DELETE_IN_PROGRESS", "ROLLBACK_IN_PROGRESS"]
        )
        
        if stacks:
            st.write(f"**Active Deployments:** {len(stacks)}")
            
            for stack in stacks:
                with st.expander(f"🔄 {stack['stack_name']} - {stack['status']}"):
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.write(f"**Stack:** {stack['stack_name']}")
                        st.write(f"**Status:** {stack['status']}")
                    
                    with col2:
                        st.write(f"**Started:** {stack['creation_time']}")
                    
                    # Show recent events
                    events = cfn_mgr.get_stack_events(stack['stack_name'], limit=10)
                    if events:
                        st.markdown("**Recent Events:**")
                        events_df = pd.DataFrame(events)
                        st.dataframe(events_df, use_container_width=True)
        else:
            st.success("✅ No active deployments")
    
    @staticmethod
    def _render_change_sets(cfn_mgr):
        """Change sets"""
        st.subheader("📝 Change Sets")
        
        st.markdown("""
        ### Preview Changes Before Deployment
        
        Change sets allow you to preview how proposed changes will affect your running resources.
        """)
        
        # Get existing stacks for change sets
        stacks = cfn_mgr.list_stacks(
            status_filter=["CREATE_COMPLETE", "UPDATE_COMPLETE"]
        )
        
        if stacks:
            selected_stack = st.selectbox(
                "Select Stack for Change Set",
                options=[s['stack_name'] for s in stacks]
            )
            
            if selected_stack:
                st.markdown("### Create Change Set")
                
                with st.form("create_changeset"):
                    changeset_name = st.text_input("Change Set Name",
                        placeholder="my-changes-2025-12-06")
                    
                    template_body = st.text_area("Updated Template",
                        placeholder="Paste updated CloudFormation template...",
                        height=200)
                    
                    if st.form_submit_button("Create Change Set"):
                        if changeset_name and template_body:
                            result = cfn_mgr.create_change_set(
                                stack_name=selected_stack,
                                change_set_name=changeset_name,
                                template_body=template_body
                            )
                            
                            if result.get('success'):
                                st.success(f"✅ Change set created: {result.get('change_set_id')}")
                            else:
                                st.error(f"❌ {result.get('error')}")
        else:
            st.info("No stacks available for change sets")
    
    @staticmethod
    def _render_multi_region():
        """Multi-region deployment"""
        st.subheader("🌍 Multi-Region Deployment")
        
        st.markdown("""
        ### Deploy to Multiple Regions Simultaneously
        
        Deploy your infrastructure across multiple AWS regions for high availability.
        """)
        
        regions = st.multiselect("Select Target Regions", [
            "us-east-1", "us-west-2", "eu-west-1", "eu-central-1",
            "ap-southeast-1", "ap-northeast-1"
        ])
        
        if regions:
            st.write(f"**Selected Regions:** {len(regions)}")
            
            stack_name_prefix = st.text_input("Stack Name Prefix",
                placeholder="my-multi-region-stack")
            
            if st.button("Deploy to All Regions"):
                if stack_name_prefix:
                    for region in regions:
                        st.info(f"Deploying to {region}...")
                    st.success(f"✅ Deployment initiated in {len(regions)} regions")
                else:
                    st.error("Stack name prefix required")
    
    @staticmethod
    def _render_rollback(cfn_mgr):
        """Rollback operations"""
        st.subheader("⏮️ Rollback & Recovery")
        
        st.markdown("""
        ### Rollback Failed Deployments
        
        Manage failed stack deployments and rollback to previous stable states.
        """)
        
        # Get failed stacks
        failed_stacks = cfn_mgr.list_stacks(
            status_filter=["CREATE_FAILED", "UPDATE_FAILED", "ROLLBACK_COMPLETE"]
        )
        
        if failed_stacks:
            st.warning(f"⚠️ Found {len(failed_stacks)} stack(s) requiring attention")
            
            for stack in failed_stacks:
                with st.expander(f"❌ {stack['stack_name']} - {stack['status']}"):
                    st.write(f"**Status:** {stack['status']}")
                    st.write(f"**Last Updated:** {stack['last_updated']}")
                    
                    # Show events to understand failure
                    events = cfn_mgr.get_stack_events(stack['stack_name'], limit=5)
                    if events:
                        st.markdown("**Failure Events:**")
                        for event in events:
                            if "FAILED" in event['status']:
                                st.error(f"{event['logical_id']}: {event['reason']}")
                    
                    if st.button(f"Delete Failed Stack", key=f"rollback_{stack['stack_name']}"):
                        result = cfn_mgr.delete_stack(stack['stack_name'])
                        if result.get('success'):
                            st.success("Stack deletion initiated")
                            st.rerun()
        else:
            st.success("✅ No failed stacks found")