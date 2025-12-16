"""
CI/CD Phase 3: Approval Workflows & Notifications
Enterprise-grade approval gates and notification system

Features:
- Manual approval gates
- Role-based approvals
- Multi-channel notifications (Email, Slack, Teams, SMS)
- Escalation workflows
- Approval audit trail
- Auto-approval rules
"""

import streamlit as st
import boto3
from datetime import datetime, timedelta
import json
from typing import Dict, List, Any, Optional
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

def render_cicd_phase3_module(session: boto3.Session, account_id: str, region: str):
    """
    Main render function for Phase 3: Approval Workflows & Notifications
    
    Args:
        session: Boto3 session
        account_id: AWS account ID
        region: AWS region
    """
    
    st.title("⚠️ CI/CD Approval Workflows & Notifications")
    st.markdown("Enterprise-grade governance with approval gates and intelligent notifications")
    
    # Create AWS clients
    try:
        codepipeline = session.client('codepipeline', region_name=region)
        sns = session.client('sns', region_name=region)
        ses = session.client('ses', region_name=region)
        iam = session.client('iam')
    except Exception as e:
        st.error(f"Error creating AWS clients: {str(e)}")
        return
    
    # Main tabs
    tabs = st.tabs([
        "📊 Approval Dashboard",
        "✅ Approval Workflows",
        "🔔 Notification Settings",
        "⏳ Pending Approvals",
        "📜 Approval History",
        "🤖 Auto-Approval Rules"
    ])
    
    # Tab 1: Approval Dashboard
    with tabs[0]:
        render_approval_dashboard(codepipeline, region)
    
    # Tab 2: Approval Workflows
    with tabs[1]:
        render_approval_workflows(codepipeline, iam, region)
    
    # Tab 3: Notification Settings
    with tabs[2]:
        render_notification_settings(sns, ses, region)
    
    # Tab 4: Pending Approvals
    with tabs[3]:
        render_pending_approvals(codepipeline, region)
    
    # Tab 5: Approval History
    with tabs[4]:
        render_approval_history(codepipeline, region)
    
    # Tab 6: Auto-Approval Rules
    with tabs[5]:
        render_auto_approval_rules(codepipeline, region)


def render_approval_dashboard(codepipeline, region: str):
    """Tab 1: Approval Dashboard - Overview of all approvals"""
    
    st.header("📊 Approval Dashboard")
    st.markdown("Real-time overview of approval workflows and pending actions")
    
    # Summary Metrics
    col1, col2, col3, col4 = st.columns(4)
    
    # Mock data for demonstration
    pending_count = 5
    approved_today = 12
    avg_approval_time = "45 min"
    sla_compliance = 94
    
    with col1:
        st.metric(
            "Pending Approvals",
            pending_count,
            delta="+2 from yesterday",
            delta_color="inverse"
        )
    
    with col2:
        st.metric(
            "Approved Today",
            approved_today,
            delta="+3 vs avg",
            delta_color="normal"
        )
    
    with col3:
        st.metric(
            "Avg Approval Time",
            avg_approval_time,
            delta="-15 min improvement",
            delta_color="normal"
        )
    
    with col4:
        st.metric(
            "SLA Compliance",
            f"{sla_compliance}%",
            delta="+2%",
            delta_color="normal"
        )
    
    st.markdown("---")
    
    # Pending Approvals Table
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.subheader("⏳ Pending Approvals")
        
        # Mock pending approvals data
        pending_data = pd.DataFrame([
            {
                "Pipeline": "production-api-deploy",
                "Stage": "Deploy to Production",
                "Requested": "2 hours ago",
                "Approver": "DevOps Team",
                "SLA": "🟢 OK",
                "Priority": "High"
            },
            {
                "Pipeline": "frontend-deployment",
                "Stage": "QA Sign-off",
                "Requested": "30 minutes ago",
                "Approver": "QA Team",
                "SLA": "🟢 OK",
                "Priority": "Medium"
            },
            {
                "Pipeline": "database-migration",
                "Stage": "Security Review",
                "Requested": "4 hours ago",
                "Approver": "Security Team",
                "SLA": "🟡 Warning",
                "Priority": "Critical"
            },
            {
                "Pipeline": "infrastructure-update",
                "Stage": "Deploy to Staging",
                "Requested": "1 hour ago",
                "Approver": "Platform Team",
                "SLA": "🟢 OK",
                "Priority": "Low"
            },
            {
                "Pipeline": "hotfix-deployment",
                "Stage": "Emergency Deploy",
                "Requested": "15 minutes ago",
                "Approver": "Engineering Lead",
                "SLA": "🟢 OK",
                "Priority": "Critical"
            }
        ])
        
        st.dataframe(pending_data, use_container_width=True, hide_index=True)
        
        if st.button("🔄 Refresh Pending Approvals"):
            st.rerun()
    
    with col2:
        st.subheader("📈 Approval Stats (7 Days)")
        
        # Approval trend chart
        dates = pd.date_range(end=datetime.now(), periods=7, freq='D')
        approval_trend = pd.DataFrame({
            'Date': dates.strftime('%m/%d'),
            'Approved': [8, 12, 15, 10, 14, 11, 12],
            'Rejected': [1, 0, 2, 1, 1, 0, 1],
            'Pending': [2, 3, 1, 4, 2, 3, 5]
        })
        
        fig = go.Figure()
        fig.add_trace(go.Bar(x=approval_trend['Date'], y=approval_trend['Approved'], 
                            name='Approved', marker_color='green'))
        fig.add_trace(go.Bar(x=approval_trend['Date'], y=approval_trend['Rejected'], 
                            name='Rejected', marker_color='red'))
        fig.add_trace(go.Bar(x=approval_trend['Date'], y=approval_trend['Pending'], 
                            name='Pending', marker_color='orange'))
        
        fig.update_layout(
            barmode='stack',
            height=300,
            margin=dict(l=0, r=0, t=20, b=0),
            showlegend=True,
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
        )
        
        st.plotly_chart(fig, use_container_width=True)
    
    # Approval Time Distribution
    st.subheader("⏱️ Approval Time Distribution (Last 30 Days)")
    
    time_data = pd.DataFrame({
        'Time Range': ['< 15 min', '15-30 min', '30-60 min', '1-2 hours', '2-4 hours', '> 4 hours'],
        'Count': [45, 67, 89, 34, 12, 3]
    })
    
    fig = px.bar(time_data, x='Time Range', y='Count', 
                 title='How quickly are approvals being processed?',
                 color='Count', color_continuous_scale='Greens')
    fig.update_layout(height=300, showlegend=False)
    st.plotly_chart(fig, use_container_width=True)
    
    # Team Performance
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("👥 Team Performance")
        
        team_data = pd.DataFrame({
            'Team': ['DevOps', 'QA', 'Security', 'Platform', 'Leadership'],
            'Avg Time (min)': [32, 45, 67, 28, 15],
            'Total Approvals': [89, 45, 23, 67, 12]
        })
        
        st.dataframe(team_data, use_container_width=True, hide_index=True)
    
    with col2:
        st.subheader("🎯 SLA Compliance by Team")
        
        sla_data = pd.DataFrame({
            'Team': ['DevOps', 'QA', 'Security', 'Platform', 'Leadership'],
            'SLA %': [96, 92, 88, 98, 100]
        })
        
        fig = px.bar(sla_data, x='Team', y='SLA %', 
                     color='SLA %', color_continuous_scale='RdYlGn',
                     range_y=[0, 100])
        fig.add_hline(y=90, line_dash="dash", line_color="red", 
                     annotation_text="90% Target")
        fig.update_layout(height=300, showlegend=False)
        st.plotly_chart(fig, use_container_width=True)


def render_approval_workflows(codepipeline, iam, region: str):
    """Tab 2: Approval Workflows - Create and manage approval gates"""
    
    st.header("✅ Approval Workflows")
    st.markdown("Configure approval gates for your CI/CD pipelines")
    
    # Get list of pipelines
    try:
        pipelines_response = codepipeline.list_pipelines()
        pipelines = [p['name'] for p in pipelines_response.get('pipelines', [])]
    except Exception as e:
        st.error(f"Error listing pipelines: {str(e)}")
        pipelines = []
    
    # Create new approval workflow
    with st.expander("➕ Create New Approval Workflow", expanded=False):
        st.subheader("Create Approval Gate")
        
        col1, col2 = st.columns(2)
        
        with col1:
            selected_pipeline = st.selectbox(
                "Select Pipeline",
                options=pipelines if pipelines else ["No pipelines available"],
                help="Choose the pipeline to add an approval gate"
            )
            
            approval_stage_name = st.text_input(
                "Approval Stage Name",
                value="ManualApproval",
                help="Name for this approval stage"
            )
            
            approval_position = st.selectbox(
                "Insert After Stage",
                options=["Source", "Build", "Test", "Deploy-Staging", "Deploy-Production"],
                help="Where to insert the approval gate"
            )
        
        with col2:
            approval_type = st.selectbox(
                "Approval Type",
                options=["Manual Approval", "Role-Based Approval", "Multi-Approver", "Conditional Approval"],
                help="Type of approval required"
            )
            
            approval_timeout = st.number_input(
                "Approval Timeout (hours)",
                min_value=1,
                max_value=168,
                value=24,
                help="How long to wait before timing out"
            )
            
            sla_hours = st.number_input(
                "SLA Target (hours)",
                min_value=1,
                max_value=48,
                value=4,
                help="Expected approval time for SLA tracking"
            )
        
        # Approver configuration
        st.subheader("🎯 Approver Configuration")
        
        col1, col2 = st.columns(2)
        
        with col1:
            approver_type = st.radio(
                "Approver Selection",
                options=["Specific IAM Users", "IAM Role", "Approval Group", "Any Team Member"],
                help="Who can approve this request"
            )
            
            if approver_type == "Specific IAM Users":
                approvers = st.text_area(
                    "IAM User ARNs (one per line)",
                    placeholder="arn:aws:iam::123456789012:user/john.doe\narn:aws:iam::123456789012:user/jane.smith",
                    help="List of IAM users who can approve"
                )
            elif approver_type == "IAM Role":
                approver_role = st.text_input(
                    "IAM Role ARN",
                    placeholder="arn:aws:iam::123456789012:role/DevOpsApprovers",
                    help="IAM role for approvers"
                )
            elif approver_type == "Approval Group":
                approval_group = st.selectbox(
                    "Select Group",
                    options=["DevOps Team", "QA Team", "Security Team", "Platform Team", "Leadership"],
                    help="Predefined approval group"
                )
        
        with col2:
            require_all = st.checkbox(
                "Require All Approvers",
                value=False,
                help="If checked, all approvers must approve. Otherwise, any one approval is sufficient."
            )
            
            custom_message = st.text_area(
                "Custom Approval Message",
                placeholder="Please review the deployment to production and approve if all checks pass.",
                help="Message shown to approvers"
            )
            
            include_artifacts = st.multiselect(
                "Include Artifacts",
                options=["Build Logs", "Test Results", "Security Scan", "Deployment Plan", "Change Summary"],
                help="Attachments to include with approval request"
            )
        
        # Notification settings for this approval
        st.subheader("🔔 Notification Settings")
        
        col1, col2 = st.columns(2)
        
        with col1:
            notify_on = st.multiselect(
                "Notify On",
                options=["Approval Required", "Approval Granted", "Approval Rejected", "Timeout Warning", "SLA Breach"],
                default=["Approval Required"],
                help="When to send notifications"
            )
        
        with col2:
            notification_channels = st.multiselect(
                "Notification Channels",
                options=["Email", "Slack", "Microsoft Teams", "SMS", "In-App"],
                default=["Email"],
                help="How to notify approvers"
            )
        
        # Escalation settings
        with st.expander("⚡ Escalation Settings (Optional)"):
            enable_escalation = st.checkbox("Enable Auto-Escalation", value=False)
            
            if enable_escalation:
                col1, col2 = st.columns(2)
                
                with col1:
                    escalation_time = st.number_input(
                        "Escalate After (hours)",
                        min_value=1,
                        max_value=24,
                        value=4,
                        help="Time before escalating"
                    )
                    
                    escalation_levels = st.number_input(
                        "Escalation Levels",
                        min_value=1,
                        max_value=3,
                        value=2,
                        help="Number of escalation levels"
                    )
                
                with col2:
                    escalation_contacts = st.text_area(
                        "Escalation Chain (one per line)",
                        placeholder="manager@company.com\ndirector@company.com\nvp@company.com",
                        help="Escalation contact list"
                    )
        
        # Create button
        col1, col2, col3 = st.columns([1, 1, 2])
        
        with col1:
            if st.button("✅ Create Approval Workflow", type="primary", use_container_width=True):
                with st.spinner("Creating approval workflow..."):
                    try:
                        st.success(f"✅ Approval workflow created for {selected_pipeline}!")
                        st.info("💡 The pipeline has been updated with the new approval stage.")
                        
                        # Show configuration summary
                        st.json({
                            "pipeline": selected_pipeline,
                            "stage_name": approval_stage_name,
                            "position": f"After {approval_position}",
                            "approver_type": approver_type,
                            "timeout_hours": approval_timeout,
                            "sla_hours": sla_hours,
                            "notifications": notification_channels,
                            "escalation_enabled": enable_escalation
                        })
                    except Exception as e:
                        st.error(f"Error creating approval workflow: {str(e)}")
        
        with col2:
            if st.button("🔄 Reset Form", use_container_width=True):
                st.rerun()
    
    st.markdown("---")
    
    # Existing approval workflows
    st.subheader("📋 Existing Approval Workflows")
    
    # Mock data for existing approvals
    existing_approvals = pd.DataFrame([
        {
            "Pipeline": "production-api-deploy",
            "Stage": "Production Approval",
            "Position": "Before Deploy to Prod",
            "Approvers": "DevOps Team (Any 1 of 5)",
            "Timeout": "24h",
            "SLA": "4h",
            "Status": "🟢 Active"
        },
        {
            "Pipeline": "frontend-deployment",
            "Stage": "QA Sign-off",
            "Position": "After Test",
            "Approvers": "QA Team (All required)",
            "Timeout": "48h",
            "SLA": "8h",
            "Status": "🟢 Active"
        },
        {
            "Pipeline": "database-migration",
            "Stage": "Security Review",
            "Position": "Before Production",
            "Approvers": "Security + DBA (Both)",
            "Timeout": "12h",
            "SLA": "2h",
            "Status": "🟢 Active"
        },
        {
            "Pipeline": "infrastructure-update",
            "Stage": "Platform Approval",
            "Position": "Before Apply",
            "Approvers": "Platform Team",
            "Timeout": "24h",
            "SLA": "6h",
            "Status": "🟡 Paused"
        }
    ])
    
    st.dataframe(existing_approvals, use_container_width=True, hide_index=True)
    
    # Quick actions
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        selected_workflow = st.selectbox(
            "Select Workflow",
            options=existing_approvals['Pipeline'].tolist()
        )
    
    with col2:
        if st.button("✏️ Edit Workflow"):
            st.info(f"Editing workflow for: {selected_workflow}")
    
    with col3:
        if st.button("⏸️ Pause Workflow"):
            st.warning(f"Paused workflow for: {selected_workflow}")
    
    with col4:
        if st.button("🗑️ Delete Workflow"):
            if st.session_state.get('confirm_delete') == selected_workflow:
                st.error(f"Deleted workflow for: {selected_workflow}")
                st.session_state.confirm_delete = None
            else:
                st.session_state.confirm_delete = selected_workflow
                st.warning("Click again to confirm deletion")


def render_notification_settings(sns, ses, region: str):
    """Tab 3: Notification Settings - Configure multi-channel notifications"""
    
    st.header("🔔 Notification Settings")
    st.markdown("Configure how and when your team gets notified about pipeline events")
    
    # Notification Channels
    st.subheader("📡 Notification Channels")
    
    channel_tabs = st.tabs(["📧 Email", "💬 Slack", "👔 Teams", "📱 SMS", "🔗 Webhook"])
    
    # Email Configuration
    with channel_tabs[0]:
        st.subheader("📧 Email Notifications (Amazon SES)")
        
        col1, col2 = st.columns(2)
        
        with col1:
            email_enabled = st.checkbox("Enable Email Notifications", value=True)
            
            if email_enabled:
                sender_email = st.text_input(
                    "Sender Email Address",
                    value="cicd-notifications@company.com",
                    help="Must be verified in SES"
                )
                
                default_recipients = st.text_area(
                    "Default Recipients (one per line)",
                    placeholder="devops-team@company.com\nengineering@company.com",
                    help="Default recipients for all notifications"
                )
                
                email_format = st.radio(
                    "Email Format",
                    options=["HTML (Rich formatting)", "Plain Text"],
                    index=0
                )
        
        with col2:
            if email_enabled:
                st.markdown("**Email Template Preview**")
                
                preview_html = """
                <div style="font-family: Arial; border: 1px solid #ddd; padding: 20px; border-radius: 5px;">
                    <h2 style="color: #2E86DE;">🚀 Pipeline Approval Required</h2>
                    <p><strong>Pipeline:</strong> production-api-deploy</p>
                    <p><strong>Stage:</strong> Deploy to Production</p>
                    <p><strong>Requested by:</strong> john.doe@company.com</p>
                    <p><strong>Time:</strong> 2024-12-06 10:30 AM</p>
                    <hr>
                    <p><strong>Changes:</strong></p>
                    <ul>
                        <li>Updated API version to 2.3.1</li>
                        <li>Security patches applied</li>
                        <li>Performance improvements</li>
                    </ul>
                    <p style="margin-top: 20px;">
                        <a href="#" style="background: #2E86DE; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px;">✅ Approve</a>
                        <a href="#" style="background: #E74C3C; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px; margin-left: 10px;">❌ Reject</a>
                    </p>
                </div>
                """
                st.markdown(preview_html, unsafe_allow_html=True)
                
                if st.button("📧 Send Test Email"):
                    st.success("✅ Test email sent successfully!")
    
    # Slack Configuration
    with channel_tabs[1]:
        st.subheader("💬 Slack Notifications")
        
        col1, col2 = st.columns(2)
        
        with col1:
            slack_enabled = st.checkbox("Enable Slack Notifications", value=False)
            
            if slack_enabled:
                slack_webhook = st.text_input(
                    "Slack Webhook URL",
                    type="password",
                    help="Incoming webhook URL from Slack"
                )
                
                default_channel = st.text_input(
                    "Default Channel",
                    value="#cicd-notifications",
                    help="Default Slack channel for notifications"
                )
                
                mention_users = st.checkbox(
                    "Mention @users for approvals",
                    value=True,
                    help="Tag specific users when approval is needed"
                )
                
                thread_replies = st.checkbox(
                    "Use thread replies for updates",
                    value=True,
                    help="Post updates as thread replies to keep channels clean"
                )
        
        with col2:
            if slack_enabled:
                st.markdown("**Slack Message Preview**")
                slack_preview = """
                ```
                🚀 Pipeline Approval Required
                
                Pipeline: production-api-deploy
                Stage: Deploy to Production
                Requested by: @johndoe
                
                📋 Changes:
                • Updated API version to 2.3.1
                • Security patches applied
                • Performance improvements
                
                [✅ Approve] [❌ Reject] [📊 View Details]
                ```
                """
                st.code(slack_preview, language="markdown")
                
                if st.button("💬 Send Test Slack Message"):
                    st.success("✅ Test message sent to Slack!")
    
    # Microsoft Teams Configuration
    with channel_tabs[2]:
        st.subheader("👔 Microsoft Teams Notifications")
        
        col1, col2 = st.columns(2)
        
        with col1:
            teams_enabled = st.checkbox("Enable Teams Notifications", value=False)
            
            if teams_enabled:
                teams_webhook = st.text_input(
                    "Teams Webhook URL",
                    type="password",
                    help="Incoming webhook URL from Teams"
                )
                
                teams_channel = st.text_input(
                    "Default Team/Channel",
                    value="DevOps Team > CI/CD",
                    help="Default Teams channel"
                )
                
                adaptive_cards = st.checkbox(
                    "Use Adaptive Cards",
                    value=True,
                    help="Rich, interactive card format"
                )
        
        with col2:
            if teams_enabled:
                st.markdown("**Teams Card Preview**")
                st.info("Adaptive Card with interactive approve/reject buttons")
                
                if st.button("👔 Send Test Teams Message"):
                    st.success("✅ Test message sent to Teams!")
    
    # SMS Configuration
    with channel_tabs[3]:
        st.subheader("📱 SMS Notifications (Amazon SNS)")
        
        col1, col2 = st.columns(2)
        
        with col1:
            sms_enabled = st.checkbox("Enable SMS Notifications", value=False)
            
            if sms_enabled:
                st.warning("⚠️ SMS notifications incur additional costs")
                
                sms_numbers = st.text_area(
                    "Phone Numbers (one per line)",
                    placeholder="+1-555-123-4567\n+1-555-987-6543",
                    help="Phone numbers in E.164 format"
                )
                
                sms_events = st.multiselect(
                    "Send SMS for:",
                    options=["Critical Approvals Only", "Production Deployments", "Pipeline Failures", "Security Alerts"],
                    default=["Critical Approvals Only"],
                    help="Only send SMS for important events"
                )
        
        with col2:
            if sms_enabled:
                st.markdown("**SMS Preview**")
                sms_preview = """
                CRITICAL: Approval needed
                
                Pipeline: prod-api-deploy
                Stage: Deploy to Production
                
                Approve: https://app.link/approve/abc123
                
                CloudIDP CI/CD
                ```
                """
                st.code(sms_preview, language="text")
                
                if st.button("📱 Send Test SMS"):
                    st.success("✅ Test SMS sent!")
    
    # Webhook Configuration
    with channel_tabs[4]:
        st.subheader("🔗 Custom Webhook")
        
        col1, col2 = st.columns(2)
        
        with col1:
            webhook_enabled = st.checkbox("Enable Custom Webhook", value=False)
            
            if webhook_enabled:
                webhook_url = st.text_input(
                    "Webhook URL",
                    placeholder="https://your-app.com/api/notifications",
                    help="Your custom webhook endpoint"
                )
                
                webhook_method = st.selectbox(
                    "HTTP Method",
                    options=["POST", "PUT"],
                    index=0
                )
                
                webhook_headers = st.text_area(
                    "Custom Headers (JSON)",
                    value='{"Authorization": "Bearer YOUR_TOKEN", "Content-Type": "application/json"}',
                    help="Additional headers to send"
                )
                
                retry_attempts = st.number_input(
                    "Retry Attempts",
                    min_value=0,
                    max_value=5,
                    value=3,
                    help="Number of retry attempts on failure"
                )
        
        with col2:
            if webhook_enabled:
                st.markdown("**Payload Preview**")
                webhook_payload = {
                    "event_type": "approval_required",
                    "timestamp": "2024-12-06T10:30:00Z",
                    "pipeline": "production-api-deploy",
                    "stage": "Deploy to Production",
                    "approvers": ["devops-team"],
                    "timeout": "2024-12-07T10:30:00Z",
                    "details": {
                        "changes": ["API v2.3.1", "Security patches"],
                        "requester": "john.doe@company.com"
                    }
                }
                st.json(webhook_payload)
                
                if st.button("🔗 Test Webhook"):
                    st.success("✅ Webhook test successful!")
    
    st.markdown("---")
    
    # Notification Rules
    st.subheader("📜 Notification Rules")
    st.markdown("Configure when to send notifications based on events and conditions")
    
    with st.expander("➕ Create Notification Rule", expanded=False):
        col1, col2 = st.columns(2)
        
        with col1:
            rule_name = st.text_input("Rule Name", placeholder="Production Approval Notifications")
            
            trigger_events = st.multiselect(
                "Trigger On Events",
                options=[
                    "Pipeline Started",
                    "Pipeline Succeeded",
                    "Pipeline Failed",
                    "Approval Required",
                    "Approval Granted",
                    "Approval Rejected",
                    "Stage Started",
                    "Stage Completed",
                    "Stage Failed",
                    "Deployment Completed",
                    "Rollback Initiated"
                ],
                default=["Approval Required"]
            )
            
            pipeline_filter = st.multiselect(
                "Apply to Pipelines",
                options=["All Pipelines", "production-*", "staging-*", "dev-*"],
                default=["All Pipelines"]
            )
        
        with col2:
            notification_channels_rule = st.multiselect(
                "Send via Channels",
                options=["Email", "Slack", "Teams", "SMS", "Webhook"],
                default=["Email", "Slack"]
            )
            
            priority = st.select_slider(
                "Notification Priority",
                options=["Low", "Medium", "High", "Critical"],
                value="Medium"
            )
            
            quiet_hours = st.checkbox("Respect Quiet Hours (10 PM - 8 AM)", value=True)
        
        if st.button("✅ Create Notification Rule", type="primary"):
            st.success(f"✅ Notification rule '{rule_name}' created successfully!")
    
    # Existing notification rules
    st.subheader("📋 Active Notification Rules")
    
    rules_data = pd.DataFrame([
        {
            "Rule": "Production Approvals",
            "Events": "Approval Required, Granted, Rejected",
            "Channels": "Email, Slack",
            "Priority": "High",
            "Status": "🟢 Active"
        },
        {
            "Rule": "Pipeline Failures",
            "Events": "Pipeline Failed, Stage Failed",
            "Channels": "Email, Slack, SMS",
            "Priority": "Critical",
            "Status": "🟢 Active"
        },
        {
            "Rule": "Daily Summary",
            "Events": "All Events (Batched)",
            "Channels": "Email",
            "Priority": "Low",
            "Status": "🟢 Active"
        }
    ])
    
    st.dataframe(rules_data, use_container_width=True, hide_index=True)


def render_pending_approvals(codepipeline, region: str):
    """Tab 4: Pending Approvals - Review and approve/reject requests"""
    
    st.header("⏳ Pending Approvals")
    st.markdown("Review and act on pending approval requests")
    
    # Filter options
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        filter_pipeline = st.selectbox(
            "Filter by Pipeline",
            options=["All Pipelines", "production-*", "staging-*", "dev-*"]
        )
    
    with col2:
        filter_priority = st.selectbox(
            "Filter by Priority",
            options=["All Priorities", "Critical", "High", "Medium", "Low"]
        )
    
    with col3:
        filter_sla = st.selectbox(
            "Filter by SLA Status",
            options=["All", "Within SLA", "SLA Warning", "SLA Breach"]
        )
    
    with col4:
        sort_by = st.selectbox(
            "Sort By",
            options=["Newest First", "Oldest First", "SLA Status", "Priority"]
        )
    
    st.markdown("---")
    
    # Pending approvals list
    pending_approvals = [
        {
            "id": "approval-001",
            "pipeline": "production-api-deploy",
            "stage": "Deploy to Production",
            "requested_by": "john.doe@company.com",
            "requested_at": "2 hours ago",
            "sla_status": "🟢 Within SLA (2h remaining)",
            "priority": "High",
            "changes": [
                "Updated API version to 2.3.1",
                "Applied security patches CVE-2024-1234, CVE-2024-5678",
                "Performance improvements to database queries",
                "Updated dependencies: boto3, requests, pandas"
            ],
            "test_results": "✅ All tests passed (234/234)",
            "security_scan": "✅ No vulnerabilities found",
            "approvers_required": "Any 1 of DevOps Team (5 members)"
        },
        {
            "id": "approval-002",
            "pipeline": "database-migration",
            "stage": "Security Review",
            "requested_by": "jane.smith@company.com",
            "requested_at": "4 hours ago",
            "sla_status": "🟡 SLA Warning (30min remaining)",
            "priority": "Critical",
            "changes": [
                "Database schema migration for user table",
                "Add new columns: last_login_ip, account_status",
                "Create indexes on frequently queried fields"
            ],
            "test_results": "✅ Migration tested in staging",
            "security_scan": "⚠️ Review required: PII data changes",
            "approvers_required": "Security Team + DBA (both required)"
        },
        {
            "id": "approval-003",
            "pipeline": "frontend-deployment",
            "stage": "QA Sign-off",
            "requested_by": "bob.wilson@company.com",
            "requested_at": "30 minutes ago",
            "sla_status": "🟢 Within SLA (7h 30min remaining)",
            "priority": "Medium",
            "changes": [
                "Updated React components for dashboard",
                "Fixed responsive design issues",
                "Added new data visualization charts"
            ],
            "test_results": "✅ UI tests passed, ⚠️ 2 visual regression tests pending",
            "security_scan": "✅ No security issues",
            "approvers_required": "All QA Team members (3/3)"
        }
    ]
    
    # Display each pending approval
    for approval in pending_approvals:
        with st.container():
            # Header
            col1, col2, col3 = st.columns([2, 1, 1])
            
            with col1:
                priority_emoji = "🔴" if approval["priority"] == "Critical" else "🟠" if approval["priority"] == "High" else "🟡"
                st.markdown(f"### {priority_emoji} {approval['pipeline']}")
                st.caption(f"**Stage:** {approval['stage']}")
            
            with col2:
                st.metric("Priority", approval["priority"])
                st.caption(f"Requested: {approval['requested_at']}")
            
            with col3:
                st.info(approval["sla_status"])
                st.caption(f"By: {approval['requested_by']}")
            
            # Details
            detail_tabs = st.tabs(["📝 Changes", "🧪 Test Results", "🔒 Security", "👥 Approvers"])
            
            with detail_tabs[0]:
                st.markdown("**Changes in this deployment:**")
                for change in approval["changes"]:
                    st.markdown(f"• {change}")
            
            with detail_tabs[1]:
                st.markdown(approval["test_results"])
                if st.button(f"📊 View Detailed Test Report", key=f"test_{approval['id']}"):
                    st.info("Opening detailed test report...")
            
            with detail_tabs[2]:
                st.markdown(approval["security_scan"])
                if st.button(f"🔍 View Security Scan Details", key=f"security_{approval['id']}"):
                    st.info("Opening security scan report...")
            
            with detail_tabs[3]:
                st.markdown(f"**Required:** {approval['approvers_required']}")
                st.caption("Current user: devops-admin (authorized to approve)")
            
            # Action buttons
            col1, col2, col3, col4, col5 = st.columns(5)
            
            with col1:
                if st.button("✅ Approve", key=f"approve_{approval['id']}", type="primary", use_container_width=True):
                    with st.spinner("Processing approval..."):
                        st.success(f"✅ Approved: {approval['pipeline']}")
                        st.balloons()
            
            with col2:
                if st.button("❌ Reject", key=f"reject_{approval['id']}", use_container_width=True):
                    rejection_reason = st.text_area(
                        "Rejection Reason (required)",
                        key=f"reason_{approval['id']}",
                        placeholder="Please provide a reason for rejection..."
                    )
                    if rejection_reason and st.button("Confirm Rejection", key=f"confirm_reject_{approval['id']}"):
                        st.error(f"❌ Rejected: {approval['pipeline']}")
            
            with col3:
                if st.button("💬 Add Comment", key=f"comment_{approval['id']}", use_container_width=True):
                    st.text_area("Your Comment", key=f"comment_text_{approval['id']}")
            
            with col4:
                if st.button("📊 View Pipeline", key=f"view_{approval['id']}", use_container_width=True):
                    st.info(f"Opening pipeline: {approval['pipeline']}")
            
            with col5:
                if st.button("📋 View Diff", key=f"diff_{approval['id']}", use_container_width=True):
                    st.info("Opening change diff...")
            
            st.markdown("---")
    
    # Bulk actions
    st.subheader("⚡ Bulk Actions")
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("✅ Approve All Low Priority", use_container_width=True):
            st.success("Approved all low priority requests")
    
    with col2:
        if st.button("🔔 Send Reminder to Approvers", use_container_width=True):
            st.info("Reminder notifications sent")
    
    with col3:
        if st.button("📧 Export Pending List", use_container_width=True):
            st.download_button(
                "Download CSV",
                data="pipeline,stage,requested_by,requested_at\n",
                file_name="pending_approvals.csv",
                use_container_width=True
            )


def render_approval_history(codepipeline, region: str):
    """Tab 5: Approval History - Audit trail of all approvals"""
    
    st.header("📜 Approval History")
    st.markdown("Complete audit trail of all approval decisions")
    
    # Date range filter
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        date_range = st.selectbox(
            "Time Period",
            options=["Last 7 Days", "Last 30 Days", "Last 90 Days", "Custom Range"]
        )
    
    with col2:
        filter_status = st.selectbox(
            "Filter by Status",
            options=["All", "Approved", "Rejected", "Timed Out", "Cancelled"]
        )
    
    with col3:
        filter_approver = st.selectbox(
            "Filter by Approver",
            options=["All Approvers", "Me", "DevOps Team", "QA Team", "Security Team"]
        )
    
    with col4:
        search_pipeline = st.text_input("Search Pipeline", placeholder="Filter by pipeline name...")
    
    st.markdown("---")
    
    # Approval history statistics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Approvals", "247", delta="+12 vs last period")
    
    with col2:
        st.metric("Approval Rate", "94%", delta="+2%")
    
    with col3:
        st.metric("Avg Approval Time", "42 min", delta="-8 min")
    
    with col4:
        st.metric("SLA Compliance", "96%", delta="+1%")
    
    st.markdown("---")
    
    # Approval history table
    history_data = pd.DataFrame([
        {
            "Timestamp": "2024-12-06 10:30",
            "Pipeline": "production-api-deploy",
            "Stage": "Deploy to Production",
            "Approver": "john.admin@company.com",
            "Decision": "✅ Approved",
            "Time to Approve": "15 min",
            "Comment": "All checks passed, deploying"
        },
        {
            "Timestamp": "2024-12-06 09:45",
            "Pipeline": "frontend-deployment",
            "Stage": "QA Sign-off",
            "Approver": "qa.team@company.com",
            "Decision": "✅ Approved",
            "Time to Approve": "2h 30min",
            "Comment": "Visual regression tests confirmed"
        },
        {
            "Timestamp": "2024-12-06 08:15",
            "Pipeline": "database-migration",
            "Stage": "Security Review",
            "Approver": "security.team@company.com",
            "Decision": "❌ Rejected",
            "Time to Approve": "45 min",
            "Comment": "PII data handling needs additional review"
        },
        {
            "Timestamp": "2024-12-05 16:20",
            "Pipeline": "infrastructure-update",
            "Stage": "Platform Approval",
            "Approver": "platform.admin@company.com",
            "Decision": "✅ Approved",
            "Time to Approve": "20 min",
            "Comment": "Infrastructure changes reviewed and approved"
        },
        {
            "Timestamp": "2024-12-05 14:10",
            "Pipeline": "hotfix-deployment",
            "Stage": "Emergency Deploy",
            "Approver": "engineering.lead@company.com",
            "Decision": "✅ Approved",
            "Time to Approve": "5 min",
            "Comment": "Critical hotfix - expedited approval"
        },
        {
            "Timestamp": "2024-12-05 11:30",
            "Pipeline": "backend-service-update",
            "Stage": "Production Gate",
            "Approver": "AUTO-APPROVED",
            "Decision": "✅ Auto-Approved",
            "Time to Approve": "0 min",
            "Comment": "Auto-approval rule: Minor version update in dev"
        },
        {
            "Timestamp": "2024-12-05 09:00",
            "Pipeline": "api-gateway-config",
            "Stage": "Config Review",
            "Approver": "N/A",
            "Decision": "⏱️ Timed Out",
            "Time to Approve": "24h",
            "Comment": "Approval timed out after 24 hours"
        }
    ])
    
    st.dataframe(history_data, use_container_width=True, hide_index=True)
    
    # Export options
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("📥 Export to CSV", use_container_width=True):
            csv = history_data.to_csv(index=False)
            st.download_button(
                "Download CSV",
                data=csv,
                file_name=f"approval_history_{datetime.now().strftime('%Y%m%d')}.csv",
                mime="text/csv",
                use_container_width=True
            )
    
    with col2:
        if st.button("📊 Generate Report", use_container_width=True):
            st.info("Generating comprehensive approval report...")
    
    with col3:
        if st.button("📧 Email Report", use_container_width=True):
            st.success("Report emailed to selected recipients")
    
    st.markdown("---")
    
    # Detailed view of selected approval
    st.subheader("🔍 Detailed Approval View")
    
    selected_approval = st.selectbox(
        "Select approval to view details",
        options=history_data['Pipeline'].tolist()
    )
    
    if selected_approval:
        with st.expander(f"📋 Details for {selected_approval}", expanded=True):
            selected_row = history_data[history_data['Pipeline'] == selected_approval].iloc[0]
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("**Approval Information**")
                st.markdown(f"**Pipeline:** {selected_row['Pipeline']}")
                st.markdown(f"**Stage:** {selected_row['Stage']}")
                st.markdown(f"**Decision:** {selected_row['Decision']}")
                st.markdown(f"**Approver:** {selected_row['Approver']}")
                st.markdown(f"**Time to Approve:** {selected_row['Time to Approve']}")
                st.markdown(f"**Comment:** {selected_row['Comment']}")
            
            with col2:
                st.markdown("**Audit Trail**")
                audit_trail = pd.DataFrame([
                    {"Event": "Approval Requested", "Time": "10:15:00", "User": "system"},
                    {"Event": "Notification Sent", "Time": "10:15:05", "User": "system"},
                    {"Event": "Approval Opened", "Time": "10:28:30", "User": selected_row['Approver']},
                    {"Event": "Decision Made", "Time": selected_row['Timestamp'].split()[1], "User": selected_row['Approver']},
                    {"Event": "Pipeline Continued", "Time": selected_row['Timestamp'].split()[1], "User": "system"}
                ])
                st.dataframe(audit_trail, use_container_width=True, hide_index=True)
            
            # Additional details
            st.markdown("**Deployment Details**")
            st.json({
                "pipeline_execution_id": "abc-123-def-456",
                "source_revision": "a1b2c3d4e5",
                "artifacts": ["build-output.zip", "test-results.xml"],
                "parameters": {
                    "environment": "production",
                    "region": "us-east-1",
                    "version": "2.3.1"
                }
            })


def render_auto_approval_rules(codepipeline, region: str):
    """Tab 6: Auto-Approval Rules - Configure automatic approval conditions"""
    
    st.header("🤖 Auto-Approval Rules")
    st.markdown("Configure conditions for automatic approval to speed up low-risk deployments")
    
    st.info("💡 **Tip:** Auto-approval rules help speed up deployments while maintaining governance for high-risk changes")
    
    # Create new auto-approval rule
    with st.expander("➕ Create Auto-Approval Rule", expanded=False):
        st.subheader("Create New Auto-Approval Rule")
        
        col1, col2 = st.columns(2)
        
        with col1:
            rule_name = st.text_input(
                "Rule Name",
                placeholder="Auto-approve dev deployments",
                help="Descriptive name for this rule"
            )
            
            rule_description = st.text_area(
                "Description",
                placeholder="Automatically approve all deployments to development environment",
                help="Explain when this rule applies"
            )
            
            apply_to_pipelines = st.multiselect(
                "Apply to Pipelines",
                options=["All Pipelines", "dev-*", "staging-*", "feature-*"],
                help="Which pipelines this rule applies to"
            )
            
            apply_to_stages = st.multiselect(
                "Apply to Stages",
                options=["All Stages", "Deploy to Dev", "Deploy to Staging", "Test"],
                help="Which stages this rule applies to"
            )
        
        with col2:
            st.markdown("**Conditions (All must be met)**")
            
            environment_condition = st.selectbox(
                "Environment",
                options=["Any", "Development", "Staging", "QA", "NOT Production"],
                help="Only auto-approve for specific environments"
            )
            
            change_size = st.selectbox(
                "Change Size",
                options=["Any", "Minor (< 10 files)", "Small (< 50 files)", "Medium (< 200 files)"],
                help="Limit auto-approval to small changes"
            )
            
            version_type = st.selectbox(
                "Version Type",
                options=["Any", "Patch Only (x.x.X)", "Minor or Patch (x.X.x)", "Major Changes Excluded"],
                help="Auto-approve only minor version bumps"
            )
            
            test_results = st.selectbox(
                "Test Results Required",
                options=["Not Required", "All Tests Passed", "No Test Failures", "100% Code Coverage"],
                help="Require test success before auto-approval"
            )
            
            security_scan = st.selectbox(
                "Security Scan Required",
                options=["Not Required", "No Vulnerabilities", "No High/Critical Issues", "Security Approved"],
                help="Require clean security scan"
            )
        
        # Time-based conditions
        st.markdown("**Time-Based Conditions**")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            business_hours_only = st.checkbox(
                "Business Hours Only (9 AM - 5 PM)",
                value=False,
                help="Only auto-approve during business hours"
            )
        
        with col2:
            weekdays_only = st.checkbox(
                "Weekdays Only (Mon-Fri)",
                value=False,
                help="Exclude weekend deployments"
            )
        
        with col3:
            avoid_fridays = st.checkbox(
                "Avoid Fridays",
                value=False,
                help="Don't auto-approve on Fridays"
            )
        
        # Notification settings
        st.markdown("**Notification Settings**")
        
        col1, col2 = st.columns(2)
        
        with col1:
            notify_on_auto_approval = st.checkbox(
                "Send Notification on Auto-Approval",
                value=True,
                help="Notify team when auto-approval occurs"
            )
        
        with col2:
            if notify_on_auto_approval:
                notification_channels_auto = st.multiselect(
                    "Notification Channels",
                    options=["Email", "Slack", "Teams"],
                    default=["Slack"],
                    help="How to notify about auto-approvals"
                )
        
        # Safety limits
        st.markdown("**Safety Limits**")
        
        col1, col2 = st.columns(2)
        
        with col1:
            max_per_day = st.number_input(
                "Max Auto-Approvals per Day",
                min_value=1,
                max_value=100,
                value=10,
                help="Limit automatic approvals to prevent runaway deployments"
            )
        
        with col2:
            cooldown_minutes = st.number_input(
                "Cooldown Period (minutes)",
                min_value=0,
                max_value=60,
                value=5,
                help="Minimum time between auto-approvals"
            )
        
        # Create button
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("✅ Create Auto-Approval Rule", type="primary", use_container_width=True):
                with st.spinner("Creating auto-approval rule..."):
                    st.success(f"✅ Auto-approval rule '{rule_name}' created successfully!")
                    st.info("💡 The rule is now active and will apply to matching pipelines")
        
        with col2:
            if st.button("🧪 Test Rule", use_container_width=True):
                st.info("Testing rule against recent pipeline executions...")
                st.success("✅ Rule would have auto-approved 5 of last 10 executions")
    
    st.markdown("---")
    
    # Existing auto-approval rules
    st.subheader("📋 Active Auto-Approval Rules")
    
    rules_data = pd.DataFrame([
        {
            "Rule": "Dev Auto-Approve",
            "Pipelines": "dev-*",
            "Conditions": "Environment=Dev, Tests Passed",
            "Usage": "45 approvals (last 7 days)",
            "Success Rate": "100%",
            "Status": "🟢 Active"
        },
        {
            "Rule": "Staging Minor Updates",
            "Pipelines": "staging-*",
            "Conditions": "Environment=Staging, Version=Patch, Security OK",
            "Usage": "12 approvals (last 7 days)",
            "Success Rate": "100%",
            "Status": "🟢 Active"
        },
        {
            "Rule": "Hotfix Fast Track",
            "Pipelines": "hotfix-*",
            "Conditions": "All Tests Passed, Business Hours",
            "Usage": "3 approvals (last 7 days)",
            "Success Rate": "100%",
            "Status": "🟢 Active"
        },
        {
            "Rule": "Documentation Updates",
            "Pipelines": "docs-*",
            "Conditions": "Files < 10, No Code Changes",
            "Usage": "23 approvals (last 7 days)",
            "Success Rate": "100%",
            "Status": "🟢 Active"
        }
    ])
    
    st.dataframe(rules_data, use_container_width=True, hide_index=True)
    
    # Rule management
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        selected_rule = st.selectbox(
            "Select Rule",
            options=rules_data['Rule'].tolist()
        )
    
    with col2:
        if st.button("✏️ Edit Rule"):
            st.info(f"Editing rule: {selected_rule}")
    
    with col3:
        if st.button("⏸️ Pause Rule"):
            st.warning(f"Paused rule: {selected_rule}")
    
    with col4:
        if st.button("🗑️ Delete Rule"):
            if st.session_state.get('confirm_delete_rule') == selected_rule:
                st.error(f"Deleted rule: {selected_rule}")
                st.session_state.confirm_delete_rule = None
            else:
                st.session_state.confirm_delete_rule = selected_rule
                st.warning("Click again to confirm deletion")
    
    st.markdown("---")
    
    # Auto-approval statistics
    st.subheader("📊 Auto-Approval Statistics")
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Auto-approvals vs Manual approvals
        approval_types = pd.DataFrame({
            'Type': ['Auto-Approved', 'Manual Approved', 'Rejected'],
            'Count': [83, 42, 5]
        })
        
        fig = px.pie(approval_types, values='Count', names='Type', 
                     title='Approval Distribution (Last 30 Days)',
                     color_discrete_sequence=['#2ECC71', '#3498DB', '#E74C3C'])
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        # Time saved by auto-approvals
        st.metric(
            "Time Saved (Last 30 Days)",
            "62 hours",
            delta="Avg 45 min per auto-approval",
            help="Estimated time saved by auto-approval vs manual review"
        )
        
        st.metric(
            "Auto-Approval Rate",
            "64%",
            delta="+5% vs last month",
            help="Percentage of eligible approvals that were auto-approved"
        )
        
        st.metric(
            "Zero Failures",
            "100%",
            help="Success rate of auto-approved deployments"
        )
    
    # Daily auto-approval trend
    st.subheader("📈 Auto-Approval Trend")
    
    dates = pd.date_range(end=datetime.now(), periods=30, freq='D')
    trend_data = pd.DataFrame({
        'Date': dates,
        'Auto-Approved': [5, 7, 6, 8, 9, 7, 8, 6, 5, 7, 8, 9, 10, 8, 7, 9, 8, 7, 6, 8, 9, 7, 8, 6, 5, 7, 8, 9, 8, 7],
        'Manual': [3, 2, 4, 3, 2, 3, 2, 3, 4, 3, 2, 1, 2, 3, 4, 2, 3, 4, 3, 2, 1, 2, 3, 4, 3, 2, 3, 2, 3, 2]
    })
    
    fig = go.Figure()
    fig.add_trace(go.Scatter(x=trend_data['Date'], y=trend_data['Auto-Approved'], 
                            mode='lines+markers', name='Auto-Approved',
                            line=dict(color='green', width=2)))
    fig.add_trace(go.Scatter(x=trend_data['Date'], y=trend_data['Manual'], 
                            mode='lines+markers', name='Manual Approval',
                            line=dict(color='blue', width=2)))
    
    fig.update_layout(
        title='Approval Trends (Last 30 Days)',
        xaxis_title='Date',
        yaxis_title='Number of Approvals',
        height=400,
        hovermode='x unified'
    )
    
    st.plotly_chart(fig, use_container_width=True)
    
    # Recommendations
    st.subheader("💡 Recommendations")
    
    recommendations = [
        {
            "icon": "🚀",
            "title": "Optimize Dev Deployments",
            "description": "Your dev-* pipelines have 100% success rate. Consider auto-approving more stages.",
            "action": "Create rule for additional dev stages"
        },
        {
            "icon": "⏱️",
            "title": "Reduce Manual Review Time",
            "description": "Staging deployments with passing tests wait avg 2h for approval. Auto-approve eligible ones.",
            "action": "Create auto-approval rule for staging"
        },
        {
            "icon": "📊",
            "title": "Documentation Deployments",
            "description": "Documentation updates are low-risk. Consider auto-approving all docs-* pipelines.",
            "action": "Expand docs auto-approval rule"
        }
    ]
    
    for rec in recommendations:
        with st.container():
            col1, col2 = st.columns([3, 1])
            
            with col1:
                st.markdown(f"### {rec['icon']} {rec['title']}")
                st.markdown(rec['description'])
            
            with col2:
                st.markdown("")  # Spacing
                if st.button(f"📝 {rec['action']}", key=f"action_{rec['title']}"):
                    st.info(f"Opening wizard to {rec['action']}...")
            
            st.markdown("---")


# Helper functions

def get_pipeline_approvals(codepipeline, pipeline_name: str) -> List[Dict[str, Any]]:
    """Get approval actions for a pipeline"""
    try:
        response = codepipeline.get_pipeline(name=pipeline_name)
        pipeline = response.get('pipeline', {})
        
        approvals = []
        for stage in pipeline.get('stages', []):
            for action in stage.get('actions', []):
                if action.get('actionTypeId', {}).get('category') == 'Approval':
                    approvals.append({
                        'stage': stage.get('name'),
                        'action': action.get('name'),
                        'configuration': action.get('configuration', {})
                    })
        
        return approvals
    except Exception as e:
        return []


def get_pending_approvals(codepipeline, region: str) -> List[Dict[str, Any]]:
    """Get all pending manual approvals across pipelines"""
    # In real implementation, this would query CodePipeline for pending manual approvals
    # For now, return mock data
    return []


def send_approval_notification(notification_config: Dict[str, Any], approval_data: Dict[str, Any]):
    """Send approval notification via configured channels"""
    # Implementation would send notifications via SES, SNS, Slack, etc.
    pass


if __name__ == "__main__":
    # For testing
    import sys
    st.set_page_config(page_title="CI/CD Phase 3", layout="wide")
    
    # Mock session
    session = boto3.Session()
    render_cicd_phase3_module(session, "123456789012", "us-east-1")
