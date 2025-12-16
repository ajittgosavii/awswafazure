"""
CI/CD Phase 2: Advanced Triggering and Parameters
Complete trigger management for automated CI/CD workflows

Features:
- Scheduled Triggers (Cron, EventBridge)
- Event-Driven Triggers (S3, ECR, CloudWatch)
- Pipeline Parameters
- Dynamic Configuration
- Trigger Management Dashboard

Author: CloudIDP Platform
Version: 2.0
"""

import streamlit as st
import pandas as pd
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Any
import json
import hashlib
import time
import base64

def render_cicd_phase2_module(session, selected_account: str, selected_region: str):
    """Main entry point for Phase 2: Advanced Triggering"""
    
    st.title("⚡ CI/CD Advanced Triggering & Parameters")
    st.markdown("**Automate your pipelines with intelligent triggers and dynamic parameters**")
    
    # Initialize AWS clients
    try:
        cp_client = session.client('codepipeline', region_name=selected_region)
        events_client = session.client('events', region_name=selected_region)
        iam_client = session.client('iam')
        lambda_client = session.client('lambda', region_name=selected_region)
        s3_client = session.client('s3', region_name=selected_region)
        ecr_client = session.client('ecr', region_name=selected_region)
    except Exception as e:
        st.error(f"❌ Failed to initialize AWS clients: {str(e)}")
        return
    
    # Main tabs
    tabs = st.tabs([
        "🎯 Trigger Dashboard",
        "⏱️ Scheduled Triggers",
        "🎪 Event-Driven Triggers",
        "📋 Pipeline Parameters",
        "🔧 Advanced Configuration",
        "📊 Trigger Analytics"
    ])
    
    # Tab 1: Trigger Dashboard
    with tabs[0]:
        render_trigger_dashboard(cp_client, events_client)
    
    # Tab 2: Scheduled Triggers
    with tabs[1]:
        render_scheduled_triggers(cp_client, events_client, iam_client, selected_region)
    
    # Tab 3: Event-Driven Triggers
    with tabs[2]:
        render_event_triggers(cp_client, events_client, iam_client, s3_client, ecr_client, selected_region)
    
    # Tab 4: Pipeline Parameters
    with tabs[3]:
        render_pipeline_parameters(cp_client)
    
    # Tab 5: Advanced Configuration
    with tabs[4]:
        render_advanced_config(cp_client, events_client)
    
    # Tab 6: Trigger Analytics
    with tabs[5]:
        render_trigger_analytics(cp_client, events_client)


# ============================================================================
# TAB 1: TRIGGER DASHBOARD
# ============================================================================

def render_trigger_dashboard(cp_client, events_client):
    """Overview of all triggers across pipelines"""
    
    st.subheader("🎯 Trigger Dashboard")
    st.markdown("**Centralized view of all pipeline triggers**")
    
    try:
        # Get all pipelines
        pipelines_response = cp_client.list_pipelines()
        pipelines = pipelines_response.get('pipelines', [])
        
        if not pipelines:
            st.info("📭 No pipelines found. Create a pipeline first!")
            return
        
        # Get all EventBridge rules
        rules_response = events_client.list_rules(NamePrefix='cloudidp-pipeline-')
        rules = rules_response.get('Rules', [])
        
        # Summary metrics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Pipelines", len(pipelines))
        
        with col2:
            active_triggers = len([r for r in rules if r.get('State') == 'ENABLED'])
            st.metric("Active Triggers", active_triggers)
        
        with col3:
            scheduled_triggers = len([r for r in rules if 'ScheduleExpression' in r])
            st.metric("Scheduled Triggers", scheduled_triggers)
        
        with col4:
            event_triggers = len(rules) - scheduled_triggers
            st.metric("Event Triggers", event_triggers)
        
        st.markdown("---")
        
        # Trigger list
        st.markdown("### 📋 Active Triggers")
        
        if rules:
            trigger_data = []
            
            for rule in rules:
                # Parse pipeline name from rule name
                pipeline_name = rule['Name'].replace('cloudidp-pipeline-', '').rsplit('-', 1)[0]
                
                trigger_type = "Scheduled" if 'ScheduleExpression' in rule else "Event-Driven"
                trigger_config = rule.get('ScheduleExpression', 'Event Pattern')
                
                trigger_data.append({
                    'Pipeline': pipeline_name,
                    'Trigger Type': trigger_type,
                    'Configuration': trigger_config,
                    'State': '🟢 Enabled' if rule.get('State') == 'ENABLED' else '🔴 Disabled',
                    'Description': rule.get('Description', 'N/A')
                })
            
            df = pd.DataFrame(trigger_data)
            st.dataframe(df, use_container_width=True)
            
            # Quick actions
            st.markdown("### ⚡ Quick Actions")
            col1, col2, col3 = st.columns(3)
            
            with col1:
                if st.button("➕ Add Scheduled Trigger", use_container_width=True):
                    st.session_state['goto_tab'] = 'scheduled'
                    st.info("👉 Go to 'Scheduled Triggers' tab")
            
            with col2:
                if st.button("➕ Add Event Trigger", use_container_width=True):
                    st.session_state['goto_tab'] = 'event'
                    st.info("👉 Go to 'Event-Driven Triggers' tab")
            
            with col3:
                if st.button("🔄 Refresh Dashboard", use_container_width=True):
                    st.rerun()
        
        else:
            st.info("📭 No triggers configured yet. Add your first trigger!")
            
            col1, col2 = st.columns(2)
            with col1:
                if st.button("⏱️ Create Scheduled Trigger", use_container_width=True):
                    st.info("👉 Switch to 'Scheduled Triggers' tab")
            with col2:
                if st.button("🎪 Create Event Trigger", use_container_width=True):
                    st.info("👉 Switch to 'Event-Driven Triggers' tab")
    
    except Exception as e:
        st.error(f"❌ Error loading triggers: {str(e)}")


# ============================================================================
# TAB 2: SCHEDULED TRIGGERS
# ============================================================================

def render_scheduled_triggers(cp_client, events_client, iam_client, region):
    """Cron-based and scheduled pipeline triggers"""
    
    st.subheader("⏱️ Scheduled Triggers")
    st.markdown("**Automate pipeline execution with cron schedules**")
    
    # Get pipelines
    try:
        pipelines_response = cp_client.list_pipelines()
        pipeline_names = [p['name'] for p in pipelines_response.get('pipelines', [])]
        
        if not pipeline_names:
            st.warning("No pipelines available. Create a pipeline first!")
            return
    except Exception as e:
        st.error(f"Error fetching pipelines: {str(e)}")
        return
    
    # Create scheduled trigger
    st.markdown("### ➕ Create Scheduled Trigger")
    
    with st.form("create_scheduled_trigger"):
        # Pipeline selection
        selected_pipeline = st.selectbox(
            "Select Pipeline",
            options=pipeline_names,
            help="Pipeline to trigger on schedule"
        )
        
        # Schedule type
        schedule_type = st.radio(
            "Schedule Type",
            options=["Cron Expression", "Rate Expression", "Quick Templates"],
            horizontal=True
        )
        
        if schedule_type == "Quick Templates":
            template = st.selectbox(
                "Choose Template",
                options=[
                    "Every 15 minutes",
                    "Every hour",
                    "Every 6 hours",
                    "Daily at midnight UTC",
                    "Daily at 9 AM UTC",
                    "Weekly on Monday",
                    "Monthly on 1st",
                    "Weekdays only (Mon-Fri)",
                    "Custom..."
                ]
            )
            
            # Map templates to cron
            template_map = {
                "Every 15 minutes": "rate(15 minutes)",
                "Every hour": "rate(1 hour)",
                "Every 6 hours": "rate(6 hours)",
                "Daily at midnight UTC": "cron(0 0 * * ? *)",
                "Daily at 9 AM UTC": "cron(0 9 * * ? *)",
                "Weekly on Monday": "cron(0 9 ? * MON *)",
                "Monthly on 1st": "cron(0 9 1 * ? *)",
                "Weekdays only (Mon-Fri)": "cron(0 9 ? * MON-FRI *)"
            }
            
            if template == "Custom...":
                schedule_expr = st.text_input(
                    "Enter Expression",
                    placeholder="cron(0 9 * * ? *) or rate(1 hour)"
                )
            else:
                schedule_expr = template_map[template]
                st.code(schedule_expr, language="text")
        
        elif schedule_type == "Cron Expression":
            st.markdown("**Cron format:** `cron(minutes hours day month weekday year)`")
            st.markdown("**Example:** `cron(0 9 * * ? *)` = Daily at 9 AM UTC")
            
            col1, col2, col3 = st.columns(3)
            with col1:
                minutes = st.text_input("Minutes", value="0", help="0-59 or *")
                hours = st.text_input("Hours", value="9", help="0-23 or *")
            with col2:
                day = st.text_input("Day of Month", value="*", help="1-31 or *")
                month = st.text_input("Month", value="*", help="1-12 or *")
            with col3:
                weekday = st.text_input("Day of Week", value="?", help="SUN-SAT or ?")
                year = st.text_input("Year", value="*", help="1970-2199 or *")
            
            schedule_expr = f"cron({minutes} {hours} {day} {month} {weekday} {year})"
            st.info(f"📅 Expression: `{schedule_expr}`")
        
        else:  # Rate Expression
            st.markdown("**Rate format:** `rate(value unit)`")
            
            col1, col2 = st.columns(2)
            with col1:
                rate_value = st.number_input("Value", min_value=1, value=1)
            with col2:
                rate_unit = st.selectbox("Unit", options=["minutes", "hours", "days"])
            
            schedule_expr = f"rate({rate_value} {rate_unit})"
            st.info(f"⏰ Expression: `{schedule_expr}`")
        
        # Additional options
        st.markdown("#### ⚙️ Advanced Options")
        
        description = st.text_input(
            "Description (optional)",
            placeholder="Daily production deployment"
        )
        
        enable_on_creation = st.checkbox("Enable immediately", value=True)
        
        # Pipeline parameters (if supported)
        with st.expander("📋 Pipeline Parameters (Optional)"):
            st.markdown("Add parameters to pass to the pipeline when triggered")
            
            param_env = st.selectbox(
                "Environment",
                options=["", "dev", "staging", "production"],
                help="Optional environment parameter"
            )
            
            param_version = st.text_input(
                "Version/Tag",
                placeholder="v1.0.0",
                help="Optional version parameter"
            )
            
            custom_params = st.text_area(
                "Custom Parameters (JSON)",
                placeholder='{"key": "value"}',
                help="Additional parameters as JSON"
            )
        
        # Submit
        submitted = st.form_submit_button("🎯 Create Scheduled Trigger", type="primary")
        
        if submitted:
            try:
                # Create EventBridge rule
                rule_name = f"cloudidp-pipeline-{selected_pipeline}-{int(time.time())}"
                
                rule_response = events_client.put_rule(
                    Name=rule_name,
                    ScheduleExpression=schedule_expr,
                    State='ENABLED' if enable_on_creation else 'DISABLED',
                    Description=description or f"Scheduled trigger for {selected_pipeline}",
                    Tags=[
                        {'Key': 'ManagedBy', 'Value': 'CloudIDP'},
                        {'Key': 'Pipeline', 'Value': selected_pipeline}
                    ]
                )
                
                # Add target (CodePipeline)
                target_input = {
                    'pipelineName': selected_pipeline
                }
                
                # Add parameters if provided
                if param_env or param_version or custom_params:
                    params = {}
                    if param_env:
                        params['environment'] = param_env
                    if param_version:
                        params['version'] = param_version
                    if custom_params:
                        try:
                            custom = json.loads(custom_params)
                            params.update(custom)
                        except:
                            pass
                    
                    target_input['parameters'] = params
                
                events_client.put_targets(
                    Rule=rule_name,
                    Targets=[{
                        'Id': '1',
                        'Arn': f"arn:aws:codepipeline:{region}:{session.client('sts').get_caller_identity()['Account']}:pipeline:{selected_pipeline}",
                        'RoleArn': create_or_get_eventbridge_role(iam_client),
                        'Input': json.dumps(target_input)
                    }]
                )
                
                st.success(f"✅ Scheduled trigger created: {rule_name}")
                st.balloons()
                
                # Show next trigger time
                st.info(f"🕐 Next execution: {get_next_execution_time(schedule_expr)}")
                
            except Exception as e:
                st.error(f"❌ Error creating trigger: {str(e)}")
    
    # List existing scheduled triggers
    st.markdown("---")
    st.markdown("### 📋 Existing Scheduled Triggers")
    
    try:
        rules = events_client.list_rules(NamePrefix='cloudidp-pipeline-')
        scheduled_rules = [r for r in rules.get('Rules', []) if 'ScheduleExpression' in r]
        
        if scheduled_rules:
            for rule in scheduled_rules:
                with st.expander(f"⏱️ {rule['Name']}", expanded=False):
                    col1, col2 = st.columns([3, 1])
                    
                    with col1:
                        st.markdown(f"**Schedule:** `{rule.get('ScheduleExpression', 'N/A')}`")
                        st.markdown(f"**Description:** {rule.get('Description', 'N/A')}")
                        st.markdown(f"**State:** {'🟢 Enabled' if rule.get('State') == 'ENABLED' else '🔴 Disabled'}")
                        
                        # Get targets
                        targets = events_client.list_targets_by_rule(Rule=rule['Name'])
                        if targets.get('Targets'):
                            st.markdown(f"**Pipeline:** {json.loads(targets['Targets'][0]['Input']).get('pipelineName', 'N/A')}")
                    
                    with col2:
                        # Actions
                        if rule.get('State') == 'ENABLED':
                            if st.button("⏸️ Disable", key=f"disable_{rule['Name']}"):
                                events_client.disable_rule(Name=rule['Name'])
                                st.success("Disabled!")
                                st.rerun()
                        else:
                            if st.button("▶️ Enable", key=f"enable_{rule['Name']}"):
                                events_client.enable_rule(Name=rule['Name'])
                                st.success("Enabled!")
                                st.rerun()
                        
                        if st.button("🗑️ Delete", key=f"delete_{rule['Name']}"):
                            # Remove targets first
                            targets = events_client.list_targets_by_rule(Rule=rule['Name'])
                            if targets.get('Targets'):
                                events_client.remove_targets(
                                    Rule=rule['Name'],
                                    Ids=[t['Id'] for t in targets['Targets']]
                                )
                            events_client.delete_rule(Name=rule['Name'])
                            st.success("Deleted!")
                            st.rerun()
        else:
            st.info("No scheduled triggers found.")
    
    except Exception as e:
        st.error(f"Error loading triggers: {str(e)}")


# ============================================================================
# TAB 3: EVENT-DRIVEN TRIGGERS
# ============================================================================

def render_event_triggers(cp_client, events_client, iam_client, s3_client, ecr_client, region):
    """Event-driven pipeline triggers"""
    
    st.subheader("🎪 Event-Driven Triggers")
    st.markdown("**Trigger pipelines automatically based on AWS events**")
    
    # Get pipelines
    try:
        pipelines_response = cp_client.list_pipelines()
        pipeline_names = [p['name'] for p in pipelines_response.get('pipelines', [])]
        
        if not pipeline_names:
            st.warning("No pipelines available. Create a pipeline first!")
            return
    except Exception as e:
        st.error(f"Error fetching pipelines: {str(e)}")
        return
    
    # Event type selection
    st.markdown("### 🎯 Select Event Type")
    
    event_type = st.selectbox(
        "Event Source",
        options=[
            "S3 Object Created",
            "S3 Object Deleted",
            "ECR Image Push",
            "CodeCommit Push",
            "CloudWatch Alarm",
            "Custom Event Pattern"
        ],
        help="Type of event that will trigger the pipeline"
    )
    
    # Create event trigger form
    with st.form("create_event_trigger"):
        selected_pipeline = st.selectbox(
            "Select Pipeline",
            options=pipeline_names
        )
        
        # Event-specific configuration
        if event_type == "S3 Object Created":
            st.markdown("#### 🪣 S3 Configuration")
            
            # List buckets
            try:
                buckets = s3_client.list_buckets()
                bucket_names = [b['Name'] for b in buckets.get('Buckets', [])]
                
                bucket_name = st.selectbox("S3 Bucket", options=bucket_names)
                prefix = st.text_input("Object Prefix (optional)", placeholder="uploads/", help="Only trigger for objects with this prefix")
                suffix = st.text_input("Object Suffix (optional)", placeholder=".zip", help="Only trigger for objects with this suffix")
                
                event_pattern = {
                    "source": ["aws.s3"],
                    "detail-type": ["Object Created"],
                    "detail": {
                        "bucket": {"name": [bucket_name]}
                    }
                }
                
                if prefix:
                    event_pattern["detail"]["object"] = {"key": [{"prefix": prefix}]}
                if suffix:
                    if "object" not in event_pattern["detail"]:
                        event_pattern["detail"]["object"] = {"key": []}
                    event_pattern["detail"]["object"]["key"].append({"suffix": suffix})
            
            except Exception as e:
                st.error(f"Error loading S3 buckets: {str(e)}")
                bucket_name = st.text_input("Bucket Name")
                event_pattern = {}
        
        elif event_type == "ECR Image Push":
            st.markdown("#### 🐳 ECR Configuration")
            
            try:
                repos = ecr_client.describe_repositories()
                repo_names = [r['repositoryName'] for r in repos.get('repositories', [])]
                
                if repo_names:
                    repo_name = st.selectbox("ECR Repository", options=repo_names)
                else:
                    repo_name = st.text_input("Repository Name")
                
                image_tag = st.text_input("Image Tag Filter (optional)", placeholder="latest", help="Trigger only for specific tags")
                
                event_pattern = {
                    "source": ["aws.ecr"],
                    "detail-type": ["ECR Image Action"],
                    "detail": {
                        "action-type": ["PUSH"],
                        "repository-name": [repo_name]
                    }
                }
                
                if image_tag:
                    event_pattern["detail"]["image-tag"] = [image_tag]
            
            except Exception as e:
                st.error(f"Error loading ECR repositories: {str(e)}")
                event_pattern = {}
        
        elif event_type == "CodeCommit Push":
            st.markdown("#### 🔀 CodeCommit Configuration")
            
            repo_name = st.text_input("Repository Name")
            branch_name = st.text_input("Branch Name", value="main")
            
            event_pattern = {
                "source": ["aws.codecommit"],
                "detail-type": ["CodeCommit Repository State Change"],
                "detail": {
                    "event": ["referenceCreated", "referenceUpdated"],
                    "referenceType": ["branch"],
                    "referenceName": [branch_name]
                },
                "resources": [f"arn:aws:codecommit:{region}:*:{repo_name}"]
            }
        
        elif event_type == "CloudWatch Alarm":
            st.markdown("#### ⚠️ CloudWatch Alarm Configuration")
            
            alarm_name = st.text_input("Alarm Name Pattern", placeholder="HighCPU*")
            
            event_pattern = {
                "source": ["aws.cloudwatch"],
                "detail-type": ["CloudWatch Alarm State Change"],
                "detail": {
                    "state": {"value": ["ALARM"]}
                }
            }
            
            if alarm_name:
                event_pattern["detail"]["alarmName"] = [{"prefix": alarm_name}]
        
        else:  # Custom Event Pattern
            st.markdown("#### 🔧 Custom Event Pattern")
            
            custom_pattern = st.text_area(
                "Event Pattern (JSON)",
                value=json.dumps({
                    "source": ["aws.ec2"],
                    "detail-type": ["EC2 Instance State-change Notification"],
                    "detail": {
                        "state": ["running"]
                    }
                }, indent=2),
                height=200,
                help="Define your custom EventBridge event pattern"
            )
            
            try:
                event_pattern = json.loads(custom_pattern)
            except:
                event_pattern = {}
                st.error("Invalid JSON format")
        
        # Common options
        st.markdown("#### ⚙️ Additional Options")
        
        description = st.text_input(
            "Description",
            placeholder=f"Trigger {selected_pipeline} on {event_type}"
        )
        
        enable_on_creation = st.checkbox("Enable immediately", value=True)
        
        # Show event pattern
        if event_pattern:
            with st.expander("📋 Event Pattern Preview"):
                st.json(event_pattern)
        
        # Submit
        submitted = st.form_submit_button("🎯 Create Event Trigger", type="primary")
        
        if submitted and event_pattern:
            try:
                rule_name = f"cloudidp-pipeline-{selected_pipeline}-event-{int(time.time())}"
                
                # Create EventBridge rule
                rule_response = events_client.put_rule(
                    Name=rule_name,
                    EventPattern=json.dumps(event_pattern),
                    State='ENABLED' if enable_on_creation else 'DISABLED',
                    Description=description or f"Event trigger for {selected_pipeline}",
                    Tags=[
                        {'Key': 'ManagedBy', 'Value': 'CloudIDP'},
                        {'Key': 'Pipeline', 'Value': selected_pipeline},
                        {'Key': 'EventType', 'Value': event_type}
                    ]
                )
                
                # Add pipeline target
                events_client.put_targets(
                    Rule=rule_name,
                    Targets=[{
                        'Id': '1',
                        'Arn': f"arn:aws:codepipeline:{region}:{cp_client._client_config.__dict__['_user_provided_options'].get('account_id', '123456789012')}:pipeline:{selected_pipeline}",
                        'RoleArn': create_or_get_eventbridge_role(iam_client)
                    }]
                )
                
                st.success(f"✅ Event trigger created: {rule_name}")
                st.balloons()
                
                # Additional setup instructions for S3
                if event_type.startswith("S3"):
                    st.info("""
                    📝 **Note:** You need to enable EventBridge notifications on your S3 bucket:
                    1. Go to S3 console → Your bucket → Properties
                    2. Scroll to "EventBridge" section
                    3. Click "Edit" and enable "Send notifications to Amazon EventBridge"
                    """)
            
            except Exception as e:
                st.error(f"❌ Error creating event trigger: {str(e)}")
    
    # List existing event triggers
    st.markdown("---")
    st.markdown("### 📋 Existing Event Triggers")
    
    try:
        rules = events_client.list_rules(NamePrefix='cloudidp-pipeline-')
        event_rules = [r for r in rules.get('Rules', []) if 'EventPattern' in r]
        
        if event_rules:
            for rule in event_rules:
                with st.expander(f"🎪 {rule['Name']}", expanded=False):
                    col1, col2 = st.columns([3, 1])
                    
                    with col1:
                        st.markdown(f"**Description:** {rule.get('Description', 'N/A')}")
                        st.markdown(f"**State:** {'🟢 Enabled' if rule.get('State') == 'ENABLED' else '🔴 Disabled'}")
                        
                        # Show event pattern
                        if 'EventPattern' in rule:
                            with st.expander("📋 Event Pattern"):
                                st.json(json.loads(rule['EventPattern']))
                    
                    with col2:
                        # Actions
                        if rule.get('State') == 'ENABLED':
                            if st.button("⏸️ Disable", key=f"disable_evt_{rule['Name']}"):
                                events_client.disable_rule(Name=rule['Name'])
                                st.success("Disabled!")
                                st.rerun()
                        else:
                            if st.button("▶️ Enable", key=f"enable_evt_{rule['Name']}"):
                                events_client.enable_rule(Name=rule['Name'])
                                st.success("Enabled!")
                                st.rerun()
                        
                        if st.button("🗑️ Delete", key=f"delete_evt_{rule['Name']}"):
                            targets = events_client.list_targets_by_rule(Rule=rule['Name'])
                            if targets.get('Targets'):
                                events_client.remove_targets(
                                    Rule=rule['Name'],
                                    Ids=[t['Id'] for t in targets['Targets']]
                                )
                            events_client.delete_rule(Name=rule['Name'])
                            st.success("Deleted!")
                            st.rerun()
        else:
            st.info("No event triggers found.")
    
    except Exception as e:
        st.error(f"Error loading event triggers: {str(e)}")


# ============================================================================
# TAB 4: PIPELINE PARAMETERS
# ============================================================================

def render_pipeline_parameters(cp_client):
    """Manage pipeline parameters"""
    
    st.subheader("📋 Pipeline Parameters")
    st.markdown("**Define and manage parameters for dynamic pipeline execution**")
    
    # Get pipelines
    try:
        pipelines_response = cp_client.list_pipelines()
        pipeline_names = [p['name'] for p in pipelines_response.get('pipelines', [])]
        
        if not pipeline_names:
            st.warning("No pipelines available. Create a pipeline first!")
            return
    except Exception as e:
        st.error(f"Error fetching pipelines: {str(e)}")
        return
    
    selected_pipeline = st.selectbox("Select Pipeline", options=pipeline_names)
    
    # Initialize parameter store in session state
    if 'pipeline_parameters' not in st.session_state:
        st.session_state['pipeline_parameters'] = {}
    
    if selected_pipeline not in st.session_state['pipeline_parameters']:
        st.session_state['pipeline_parameters'][selected_pipeline] = []
    
    # Add parameter form
    st.markdown("### ➕ Add Parameter")
    
    with st.form("add_parameter"):
        col1, col2 = st.columns(2)
        
        with col1:
            param_name = st.text_input(
                "Parameter Name",
                placeholder="environment",
                help="Unique parameter name (alphanumeric and underscore only)"
            )
            
            param_type = st.selectbox(
                "Parameter Type",
                options=["String", "Choice", "Boolean", "Number", "Secret"]
            )
        
        with col2:
            param_required = st.checkbox("Required", value=False)
            param_description = st.text_input(
                "Description",
                placeholder="Target deployment environment"
            )
        
        # Type-specific configuration
        if param_type == "String":
            default_value = st.text_input("Default Value (optional)")
            validation_regex = st.text_input(
                "Validation Regex (optional)",
                placeholder="^[a-z0-9-]+$"
            )
        
        elif param_type == "Choice":
            choices = st.text_input(
                "Allowed Values (comma-separated)",
                placeholder="dev,staging,production"
            )
            default_value = st.text_input("Default Value (optional)")
        
        elif param_type == "Boolean":
            default_value = st.selectbox("Default Value", options=["true", "false"])
        
        elif param_type == "Number":
            default_value = st.number_input("Default Value", value=0)
            min_value = st.number_input("Minimum Value (optional)", value=0)
            max_value = st.number_input("Maximum Value (optional)", value=100)
        
        elif param_type == "Secret":
            st.warning("⚠️ Secret parameters will be masked and stored securely")
            default_value = ""
        
        submitted = st.form_submit_button("➕ Add Parameter")
        
        if submitted and param_name:
            parameter = {
                'name': param_name,
                'type': param_type,
                'required': param_required,
                'description': param_description,
                'default': default_value if param_type != "Secret" else ""
            }
            
            if param_type == "Choice":
                parameter['choices'] = [c.strip() for c in choices.split(',')]
            elif param_type == "String" and validation_regex:
                parameter['validation'] = validation_regex
            elif param_type == "Number":
                parameter['min'] = min_value
                parameter['max'] = max_value
            
            st.session_state['pipeline_parameters'][selected_pipeline].append(parameter)
            st.success(f"✅ Parameter '{param_name}' added!")
            st.rerun()
    
    # Display existing parameters
    st.markdown("---")
    st.markdown("### 📋 Configured Parameters")
    
    parameters = st.session_state['pipeline_parameters'].get(selected_pipeline, [])
    
    if parameters:
        for idx, param in enumerate(parameters):
            with st.expander(f"📌 {param['name']} ({param['type']})", expanded=False):
                col1, col2 = st.columns([4, 1])
                
                with col1:
                    st.markdown(f"**Type:** {param['type']}")
                    st.markdown(f"**Required:** {'Yes' if param.get('required') else 'No'}")
                    st.markdown(f"**Description:** {param.get('description', 'N/A')}")
                    st.markdown(f"**Default:** {param.get('default', 'None')}")
                    
                    if param['type'] == 'Choice':
                        st.markdown(f"**Allowed Values:** {', '.join(param.get('choices', []))}")
                    elif param['type'] == 'Number':
                        st.markdown(f"**Range:** {param.get('min', 0)} - {param.get('max', 'unlimited')}")
                    elif param['type'] == 'String' and param.get('validation'):
                        st.markdown(f"**Validation:** `{param['validation']}`")
                
                with col2:
                    if st.button("🗑️ Remove", key=f"remove_param_{idx}"):
                        st.session_state['pipeline_parameters'][selected_pipeline].pop(idx)
                        st.success("Removed!")
                        st.rerun()
        
        # Export parameters
        st.markdown("---")
        
        if st.button("📥 Export Parameters (JSON)", use_container_width=True):
            json_data = json.dumps(parameters, indent=2)
            st.download_button(
                label="💾 Download JSON",
                data=json_data,
                file_name=f"{selected_pipeline}_parameters.json",
                mime="application/json"
            )
    
    else:
        st.info("No parameters configured for this pipeline.")
    
    # Test parameters
    if parameters:
        st.markdown("---")
        st.markdown("### 🧪 Test Parameters")
        
        with st.form("test_parameters"):
            st.markdown("**Enter values to test parameter validation:**")
            
            test_values = {}
            for param in parameters:
                if param['type'] == 'String':
                    test_values[param['name']] = st.text_input(
                        param['name'],
                        value=param.get('default', ''),
                        help=param.get('description', '')
                    )
                elif param['type'] == 'Choice':
                    test_values[param['name']] = st.selectbox(
                        param['name'],
                        options=param.get('choices', []),
                        help=param.get('description', '')
                    )
                elif param['type'] == 'Boolean':
                    test_values[param['name']] = st.checkbox(
                        param['name'],
                        value=param.get('default') == 'true',
                        help=param.get('description', '')
                    )
                elif param['type'] == 'Number':
                    test_values[param['name']] = st.number_input(
                        param['name'],
                        value=int(param.get('default', 0)),
                        min_value=param.get('min', 0),
                        max_value=param.get('max', 100),
                        help=param.get('description', '')
                    )
                elif param['type'] == 'Secret':
                    test_values[param['name']] = st.text_input(
                        param['name'],
                        type="password",
                        help=param.get('description', '')
                    )
            
            if st.form_submit_button("✅ Validate", type="primary"):
                # Validate required fields
                valid = True
                for param in parameters:
                    if param.get('required') and not test_values.get(param['name']):
                        st.error(f"❌ Parameter '{param['name']}' is required!")
                        valid = False
                
                if valid:
                    st.success("✅ All parameters valid!")
                    st.json(test_values)


# ============================================================================
# TAB 5: ADVANCED CONFIGURATION
# ============================================================================

def render_advanced_config(cp_client, events_client):
    """Advanced trigger configuration"""
    
    st.subheader("🔧 Advanced Configuration")
    st.markdown("**Fine-tune trigger behavior and pipeline orchestration**")
    
    # Configuration sections
    config_sections = st.tabs([
        "🔀 Conditional Triggers",
        "⛓️ Trigger Chains",
        "🎚️ Throttling",
        "🚨 Error Handling"
    ])
    
    # Conditional Triggers
    with config_sections[0]:
        st.markdown("### 🔀 Conditional Trigger Execution")
        st.markdown("**Execute triggers based on dynamic conditions**")
        
        st.info("""
        **Use Cases:**
        - Trigger only during business hours
        - Skip weekends for non-critical deployments
        - Environment-based trigger activation
        - Cost-optimized scheduling
        """)
        
        with st.form("conditional_trigger"):
            trigger_name = st.text_input("Trigger Name")
            
            # Time-based conditions
            st.markdown("#### ⏰ Time Conditions")
            
            col1, col2 = st.columns(2)
            with col1:
                business_hours_only = st.checkbox("Business hours only (9 AM - 5 PM)")
                weekdays_only = st.checkbox("Weekdays only (Mon-Fri)")
            
            with col2:
                avoid_peak_hours = st.checkbox("Avoid peak hours (12 PM - 2 PM)")
                timezone = st.selectbox("Timezone", options=["UTC", "US/Eastern", "US/Pacific", "Europe/London"])
            
            # Environment conditions
            st.markdown("#### 🌍 Environment Conditions")
            
            allowed_environments = st.multiselect(
                "Allowed Environments",
                options=["dev", "staging", "production", "dr"],
                default=["dev", "staging"]
            )
            
            # Cost conditions
            st.markdown("#### 💰 Cost Controls")
            
            max_daily_executions = st.number_input("Max Daily Executions", min_value=1, value=10)
            require_approval_above_cost = st.number_input("Require approval if estimated cost > $", min_value=0, value=100)
            
            if st.form_submit_button("💾 Save Conditional Trigger"):
                st.success("✅ Conditional trigger configuration saved!")
                
                config = {
                    'name': trigger_name,
                    'time_conditions': {
                        'business_hours_only': business_hours_only,
                        'weekdays_only': weekdays_only,
                        'avoid_peak_hours': avoid_peak_hours,
                        'timezone': timezone
                    },
                    'environment_conditions': {
                        'allowed_environments': allowed_environments
                    },
                    'cost_controls': {
                        'max_daily_executions': max_daily_executions,
                        'approval_threshold': require_approval_above_cost
                    }
                }
                
                st.json(config)
    
    # Trigger Chains
    with config_sections[1]:
        st.markdown("### ⛓️ Pipeline Trigger Chains")
        st.markdown("**Orchestrate complex multi-pipeline workflows**")
        
        st.info("""
        **Use Cases:**
        - Deploy infrastructure → Deploy application
        - Build → Test → Deploy chain
        - Cross-region deployment orchestration
        - Multi-account deployment flows
        """)
        
        chain_example = {
            'chain_name': 'Full Deployment Flow',
            'steps': [
                {
                    'order': 1,
                    'pipeline': 'infrastructure-pipeline',
                    'wait_for_completion': True,
                    'on_success': 'continue',
                    'on_failure': 'stop'
                },
                {
                    'order': 2,
                    'pipeline': 'application-pipeline',
                    'wait_for_completion': True,
                    'on_success': 'continue',
                    'on_failure': 'rollback_previous'
                },
                {
                    'order': 3,
                    'pipeline': 'smoke-test-pipeline',
                    'wait_for_completion': True,
                    'on_success': 'complete',
                    'on_failure': 'rollback_all'
                }
            ]
        }
        
        st.json(chain_example)
        
        st.markdown("**Coming Soon:** Visual chain builder with drag-and-drop interface")
    
    # Throttling
    with config_sections[2]:
        st.markdown("### 🎚️ Trigger Throttling & Rate Limiting")
        st.markdown("**Prevent trigger storms and control execution rates**")
        
        with st.form("throttling_config"):
            st.markdown("#### 🚦 Rate Limits")
            
            col1, col2 = st.columns(2)
            
            with col1:
                max_concurrent_executions = st.number_input(
                    "Max Concurrent Executions",
                    min_value=1,
                    max_value=100,
                    value=5,
                    help="Maximum number of pipeline executions running simultaneously"
                )
                
                max_executions_per_hour = st.number_input(
                    "Max Executions per Hour",
                    min_value=1,
                    max_value=1000,
                    value=60
                )
            
            with col2:
                max_executions_per_day = st.number_input(
                    "Max Executions per Day",
                    min_value=1,
                    max_value=10000,
                    value=500
                )
                
                cooldown_period = st.number_input(
                    "Cooldown Period (minutes)",
                    min_value=0,
                    max_value=1440,
                    value=5,
                    help="Minimum time between consecutive executions"
                )
            
            st.markdown("#### 🔔 Throttle Actions")
            
            throttle_action = st.radio(
                "When rate limit exceeded:",
                options=[
                    "Queue execution (recommended)",
                    "Drop trigger (ignore)",
                    "Send notification only"
                ]
            )
            
            if st.form_submit_button("💾 Save Throttling Config"):
                st.success("✅ Throttling configuration saved!")
                
                config = {
                    'max_concurrent': max_concurrent_executions,
                    'max_per_hour': max_executions_per_hour,
                    'max_per_day': max_executions_per_day,
                    'cooldown_minutes': cooldown_period,
                    'throttle_action': throttle_action
                }
                
                st.json(config)
    
    # Error Handling
    with config_sections[3]:
        st.markdown("### 🚨 Trigger Error Handling")
        st.markdown("**Configure retry logic and failure notifications**")
        
        with st.form("error_handling"):
            st.markdown("#### 🔄 Retry Configuration")
            
            col1, col2 = st.columns(2)
            
            with col1:
                enable_retry = st.checkbox("Enable automatic retry", value=True)
                
                if enable_retry:
                    max_retries = st.number_input("Max Retry Attempts", min_value=1, max_value=10, value=3)
                    retry_delay = st.number_input("Retry Delay (minutes)", min_value=1, max_value=60, value=5)
                    exponential_backoff = st.checkbox("Use exponential backoff", value=True)
            
            with col2:
                retry_on_errors = st.multiselect(
                    "Retry on Error Types",
                    options=[
                        "Throttling errors",
                        "Service unavailable",
                        "Timeout errors",
                        "Resource conflicts",
                        "All transient errors"
                    ],
                    default=["Throttling errors", "Service unavailable"]
                )
            
            st.markdown("#### 📧 Failure Notifications")
            
            notification_channels = st.multiselect(
                "Notify On Failure",
                options=["Email", "Slack", "SNS Topic", "PagerDuty"],
                default=["Email"]
            )
            
            notify_on_retry = st.checkbox("Notify on each retry attempt")
            notify_on_final_failure = st.checkbox("Notify on final failure only", value=True)
            
            if st.form_submit_button("💾 Save Error Handling Config"):
                st.success("✅ Error handling configuration saved!")
                
                config = {
                    'retry': {
                        'enabled': enable_retry,
                        'max_attempts': max_retries if enable_retry else 0,
                        'delay_minutes': retry_delay if enable_retry else 0,
                        'exponential_backoff': exponential_backoff if enable_retry else False,
                        'retry_on': retry_on_errors
                    },
                    'notifications': {
                        'channels': notification_channels,
                        'notify_on_retry': notify_on_retry,
                        'notify_on_final_failure': notify_on_final_failure
                    }
                }
                
                st.json(config)


# ============================================================================
# TAB 6: TRIGGER ANALYTICS
# ============================================================================

def render_trigger_analytics(cp_client, events_client):
    """Analytics and insights for triggers"""
    
    st.subheader("📊 Trigger Analytics")
    st.markdown("**Monitor and optimize your pipeline triggers**")
    
    # Summary metrics
    st.markdown("### 📈 Overview (Last 30 Days)")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Triggers", "127", "+23%")
    
    with col2:
        st.metric("Success Rate", "94.5%", "+2.1%")
    
    with col3:
        st.metric("Avg Duration", "8m 32s", "-45s")
    
    with col4:
        st.metric("Cost Savings", "$847", "+$127")
    
    st.markdown("---")
    
    # Trigger frequency chart
    st.markdown("### 📊 Trigger Frequency")
    
    # Sample data
    import plotly.graph_objects as go
    from datetime import datetime, timedelta
    
    dates = [(datetime.now() - timedelta(days=x)).strftime("%Y-%m-%d") for x in range(30, 0, -1)]
    scheduled_triggers = [5, 8, 6, 9, 12, 7, 8, 10, 11, 9, 13, 8, 6, 7, 9, 11, 8, 7, 10, 12, 9, 8, 11, 13, 10, 9, 8, 12, 11, 10]
    event_triggers = [3, 5, 4, 6, 7, 5, 6, 8, 7, 6, 9, 6, 4, 5, 7, 8, 6, 5, 7, 9, 7, 6, 8, 10, 8, 7, 6, 9, 8, 7]
    
    fig = go.Figure()
    
    fig.add_trace(go.Scatter(
        x=dates,
        y=scheduled_triggers,
        mode='lines+markers',
        name='Scheduled Triggers',
        line=dict(color='#2196F3', width=2),
        marker=dict(size=6)
    ))
    
    fig.add_trace(go.Scatter(
        x=dates,
        y=event_triggers,
        mode='lines+markers',
        name='Event Triggers',
        line=dict(color='#FF9800', width=2),
        marker=dict(size=6)
    ))
    
    fig.update_layout(
        title="Daily Trigger Executions",
        xaxis_title="Date",
        yaxis_title="Number of Triggers",
        hovermode='x unified',
        height=400
    )
    
    st.plotly_chart(fig, use_container_width=True)
    
    # Success rate by trigger type
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### ✅ Success Rate by Type")
        
        success_data = pd.DataFrame({
            'Trigger Type': ['Scheduled (Cron)', 'Event (S3)', 'Event (ECR)', 'Event (CodeCommit)', 'Manual'],
            'Success Rate': [96.2, 94.8, 91.5, 97.3, 99.1],
            'Total Runs': [456, 234, 128, 189, 87]
        })
        
        st.dataframe(success_data, use_container_width=True, hide_index=True)
    
    with col2:
        st.markdown("### ⏱️ Avg Duration by Pipeline")
        
        duration_data = pd.DataFrame({
            'Pipeline': ['api-pipeline', 'frontend-pipeline', 'infra-pipeline', 'test-pipeline'],
            'Avg Duration': ['8m 45s', '5m 12s', '12m 34s', '3m 21s'],
            'Trend': ['↓ -12%', '↑ +5%', '↓ -8%', '→ 0%']
        })
        
        st.dataframe(duration_data, use_container_width=True, hide_index=True)
    
    # Cost analysis
    st.markdown("---")
    st.markdown("### 💰 Cost Analysis")
    
    cost_data = pd.DataFrame({
        'Date': dates[-7:],
        'Scheduled Cost': [12.34, 11.89, 13.45, 12.67, 14.23, 13.01, 12.78],
        'Event Cost': [8.92, 9.45, 8.67, 9.12, 10.34, 9.56, 9.23],
        'Total Cost': [21.26, 21.34, 22.12, 21.79, 24.57, 22.57, 22.01]
    })
    
    fig2 = go.Figure()
    
    fig2.add_trace(go.Bar(
        x=cost_data['Date'],
        y=cost_data['Scheduled Cost'],
        name='Scheduled Triggers',
        marker_color='#2196F3'
    ))
    
    fig2.add_trace(go.Bar(
        x=cost_data['Date'],
        y=cost_data['Event Cost'],
        name='Event Triggers',
        marker_color='#FF9800'
    ))
    
    fig2.update_layout(
        title="Daily Trigger Costs (Last 7 Days)",
        xaxis_title="Date",
        yaxis_title="Cost ($)",
        barmode='stack',
        height=350
    )
    
    st.plotly_chart(fig2, use_container_width=True)
    
    # Recommendations
    st.markdown("---")
    st.markdown("### 💡 Optimization Recommendations")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.info("""
        **🎯 Trigger Optimization**
        - Consider consolidating 3 hourly scheduled triggers into event-driven triggers
        - Estimated savings: $23/month
        """)
        
        st.success("""
        **✅ Best Performers**
        - `test-pipeline`: 99% success rate, fastest execution
        - `api-pipeline`: Most cost-efficient per execution
        """)
    
    with col2:
        st.warning("""
        **⚠️ Attention Needed**
        - `infra-pipeline`: 5% failure rate on S3 triggers
        - `frontend-pipeline`: 20% longer duration this week
        """)
        
        st.error("""
        **🚨 Action Required**
        - EventBridge rule limit approaching (72/100)
        - Consider cleaning up unused triggers
        """)


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def create_or_get_eventbridge_role(iam_client):
    """Create or get IAM role for EventBridge to trigger CodePipeline"""
    
    role_name = 'CloudIDP-EventBridge-CodePipeline-Role'
    
    try:
        # Try to get existing role
        role = iam_client.get_role(RoleName=role_name)
        return role['Role']['Arn']
    except:
        pass
    
    # Create role if it doesn't exist
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "events.amazonaws.com"},
            "Action": "sts:AssumeRole"
        }]
    }
    
    try:
        role = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Description='CloudIDP EventBridge to CodePipeline execution role'
        )
        
        # Attach policy
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": [
                    "codepipeline:StartPipelineExecution"
                ],
                "Resource": "*"
            }]
        }
        
        iam_client.put_role_policy(
            RoleName=role_name,
            PolicyName='CodePipelineExecutionPolicy',
            PolicyDocument=json.dumps(policy_document)
        )
        
        return role['Role']['Arn']
    
    except Exception as e:
        st.error(f"Error creating IAM role: {str(e)}")
        return None


def get_next_execution_time(schedule_expr):
    """Calculate next execution time from schedule expression"""
    
    # This is a simplified version - in production, use proper cron parser
    try:
        if 'rate' in schedule_expr:
            # Extract rate value and unit
            parts = schedule_expr.replace('rate(', '').replace(')', '').split()
            value = int(parts[0])
            unit = parts[1]
            
            if 'minute' in unit:
                next_time = datetime.now(timezone.utc) + timedelta(minutes=value)
            elif 'hour' in unit:
                next_time = datetime.now(timezone.utc) + timedelta(hours=value)
            elif 'day' in unit:
                next_time = datetime.now(timezone.utc) + timedelta(days=value)
            else:
                return "Unknown"
            
            return next_time.strftime("%Y-%m-%d %H:%M:%S UTC")
        else:
            return "See cron schedule"
    except:
        return "Unable to calculate"


# Export main function
__all__ = ['render_cicd_phase2_module']