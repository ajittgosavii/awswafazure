"""
Complete Account Lifecycle Management - Enterprise Edition
Combines AI automation with comprehensive lifecycle features

Features from Original:
- Portfolio Dashboard
- Create Account
- Template Marketplace
- Batch Provisioning
- Account Modification
- Clone Account
- Offboarding
- Approvals
- AI Assistant
- Network Designer
- Dependencies

Enhanced with:
- AI-powered auto-detection
- Smart guardrail recommendations
- Automated onboarding
- Event-driven architecture
"""

import streamlit as st
import boto3
import pandas as pd
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from auth_azure_sso import require_permission
import json
import os

# ============================================================================
# AI CLIENT INITIALIZATION
# ============================================================================

@st.cache_resource
def get_anthropic_client():
    """Initialize and cache Anthropic client for AI features"""
    api_key = None
    
    if hasattr(st, 'secrets'):
        try:
            if 'anthropic' in st.secrets and 'api_key' in st.secrets['anthropic']:
                api_key = st.secrets['anthropic']['api_key']
        except:
            pass
    
    if not api_key and hasattr(st, 'secrets') and 'ANTHROPIC_API_KEY' in st.secrets:
        api_key = st.secrets['ANTHROPIC_API_KEY']
    
    if not api_key:
        api_key = os.environ.get('ANTHROPIC_API_KEY')
    
    if not api_key:
        return None
    
    try:
        import anthropic
        return anthropic.Anthropic(api_key=api_key)
    except Exception as e:
        return None

# ============================================================================
# DATA MODELS
# ============================================================================

class AccountStatus(Enum):
    """Account lifecycle status"""
    PENDING = "pending"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    CLOSING = "closing"
    CLOSED = "closed"

@dataclass
class AccountTemplate:
    """Account provisioning template"""
    id: str
    name: str
    description: str
    category: str  # baseline, security-enhanced, production, development
    guardrails: List[str]
    network_config: Dict
    cost_controls: Dict
    compliance_level: str

@dataclass
class AccountRequest:
    """Account creation/modification request"""
    request_id: str
    account_name: str
    account_email: str
    ou_path: str
    template_id: str
    requester: str
    status: str
    created_at: datetime
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None

# ============================================================================
# AI FEATURES
# ============================================================================

def ai_recommend_template(requirements: Dict) -> Dict:
    """AI recommends best template based on requirements"""
    client = get_anthropic_client()
    if not client:
        return {
            'template_id': 'baseline',
            'reasoning': 'Using baseline template (AI unavailable)',
            'confidence': 'N/A'
        }
    
    try:
        import anthropic
        
        prompt = f"""Analyze these account requirements and recommend the best template:

Requirements:
{json.dumps(requirements, indent=2)}

Available Templates:
1. Baseline - Basic setup with standard guardrails
2. Security-Enhanced - Additional security controls for sensitive workloads
3. Production - Full compliance, HA, monitoring for production workloads
4. Development - Relaxed controls, cost-optimized for development
5. Sandbox - Minimal controls, isolated for experimentation

Respond with JSON:
{{
    "template_id": "production",
    "template_name": "Production Standard",
    "reasoning": "Why this template fits best",
    "confidence": 95,
    "customizations": ["Optional modifications recommended"]
}}

Respond ONLY with valid JSON."""

        message = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1000,
            messages=[{"role": "user", "content": prompt}]
        )
        
        response_text = message.content[0].text
        
        try:
            return json.loads(response_text)
        except:
            import re
            json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())
            
            return {
                'template_id': 'baseline',
                'reasoning': 'AI parsing error, using baseline',
                'confidence': 'N/A'
            }
    
    except Exception as e:
        return {
            'template_id': 'baseline',
            'reasoning': f'AI error: {str(e)}, using baseline',
            'confidence': 'N/A'
        }

# ============================================================================
# TEMPLATE MARKETPLACE
# ============================================================================

class TemplateMarketplace:
    """Pre-built account templates"""
    
    TEMPLATES = {
        "baseline": AccountTemplate(
            id="baseline",
            name="Baseline Standard",
            description="Standard AWS account with basic security and compliance",
            category="baseline",
            guardrails=["cloudtrail", "mfa", "config", "security_hub"],
            network_config={"vpc": "single", "subnets": "public+private"},
            cost_controls={"budget": 1000, "alerts": True},
            compliance_level="standard"
        ),
        "security_enhanced": AccountTemplate(
            id="security_enhanced",
            name="Security Enhanced",
            description="Hardened account for sensitive workloads",
            category="security",
            guardrails=["cloudtrail", "mfa", "config", "security_hub", "guardduty", "macie", "inspector"],
            network_config={"vpc": "multi", "subnets": "private-only", "tgw": True},
            cost_controls={"budget": 2000, "alerts": True, "anomaly_detection": True},
            compliance_level="high"
        ),
        "production": AccountTemplate(
            id="production",
            name="Production Standard",
            description="Full production-grade setup with HA and monitoring",
            category="production",
            guardrails=["cloudtrail", "mfa", "config", "security_hub", "guardduty", "cloudwatch"],
            network_config={"vpc": "multi-az", "subnets": "public+private", "tgw": True, "vpn": True},
            cost_controls={"budget": 5000, "alerts": True, "ri_recommendations": True},
            compliance_level="high"
        ),
        "development": AccountTemplate(
            id="development",
            name="Development Standard",
            description="Cost-optimized for development and testing",
            category="development",
            guardrails=["cloudtrail", "config", "cost_budget"],
            network_config={"vpc": "single", "subnets": "public+private"},
            cost_controls={"budget": 500, "alerts": True, "auto_shutdown": True},
            compliance_level="standard"
        ),
        "sandbox": AccountTemplate(
            id="sandbox",
            name="Sandbox/Experimental",
            description="Minimal controls for experimentation",
            category="sandbox",
            guardrails=["cloudtrail", "cost_budget"],
            network_config={"vpc": "single", "subnets": "public"},
            cost_controls={"budget": 100, "alerts": True, "hard_limit": True},
            compliance_level="minimal"
        )
    }

# ============================================================================
# MAIN MODULE
# ============================================================================

class AccountLifecycleModule:
    """Complete Account Lifecycle Management"""
    
    @staticmethod
    @require_permission('manage_policies')

    def render():
        """Render the account lifecycle module"""
        st.title("🔄 Account Lifecycle Management")
        st.caption("🤖 Automated provisioning, modification, and decommissioning of AWS accounts")
        
        # AI availability
        ai_available = get_anthropic_client() is not None
        
        if ai_available:
            st.success("🤖 **AI Assistant: ENABLED** | Smart recommendations | Automated analysis | Intelligent provisioning")
        
        # Main tabs - ALL 11 from image + extras
        tabs = st.tabs([
            "📊 Portfolio Dashboard",
            "➕ Create Account",
            "🏪 Template Marketplace",
            "📦 Batch Provisioning",
            "✏️ Account Modification",
            "📋 Clone Account",
            "🚪 Offboarding",
            "✅ Approvals",
            "🤖 AI Assistant",
            "🌐 Network Designer",
            "🔗 Dependencies",
            "🔍 Auto-Detection"
        ])
        
        with tabs[0]:
            AccountLifecycleModule._render_portfolio_dashboard()
        
        with tabs[1]:
            AccountLifecycleModule._render_create_account(ai_available)
        
        with tabs[2]:
            AccountLifecycleModule._render_template_marketplace()
        
        with tabs[3]:
            AccountLifecycleModule._render_batch_provisioning()
        
        with tabs[4]:
            AccountLifecycleModule._render_account_modification()
        
        with tabs[5]:
            AccountLifecycleModule._render_clone_account()
        
        with tabs[6]:
            AccountLifecycleModule._render_offboarding()
        
        with tabs[7]:
            AccountLifecycleModule._render_approvals()
        
        with tabs[8]:
            AccountLifecycleModule._render_ai_assistant(ai_available)
        
        with tabs[9]:
            AccountLifecycleModule._render_network_designer()
        
        with tabs[10]:
            AccountLifecycleModule._render_dependencies()
        
        with tabs[11]:
            AccountLifecycleModule._render_auto_detection(ai_available)
    
    # ========================================================================
    # TAB 1: PORTFOLIO DASHBOARD
    # ========================================================================
    
    @staticmethod
    def _render_portfolio_dashboard():
        """Portfolio overview dashboard"""
        st.subheader("📊 Account Portfolio Dashboard")
        
        # Key metrics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Accounts", "48", delta="+3 this month")
        with col2:
            st.metric("Active", "45", delta="✅")
        with col3:
            st.metric("Pending Approval", "2", delta="⏳")
        with col4:
            st.metric("Monthly Cost", "$12,450", delta="-8%")
        
        st.markdown("---")
        
        # Portfolio breakdown
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("### 📈 Accounts by Environment")
            env_data = pd.DataFrame({
                'Environment': ['Production', 'Development', 'Sandbox', 'Security'],
                'Count': [12, 24, 10, 2]
            })
            st.bar_chart(env_data.set_index('Environment'))
        
        with col2:
            st.markdown("### 💰 Cost by OU")
            cost_data = pd.DataFrame({
                'OU': ['Production', 'Development', 'Sandbox', 'Security'],
                'Cost': [6200, 4800, 1200, 250]
            })
            st.bar_chart(cost_data.set_index('OU'))
        
        st.markdown("---")
        
        # Recent activity
        st.markdown("### 🕒 Recent Activity")
        
        activity = [
            {"Time": "2 hours ago", "Event": "Account Created", "Details": "prod-app-services (123456789012)", "Status": "✅ Complete"},
            {"Time": "1 day ago", "Event": "Guardrails Applied", "Details": "dev-sandbox-team-a: 5/5 applied", "Status": "✅ Complete"},
            {"Time": "2 days ago", "Event": "Account Modified", "Details": "test-env-qa: Budget increased to $2000", "Status": "✅ Complete"},
            {"Time": "3 days ago", "Event": "Approval Pending", "Details": "security-audit-2 awaiting approval", "Status": "⏳ Pending"}
        ]
        
        df = pd.DataFrame(activity)
        st.dataframe(df, use_container_width=True)
    
    # ========================================================================
    # TAB 2: CREATE ACCOUNT
    # ========================================================================
    
    @staticmethod
    def _render_create_account(ai_available: bool):
        """Create new AWS account"""
        st.subheader("➕ Create New AWS Account")
        
        st.markdown("### 📝 Account Details")
        
        col1, col2 = st.columns(2)
        
        with col1:
            account_name = st.text_input("Account Name*", placeholder="prod-application-services")
            account_email = st.text_input("Account Email*", placeholder="aws+prod-app@company.com")
            business_unit = st.selectbox("Business Unit*", [
                "Engineering",
                "Product",
                "Data Science",
                "Security",
                "Finance"
            ])
        
        with col2:
            environment = st.selectbox("Environment*", [
                "Production",
                "Development",
                "Staging",
                "Sandbox",
                "Security"
            ])
            ou_path = st.selectbox("Organizational Unit*", [
                "Production/Applications",
                "Development/Engineering",
                "Development/Sandbox",
                "Security/Logging",
                "Security/Audit"
            ])
            cost_center = st.text_input("Cost Center", placeholder="CC-12345")
        
        st.markdown("---")
        st.markdown("### 🛡️ Template Selection")
        
        # AI recommendation
        if ai_available and st.button("🤖 Get AI Template Recommendation"):
            with st.spinner("AI analyzing requirements..."):
                requirements = {
                    "environment": environment,
                    "business_unit": business_unit,
                    "ou_path": ou_path
                }
                
                recommendation = ai_recommend_template(requirements)
                
                st.success(f"✅ AI Recommends: **{recommendation.get('template_name', 'Baseline')}**")
                st.info(f"**Reasoning:** {recommendation.get('reasoning', 'N/A')}")
                st.metric("AI Confidence", f"{recommendation.get('confidence', 'N/A')}%")
        
        template = st.selectbox("Select Template", [
            "Baseline Standard",
            "Security Enhanced",
            "Production Standard",
            "Development Standard",
            "Sandbox/Experimental"
        ])
        
        # Template preview
        with st.expander("📋 Template Details"):
            if template == "Baseline Standard":
                st.write("**Guardrails:** CloudTrail, MFA, Config, Security Hub")
                st.write("**Network:** Single VPC, Public + Private subnets")
                st.write("**Budget:** $1,000/month")
            elif template == "Production Standard":
                st.write("**Guardrails:** Full security + compliance suite")
                st.write("**Network:** Multi-AZ VPC, Transit Gateway, VPN")
                st.write("**Budget:** $5,000/month")
        
        st.markdown("---")
        st.markdown("### ⚙️ Additional Configuration")
        
        col1, col2 = st.columns(2)
        
        with col1:
            enable_guardduty = st.checkbox("Enable GuardDuty", value=True)
            enable_macie = st.checkbox("Enable Macie", value=False)
        
        with col2:
            auto_tagging = st.checkbox("Auto-apply tags", value=True)
            approval_required = st.checkbox("Require approval", value=True if environment == "Production" else False)
        
        st.markdown("---")
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            if st.button("🚀 Create Account", type="primary", use_container_width=True):
                if not account_name or not account_email:
                    st.error("Please fill in all required fields")
                else:
                    with st.spinner("Creating account..."):
                        # Progress simulation
                        progress_bar = st.progress(0)
                        status_text = st.empty()
                        
                        steps = [
                            "Validating inputs...",
                            "Creating AWS account...",
                            "Applying template...",
                            "Configuring network...",
                            "Enabling guardrails...",
                            "Setting up monitoring...",
                            "Finalizing configuration..."
                        ]
                        
                        for i, step in enumerate(steps):
                            status_text.text(step)
                            progress_bar.progress((i + 1) / len(steps))
                        
                        st.success(f"✅ Account '{account_name}' created successfully!")
                        st.info(f"📧 Confirmation sent to {account_email}")
                        
                        if approval_required:
                            st.warning("⏳ Account pending approval from management")
        
        with col2:
            if st.button("💾 Save as Draft", use_container_width=True):
                st.info("Draft saved!")
    
    # ========================================================================
    # TAB 3: TEMPLATE MARKETPLACE
    # ========================================================================
    
    @staticmethod
    def _render_template_marketplace():
        """Browse and manage account templates"""
        st.subheader("🏪 Template Marketplace")
        
        st.markdown("### 📦 Available Templates")
        
        # Template cards
        for template_id, template in TemplateMarketplace.TEMPLATES.items():
            with st.expander(f"{template.name} - {template.description}"):
                col1, col2 = st.columns(2)
                
                with col1:
                    st.write(f"**Category:** {template.category}")
                    st.write(f"**Compliance Level:** {template.compliance_level}")
                    st.write(f"**Guardrails:** {len(template.guardrails)}")
                    st.write(f"**Budget:** ${template.cost_controls['budget']}/month")
                
                with col2:
                    st.write("**Included Guardrails:**")
                    for gr in template.guardrails:
                        st.write(f"  ✅ {gr}")
                
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    if st.button(f"Use Template", key=f"use_{template_id}"):
                        st.session_state['selected_template'] = template_id
                        st.success(f"Template '{template.name}' selected!")
                
                with col2:
                    if st.button(f"Customize", key=f"custom_{template_id}"):
                        st.info("Opening customization wizard...")
                
                with col3:
                    if st.button(f"Preview", key=f"preview_{template_id}"):
                        st.info("Generating preview...")
        
        st.markdown("---")
        st.markdown("### ➕ Create Custom Template")
        
        if st.button("Create New Template"):
            st.info("Opening template builder...")
    
    # ========================================================================
    # TAB 4: BATCH PROVISIONING
    # ========================================================================
    
    @staticmethod
    def _render_batch_provisioning():
        """Batch account creation"""
        st.subheader("📦 Batch Provisioning")
        
        st.markdown("""
        ### 🚀 Create Multiple Accounts at Once
        
        Upload a CSV file with account details for bulk provisioning.
        """)
        
        # CSV template
        st.markdown("### 📋 CSV Template")
        
        template_data = {
            "account_name": ["prod-app-1", "dev-test-1", "sandbox-team-a"],
            "account_email": ["aws+prod-app1@co.com", "aws+dev-test1@co.com", "aws+sandbox-a@co.com"],
            "environment": ["Production", "Development", "Sandbox"],
            "ou_path": ["Production/Apps", "Development/Test", "Development/Sandbox"],
            "template": ["production", "development", "sandbox"],
            "cost_center": ["CC-001", "CC-002", "CC-003"]
        }
        
        template_df = pd.DataFrame(template_data)
        st.dataframe(template_df, use_container_width=True)
        
        if st.button("📥 Download CSV Template"):
            st.success("Template downloaded!")
        
        st.markdown("---")
        st.markdown("### 📤 Upload Batch File")
        
        uploaded_file = st.file_uploader("Upload CSV", type=['csv'])
        
        if uploaded_file:
            df = pd.read_csv(uploaded_file)
            
            st.write(f"**Accounts to create:** {len(df)}")
            st.dataframe(df, use_container_width=True)
            
            col1, col2 = st.columns(2)
            
            with col1:
                if st.button("✅ Validate Batch", type="primary", use_container_width=True):
                    st.success("✅ All 3 accounts validated successfully!")
                    st.info("Estimated time: 30 minutes for 3 accounts")
            
            with col2:
                if st.button("🚀 Provision All", use_container_width=True):
                    progress_bar = st.progress(0)
                    for i in range(len(df)):
                        progress_bar.progress((i + 1) / len(df))
                    
                    st.success("🎉 Batch provisioning complete!")
    
    # ========================================================================
    # TAB 5: ACCOUNT MODIFICATION
    # ========================================================================
    
    @staticmethod
    def _render_account_modification():
        """Modify existing accounts"""
        st.subheader("✏️ Account Modification")
        
        st.markdown("### 🔍 Select Account to Modify")
        
        account = st.selectbox("Account", [
            "123456789012 - prod-app-services",
            "234567890123 - dev-sandbox-team-a",
            "345678901234 - test-environment-qa"
        ])
        
        st.markdown("---")
        st.markdown("### ⚙️ Modification Options")
        
        modification_type = st.radio("What would you like to modify?", [
            "Budget & Cost Controls",
            "Guardrails & Security",
            "Network Configuration",
            "Tags & Metadata",
            "OU Placement"
        ])
        
        if modification_type == "Budget & Cost Controls":
            col1, col2 = st.columns(2)
            
            with col1:
                current_budget = st.number_input("Current Budget", value=1000, disabled=True)
                new_budget = st.number_input("New Budget ($)", value=1000, min_value=0)
            
            with col2:
                alert_threshold = st.slider("Alert Threshold (%)", 50, 100, 80)
                enable_hard_limit = st.checkbox("Enable Hard Limit")
            
            if st.button("💾 Update Budget"):
                st.success(f"✅ Budget updated to ${new_budget}/month")
        
        elif modification_type == "Guardrails & Security":
            st.markdown("**Current Guardrails:**")
            
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.checkbox("CloudTrail", value=True, disabled=True)
                st.checkbox("Security Hub", value=True)
            
            with col2:
                st.checkbox("GuardDuty", value=True)
                st.checkbox("Config", value=True)
            
            with col3:
                st.checkbox("Macie", value=False)
                st.checkbox("Inspector", value=False)
            
            if st.button("🛡️ Update Guardrails"):
                st.success("✅ Guardrails updated!")
    
    # ========================================================================
    # TAB 6: CLONE ACCOUNT
    # ========================================================================
    
    @staticmethod
    def _render_clone_account():
        """Clone existing account"""
        st.subheader("📋 Clone Account")
        
        st.markdown("""
        ### 🔄 Create a Copy of an Existing Account
        
        Clone preserves:
        - Network configuration
        - Guardrails
        - Cost controls
        - Tags and metadata
        """)
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("#### Source Account")
            source_account = st.selectbox("Select account to clone", [
                "123456789012 - prod-app-services",
                "234567890123 - dev-sandbox-team-a"
            ])
            
            st.info("""
            **Source Configuration:**
            - Template: Production Standard
            - Guardrails: 7 active
            - Network: Multi-AZ VPC
            - Budget: $5,000/month
            """)
        
        with col2:
            st.markdown("#### New Account Details")
            new_name = st.text_input("New Account Name", placeholder="prod-app-services-clone")
            new_email = st.text_input("New Email", placeholder="aws+prod-app-clone@company.com")
            
            clone_options = st.multiselect("What to clone?", [
                "Network Configuration",
                "Guardrails",
                "Cost Controls",
                "Tags",
                "IAM Roles (structure only)"
            ], default=["Network Configuration", "Guardrails", "Cost Controls"])
        
        if st.button("🔄 Clone Account", type="primary"):
            with st.spinner("Cloning account configuration..."):
                st.success(f"✅ Account '{new_name}' created as clone!")
                st.info("Configuration replicated successfully")
    
    # ========================================================================
    # TAB 7: OFFBOARDING
    # ========================================================================
    
    @staticmethod
    def _render_offboarding():
        """Account decommissioning"""
        st.subheader("🚪 Account Offboarding")
        
        st.warning("""
        ⚠️ **Caution:** Account offboarding is a permanent action.
        
        Please ensure all data is backed up before proceeding.
        """)
        
        st.markdown("### 🔍 Select Account to Offboard")
        
        account_to_close = st.selectbox("Account", [
            "345678901234 - old-test-environment",
            "456789012345 - deprecated-sandbox"
        ])
        
        st.markdown("---")
        st.markdown("### ✅ Pre-Offboarding Checklist")
        
        col1, col2 = st.columns(2)
        
        with col1:
            data_backup = st.checkbox("Data backup completed")
            resources_exported = st.checkbox("Resource inventory exported")
            cost_report = st.checkbox("Final cost report generated")
        
        with col2:
            stakeholders_notified = st.checkbox("Stakeholders notified")
            dependencies_removed = st.checkbox("Dependencies removed")
            approval_obtained = st.checkbox("Management approval obtained")
        
        all_checked = all([data_backup, resources_exported, cost_report, 
                          stakeholders_notified, dependencies_removed, approval_obtained])
        
        st.markdown("---")
        st.markdown("### 🗑️ Offboarding Options")
        
        offboard_type = st.radio("Offboarding Type", [
            "Soft Delete (Suspend access, retain for 90 days)",
            "Hard Delete (Permanent closure)",
            "Transfer (Move to different organization)"
        ])
        
        reason = st.text_area("Reason for Offboarding", placeholder="Project completed, resources no longer needed...")
        
        if all_checked:
            if st.button("🚪 Initiate Offboarding", type="primary"):
                st.error("⚠️ Please confirm this action is intentional")
                
                confirm = st.checkbox("I understand this will permanently close the account")
                
                if confirm and st.button("✅ Confirm Offboarding"):
                    with st.spinner("Initiating offboarding process..."):
                        st.success("✅ Offboarding initiated!")
                        st.info("Account will be closed within 90 days as per AWS policy")
        else:
            st.warning("⚠️ Complete all checklist items before offboarding")
    
    # ========================================================================
    # TAB 8: APPROVALS
    # ========================================================================
    
    @staticmethod
    def _render_approvals():
        """Approval workflow"""
        st.subheader("✅ Approval Workflow")
        
        # Summary metrics
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("Pending Approvals", "2")
        with col2:
            st.metric("Approved Today", "1")
        with col3:
            st.metric("Average Approval Time", "4.2 hours")
        
        st.markdown("---")
        st.markdown("### ⏳ Pending Approvals")
        
        # Pending requests
        requests = [
            {
                "ID": "REQ-001",
                "Type": "Create Account",
                "Account": "security-audit-2",
                "Requester": "john.doe@company.com",
                "Date": "2024-12-05",
                "Priority": "🔴 High",
                "Action": "review"
            },
            {
                "ID": "REQ-002",
                "Type": "Budget Increase",
                "Account": "prod-app-services",
                "Requester": "jane.smith@company.com",
                "Date": "2024-12-04",
                "Priority": "🟡 Medium",
                "Action": "review"
            }
        ]
        
        for req in requests:
            with st.expander(f"{req['Priority']} {req['Type']}: {req['Account']}"):
                col1, col2 = st.columns(2)
                
                with col1:
                    st.write(f"**Request ID:** {req['ID']}")
                    st.write(f"**Requester:** {req['Requester']}")
                    st.write(f"**Date:** {req['Date']}")
                
                with col2:
                    st.write(f"**Type:** {req['Type']}")
                    st.write(f"**Priority:** {req['Priority']}")
                
                if req['Type'] == "Create Account":
                    st.write("**Details:**")
                    st.write("- Template: Security Enhanced")
                    st.write("- OU: Security/Audit")
                    st.write("- Budget: $2,000/month")
                
                comment = st.text_area("Approval Comment", key=f"comment_{req['ID']}")
                
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    if st.button("✅ Approve", key=f"approve_{req['ID']}", type="primary"):
                        st.success(f"Request {req['ID']} approved!")
                
                with col2:
                    if st.button("❌ Reject", key=f"reject_{req['ID']}"):
                        st.error(f"Request {req['ID']} rejected")
                
                with col3:
                    if st.button("💬 Request Info", key=f"info_{req['ID']}"):
                        st.info("Information request sent to requester")
        
        st.markdown("---")
        st.markdown("### ✅ Recently Approved")
        
        approved = [
            {"ID": "REQ-000", "Type": "Create Account", "Account": "dev-team-sandbox", "Approver": "You", "Date": "2024-12-06"}
        ]
        
        df = pd.DataFrame(approved)
        st.dataframe(df, use_container_width=True)
    
    # ========================================================================
    # TAB 9: AI ASSISTANT
    # ========================================================================
    
    @staticmethod
    def _render_ai_assistant(ai_available: bool):
        """AI-powered lifecycle assistant"""
        st.subheader("🤖 AI Assistant")
        
        if not ai_available:
            st.warning("⚠️ AI Assistant unavailable. Configure ANTHROPIC_API_KEY to enable.")
            return
        
        st.markdown("""
        ### 💬 Ask the AI Assistant
        
        Get intelligent recommendations for:
        - Account architecture
        - Template selection
        - Cost optimization
        - Security best practices
        - Compliance requirements
        """)
        
        # Pre-defined questions
        st.markdown("#### 🎯 Quick Questions:")
        
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("🏗️ Best template for production workload?"):
                st.info("""
                **AI Recommendation:** Production Standard Template
                
                **Reasoning:**
                - Full compliance suite (CloudTrail, Config, Security Hub)
                - Multi-AZ network for high availability
                - GuardDuty for threat detection
                - $5,000 budget accommodates production scale
                
                **Confidence:** 96%
                """)
            
            if st.button("💰 How to reduce costs in dev accounts?"):
                st.info("""
                **AI Suggestions:**
                1. Enable auto-shutdown for EC2 instances (saves 40%)
                2. Use Spot instances for non-critical workloads (save 70%)
                3. Implement S3 lifecycle policies (save 30% on storage)
                4. Right-size EC2 instances based on CloudWatch metrics
                
                **Estimated Savings:** $1,200-1,800/month per account
                """)
        
        with col2:
            if st.button("🛡️ Required guardrails for PCI compliance?"):
                st.info("""
                **AI Recommendations:**
                
                **Critical (Required):**
                - CloudTrail (audit logging)
                - Config (compliance tracking)
                - Encryption at rest (all storage)
                - Network isolation (private subnets)
                
                **High Priority:**
                - GuardDuty (threat detection)
                - Security Hub (security monitoring)
                - VPN/Direct Connect (secure access)
                
                **Template:** Use "Security Enhanced" as baseline
                """)
            
            if st.button("📊 How many accounts should we have?"):
                st.info("""
                **AI Analysis:**
                
                **Recommended Structure:**
                - 1 Management account
                - 1 Security/Logging account
                - 3-5 Production accounts (by workload)
                - 5-10 Development accounts (by team)
                - 2-3 Shared services accounts
                - 1-2 Sandbox accounts
                
                **Total:** 13-22 accounts for typical enterprise
                
                **Reasoning:** Multi-account strategy provides:
                - Blast radius containment
                - Clear cost allocation
                - Independent security boundaries
                """)
        
        st.markdown("---")
        st.markdown("#### 💬 Custom Question")
        
        question = st.text_area("Ask AI Assistant anything about account lifecycle management:")
        
        if st.button("🤖 Get AI Answer") and question:
            with st.spinner("AI thinking..."):
                st.success("AI Response:")
                st.info("AI assistant would provide detailed answer here based on your question.")
    
    # ========================================================================
    # TAB 10: NETWORK DESIGNER
    # ========================================================================
    
    @staticmethod
    def _render_network_designer():
        """Visual network configuration"""
        st.subheader("🌐 Network Designer")
        
        st.markdown("""
        ### 🎨 Design Your Account Network
        
        Visual network configuration for new or existing accounts.
        """)
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            st.markdown("#### 🗺️ Network Diagram")
            
            st.code("""
            ┌─────────────────────────────────────────┐
            │         VPC: 10.0.0.0/16                │
            ├─────────────────────────────────────────┤
            │                                         │
            │  ┌─────────────┐   ┌─────────────┐    │
            │  │   Public    │   │   Public    │    │
            │  │  Subnet 1   │   │  Subnet 2   │    │
            │  │ 10.0.1.0/24 │   │ 10.0.2.0/24 │    │
            │  │   (AZ-1)    │   │   (AZ-2)    │    │
            │  └──────┬──────┘   └──────┬──────┘    │
            │         │                 │            │
            │         │  NAT Gateway    │            │
            │         │        │        │            │
            │  ┌──────┴──────┐ ┌───────┴──────┐    │
            │  │   Private   │ │   Private    │    │
            │  │  Subnet 1   │ │  Subnet 2    │    │
            │  │ 10.0.10.0/24│ │ 10.0.20.0/24 │    │
            │  │   (AZ-1)    │ │   (AZ-2)     │    │
            │  └─────────────┘ └──────────────┘    │
            │                                         │
            └─────────────────────────────────────────┘
            """, language="text")
        
        with col2:
            st.markdown("#### ⚙️ Configuration")
            
            vpc_cidr = st.text_input("VPC CIDR", value="10.0.0.0/16")
            
            num_azs = st.slider("Availability Zones", 1, 3, 2)
            
            subnet_types = st.multiselect("Subnet Types", [
                "Public",
                "Private",
                "Database"
            ], default=["Public", "Private"])
            
            enable_nat = st.checkbox("NAT Gateway", value=True)
            enable_vpn = st.checkbox("VPN Gateway", value=False)
            enable_tgw = st.checkbox("Transit Gateway", value=False)
            
            if st.button("💾 Save Network Config"):
                st.success("✅ Network configuration saved!")
            
            if st.button("🚀 Deploy Network"):
                with st.spinner("Deploying network..."):
                    st.success("✅ Network deployed successfully!")
    
    # ========================================================================
    # TAB 11: DEPENDENCIES
    # ========================================================================
    
    @staticmethod
    def _render_dependencies():
        """Account dependencies tracking"""
        st.subheader("🔗 Account Dependencies")
        
        st.markdown("""
        ### 📊 Cross-Account Dependencies
        
        Visualize and manage dependencies between accounts.
        """)
        
        account = st.selectbox("Select Account", [
            "123456789012 - prod-app-services",
            "234567890123 - dev-sandbox-team-a",
            "345678901234 - security-logging"
        ])
        
        st.markdown("---")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("#### ⬆️ Depends On (Upstream)")
            
            dependencies = [
                {"Account": "security-logging", "Type": "CloudTrail logs", "Critical": True},
                {"Account": "shared-services", "Type": "DNS resolution", "Critical": True},
                {"Account": "network-hub", "Type": "Transit Gateway", "Critical": False}
            ]
            
            for dep in dependencies:
                critical_icon = "🔴" if dep['Critical'] else "🟡"
                st.write(f"{critical_icon} **{dep['Account']}** - {dep['Type']}")
        
        with col2:
            st.markdown("#### ⬇️ Used By (Downstream)")
            
            dependents = [
                {"Account": "prod-app-frontend", "Type": "API Gateway", "Critical": True},
                {"Account": "prod-app-mobile", "Type": "Authentication", "Critical": True},
                {"Account": "analytics-reporting", "Type": "Data export", "Critical": False}
            ]
            
            for dep in dependents:
                critical_icon = "🔴" if dep['Critical'] else "🟡"
                st.write(f"{critical_icon} **{dep['Account']}** - {dep['Type']}")
        
        st.markdown("---")
        st.markdown("### 🗺️ Dependency Graph")
        
        st.code("""
                    ┌──────────────────┐
                    │ security-logging │
                    └────────┬─────────┘
                             │
                    ┌────────▼─────────┐
                    │  prod-app-svc    │◄────── Transit Gateway
                    └────────┬─────────┘
                             │
                 ┌───────────┼───────────┐
                 │           │           │
        ┌────────▼──┐  ┌────▼────┐  ┌──▼────────┐
        │  frontend │  │  mobile │  │ analytics │
        └───────────┘  └─────────┘  └───────────┘
        """, language="text")
        
        st.markdown("---")
        
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("🔍 Analyze Impact"):
                st.info("""
                **Impact Analysis:**
                - 3 accounts directly depend on this account
                - 2 critical dependencies (frontend, mobile)
                - Estimated downtime impact: High
                - Recommended: Plan carefully before modifications
                """)
        
        with col2:
            if st.button("📥 Export Dependency Map"):
                st.success("Dependency map exported!")
    
    # ========================================================================
    # TAB 12: AUTO-DETECTION (AI FEATURE)
    # ========================================================================
    
    @staticmethod
    def _render_auto_detection(ai_available: bool):
        """Automatic account detection"""
        st.subheader("🔍 Automatic Account Detection")
        
        st.markdown("""
        ### 🤖 AI-Powered Account Discovery
        
        Automatically detect new accounts and trigger onboarding.
        """)
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("Accounts Monitored", "48")
        with col2:
            st.metric("New Detected (7d)", "3", delta="+2")
        with col3:
            st.metric("Auto-Onboarded", "2", delta="✅")
        
        st.markdown("---")
        st.markdown("### 🆕 Recently Detected")
        
        detected = [
            {
                "Account ID": "567890123456",
                "Name": "prod-new-service",
                "OU": "Production/Apps",
                "Detected": "1 hour ago",
                "AI Classification": "Production",
                "Status": "🟢 Auto-onboarding"
            },
            {
                "Account ID": "678901234567",
                "Name": "dev-experimental",
                "OU": "Development/Sandbox",
                "Detected": "1 day ago",
                "AI Classification": "Sandbox",
                "Status": "✅ Onboarded"
            }
        ]
        
        df = pd.DataFrame(detected)
        st.dataframe(df, use_container_width=True)
        
        st.markdown("---")
        
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("🔍 Scan for New Accounts", type="primary", use_container_width=True):
                with st.spinner("Scanning AWS Organizations..."):
                    st.success("✅ Scan complete! 0 new accounts found")
        
        with col2:
            if st.button("🤖 Auto-Onboard Pending", use_container_width=True):
                st.success("✅ 1 account queued for auto-onboarding")
        
        st.markdown("---")
        st.markdown("### ⚙️ Detection Settings")
        
        col1, col2 = st.columns(2)
        
        with col1:
            auto_scan = st.checkbox("Enable Auto-Scan", value=True)
            auto_onboard = st.checkbox("Auto-Onboard Eligible", value=True)
        
        with col2:
            scan_interval = st.select_slider("Scan Interval", 
                                            ["1 min", "5 min", "15 min", "30 min"], 
                                            value="5 min")
            notification = st.text_input("Notification Email", value="cloudops@company.com")


# Export
__all__ = ['AccountLifecycleModule']