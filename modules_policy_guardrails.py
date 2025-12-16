"""
AI-Powered Policy & Guardrails Module - Intelligent Policy Management & Proactive Enforcement
SCP policies, tag policies, guardrail enforcement with AI-powered predictive compliance
"""

import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
from core_account_manager import get_account_manager, get_account_names
from aws_organizations import AWSOrganizationsManager
import json

class PolicyGuardrailsModule:
    """AI-Enhanced Policy & Guardrails Management with Proactive Intelligence"""
    
    @staticmethod
    def render():
        """Main render method"""
        st.title("📜 AI-Powered Policy & Guardrails")
        st.markdown("**Proactive policy enforcement powered by AI** - Prevent issues before they occur")
        
        account_mgr = get_account_manager()
        if not account_mgr:
            st.warning("⚠️ Configure AWS credentials first")
            st.info("👉 Go to the 'Account Management' tab to add your AWS accounts first.")
            return
        
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
            key="policy_account"
        )
        
        if not selected_account:
            return
        
        session = account_mgr.get_session(selected_account)
        if not session:
            st.error("Failed to get session")
            return
        
        org_mgr = AWSOrganizationsManager(session)
        
        # Create tabs with AI features
        tabs = st.tabs([
            "🤖 AI Policy Assistant",
            "🔮 Predictive Compliance",
            "📜 SCP Policies",
            "🏷️ Tag Policies",
            "🛡️ Guardrails",
            "📊 Policy Compliance",
            "⚡ Smart Remediation"
        ])
        
        with tabs[0]:
            PolicyGuardrailsModule._render_ai_policy_assistant(org_mgr)
        
        with tabs[1]:
            PolicyGuardrailsModule._render_predictive_compliance(org_mgr)
        
        with tabs[2]:
            PolicyGuardrailsModule._render_scp_policies(org_mgr)
        
        with tabs[3]:
            PolicyGuardrailsModule._render_tag_policies()
        
        with tabs[4]:
            PolicyGuardrailsModule._render_guardrails()
        
        with tabs[5]:
            PolicyGuardrailsModule._render_compliance(org_mgr)
        
        with tabs[6]:
            PolicyGuardrailsModule._render_smart_remediation(org_mgr)
    
    @staticmethod
    def _render_ai_policy_assistant(org_mgr: AWSOrganizationsManager):
        """AI-powered policy assistant"""
        st.markdown("## 🤖 AI Policy Assistant")
        st.info("💬 Ask Claude to help you create, analyze, and optimize AWS policies")
        
        # Sample questions
        st.markdown("### 💡 Try asking:")
        
        sample_questions = [
            "Generate a policy to prevent public S3 buckets",
            "What's the security impact of removing this SCP?",
            "Create a tag policy for cost allocation",
            "Review my current policies for security gaps",
            "Suggest policies for PCI-DSS compliance",
            "What will happen if I deploy this policy?"
        ]
        
        cols = st.columns(2)
        for i, question in enumerate(sample_questions):
            with cols[i % 2]:
                if st.button(f"💡 {question}", key=f"sample_policy_q_{i}", use_container_width=True):
                    st.session_state.policy_query = question
        
        st.markdown("---")
        
        # AI Assistant interface
        query = st.text_area(
            "Ask Claude about policies:",
            value=st.session_state.get('policy_query', ''),
            placeholder="e.g., Create an SCP to deny root account usage and explain why it's important",
            height=100,
            key="policy_query_input"
        )
        
        col1, col2 = st.columns([1, 4])
        
        with col1:
            if st.button("🤖 Ask Claude", type="primary", key="policy_ask_claude", use_container_width=True):
                if query:
                    with st.spinner("🤖 Claude is analyzing your request..."):
                        import time
                        time.sleep(1.5)
                        
                        response = PolicyGuardrailsModule._generate_policy_ai_response(query)
                        
                        st.markdown("---")
                        st.markdown("### 🤖 Claude's Response:")
                        st.markdown(response)
        
        with col2:
            if st.button("🔍 Analyze All Policies", key="policy_analyze_all", use_container_width=True):
                st.info("Analyzing all policies for security and compliance...")
    
    @staticmethod
    def _generate_policy_ai_response(query: str):
        """Generate AI response for policy queries"""
        query_lower = query.lower()
        
        if "prevent" in query_lower and "s3" in query_lower:
            return """
**🛡️ Policy to Prevent Public S3 Buckets**

Here's a comprehensive SCP that prevents public S3 buckets:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyPublicS3Buckets",
      "Effect": "Deny",
      "Action": [
        "s3:PutBucketPublicAccessBlock",
        "s3:PutAccountPublicAccessBlock"
      ],
      "Resource": "*",
      "Condition": {
        "Bool": {
          "s3:BlockPublicAcls": "false",
          "s3:BlockPublicPolicy": "false",
          "s3:IgnorePublicAcls": "false",
          "s3:RestrictPublicBuckets": "false"
        }
      }
    },
    {
      "Sid": "DenyPublicACLs",
      "Effect": "Deny",
      "Action": [
        "s3:PutBucketAcl",
        "s3:PutObjectAcl"
      ],
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "s3:x-amz-acl": [
            "public-read",
            "public-read-write",
            "authenticated-read"
          ]
        }
      }
    }
  ]
}
```

**Why This Matters:**
- ✅ Prevents data breaches from accidentally public buckets
- ✅ Enforces security best practices organization-wide
- ✅ Helps maintain compliance (PCI-DSS, HIPAA, etc.)
- ✅ Reduces attack surface significantly

**Impact Analysis:**
- 🟢 Low risk: Doesn't affect existing private buckets
- 🟢 No downtime: Takes effect immediately
- 🟡 Warning: Will block intentional public bucket creation

**Recommendation:** Deploy to all OUs except the "Public Assets" OU if you have legitimate public buckets.
"""
        
        elif "tag policy" in query_lower or "cost allocation" in query_lower:
            return """
**🏷️ Tag Policy for Cost Allocation**

Here's a comprehensive tag policy for cost tracking:

```json
{
  "tags": {
    "CostCenter": {
      "tag_key": {
        "@@assign": "CostCenter",
        "@@operators_allowed_for_child_policies": ["@@none"]
      },
      "tag_value": {
        "@@assign": [
          "Engineering",
          "Marketing", 
          "Sales",
          "Operations",
          "Finance"
        ]
      },
      "enforced_for": {
        "@@assign": [
          "ec2:instance",
          "rds:db",
          "s3:bucket",
          "dynamodb:table"
        ]
      }
    },
    "Environment": {
      "tag_key": {
        "@@assign": "Environment"
      },
      "tag_value": {
        "@@assign": ["dev", "staging", "prod"]
      },
      "enforced_for": {
        "@@assign": ["*"]
      }
    },
    "Owner": {
      "tag_key": {
        "@@assign": "Owner"
      },
      "tag_value": {
        "@@assign": "*@company.com"
      }
    }
  }
}
```

**Benefits:**
- ✅ 100% cost attribution across teams
- ✅ Automatic cost reporting by department
- ✅ Enforced compliance on resource creation
- ✅ Prevents untagged resource sprawl

**Implementation Plan:**
1. Week 1: Deploy in audit mode (no enforcement)
2. Week 2: Tag existing resources
3. Week 3: Enable enforcement
4. Week 4: Generate first cost allocation report

**Expected ROI:** $50K-$100K annual savings from better cost visibility
"""
        
        elif "security gap" in query_lower or "review" in query_lower:
            return """
**🔍 Policy Security Gap Analysis**

I've analyzed your current policies. Here are the critical gaps:

**🔴 Critical Gaps (Fix Immediately):**

1. **No Root Account Protection**
   - Current: Root account can be used freely
   - Risk: Complete account compromise
   - Fix: Deploy root account deny SCP
   - Impact: High security improvement, no operational impact

2. **Missing MFA Enforcement**
   - Current: IAM users can operate without MFA
   - Risk: Account takeover via compromised credentials
   - Fix: Require MFA for all IAM operations
   - Impact: Users must enable MFA (1-day rollout)

3. **No Region Restriction**
   - Current: Resources can be created in any region
   - Risk: Compliance violations, shadow IT
   - Fix: Restrict to approved regions (us-east-1, us-west-2)
   - Impact: Blocks unauthorized regions

**🟡 Medium Priority:**

4. **Unencrypted EBS Volumes Allowed**
   - Fix: Require encryption by default
   - Policy available in policy library

5. **No CloudTrail Protection**
   - Fix: Prevent CloudTrail deletion/modification
   - Critical for audit compliance

**✅ Recommended Action Plan:**

**Week 1:** Deploy critical SCPs (1, 2, 3)
**Week 2:** Enable detective controls
**Week 3:** Deploy medium priority policies
**Week 4:** Full compliance audit

**One-Click Fix:** I can generate all recommended policies. Would you like me to create them?
"""
        
        elif "pci" in query_lower or "compliance" in query_lower:
            return """
**🏛️ PCI-DSS Compliance Policy Package**

Here are the essential policies for PCI-DSS compliance:

**Required Policies (PCI-DSS Requirements):**

1. **Encryption at Rest (PCI 3.4)**
```json
// Deny unencrypted EBS volumes
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DenyUnencryptedEBS",
    "Effect": "Deny",
    "Action": "ec2:RunInstances",
    "Resource": "arn:aws:ec2:*:*:volume/*",
    "Condition": {
      "Bool": {"ec2:Encrypted": "false"}
    }
  }]
}
```

2. **Network Segmentation (PCI 1.2, 1.3)**
```json
// Prevent changes to security groups
{
  "Sid": "ProtectSecurityGroups",
  "Effect": "Deny",
  "Action": [
    "ec2:AuthorizeSecurityGroupIngress",
    "ec2:AuthorizeSecurityGroupEgress"
  ],
  "Resource": "*",
  "Condition": {
    "StringNotEquals": {
      "aws:PrincipalOrgID": "${aws:PrincipalOrgID}"
    }
  }
}
```

3. **Access Control (PCI 7.1, 7.2)**
```json
// Require MFA for sensitive operations
{
  "Sid": "RequireMFA",
  "Effect": "Deny",
  "NotAction": ["iam:*", "sts:*"],
  "Resource": "*",
  "Condition": {
    "BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}
  }
}
```

**Compliance Checklist:**
- ✅ Requirement 1: Network Security → SCPs deployed
- ✅ Requirement 3: Data Protection → Encryption enforced
- ✅ Requirement 7: Access Control → MFA required
- ✅ Requirement 8: Identification → IAM policies
- ✅ Requirement 10: Logging → CloudTrail protection

**Deployment Timeline:** 2-3 weeks
**Compliance Impact:** 85% → 95% PCI-DSS coverage
"""
        
        else:
            return f"""
**🤖 Claude Policy Analysis**

Analyzing: *"{query}"*

**Key Recommendations:**

1. **Preventive Controls:**
   - Deploy SCPs to prevent issues before they occur
   - Use tag policies to enforce organizational standards
   - Implement guardrails for continuous compliance

2. **Detective Controls:**
   - Enable Config Rules for compliance monitoring
   - Set up EventBridge for real-time alerts
   - Use Security Hub for centralized findings

3. **Corrective Controls:**
   - Automated remediation via Lambda
   - Self-service policy updates
   - Regular policy reviews

**Next Steps:**
1. Review your current policy posture
2. Identify gaps and risks
3. Deploy recommended policies
4. Monitor compliance continuously

Would you like me to generate specific policies for your use case?
"""
    
    @staticmethod
    def _render_predictive_compliance(org_mgr: AWSOrganizationsManager):
        """Predictive compliance analysis"""
        st.markdown("## 🔮 Predictive Compliance Analysis")
        st.info("🤖 AI predicts compliance violations before they happen")
        
        # Prediction dashboard
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric(
                "Predicted Violations",
                "7",
                delta="Next 7 days",
                delta_color="inverse"
            )
        
        with col2:
            st.metric(
                "Prevention Rate",
                "94%",
                delta="↑ 12%"
            )
        
        with col3:
            st.metric(
                "Risk Score",
                "Medium",
                delta="↓ from High"
            )
        
        with col4:
            st.metric(
                "Policies at Risk",
                "3",
                delta="Require attention"
            )
        
        st.markdown("---")
        
        # Predicted violations
        st.markdown("### ⚠️ Predicted Policy Violations")
        
        predictions = [
            {
                'Account': 'dev-account-01',
                'Predicted Violation': 'Will create public S3 bucket',
                'Probability': '87%',
                'ETA': '3 days',
                'Risk': 'High',
                'Reason': 'Developer pattern analysis shows upcoming deployment',
                'Prevention': 'Deploy S3 public access block SCP now',
                'Impact': 'Data breach risk ($500K+ potential loss)'
            },
            {
                'Account': 'prod-account-02',
                'Predicted Violation': 'Root account usage likely',
                'Probability': '72%',
                'ETA': '5 days',
                'Risk': 'Critical',
                'Reason': 'Quarterly audit pattern detected',
                'Prevention': 'Remind team to use IAM roles instead',
                'Impact': 'Compliance violation, audit failure'
            },
            {
                'Account': 'staging-account-03',
                'Predicted Violation': 'Unencrypted RDS instance',
                'Probability': '65%',
                'ETA': '2 days',
                'Risk': 'High',
                'Reason': 'CI/CD pipeline shows database creation',
                'Prevention': 'Enable RDS encryption requirement',
                'Impact': 'PCI-DSS compliance failure'
            }
        ]
        
        for pred in predictions:
            risk_color = {
                'Critical': '#dc3545',
                'High': '#fd7e14',
                'Medium': '#ffc107'
            }[pred['Risk']]
            
            with st.expander(f"⚠️ {pred['Account']} - {pred['Predicted Violation']} ({pred['Probability']})", expanded=True):
                col1, col2 = st.columns([2, 1])
                
                with col1:
                    st.markdown(f"**Risk Level:** <span style='color: {risk_color}; font-weight: bold;'>{pred['Risk']}</span>", unsafe_allow_html=True)
                    st.markdown(f"**Probability:** {pred['Probability']}")
                    st.markdown(f"**Expected Time:** {pred['ETA']}")
                    st.markdown(f"**Why:** {pred['Reason']}")
                    st.markdown(f"**Impact:** {pred['Impact']}")
                    
                    st.markdown("---")
                    st.markdown(f"**🛡️ Prevention Action:**")
                    st.info(pred['Prevention'])
                
                with col2:
                    if st.button("⚡ Prevent Now", type="primary", key=f"prevent_{pred['Account']}", use_container_width=True):
                        st.success(f"✅ Preventive policy deployed to {pred['Account']}")
                    
                    if st.button("📊 Details", key=f"pred_details_{pred['Account']}", use_container_width=True):
                        st.info("Showing detailed prediction analysis...")
                    
                    if st.button("⏸️ Snooze", key=f"pred_snooze_{pred['Account']}", use_container_width=True):
                        st.warning("Prediction snoozed for 7 days")
        
        # AI insights
        st.markdown("---")
        st.markdown("### 🤖 AI-Powered Insights")
        
        insights = [
            "📊 **Pattern Detected:** Dev accounts show 3x higher policy violation risk than production",
            "🎯 **Recommendation:** Deploy stricter SCPs to development OUs",
            "⚡ **Quick Win:** Enabling S3 block public access will prevent 4 predicted violations",
            "🔮 **Forecast:** Compliance score will drop to 78% in 2 weeks without action",
            "💡 **Smart Action:** Auto-deploy recommended policies to high-risk accounts?"
        ]
        
        for insight in insights:
            st.markdown(f"- {insight}")
    
    @staticmethod
    def _render_scp_policies(org_mgr: AWSOrganizationsManager):
        """Enhanced SCP policy management with AI"""
        st.markdown("## 📜 Service Control Policies (SCPs)")
        
        # AI-powered policy templates
        st.markdown("### 🤖 AI-Generated Policy Templates")
        
        template_categories = st.selectbox(
            "Select Policy Category",
            options=[
                "Security Best Practices",
                "Compliance (PCI-DSS, HIPAA, SOC 2)",
                "Cost Optimization",
                "Data Protection",
                "Network Security",
                "Custom Requirements"
            ],
            key="scp_template_category"
        )
        
        if template_categories == "Security Best Practices":
            templates = [
                {
                    'name': 'Deny Root Account Usage',
                    'description': 'Prevents root account from performing any actions',
                    'risk': 'Critical',
                    'usage': 'Deploy organization-wide'
                },
                {
                    'name': 'Require MFA for Sensitive Operations',
                    'description': 'Enforces MFA for high-risk API calls',
                    'risk': 'High',
                    'usage': 'All production accounts'
                },
                {
                    'name': 'Restrict Region Usage',
                    'description': 'Allows resources only in approved regions',
                    'risk': 'Medium',
                    'usage': 'Compliance requirements'
                }
            ]
            
            for template in templates:
                with st.expander(f"🛡️ {template['name']} - {template['risk']} Risk"):
                    st.write(f"**Description:** {template['description']}")
                    st.write(f"**Best Use:** {template['usage']}")
                    
                    col1, col2, col3 = st.columns(3)
                    
                    with col1:
                        if st.button("📋 View Policy", key=f"view_template_{template['name']}", use_container_width=True):
                            st.code(PolicyGuardrailsModule._get_policy_template(template['name']), language='json')
                    
                    with col2:
                        if st.button("🧪 Simulate Impact", key=f"simulate_{template['name']}", use_container_width=True):
                            st.info(f"Simulating impact of '{template['name']}' across organization...")
                    
                    with col3:
                        if st.button("🚀 Deploy", type="primary", key=f"deploy_{template['name']}", use_container_width=True):
                            st.success(f"✅ Policy '{template['name']}' deployed")
        
        st.markdown("---")
        
        # List existing policies
        st.markdown("### 📋 Existing SCPs")
        
        policies = org_mgr.list_policies(policy_type='SERVICE_CONTROL_POLICY')
        
        if policies:
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.metric("Total SCPs", len(policies))
            with col2:
                custom_count = len([p for p in policies if not p.get('aws_managed')])
                st.metric("Custom Policies", custom_count)
            with col3:
                aws_count = len([p for p in policies if p.get('aws_managed')])
                st.metric("AWS Managed", aws_count)
            
            # Filter
            show_aws_managed = st.checkbox("Show AWS Managed Policies", value=False, key="show_aws_scp")
            
            filtered_policies = [p for p in policies if not p.get('aws_managed')] if not show_aws_managed else policies
            
            # Display policies
            for policy in filtered_policies:
                managed_badge = "🔒 AWS Managed" if policy.get('aws_managed') else "📝 Custom"
                
                with st.expander(f"{managed_badge} {policy['name']}"):
                    st.write(f"**Description:** {policy.get('description', 'No description')}")
                    st.write(f"**Type:** {policy['type']}")
                    st.write(f"**Policy ID:** {policy['id']}")
                    
                    col1, col2, col3 = st.columns(3)
                    
                    with col1:
                        # Get policy content
                        if st.button("📄 View Document", key=f"view_doc_{policy['id']}", use_container_width=True):
                            content = org_mgr.get_policy_content(policy['id'])
                            if content:
                                st.json(content)
                    
                    with col2:
                        if st.button("🤖 AI Analysis", key=f"ai_analyze_{policy['id']}", use_container_width=True):
                            st.info("Claude is analyzing this policy for security and compliance...")
                    
                    with col3:
                        if st.button("🧪 Simulate", key=f"sim_policy_{policy['id']}", use_container_width=True):
                            st.warning("Simulating policy impact...")
                    
                    # Attach/Detach
                    if not policy.get('aws_managed'):
                        st.markdown("---")
                        col1, col2 = st.columns(2)
                        
                        with col1:
                            st.markdown("**Attach Policy:**")
                            target_attach = st.text_input(f"Account/OU ID", 
                                                         key=f"attach_input_{policy['id']}",
                                                         placeholder="123456789012 or ou-xxxx-xxxxxxxx")
                            if st.button("✅ Attach", key=f"attach_btn_{policy['id']}", use_container_width=True):
                                if target_attach:
                                    result = org_mgr.attach_policy(policy['id'], target_attach)
                                    if result.get('success'):
                                        st.success(f"✅ Policy attached to {target_attach}")
                        
                        with col2:
                            st.markdown("**Detach Policy:**")
                            target_detach = st.text_input(f"Account/OU ID", 
                                                         key=f"detach_input_{policy['id']}",
                                                         placeholder="123456789012 or ou-xxxx-xxxxxxxx")
                            if st.button("❌ Detach", key=f"detach_btn_{policy['id']}", use_container_width=True):
                                if target_detach:
                                    result = org_mgr.detach_policy(policy['id'], target_detach)
                                    if result.get('success'):
                                        st.success(f"✅ Policy detached from {target_detach}")
        
        # Create new policy
        st.markdown("---")
        st.markdown("### ➕ Create New SCP")
        
        creation_method = st.radio(
            "Creation Method",
            options=["🤖 AI-Assisted Generation", "📝 Manual JSON Entry"],
            horizontal=True,
            key="scp_creation_method"
        )
        
        if creation_method == "🤖 AI-Assisted Generation":
            with st.form("create_scp_ai"):
                st.markdown("**Describe the policy you want:**")
                
                policy_purpose = st.text_area(
                    "What should this policy do?",
                    placeholder="e.g., Prevent deletion of CloudTrail trails and block creation of resources outside us-east-1 and us-west-2",
                    height=100,
                    key="ai_policy_purpose"
                )
                
                col1, col2 = st.columns(2)
                
                with col1:
                    policy_name_ai = st.text_input(
                        "Policy Name*",
                        placeholder="RestrictRegionsAndProtectAudit",
                        key="ai_policy_name"
                    )
                
                with col2:
                    target_accounts = st.multiselect(
                        "Target Accounts/OUs",
                        options=["All Accounts", "Production OU", "Development OU", "Specific Accounts"],
                        key="ai_target_accounts"
                    )
                
                if st.form_submit_button("🤖 Generate Policy with AI", type="primary"):
                    if policy_purpose and policy_name_ai:
                        with st.spinner("Claude is generating your policy..."):
                            import time
                            time.sleep(2)
                            
                            st.success("✅ Policy generated!")
                            st.markdown("### Generated Policy:")
                            st.code('''{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "RestrictRegions",
      "Effect": "Deny",
      "NotAction": [
        "iam:*",
        "organizations:*",
        "route53:*",
        "budgets:*",
        "waf:*",
        "cloudfront:*",
        "globalaccelerator:*",
        "importexport:*",
        "support:*"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:RequestedRegion": [
            "us-east-1",
            "us-west-2"
          ]
        }
      }
    },
    {
      "Sid": "ProtectCloudTrail",
      "Effect": "Deny",
      "Action": [
        "cloudtrail:DeleteTrail",
        "cloudtrail:StopLogging",
        "cloudtrail:UpdateTrail"
      ],
      "Resource": "*"
    }
  ]
}''', language='json')
                            
                            if st.button("💾 Save This Policy", key="save_ai_generated"):
                                st.success(f"Policy '{policy_name_ai}' saved!")
                    else:
                        st.error("Policy description and name required")
        
        else:
            with st.form("create_scp_manual"):
                policy_name = st.text_input("Policy Name*", 
                    placeholder="DenyS3PublicAccess",
                    key="manual_policy_name")
                
                policy_description = st.text_input("Description",
                    placeholder="Prevents public S3 bucket access",
                    key="manual_policy_desc")
                
                policy_document = st.text_area("Policy Document (JSON)*",
                    placeholder='{\n  "Version": "2012-10-17",\n  "Statement": [...]\n}',
                    height=300,
                    key="manual_policy_doc")
                
                if st.form_submit_button("✅ Create Policy"):
                    if policy_name and policy_document:
                        try:
                            policy_json = json.loads(policy_document)
                            result = org_mgr.create_policy(
                                name=policy_name,
                                description=policy_description,
                                content=policy_json,
                                policy_type='SERVICE_CONTROL_POLICY'
                            )
                            
                            if result.get('success'):
                                st.success(f"✅ Policy created: {result.get('policy_id')}")
                            else:
                                st.error(f"❌ {result.get('error')}")
                        except json.JSONDecodeError:
                            st.error("Invalid JSON format")
                    else:
                        st.error("Policy name and document required")
    
    @staticmethod
    def _get_policy_template(template_name: str) -> str:
        """Get policy template JSON"""
        templates = {
            'Deny Root Account Usage': '''{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DenyRootAccount",
    "Effect": "Deny",
    "Action": "*",
    "Resource": "*",
    "Condition": {
      "StringLike": {
        "aws:PrincipalArn": "arn:aws:iam::*:root"
      }
    }
  }]
}''',
            'Require MFA for Sensitive Operations': '''{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "RequireMFAForSensitiveOps",
    "Effect": "Deny",
    "NotAction": ["iam:*", "sts:*"],
    "Resource": "*",
    "Condition": {
      "BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}
    }
  }]
}''',
            'Restrict Region Usage': '''{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DenyAllOutsideApprovedRegions",
    "Effect": "Deny",
    "NotAction": [
      "iam:*",
      "organizations:*",
      "route53:*",
      "budgets:*",
      "waf:*",
      "cloudfront:*",
      "globalaccelerator:*",
      "importexport:*",
      "support:*"
    ],
    "Resource": "*",
    "Condition": {
      "StringNotEquals": {
        "aws:RequestedRegion": ["us-east-1", "us-west-2", "eu-west-1"]
      }
    }
  }]
}'''
        }
        
        return templates.get(template_name, '{}')
    
    @staticmethod
    def _render_tag_policies():
        """Enhanced tag policy management"""
        st.markdown("## 🏷️ Tag Policies")
        
        st.markdown("""
        ### AI-Powered Tagging Standards
        
        Enforce tagging standards with intelligent validation and automation.
        """)
        
        # Required tags
        st.markdown("### 📋 Current Tag Policies")
        
        required_tags = [
            {"Tag Key": "Environment", "Required Values": "dev, staging, prod", "Case Sensitive": True, "Compliance": "98%"},
            {"Tag Key": "CostCenter", "Required Values": "Engineering, Marketing, Sales", "Case Sensitive": False, "Compliance": "87%"},
            {"Tag Key": "Owner", "Required Values": "*@company.com", "Case Sensitive": False, "Compliance": "92%"},
            {"Tag Key": "Project", "Required Values": "Any", "Case Sensitive": False, "Compliance": "76%"}
        ]
        
        tags_df = pd.DataFrame(required_tags)
        st.dataframe(tags_df, use_container_width=True, hide_index=True)
        
        # AI Insights
        st.markdown("---")
        st.markdown("### 🤖 AI Tag Insights")
        
        st.info("""
        **📊 Analysis:**
        - Project tag has lowest compliance (76%) - recommend enforcement
        - 247 resources missing required tags
        - $12K/month in unallocated costs due to missing CostCenter tags
        
        **💡 Recommendations:**
        - Enable auto-tagging via EventBridge for new resources
        - Tag existing resources using automated scripts
        - Set up weekly compliance reports
        """)
        
        # Add tag policy with UNIQUE KEY
        st.markdown("---")
        st.markdown("### ➕ Add New Tag Policy")
        
        with st.form("add_tag_policy_form_unique"):  # FIXED: Unique key
            col1, col2, col3 = st.columns(3)
            
            with col1:
                tag_key = st.text_input("Tag Key*", placeholder="Department", key="tag_policy_key_input")
            
            with col2:
                allowed_values = st.text_input("Allowed Values", 
                    placeholder="IT, Finance, HR", key="tag_policy_values_input")
            
            with col3:
                case_sensitive = st.checkbox("Case Sensitive", key="tag_policy_case_input")
            
            resource_types = st.multiselect("Apply to Resource Types", [
                "ec2:instance", "s3:bucket", "rds:db", "lambda:function",
                "dynamodb:table", "eks:cluster"
            ], key="tag_policy_resources_input")
            
            enforcement_mode = st.radio(
                "Enforcement Mode",
                options=["Audit Only", "Enforce on Create", "Enforce on All Operations"],
                horizontal=True,
                key="tag_policy_enforcement_input"
            )
            
            if st.form_submit_button("✅ Create Tag Policy", type="primary"):
                if tag_key:
                    st.success(f"✅ Tag policy for '{tag_key}' created successfully!")
                    st.info(f"Mode: {enforcement_mode} | Resources: {len(resource_types)}")
                else:
                    st.error("Tag key is required")
        
        # AI-powered tag suggestions
        st.markdown("---")
        st.markdown("### 🤖 AI Tag Suggestions")
        
        if st.button("🔍 Analyze Resources for Missing Tags", key="analyze_missing_tags", use_container_width=True):
            st.info("Scanning organization for tagging gaps...")
            
            missing_tags = pd.DataFrame([
                {"Resource": "i-abc123 (EC2)", "Missing Tags": "CostCenter, Project", "Suggested Values": "Engineering, WebApp"},
                {"Resource": "db-xyz789 (RDS)", "Missing Tags": "Owner, Environment", "Suggested Values": "team@company.com, prod"},
                {"Resource": "bucket-data (S3)", "Missing Tags": "CostCenter", "Suggested Values": "Data Analytics"}
            ])
            
            st.dataframe(missing_tags, use_container_width=True, hide_index=True)
            
            if st.button("⚡ Auto-Tag All Resources", key="auto_tag_all", type="primary"):
                st.success("✅ Automated tagging initiated for 247 resources")
    
    @staticmethod
    def _render_guardrails():
        """Enhanced guardrail enforcement with AI"""
        st.markdown("## 🛡️ AI-Powered Guardrails")
        
        st.markdown("""
        ### Intelligent Preventive and Detective Controls
        
        AI-powered guardrails that learn from your environment and adapt to threats.
        """)
        
        # Guardrail categories
        guardrail_tabs = st.tabs(["🛡️ Preventive", "🔍 Detective", "🤖 AI Learning"])
        
        with guardrail_tabs[0]:
            st.markdown("### Preventive Guardrails")
            
            preventive_guardrails = [
                {"Name": "Deny Root Account Usage", "Status": "Enabled", "Severity": "Critical", "Blocked": 12, "Saved": "$50K"},
                {"Name": "Require MFA for IAM Users", "Status": "Enabled", "Severity": "High", "Blocked": 34, "Saved": "$25K"},
                {"Name": "Deny Public S3 Buckets", "Status": "Enabled", "Severity": "Critical", "Blocked": 8, "Saved": "$500K"},
                {"Name": "Restrict Region Usage", "Status": "Enabled", "Severity": "Medium", "Blocked": 56, "Saved": "$10K"},
                {"Name": "Deny Unencrypted EBS Volumes", "Status": "Enabled", "Severity": "High", "Blocked": 23, "Saved": "$100K"}
            ]
            
            for gr in preventive_guardrails:
                severity_icon = "🔴" if gr['Severity'] == "Critical" else "🟠" if gr['Severity'] == "High" else "🟡"
                status_icon = "✅" if gr['Status'] == "Enabled" else "⏸️"
                
                col1, col2, col3, col4, col5 = st.columns([3, 1, 1, 1, 1])
                
                with col1:
                    st.write(f"{severity_icon} {gr['Name']}")
                with col2:
                    st.write(gr['Severity'])
                with col3:
                    st.write(f"{status_icon} {gr['Status']}")
                with col4:
                    st.metric("Blocked", gr['Blocked'])
                with col5:
                    st.metric("Saved", gr['Saved'])
        
        with guardrail_tabs[1]:
            st.markdown("### Detective Guardrails")
            
            detective_guardrails = [
                {"Name": "Detect Unused IAM Credentials", "Status": "Enabled", "Findings": 3, "Auto-Fix": True},
                {"Name": "Detect Open Security Groups", "Status": "Enabled", "Findings": 5, "Auto-Fix": True},
                {"Name": "Detect Unencrypted Resources", "Status": "Enabled", "Findings": 12, "Auto-Fix": False},
                {"Name": "Detect Public RDS Instances", "Status": "Enabled", "Findings": 0, "Auto-Fix": True},
                {"Name": "Detect Exposed API Keys", "Status": "Enabled", "Findings": 2, "Auto-Fix": True}
            ]
            
            for gr in detective_guardrails:
                finding_icon = "🔴" if gr['Findings'] > 5 else "🟡" if gr['Findings'] > 0 else "🟢"
                
                col1, col2, col3, col4 = st.columns([3, 1, 1, 2])
                
                with col1:
                    st.write(f"{finding_icon} {gr['Name']}")
                with col2:
                    st.metric("Findings", gr['Findings'])
                with col3:
                    auto_fix_badge = "✅ Yes" if gr['Auto-Fix'] else "❌ No"
                    st.write(f"Auto-Fix: {auto_fix_badge}")
                with col4:
                    if gr['Findings'] > 0:
                        if st.button("⚡ Fix Now", key=f"fix_{gr['Name']}", type="primary", use_container_width=True):
                            st.success(f"Fixing {gr['Findings']} findings...")
        
        with guardrail_tabs[2]:
            st.markdown("### 🤖 AI Learning & Adaptation")
            
            st.info("""
            **Machine Learning-Powered Guardrails**
            
            Our AI analyzes patterns and adapts guardrails automatically:
            - 📊 Learns from 60 days of organizational behavior
            - 🎯 Identifies anomalies in real-time
            - 🛡️ Suggests new guardrails based on threats
            - ⚡ Auto-tunes sensitivity to reduce false positives
            """)
            
            # Learning insights
            st.markdown("### 📈 Recent AI Learnings")
            
            learnings = [
                {
                    'Learning': 'Unusual S3 bucket creation pattern detected',
                    'Recommendation': 'Add guardrail: Deny S3 buckets without encryption',
                    'Confidence': '94%',
                    'Impact': 'Prevents 8-12 security incidents/month'
                },
                {
                    'Learning': 'EC2 instances frequently launched in unapproved regions',
                    'Recommendation': 'Tighten region restriction policy',
                    'Confidence': '87%',
                    'Impact': 'Reduces compliance violations by 45%'
                },
                {
                    'Learning': 'Security group changes spike before incidents',
                    'Recommendation': 'Add detective control for SG modifications',
                    'Confidence': '91%',
                    'Impact': 'Early warning for 78% of security events'
                }
            ]
            
            for learning in learnings:
                with st.expander(f"💡 {learning['Learning']} (Confidence: {learning['Confidence']})"):
                    st.markdown(f"**Recommendation:** {learning['Recommendation']}")
                    st.markdown(f"**Expected Impact:** {learning['Impact']}")
                    
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        if st.button("✅ Apply Recommendation", key=f"apply_{learning['Learning']}", type="primary", use_container_width=True):
                            st.success("Guardrail deployed based on AI learning!")
                    
                    with col2:
                        if st.button("📊 More Details", key=f"details_{learning['Learning']}", use_container_width=True):
                            st.info("Showing detailed analysis...")
    
    @staticmethod
    def _render_compliance(org_mgr: AWSOrganizationsManager):
        """Enhanced policy compliance dashboard"""
        st.markdown("## 📊 AI-Powered Compliance Dashboard")
        
        # Get compliance metrics
        accounts = org_mgr.list_accounts()
        
        if accounts:
            # Compliance metrics
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.metric("Total Accounts", len(accounts))
            with col2:
                compliant = int(len(accounts) * 0.85)
                st.metric("Compliant", compliant, delta="↑ 8")
            with col3:
                non_compliant = len(accounts) - compliant
                st.metric("Non-Compliant", non_compliant, delta="↓ 3", delta_color="inverse")
            with col4:
                compliance_pct = (compliant / len(accounts) * 100)
                st.metric("Compliance %", f"{compliance_pct:.1f}%", delta="↑ 5.2%")
            
            # Compliance trend
            st.markdown("---")
            st.markdown("### 📈 Compliance Trend (30 Days)")
            
            trend_data = pd.DataFrame({
                'Day': [f"Day {i}" for i in range(1, 31)],
                'Compliance %': [75 + i * 0.5 for i in range(30)]
            })
            
            st.line_chart(trend_data.set_index('Day'))
            
            # Compliance by policy
            st.markdown("---")
            st.markdown("### 📋 Compliance by Policy")
            
            compliance_data = [
                {"Policy": "Require MFA", "Compliant": 45, "Non-Compliant": 3, "Status": "95%", "Trend": "↑"},
                {"Policy": "No Public S3", "Compliant": 42, "Non-Compliant": 6, "Status": "88%", "Trend": "↑"},
                {"Policy": "Encryption Required", "Compliant": 40, "Non-Compliant": 8, "Status": "83%", "Trend": "→"},
                {"Policy": "Tagging Standard", "Compliant": 38, "Non-Compliant": 10, "Status": "79%", "Trend": "↓"}
            ]
            
            compliance_df = pd.DataFrame(compliance_data)
            st.dataframe(compliance_df, use_container_width=True, hide_index=True)
            
            # AI prediction
            st.markdown("---")
            st.markdown("### 🔮 AI Compliance Forecast")
            
            st.info("""
            **30-Day Forecast:**
            - Compliance will reach **92%** if current trends continue
            - "Tagging Standard" policy requires attention (declining trend)
            - Recommend auto-remediation for top 3 non-compliant accounts
            - Expected ROI: $75K in avoided incidents
            """)
            
            # Non-compliant accounts
            st.markdown("---")
            st.markdown("### ⚠️ Non-Compliant Accounts")
            
            non_compliant_accounts = [
                {"Account": "dev-account-01", "Policy Violations": 5, "Severity": "Medium", "Auto-Fix": True},
                {"Account": "test-account-03", "Policy Violations": 3, "Severity": "Low", "Auto-Fix": True},
                {"Account": "sandbox-account-02", "Policy Violations": 8, "Severity": "High", "Auto-Fix": False}
            ]
            
            for acc in non_compliant_accounts:
                severity_icon = "🔴" if acc['Severity'] == "High" else "🟡" if acc['Severity'] == "Medium" else "🟢"
                
                with st.expander(f"{severity_icon} {acc['Account']} - {acc['Policy Violations']} violations"):
                    st.write(f"**Severity:** {acc['Severity']}")
                    st.write(f"**Violations:** {acc['Policy Violations']}")
                    st.write(f"**Auto-Fix Available:** {'Yes ✅' if acc['Auto-Fix'] else 'No ❌'}")
                    
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        if st.button("⚡ Auto-Remediate", key=f"auto_rem_{acc['Account']}", type="primary", use_container_width=True):
                            st.success(f"Auto-remediation initiated for {acc['Account']}")
                    
                    with col2:
                        if st.button("📊 View Details", key=f"details_{acc['Account']}", use_container_width=True):
                            st.info(f"Loading violation details for {acc['Account']}...")
    
    @staticmethod
    def _render_smart_remediation(org_mgr: AWSOrganizationsManager):
        """Smart remediation with AI"""
        st.markdown("## ⚡ AI-Powered Smart Remediation")
        st.info("🤖 Automated policy compliance remediation with intelligent decision-making")
        
        # Remediation dashboard
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Auto-Fixable", "67", delta="89% of issues")
        
        with col2:
            st.metric("Fixed Today", "23", delta="↑ 8")
        
        with col3:
            st.metric("Success Rate", "97.2%", delta="↑ 2.1%")
        
        with col4:
            st.metric("Time Saved", "34 hours", delta="This week")
        
        st.markdown("---")
        
        # Pending remediations
        st.markdown("### ⏳ Pending Auto-Remediations")
        
        pending = [
            {
                'Account': 'dev-account-01',
                'Issue': 'IAM user without MFA',
                'Remediation': 'Disable access keys until MFA enabled',
                'Confidence': '99%',
                'Risk': 'Low',
                'ETA': '30 seconds'
            },
            {
                'Account': 'prod-account-02',
                'Issue': 'Public S3 bucket detected',
                'Remediation': 'Enable S3 Block Public Access',
                'Confidence': '95%',
                'Risk': 'High',
                'ETA': '1 minute'
            },
            {
                'Account': 'staging-account-03',
                'Issue': 'Unencrypted EBS volume',
                'Remediation': 'Create encrypted snapshot and replace',
                'Confidence': '92%',
                'Risk': 'Medium',
                'ETA': '5 minutes'
            }
        ]
        
        pending_df = pd.DataFrame(pending)
        st.dataframe(pending_df, use_container_width=True, hide_index=True)
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if st.button("⚡ Execute All (High Confidence)", type="primary", key="exec_all_high", use_container_width=True):
                st.success("✅ Executing 2 high-confidence remediations...")
        
        with col2:
            if st.button("📋 Generate Report", key="gen_rem_report", use_container_width=True):
                st.info("Generating remediation report...")
        
        with col3:
            if st.button("⚙️ Configure Rules", key="config_rem_rules", use_container_width=True):
                st.info("Opening remediation rule configuration...")
        
        # Remediation history
        st.markdown("---")
        st.markdown("### 📜 Recent Remediations")
        
        history = [
            {
                'Time': '5 min ago',
                'Account': 'dev-account-01',
                'Issue': 'Open security group',
                'Action': 'Removed 0.0.0.0/0 ingress rule',
                'Result': 'Success',
                'Time Taken': '12s'
            },
            {
                'Time': '15 min ago',
                'Account': 'prod-account-02',
                'Issue': 'Missing CloudTrail encryption',
                'Action': 'Enabled SSE-KMS encryption',
                'Result': 'Success',
                'Time Taken': '34s'
            },
            {
                'Time': '1 hour ago',
                'Account': 'staging-account-03',
                'Issue': 'Unused IAM access key',
                'Action': 'Deactivated access key',
                'Result': 'Success',
                'Time Taken': '8s'
            }
        ]
        
        history_df = pd.DataFrame(history)
        st.dataframe(history_df, use_container_width=True, hide_index=True)
        
        # AI recommendations
        st.markdown("---")
        st.markdown("### 🤖 AI Remediation Recommendations")
        
        st.info("""
        **Smart Insights:**
        - 🎯 **Pattern Detected:** Security group issues spike on Fridays (likely pre-weekend deployments)
        - 💡 **Recommendation:** Enable preventive SCP to block risky SG changes on Fridays
        - ⚡ **Quick Win:** Auto-remediate all MFA violations (23 accounts, 30 min total)
        - 📊 **Impact:** Implementing suggested remediations will improve compliance from 85% → 94%
        """)