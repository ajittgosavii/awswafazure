"""
AI-Based AWS Well-Architected Framework Advisor
AWS-focused architecture design and assessment platform
"""

import streamlit as st
import sys
from datetime import datetime

# Page configuration
st.set_page_config(
    page_title="AI-Based Well-Architected Framework",
    page_icon="🏗️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize session state
if 'initialized' not in st.session_state:
    st.session_state.initialized = True
    st.session_state.current_tab = "architecture_designer"

# Module import status tracking
MODULE_STATUS = {}
MODULE_ERRORS = {}

# ============================================================================
# IMPORT AWS MODULES
# ============================================================================

print("Loading AWS modules...")

# Core modules
try:
    from aws_connector import get_aws_session, test_aws_connection
    MODULE_STATUS['AWS Connector'] = True
except Exception as e:
    MODULE_STATUS['AWS Connector'] = False
    MODULE_ERRORS['AWS Connector'] = str(e)

try:
    from landscape_scanner import AWSLandscapeScanner
    MODULE_STATUS['Landscape Scanner'] = True
except Exception as e:
    MODULE_STATUS['Landscape Scanner'] = False
    MODULE_ERRORS['Landscape Scanner'] = str(e)

try:
    from waf_review_module import render_waf_review_tab
    MODULE_STATUS['WAF Review'] = True
except Exception as e:
    MODULE_STATUS['WAF Review'] = False
    MODULE_ERRORS['WAF Review'] = str(e)

try:
    from modules_architecture_designer_waf import ArchitectureDesignerModule
    MODULE_STATUS['Architecture Designer'] = True
except Exception as e:
    MODULE_STATUS['Architecture Designer'] = False
    MODULE_ERRORS['Architecture Designer'] = str(e)

try:
    from modules_design_planning import DesignPlanningModule
    MODULE_STATUS['Design Planning'] = True
except Exception as e:
    MODULE_STATUS['Design Planning'] = False
    MODULE_ERRORS['Design Planning'] = str(e)

# Optional advanced modules
try:
    from eks_modernization_module import EKSModernizationModule
    MODULE_STATUS['EKS Modernization'] = True
except Exception as e:
    MODULE_STATUS['EKS Modernization'] = False
    MODULE_ERRORS['EKS Modernization'] = str(e)


try:
try:
    from compliance_module import ComplianceModule
    MODULE_STATUS['Compliance'] = True
except Exception as e:
    MODULE_STATUS['Compliance'] = False
    MODULE_ERRORS['Compliance'] = str(e)

try:
try:
    from multi_account_scanner import MultiAccountScanner
    MODULE_STATUS['Multi-Account Scanner'] = True
except Exception as e:
    MODULE_STATUS['Multi-Account Scanner'] = False
    MODULE_ERRORS['Multi-Account Scanner'] = str(e)

# ============================================================================
# HEADER
# ============================================================================

def render_header():
    """Render application header"""
    
    st.markdown("""
        <div style="background: linear-gradient(135deg, #FF9900 0%, #232F3E 100%); 
                    padding: 2rem; border-radius: 10px; margin-bottom: 2rem; color: white;">
            <h1 style="margin: 0; font-size: 2.5rem;">
                🏗️ AI-Based Well-Architected Framework Advisor
            </h1>
            <p style="margin: 0.5rem 0 0 0; font-size: 1.1rem; opacity: 0.95;">
                Enterprise AWS Architecture Design, Assessment & Optimization Platform
            </p>
        </div>
    """, unsafe_allow_html=True)

# ============================================================================
# SIDEBAR
# ============================================================================

def render_sidebar():
    """Render sidebar with AWS connection status"""
    
    with st.sidebar:
        st.markdown("### 🔧 AWS Configuration")
        
        # AWS connection status
        try:
            session = get_aws_session()
            if session:
                st.success("✅ AWS Connected")
                
                # Show account info if available
                try:
                    import boto3
                    sts = session.client('sts')
                    identity = sts.get_caller_identity()
                    account_id = identity['Account']
                    st.info(f"Account: {account_id}")
                except:
                    pass
            else:
                st.warning("⚠️ AWS Not Connected")
                st.info("Configure AWS credentials in AWS Connector tab")
        except:
            st.warning("⚠️ AWS Not Connected")
        
        st.markdown("---")
        
        # Module status
        with st.expander("📦 Module Status"):
            for module, status in MODULE_STATUS.items():
                if status:
                    st.success(f"✅ {module}")
                else:
                    st.error(f"❌ {module}")
        
        st.markdown("---")
        
        # Quick links
        st.markdown("### 🔗 Quick Links")
        st.markdown("""
        - [AWS Well-Architected](https://aws.amazon.com/architecture/well-architected/)
        - [Architecture Center](https://aws.amazon.com/architecture/)
        - [Best Practices](https://aws.amazon.com/architecture/best-practices/)
        """)
        
        st.markdown("---")
        st.caption(f"Version 1.0.0 | {datetime.now().strftime('%Y-%m-%d')}")

# ============================================================================
# MAIN TABS
# ============================================================================

def render_aws_connector_tab():
    """AWS Connector configuration"""
    
    st.subheader("☁️ AWS Connector")
    
    st.info("""
    Configure your AWS credentials here. You can use:
    - AWS Access Keys
    - IAM Roles (if running on EC2)
    - AWS CLI profile
    - Environment variables
    """)
    
    # Configuration options
    col1, col2 = st.columns(2)
    
    with col1:
        aws_access_key = st.text_input("AWS Access Key ID", type="password")
        aws_region = st.selectbox(
            "Default Region",
            ["us-east-1", "us-east-2", "us-west-1", "us-west-2", 
             "eu-west-1", "eu-central-1", "ap-southeast-1", "ap-northeast-1"]
        )
    
    with col2:
        aws_secret_key = st.text_input("AWS Secret Access Key", type="password")
    
    if st.button("💾 Save Credentials", type="primary"):
        if aws_access_key and aws_secret_key:
            # Save to session state
            st.session_state.aws_access_key = aws_access_key
            st.session_state.aws_secret_key = aws_secret_key
            st.session_state.aws_region = aws_region
            st.success("✅ Credentials saved!")
            st.rerun()
        else:
            st.error("Please provide both Access Key and Secret Key")
    
    st.markdown("---")
    
    # Test connection
    if st.button("🔍 Test Connection"):
        with st.spinner("Testing AWS connection..."):
            try:
                session = get_aws_session()
                if session:
                    import boto3
                    sts = session.client('sts')
                    identity = sts.get_caller_identity()
                    
                    st.success("✅ Connection successful!")
                    st.json({
                        "Account": identity['Account'],
                        "UserId": identity['UserId'],
                        "Arn": identity['Arn']
                    })
                else:
                    st.error("❌ Connection failed")
            except Exception as e:
                st.error(f"❌ Error: {str(e)}")

def render_main_content():
    """Render main content area with tabs"""
    
    # Create tabs
    tabs = st.tabs([
        "🎨 Architecture Designer",
        "⚡ WAF Assessment",
        "🔍 AWS Scanner",
        "🚀 EKS Modernization",
        "📊 Resource Inventory",
        "☁️ AWS Connector"
    ])
    
    # Tab 1: Architecture Designer
    with tabs[0]:
        if MODULE_STATUS.get('Architecture Designer'):
            try:
                ArchitectureDesignerModule.render()
            except Exception as e:
                st.error(f"Error loading Architecture Designer: {str(e)}")
        else:
            st.error("Architecture Designer module not available")
            st.info("This module provides: NLP design, Terraform import, AWS scanning, visual builder")
    
    # Tab 2: WAF Assessment
    with tabs[1]:
        if MODULE_STATUS.get('WAF Review'):
            try:
                render_waf_review_tab()
            except Exception as e:
                st.error(f"Error loading WAF Review: {str(e)}")
        else:
            st.error("WAF Review module not available")
    
    # Tab 3: AWS Scanner
    with tabs[2]:
        if MODULE_STATUS.get('Landscape Scanner'):
            st.subheader("🔍 AWS Infrastructure Scanner")
            
            st.info("""
            Scan your AWS environment to discover:
            - EC2 instances and Auto Scaling groups
            - RDS databases and DynamoDB tables
            - S3 buckets and storage
            - VPCs, subnets, and networking
            - Lambda functions
            - ECS/EKS clusters
            - And more...
            """)
            
            col1, col2 = st.columns(2)
            with col1:
                region = st.selectbox(
                    "Region to Scan",
                    ["us-east-1", "us-east-2", "us-west-1", "us-west-2"]
                )
            
            with col2:
                if st.button("🔍 Start Scan", type="primary"):
                    with st.spinner("Scanning AWS environment..."):
                        try:
                            session = get_aws_session()
                            if session:
                                scanner = AWSLandscapeScanner(session, region)
                                assessment = scanner.scan_landscape()
                                
                                st.success(f"✅ Scan complete!")
                                st.json({
                                    "Region": region,
                                    "Resources Found": "Processing...",
                                    "Status": "Complete"
                                })
                            else:
                                st.error("Configure AWS credentials first")
                        except Exception as e:
                            st.error(f"Scan error: {str(e)}")
        else:
            st.error("Landscape Scanner module not available")
    
    # Tab 4: EKS Modernization
    with tabs[3]:
        if MODULE_STATUS.get('EKS Modernization'):
            try:
                EKSModernizationModule.render()
            except Exception as e:
                st.error(f"Error loading EKS Modernization: {str(e)}")
        else:
            st.warning("EKS Modernization module not available")
            st.info("Install eks_modernization_module.py to enable this feature")
    
    # Tab 5: FinOps
    with tabs[4]:
        if MODULE_STATUS.get('FinOps'):
            try:
            except Exception as e:
                st.error(f"Error loading FinOps: {str(e)}")
        else:
            st.warning("FinOps module not available")
            st.info("Install finops_module.py to enable this feature")
    
    # Tab 6: Security & Compliance
    with tabs[5]:
        if MODULE_STATUS.get('Security & Compliance'):
            try:
            except Exception as e:
                st.error(f"Error loading Security: {str(e)}")
        elif MODULE_STATUS.get('Compliance'):
            try:
                ComplianceModule.render()
            except Exception as e:
                st.error(f"Error loading Compliance: {str(e)}")
        else:
            st.warning("Security & Compliance modules not available")
    
    # Tab 7: Resource Inventory
    with tabs[6]:
        if MODULE_STATUS.get('Resource Inventory'):
            try:
            except Exception as e:
                st.error(f"Error loading Resource Inventory: {str(e)}")
        else:
            st.warning("Resource Inventory module not available")
    
    # Tab 8: AWS Connector
    with tabs[7]:
        render_aws_connector_tab()

# ============================================================================
# MAIN APPLICATION
# ============================================================================

def main():
    """Main application"""
    
    # Render header
    render_header()
    
    # Render sidebar
    render_sidebar()
    
    # Render main content
    render_main_content()

if __name__ == "__main__":
    main()
