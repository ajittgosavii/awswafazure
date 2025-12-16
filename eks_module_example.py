"""
Example: How to integrate Real AWS Pricing and AI into EKS Module
This shows the exact code changes needed
"""

import streamlit as st
from eks_integrations import (
    AWSPricingFetcher,
    AnthropicAIValidator,
    display_integration_status
)

# ============================================================================
# EXAMPLE 1: Replace Old Cost Calculator
# ============================================================================

# ❌ OLD CODE (Remove this):
"""
class EKSCostCalculator:
    def __init__(self):
        self.pricing_cache = {}
    
    def get_ec2_pricing(self, instance_type, region):
        # Hardcoded pricing...
        pricing_db = {
            'm5.xlarge': {'on_demand': 0.192, 'spot_avg': 0.058},
            't3.large': {'on_demand': 0.0832, 'spot_avg': 0.025},
            # ... more hardcoded prices
        }
        pricing = pricing_db.get(instance_type, {'on_demand': 0.10, 'spot_avg': 0.03})
        return pricing
"""

# ✅ NEW CODE (Use this):
class EKSCostCalculator:
    """Enhanced cost calculator with real AWS pricing"""
    
    def __init__(self):
        self.pricing = AWSPricingFetcher()
        self.connection_status = self.pricing.connection_status
    
    def calculate_cluster_cost(self, instance_type, node_count, region, use_spot=True):
        """Calculate comprehensive cluster costs"""
        return self.pricing.calculate_cluster_cost(
            instance_type=instance_type,
            node_count=node_count,
            region=region,
            use_spot=use_spot,
            spot_percentage=0.7
        )
    
    def get_ec2_pricing(self, instance_type, region):
        """Get EC2 pricing (backward compatible)"""
        result = self.pricing.get_ec2_pricing(instance_type, region)
        return {
            'on_demand': result['hourly_on_demand'],
            'spot_avg': result['hourly_spot_avg'],
            'monthly_on_demand': result['monthly_on_demand'],
            'monthly_spot_avg': result['monthly_spot_avg']
        }

# ============================================================================
# EXAMPLE 2: Replace AI Validator
# ============================================================================

# ❌ OLD CODE (Remove this):
"""
class AIRecommendationEngine:
    def __init__(self, api_key=None):
        self.api_key = api_key or st.secrets.get("ANTHROPIC_API_KEY", "")
        
        if not self.api_key:
            st.warning("⚠️ Please enter your Anthropic API key")
            self.api_key = st.text_input("API Key", type="password")
        
        if self.api_key:
            try:
                from anthropic import Anthropic
                self.client = Anthropic(api_key=self.api_key)
            except:
                st.error("Failed to initialize Anthropic client")
"""

# ✅ NEW CODE (Use this):
class AIRecommendationEngine:
    """AI-powered validation with automatic secret loading"""
    
    def __init__(self):
        self.validator = AnthropicAIValidator()
        self.available = "✅" in self.validator.api_key_status
        
        if not self.available:
            st.info(f"💡 {self.validator.api_key_status}")
            st.info("Configure ANTHROPIC_API_KEY in .streamlit/secrets.toml")
    
    def validate_configuration(self, config):
        """Validate EKS configuration using AI"""
        if not self.available:
            return {
                'status': 'unavailable',
                'message': 'Configure ANTHROPIC_API_KEY in secrets',
                'recommendations': []
            }
        
        return self.validator.validate_configuration(config)
    
    def generate_recommendations(self, cluster_data):
        """Generate recommendations from cluster analysis"""
        config = {
            'instance_type': cluster_data.get('instance_type'),
            'node_count': cluster_data.get('node_count'),
            'region': cluster_data.get('region'),
            'k8s_version': cluster_data.get('k8s_version', '1.28'),
            'use_spot': cluster_data.get('use_spot', False),
            'karpenter_enabled': cluster_data.get('karpenter_enabled', False)
        }
        
        return self.validate_configuration(config)

# ============================================================================
# EXAMPLE 3: Full Integration in Streamlit App
# ============================================================================

def render_eks_cost_calculator():
    """Complete EKS cost calculator with real pricing and AI"""
    
    st.header("💰 EKS Cost Calculator")
    
    # Show integration status
    with st.expander("🔌 Integration Status", expanded=False):
        display_integration_status()
    
    # Initialize
    calculator = EKSCostCalculator()
    ai_engine = AIRecommendationEngine()
    
    # Input form
    col1, col2 = st.columns(2)
    
    with col1:
        instance_type = st.selectbox(
            "Instance Type",
            ['t3.medium', 't3.large', 't3.xlarge', 
             'm5.large', 'm5.xlarge', 'm5.2xlarge',
             'c5.large', 'c5.xlarge', 'c5.2xlarge',
             'r5.large', 'r5.xlarge', 'r5.2xlarge']
        )
        
        node_count = st.slider("Number of Nodes", 1, 20, 3)
    
    with col2:
        region = st.selectbox(
            "Region",
            ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
             'eu-west-1', 'eu-central-1', 'ap-southeast-1']
        )
        
        use_spot = st.checkbox("Use Spot Instances (70%)", value=True)
    
    # Calculate costs
    if st.button("🔍 Calculate Costs", type="primary"):
        with st.spinner("Fetching real-time pricing from AWS..."):
            
            # Get comprehensive cost analysis
            result = calculator.calculate_cluster_cost(
                instance_type=instance_type,
                node_count=node_count,
                region=region,
                use_spot=use_spot
            )
            
            # Display status
            if result['is_real_data']:
                st.success(f"✅ Real pricing from: {result['pricing_source']}")
            else:
                st.warning(f"⚠️ Using: {result['pricing_source']}")
                st.info("💡 Configure AWS credentials in secrets for real pricing")
            
            # Key metrics
            col1, col2, col3 = st.columns(3)
            
            col1.metric(
                "💵 Monthly Cost",
                f"${result['breakdown']['total_monthly']:.2f}",
                help="Total monthly cost including EC2 and EKS control plane"
            )
            
            col2.metric(
                "💰 Savings",
                f"${result['comparison']['monthly_savings']:.2f}",
                delta=f"-{result['comparison']['savings_percent']:.1f}%",
                delta_color="inverse",
                help="Savings vs all On-Demand instances"
            )
            
            col3.metric(
                "📊 Data Source",
                "Real" if result['is_real_data'] else "Estimate",
                help="Real = AWS API, Estimate = Fallback"
            )
            
            # Detailed breakdown
            with st.expander("📋 Detailed Cost Breakdown"):
                breakdown = result['breakdown']
                
                st.markdown("### Monthly Costs")
                st.markdown(f"""
                - **EC2 Compute:** ${breakdown['ec2_compute']:.2f}
                - **EKS Control Plane:** ${breakdown['eks_control_plane']:.2f}
                - **Total:** ${breakdown['total_monthly']:.2f}
                """)
                
                st.markdown("### Cost Comparison")
                comp = result['comparison']
                st.markdown(f"""
                - **All On-Demand:** ${comp['all_on_demand_cost']:.2f}
                - **Current Configuration:** ${comp['current_config_cost']:.2f}
                - **Monthly Savings:** ${comp['monthly_savings']:.2f} ({comp['savings_percent']:.1f}%)
                """)
                
                st.markdown("### Configuration")
                st.json({
                    'instance_type': result['instance_type'],
                    'node_count': result['node_count'],
                    'region': result['region'],
                    'use_spot': result['use_spot'],
                    'spot_percentage': f"{result['spot_percentage']*100:.0f}%",
                    'last_updated': result['last_updated']
                })
    
    # AI Validation Section
    st.markdown("---")
    st.subheader("🤖 AI-Powered Configuration Validation")
    
    if ai_engine.available:
        st.success("✅ AI validation available")
        
        if st.button("Validate Configuration with AI", type="secondary"):
            
            # Prepare configuration
            config = {
                'instance_type': instance_type,
                'node_count': node_count,
                'region': region,
                'k8s_version': '1.28',
                'use_spot': use_spot,
                'karpenter_enabled': False
            }
            
            # Validate
            with st.spinner("Analyzing configuration with Claude AI..."):
                validation = ai_engine.validate_configuration(config)
                
                if validation['status'] == 'success':
                    st.success("✅ AI Analysis Complete")
                    
                    # Show full analysis
                    with st.expander("📄 Full Analysis", expanded=True):
                        st.markdown(validation['analysis'])
                    
                    # Show key recommendations
                    if validation['recommendations']:
                        st.markdown("### 🎯 Key Recommendations")
                        for i, rec in enumerate(validation['recommendations'], 1):
                            st.info(f"**{i}.** {rec}")
                
                elif validation['status'] == 'unavailable':
                    st.info(validation['message'])
                
                else:
                    st.error(f"❌ {validation['message']}")
    
    else:
        st.info("💡 Configure ANTHROPIC_API_KEY in secrets to enable AI validation")
        st.code("""
# Add to .streamlit/secrets.toml:
ANTHROPIC_API_KEY = "sk-ant-api03-..."
        """, language="toml")

# ============================================================================
# EXAMPLE 4: Simple Usage in Existing Code
# ============================================================================

def simple_integration_example():
    """Minimal example showing how to get started"""
    
    from eks_integrations import AWSPricingFetcher, AnthropicAIValidator
    
    # Get real pricing
    pricing = AWSPricingFetcher()
    cost_data = pricing.calculate_cluster_cost(
        instance_type='m5.xlarge',
        node_count=5,
        region='us-east-1',
        use_spot=True
    )
    
    st.metric("Monthly Cost", f"${cost_data['breakdown']['total_monthly']:.2f}")
    st.caption(f"Source: {cost_data['pricing_source']}")
    
    # Get AI validation
    ai = AnthropicAIValidator()
    if "✅" in ai.api_key_status:
        config = {'instance_type': 'm5.xlarge', 'node_count': 5}
        result = ai.validate_configuration(config)
        
        if result['status'] == 'success':
            st.write(result['analysis'])

# ============================================================================
# USAGE IN YOUR MAIN APP
# ============================================================================

if __name__ == "__main__":
    st.set_page_config(
        page_title="EKS Modernization Hub",
        page_icon="🚀",
        layout="wide"
    )
    
    # Render the calculator
    render_eks_cost_calculator()
    
    # Or use simple example
    # simple_integration_example()
