"""
EKS Modernization Module - PRODUCTION READY
Integrated with:
- Real AWS Pricing API
- Anthropic API from Streamlit Secrets
- Cost optimization features
"""

import streamlit as st
import boto3
import json
from datetime import datetime, timedelta
from typing import Dict, Optional

# ============================================================================
# REAL AWS PRICING INTEGRATION
# ============================================================================

class AWSPricingFetcher:
    """Fetch real-time AWS pricing data from AWS Price List API"""
    
    def __init__(self):
        """Initialize pricing client using secrets"""
        self.cache = {}
        self.cache_duration = timedelta(hours=24)
        self.pricing_client = None
        self.connection_status = self._initialize_client()
    
    def _initialize_client(self) -> str:
        """Initialize AWS Pricing client from secrets"""
        try:
            # Get AWS credentials from secrets
            if "aws" not in st.secrets:
                return "❌ AWS credentials not configured in secrets"
            
            aws_config = st.secrets["aws"]
            
            # Validate required keys
            required_keys = ["access_key_id", "secret_access_key"]
            missing_keys = [k for k in required_keys if k not in aws_config]
            
            if missing_keys:
                return f"❌ Missing AWS keys in secrets: {', '.join(missing_keys)}"
            
            # Create session
            session = boto3.Session(
                aws_access_key_id=aws_config["access_key_id"],
                aws_secret_access_key=aws_config["secret_access_key"],
                region_name='us-east-1'  # Pricing API only available in us-east-1
            )
            
            # Test connection
            self.pricing_client = session.client('pricing', region_name='us-east-1')
            
            # Quick test
            self.pricing_client.describe_services(
                ServiceCode='AmazonEC2',
                MaxResults=1
            )
            
            return "✅ Connected to AWS Pricing API"
            
        except Exception as e:
            return f"⚠️ AWS Pricing API connection failed: {str(e)}"
    
    def get_ec2_pricing(self, instance_type: str, region: str = 'us-east-1', 
                        operating_system: str = 'Linux') -> Dict:
        """
        Get EC2 instance pricing from AWS Price List API
        
        Args:
            instance_type: EC2 instance type (e.g., 'm5.xlarge')
            region: AWS region
            operating_system: OS type ('Linux', 'Windows', 'RHEL')
        
        Returns:
            Dict with comprehensive pricing information
        """
        cache_key = f"ec2_{instance_type}_{region}_{operating_system}"
        
        # Check cache
        if cache_key in self.cache:
            cached_data, cached_time = self.cache[cache_key]
            if datetime.now() - cached_time < self.cache_duration:
                return cached_data
        
        # If no pricing client, use fallback
        if not self.pricing_client:
            return self._get_fallback_pricing(instance_type)
        
        try:
            # Map region codes to AWS location names
            region_map = {
                'us-east-1': 'US East (N. Virginia)',
                'us-east-2': 'US East (Ohio)',
                'us-west-1': 'US West (N. California)',
                'us-west-2': 'US West (Oregon)',
                'eu-west-1': 'EU (Ireland)',
                'eu-west-2': 'EU (London)',
                'eu-central-1': 'EU (Frankfurt)',
                'ap-southeast-1': 'Asia Pacific (Singapore)',
                'ap-southeast-2': 'Asia Pacific (Sydney)',
                'ap-northeast-1': 'Asia Pacific (Tokyo)',
                'ap-south-1': 'Asia Pacific (Mumbai)',
                'ca-central-1': 'Canada (Central)',
            }
            
            location = region_map.get(region, region)
            
            # Query AWS Pricing API
            response = self.pricing_client.get_products(
                ServiceCode='AmazonEC2',
                Filters=[
                    {'Type': 'TERM_MATCH', 'Field': 'instanceType', 'Value': instance_type},
                    {'Type': 'TERM_MATCH', 'Field': 'location', 'Value': location},
                    {'Type': 'TERM_MATCH', 'Field': 'operatingSystem', 'Value': operating_system},
                    {'Type': 'TERM_MATCH', 'Field': 'tenancy', 'Value': 'Shared'},
                    {'Type': 'TERM_MATCH', 'Field': 'preInstalledSw', 'Value': 'NA'},
                    {'Type': 'TERM_MATCH', 'Field': 'capacitystatus', 'Value': 'Used'},
                ],
                MaxResults=1
            )
            
            if not response.get('PriceList'):
                return self._get_fallback_pricing(instance_type)
            
            # Parse pricing data
            price_item = json.loads(response['PriceList'][0])
            on_demand_terms = price_item['terms']['OnDemand']
            
            # Extract price
            for term in on_demand_terms.values():
                for price_dimension in term['priceDimensions'].values():
                    price_per_hour = float(price_dimension['pricePerUnit']['USD'])
                    
                    # Calculate monthly price (730 hours)
                    monthly_on_demand = price_per_hour * 730
                    
                    # Spot pricing (average 70% discount based on AWS historical data)
                    monthly_spot_avg = price_per_hour * 730 * 0.30
                    
                    result = {
                        'instance_type': instance_type,
                        'region': region,
                        'hourly_on_demand': price_per_hour,
                        'hourly_spot_avg': price_per_hour * 0.30,
                        'monthly_on_demand': monthly_on_demand,
                        'monthly_spot_avg': monthly_spot_avg,
                        'spot_savings_percent': 70.0,
                        'currency': 'USD',
                        'last_updated': datetime.now().isoformat(),
                        'source': 'AWS Pricing API',
                        'is_real_data': True
                    }
                    
                    # Cache the result
                    self.cache[cache_key] = (result, datetime.now())
                    
                    return result
            
            return self._get_fallback_pricing(instance_type)
            
        except Exception as e:
            # Silently fall back to estimates
            return self._get_fallback_pricing(instance_type)
    
    def _get_fallback_pricing(self, instance_type: str) -> Dict:
        """Fallback pricing when API unavailable (Dec 2024 estimates)"""
        
        fallback_prices = {
            # T3 instances - Burstable
            't3.nano': 0.0052, 't3.micro': 0.0104, 't3.small': 0.0208,
            't3.medium': 0.0416, 't3.large': 0.0832, 't3.xlarge': 0.1664,
            't3.2xlarge': 0.3328,
            
            # M5 instances - General Purpose
            'm5.large': 0.096, 'm5.xlarge': 0.192, 'm5.2xlarge': 0.384,
            'm5.4xlarge': 0.768, 'm5.8xlarge': 1.536, 'm5.12xlarge': 2.304,
            'm5.16xlarge': 3.072, 'm5.24xlarge': 4.608,
            
            # C5 instances - Compute Optimized
            'c5.large': 0.085, 'c5.xlarge': 0.17, 'c5.2xlarge': 0.34,
            'c5.4xlarge': 0.68, 'c5.9xlarge': 1.53, 'c5.12xlarge': 2.04,
            'c5.18xlarge': 3.06, 'c5.24xlarge': 4.08,
            
            # R5 instances - Memory Optimized
            'r5.large': 0.126, 'r5.xlarge': 0.252, 'r5.2xlarge': 0.504,
            'r5.4xlarge': 1.008, 'r5.8xlarge': 2.016, 'r5.12xlarge': 3.024,
            'r5.16xlarge': 4.032, 'r5.24xlarge': 6.048,
            
            # M6i instances - Latest generation
            'm6i.large': 0.096, 'm6i.xlarge': 0.192, 'm6i.2xlarge': 0.384,
            'm6i.4xlarge': 0.768, 'm6i.8xlarge': 1.536,
        }
        
        hourly_price = fallback_prices.get(instance_type, 0.10)
        
        return {
            'instance_type': instance_type,
            'region': 'us-east-1',
            'hourly_on_demand': hourly_price,
            'hourly_spot_avg': hourly_price * 0.30,
            'monthly_on_demand': hourly_price * 730,
            'monthly_spot_avg': hourly_price * 730 * 0.30,
            'spot_savings_percent': 70.0,
            'currency': 'USD',
            'last_updated': datetime.now().isoformat(),
            'source': 'Fallback Estimates (Dec 2024)',
            'is_real_data': False
        }
    
    def get_eks_pricing(self, region: str = 'us-east-1') -> Dict:
        """Get EKS control plane pricing"""
        return {
            'control_plane_hourly': 0.10,
            'control_plane_monthly': 73.0,
            'fargate_vcpu_hourly': 0.04048,
            'fargate_gb_hourly': 0.004445,
            'region': region,
            'currency': 'USD',
            'source': 'AWS Standard Pricing'
        }
    
    def calculate_cluster_cost(self, instance_type: str, node_count: int, 
                              region: str, use_spot: bool = False,
                              spot_percentage: float = 0.7) -> Dict:
        """
        Calculate comprehensive EKS cluster costs
        
        Args:
            instance_type: EC2 instance type
            node_count: Number of worker nodes
            region: AWS region
            use_spot: Whether to use Spot instances
            spot_percentage: Percentage of nodes to run as Spot (0.0-1.0)
        
        Returns:
            Dict with detailed cost breakdown
        """
        ec2_pricing = self.get_ec2_pricing(instance_type, region)
        eks_pricing = self.get_eks_pricing(region)
        
        # Calculate EC2 costs
        if use_spot and spot_percentage > 0:
            spot_nodes = int(node_count * spot_percentage)
            on_demand_nodes = node_count - spot_nodes
            
            ec2_monthly = (
                ec2_pricing['monthly_on_demand'] * on_demand_nodes +
                ec2_pricing['monthly_spot_avg'] * spot_nodes
            )
        else:
            ec2_monthly = ec2_pricing['monthly_on_demand'] * node_count
        
        # Add EKS control plane
        eks_control_plane = eks_pricing['control_plane_monthly']
        
        # Total
        total_monthly = ec2_monthly + eks_control_plane
        
        # Calculate savings vs all On-Demand
        all_on_demand_cost = (ec2_pricing['monthly_on_demand'] * node_count + 
                              eks_control_plane)
        savings = all_on_demand_cost - total_monthly
        savings_percent = (savings / all_on_demand_cost * 100) if all_on_demand_cost > 0 else 0
        
        return {
            'instance_type': instance_type,
            'node_count': node_count,
            'region': region,
            'use_spot': use_spot,
            'spot_percentage': spot_percentage if use_spot else 0,
            'breakdown': {
                'ec2_compute': ec2_monthly,
                'eks_control_plane': eks_control_plane,
                'total_monthly': total_monthly
            },
            'comparison': {
                'all_on_demand_cost': all_on_demand_cost,
                'current_config_cost': total_monthly,
                'monthly_savings': savings,
                'savings_percent': savings_percent
            },
            'pricing_source': ec2_pricing['source'],
            'is_real_data': ec2_pricing.get('is_real_data', False),
            'last_updated': ec2_pricing['last_updated']
        }

# ============================================================================
# ANTHROPIC API INTEGRATION
# ============================================================================

class AnthropicAIValidator:
    """AI-powered validation using Anthropic Claude API from secrets"""
    
    def __init__(self):
        """Initialize Anthropic client from secrets"""
        self.client = None
        self.api_key_status = self._initialize_client()
    
    def _initialize_client(self) -> str:
        """Initialize Anthropic client from Streamlit secrets"""
        try:
            # Try to get API key from secrets - supports both formats
            api_key = None
            
            # Try format 1: [anthropic] section (user's format)
            if "anthropic" in st.secrets:
                api_key = st.secrets["anthropic"].get("ANTHROPIC_API_KEY")
            
            # Try format 2: root level (if not found in section)
            if not api_key:
                api_key = st.secrets.get("ANTHROPIC_API_KEY")
            
            if not api_key:
                return "❌ ANTHROPIC_API_KEY not found in secrets (tried [anthropic] section and root level)"
            
            if not api_key.startswith("sk-ant-"):
                return "❌ Invalid ANTHROPIC_API_KEY format in secrets"
            
            # Import Anthropic library
            try:
                from anthropic import Anthropic
            except ImportError:
                return "❌ Anthropic library not installed. Run: pip install anthropic"
            
            # Initialize client
            self.client = Anthropic(api_key=api_key)
            
            return "✅ Anthropic API connected"
            
        except Exception as e:
            return f"❌ Anthropic initialization failed: {str(e)}"
    
    def validate_configuration(self, config: Dict) -> Dict:
        """
        Validate EKS configuration using AI
        
        Args:
            config: EKS configuration dictionary
        
        Returns:
            Dict with validation results and recommendations
        """
        if not self.client:
            return {
                'status': 'unavailable',
                'message': 'AI validation unavailable. Configure ANTHROPIC_API_KEY in secrets.',
                'recommendations': []
            }
        
        try:
            # Create validation prompt
            prompt = self._create_validation_prompt(config)
            
            # Call Claude API
            response = self.client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=2048,
                messages=[{
                    "role": "user",
                    "content": prompt
                }]
            )
            
            # Parse response
            analysis = response.content[0].text
            
            return {
                'status': 'success',
                'message': 'AI validation completed',
                'analysis': analysis,
                'recommendations': self._extract_recommendations(analysis)
            }
            
        except Exception as e:
            return {
                'status': 'error',
                'message': f'AI validation failed: {str(e)}',
                'recommendations': []
            }
    
    def _create_validation_prompt(self, config: Dict) -> str:
        """Create validation prompt for Claude"""
        return f"""Analyze this EKS cluster configuration and provide recommendations:

Configuration:
- Instance Type: {config.get('instance_type', 'Unknown')}
- Node Count: {config.get('node_count', 'Unknown')}
- Region: {config.get('region', 'Unknown')}
- Kubernetes Version: {config.get('k8s_version', 'Unknown')}
- Use Spot: {config.get('use_spot', False)}
- Karpenter Enabled: {config.get('karpenter_enabled', False)}

Please analyze:
1. Instance sizing appropriateness
2. Cost optimization opportunities
3. High availability considerations
4. Security best practices
5. Karpenter implementation recommendations

Provide specific, actionable recommendations."""
    
    def _extract_recommendations(self, analysis: str) -> list:
        """Extract key recommendations from AI analysis"""
        # Simple extraction - look for numbered points or bullet points
        recommendations = []
        lines = analysis.split('\n')
        
        for line in lines:
            line = line.strip()
            # Look for numbered or bulleted lists
            if line and (line[0].isdigit() or line.startswith('- ') or line.startswith('* ')):
                # Clean up the recommendation
                rec = line.lstrip('0123456789.-* ')
                if len(rec) > 20:  # Ignore very short lines
                    recommendations.append(rec)
        
        return recommendations[:10]  # Return top 10

# ============================================================================
# HELPER FUNCTION TO DISPLAY CONNECTION STATUS
# ============================================================================

def display_integration_status():
    """Display connection status for AWS Pricing and Anthropic API"""
    st.markdown("### 🔌 Integration Status")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### AWS Pricing API")
        pricing = AWSPricingFetcher()
        if "✅" in pricing.connection_status:
            st.success(pricing.connection_status)
        elif "⚠️" in pricing.connection_status:
            st.warning(pricing.connection_status)
            st.info("💡 Using fallback pricing estimates")
        else:
            st.error(pricing.connection_status)
            st.info("💡 Configure AWS credentials in Streamlit secrets")
    
    with col2:
        st.markdown("#### Anthropic AI")
        ai = AnthropicAIValidator()
        if "✅" in ai.api_key_status:
            st.success(ai.api_key_status)
        else:
            st.error(ai.api_key_status)
            st.info("💡 Configure ANTHROPIC_API_KEY in Streamlit secrets")
    
    # Show secrets configuration guide
    with st.expander("📖 How to Configure Secrets"):
        st.markdown("""
        ### Local Development
        1. Create `.streamlit/secrets.toml` file
        2. Add your keys:
        ```toml
        ANTHROPIC_API_KEY = "sk-ant-api03-..."
        
        [aws]
        access_key_id = "AKIA..."
        secret_access_key = "..."
        region = "us-east-1"
        ```
        3. Restart Streamlit
        
        ### Streamlit Cloud
        1. Go to App Settings → Secrets
        2. Paste the same TOML format
        3. Save and restart
        
        ### Getting Your Keys
        - **Anthropic**: https://console.anthropic.com/ → API Keys
        - **AWS**: IAM Console → Create access key (need PricingFullAccess policy)
        """)

# ============================================================================
# EXPORT FOR USE IN MAIN MODULE
# ============================================================================

__all__ = [
    'AWSPricingFetcher',
    'AnthropicAIValidator',
    'display_integration_status'
]
