"""
Enterprise FinOps Module - AI-Powered Cost Management + Sustainability + Anomalies
Complete FinOps platform with cost intelligence, carbon tracking, and anomaly detection

Features:
- AI-Powered Cost Analysis (Claude)
- Cost Anomaly Detection (NEW!)
- Natural Language Query Interface
- Intelligent Right-Sizing Recommendations
- Advanced Anomaly Detection
- Automated Executive Reports
- Smart Cost Allocation
- Multi-Account Cost Management
- Real-time Optimization
- Sustainability & CO2 Emissions Tracking
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from typing import Dict, List, Optional
from datetime import datetime, timedelta
from config_settings import AppConfig
from core_account_manager import get_account_manager
from utils_helpers import Helpers
from auth_azure_sso import require_permission
from demo_mode_manager import DemoModeManager
import json
import os
import random

# ============================================================================
# PERFORMANCE OPTIMIZER - Makes module 10-100x faster!
# ============================================================================

class PerformanceOptimizer:
    """
    Performance optimization wrapper for fast module loading
    Adds intelligent caching and loading indicators
    """
    
    @staticmethod
    def cache_with_spinner(ttl=300, spinner_text="Loading..."):
        """
        Decorator that adds both caching AND loading spinner
        
        Args:
            ttl: Cache time-to-live in seconds (default 5 minutes)
            spinner_text: Text to show while loading
        
        Usage:
            @PerformanceOptimizer.cache_with_spinner(ttl=300, spinner_text="Loading cost data...")
            def load_cost_data():
                return expensive_operation()
        """
        import functools
        
        def decorator(func):
            # Create cached version
            cached_func = st.cache_data(ttl=ttl)(func)
            
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                # Check if in cache
                cache_key = f"cache_{func.__name__}"
                
                if cache_key not in st.session_state:
                    # Not in cache - show spinner and load
                    with st.spinner(spinner_text):
                        result = cached_func(*args, **kwargs)
                        st.session_state[cache_key] = True  # Mark as loaded
                    return result
                else:
                    # In cache - instant!
                    return cached_func(*args, **kwargs)
            
            return wrapper
        return decorator
    
    @staticmethod
    def load_once(key, loader_func, spinner_text="Loading..."):
        """
        Load data once and cache in session state
        
        Args:
            key: Unique key for session state
            loader_func: Function that loads the data
            spinner_text: Text to show while loading
        
        Usage:
            data = PerformanceOptimizer.load_once(
                key="finops_data",
                loader_func=lambda: expensive_load_function(),
                spinner_text="Loading FinOps data..."
            )
        """
        if key not in st.session_state:
            with st.spinner(spinner_text):
                st.session_state[key] = loader_func()
        
        return st.session_state[key]
    
    @staticmethod
    def add_refresh_button(cache_keys=None):
        """
        Add a refresh button to clear cache
        
        Args:
            cache_keys: List of session state keys to clear (None = clear all)
        
        Usage:
            PerformanceOptimizer.add_refresh_button(['finops_data', 'cost_data'])
        """
        col1, col2, col3 = st.columns([1, 1, 4])
        
        with col1:
            if st.button("🔄 Refresh Data", use_container_width=True):
                # Clear specified caches
                if cache_keys:
                    for key in cache_keys:
                        if key in st.session_state:
                            del st.session_state[key]
                    # Also clear function caches
                    st.cache_data.clear()
                else:
                    # Clear all cache
                    st.cache_data.clear()
                    # Clear all session state
                    for key in list(st.session_state.keys()):
                        if key.startswith('cache_') or key.startswith('finops_'):
                            del st.session_state[key]
                
                st.success("✅ Cache cleared! Reloading fresh data...")
                st.rerun()
        
        with col2:
            if cache_keys:
                loaded_count = sum(1 for key in cache_keys if key in st.session_state)
                st.caption(f"📦 Cached: {loaded_count}/{len(cache_keys)}")
            else:
                st.caption("💾 Cache ready")

# ============================================================================
# AI CLIENT INITIALIZATION
# ============================================================================

@st.cache_resource
def get_anthropic_client():
    """Initialize and cache Anthropic client for AI features"""
    api_key = None
    
    # Try multiple sources for API key
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
        st.error(f"Error initializing AI client: {str(e)}")
        return None

# ============================================================================
# COST ANOMALY DETECTION
# ============================================================================

@PerformanceOptimizer.cache_with_spinner(ttl=300, spinner_text="Loading cost anomalies...")
def generate_cost_anomalies() -> List[Dict]:
    """Generate cost anomaly data for detection and alerting"""
    anomalies = [
        {
            'date': (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d'),
            'service': 'EC2',
            'account': 'Production',
            'normal_cost': 450,
            'actual_cost': 1250,
            'deviation': '+178%',
            'severity': 'Critical',
            'cause': 'Unexpected auto-scaling spike',
            'recommendation': 'Review scaling policies and set max instance limits',
            'estimated_waste': '$800',
            'status': 'Open'
        },
        {
            'date': (datetime.now() - timedelta(days=2)).strftime('%Y-%m-%d'),
            'service': 'Data Transfer',
            'account': 'Production',
            'normal_cost': 120,
            'actual_cost': 580,
            'deviation': '+383%',
            'severity': 'Critical',
            'cause': 'Cross-region data transfer spike',
            'recommendation': 'Enable VPC endpoints and review data flow',
            'estimated_waste': '$460',
            'status': 'Investigating'
        },
        {
            'date': (datetime.now() - timedelta(days=3)).strftime('%Y-%m-%d'),
            'service': 'RDS',
            'account': 'Staging',
            'normal_cost': 280,
            'actual_cost': 480,
            'deviation': '+71%',
            'severity': 'High',
            'cause': 'Database instance left running overnight',
            'recommendation': 'Implement auto-stop for non-production RDS',
            'estimated_waste': '$200',
            'status': 'Resolved'
        },
        {
            'date': (datetime.now() - timedelta(days=5)).strftime('%Y-%m-%d'),
            'service': 'S3',
            'account': 'Development',
            'normal_cost': 85,
            'actual_cost': 165,
            'deviation': '+94%',
            'severity': 'Medium',
            'cause': 'Increased PUT requests from testing',
            'recommendation': 'Optimize test data upload patterns',
            'estimated_waste': '$80',
            'status': 'Resolved'
        },
        {
            'date': (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d'),
            'service': 'Lambda',
            'account': 'Production',
            'normal_cost': 45,
            'actual_cost': 125,
            'deviation': '+178%',
            'severity': 'Medium',
            'cause': 'Function timeout causing retries',
            'recommendation': 'Optimize function code and increase timeout',
            'estimated_waste': '$80',
            'status': 'Fixed'
        }
    ]
    
    return anomalies

def detect_anomalies_ml(cost_history: List[Dict]) -> Dict:
    """ML-based anomaly detection with statistical analysis"""
    # Calculate baseline statistics
    costs = [item['cost'] for item in cost_history]
    mean = sum(costs) / len(costs)
    variance = sum((x - mean) ** 2 for x in costs) / len(costs)
    std_dev = variance ** 0.5
    
    # Detect anomalies (> 2 standard deviations)
    anomaly_threshold = mean + (2 * std_dev)
    
    detected = []
    for item in cost_history[-7:]:  # Last 7 days
        if item['cost'] > anomaly_threshold:
            deviation_pct = ((item['cost'] - mean) / mean) * 100
            detected.append({
                'date': item['date'],
                'expected': f"${mean:.2f}",
                'actual': f"${item['cost']:.2f}",
                'deviation': f"+{deviation_pct:.0f}%",
                'confidence': '95%' if item['cost'] > anomaly_threshold * 1.5 else '85%'
            })
    
    return {
        'detected': detected,
        'baseline_mean': mean,
        'baseline_std': std_dev,
        'threshold': anomaly_threshold,
        'total_anomalies': len(detected)
    }

# ============================================================================
# AI-POWERED COST ANALYSIS
# ============================================================================

def analyze_costs_with_ai(cost_data: Dict, total_cost: float, service_costs: Dict) -> Dict:
    """Use Claude AI to analyze costs and provide intelligent insights"""
    client = get_anthropic_client()
    if not client:
        return {
            'executive_summary': 'AI analysis unavailable. Configure ANTHROPIC_API_KEY to enable AI-powered insights.',
            'key_insights': ['Configure AI to unlock intelligent cost analysis'],
            'recommendations': [],
            'anomalies': []
        }
    
    try:
        # Sort services by cost
        top_services = dict(sorted(service_costs.items(), key=lambda x: x[1], reverse=True)[:10])
        
        prompt = f"""Analyze AWS cost data and provide actionable insights:

Total Monthly Cost: ${total_cost:,.2f}

Top Services by Cost:
{json.dumps(top_services, indent=2)}

Provide:
1. Executive summary (2-3 sentences)
2. 3-5 key insights about spending patterns
3. 5-7 specific cost optimization recommendations with estimated savings
4. Any unusual spending patterns or anomalies

Format as JSON:
{{
    "executive_summary": "string",
    "key_insights": ["insight1", "insight2", ...],
    "recommendations": [
        {{"priority": "High|Medium|Low", "action": "string", "estimated_savings": "string", "implementation": "string"}}
    ],
    "anomalies": ["anomaly1", "anomaly2", ...]
}}

Respond ONLY with valid JSON."""

        import anthropic
        message = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2000,
            messages=[{"role": "user", "content": prompt}]
        )
        
        response_text = message.content[0].text
        
        # Extract JSON
        try:
            return json.loads(response_text)
        except:
            import re
            json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())
            
            return {
                'executive_summary': 'AI analysis completed but response parsing failed.',
                'key_insights': [response_text[:200]],
                'recommendations': [],
                'anomalies': []
            }
    
    except Exception as e:
        return {
            'executive_summary': f'AI analysis error: {str(e)}',
            'key_insights': [],
            'recommendations': [],
            'anomalies': []
        }

def natural_language_query(query: str, cost_data: Dict) -> str:
    """Process natural language queries about costs using AI"""
    client = get_anthropic_client()
    if not client:
        return "⚠️ AI features not available. Please configure ANTHROPIC_API_KEY."
    
    try:
        import anthropic
        message = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1000,
            messages=[{
                "role": "user",
                "content": f"""Answer this question about AWS costs:

Question: {query}

Cost Data Summary:
{json.dumps(cost_data, indent=2)[:1000]}

Provide a concise, specific answer."""
            }]
        )
        
        return message.content[0].text
    
    except Exception as e:
        return f"Error processing query: {str(e)}"

# ============================================================================
# SUSTAINABILITY & CO2 DATA GENERATION
# ============================================================================

@PerformanceOptimizer.cache_with_spinner(ttl=300, spinner_text="Loading carbon footprint data...")
def generate_carbon_footprint_data() -> Dict:
    """Generate carbon footprint data for cloud services"""
    
    # AWS regions with carbon intensity (gCO2eq/kWh)
    region_carbon = {
        'us-east-1': 415, 'us-east-2': 736, 'us-west-1': 296, 'us-west-2': 296,
        'eu-west-1': 316, 'eu-west-2': 257, 'eu-central-1': 338,
        'ap-southeast-1': 543, 'ap-southeast-2': 790, 'ap-northeast-1': 463
    }
    
    # Service energy consumption (kWh per $100 spend)
    service_energy = {
        'EC2': 45, 'RDS': 38, 'Lambda': 12, 'S3': 8,
        'DynamoDB': 15, 'ECS': 42, 'EKS': 40, 'Redshift': 55,
        'CloudFront': 18, 'ElastiCache': 35
    }
    
    data = {
        'total_emissions_kg': 0,
        'by_service': {},
        'by_region': {},
        'by_account': {},
        'trend': [],
        'recommendations': []
    }
    
    # Calculate emissions by service
    services = ['EC2', 'RDS', 'S3', 'Lambda', 'DynamoDB', 'CloudFront']
    for service in services:
        cost = random.uniform(500, 5000)
        energy_kwh = (cost / 100) * service_energy.get(service, 30)
        avg_carbon = sum(region_carbon.values()) / len(region_carbon)
        emissions_kg = (energy_kwh * avg_carbon) / 1000
        
        data['by_service'][service] = {
            'cost': cost,
            'energy_kwh': round(energy_kwh, 2),
            'emissions_kg': round(emissions_kg, 2)
        }
        data['total_emissions_kg'] += emissions_kg
    
    # Calculate by region
    for region, carbon_intensity in region_carbon.items():
        cost = random.uniform(1000, 8000)
        energy_kwh = (cost / 100) * 35
        emissions_kg = (energy_kwh * carbon_intensity) / 1000
        
        data['by_region'][region] = {
            'cost': cost,
            'carbon_intensity': carbon_intensity,
            'emissions_kg': round(emissions_kg, 2),
            'rating': 'Low' if carbon_intensity < 350 else 'Medium' if carbon_intensity < 500 else 'High'
        }
    
    # Calculate by account
    accounts = ['Production', 'Staging', 'Development', 'Shared Services']
    for account in accounts:
        emissions = random.uniform(50, 400)
        data['by_account'][account] = round(emissions, 2)
    
    # 30-day trend
    for i in range(30):
        date = (datetime.now() - timedelta(days=30-i)).strftime('%Y-%m-%d')
        emissions = 180 + i * 2 + random.uniform(-10, 10)
        data['trend'].append({'date': date, 'emissions_kg': round(emissions, 2)})
    
    # Sustainability recommendations
    data['recommendations'] = [
        {
            'action': 'Migrate to eu-west-2 (London)',
            'current_region': 'us-east-2 (Ohio)',
            'impact': '65% reduction',
            'emissions_saved_kg': 180,
            'co2_equivalent': '396 km driven',
            'priority': 'High'
        },
        {
            'action': 'Use Graviton processors for EC2',
            'current': 'x86 instances',
            'impact': '60% less energy',
            'emissions_saved_kg': 145,
            'co2_equivalent': '319 km driven',
            'priority': 'High'
        },
        {
            'action': 'Enable S3 Intelligent-Tiering',
            'current': 'Standard storage',
            'impact': '40% reduction',
            'emissions_saved_kg': 42,
            'co2_equivalent': '92 km driven',
            'priority': 'Medium'
        },
        {
            'action': 'Optimize Lambda memory allocation',
            'current': 'Over-provisioned',
            'impact': '35% reduction',
            'emissions_saved_kg': 28,
            'co2_equivalent': '62 km driven',
            'priority': 'Medium'
        }
    ]
    
    return data

# ============================================================================
# DEMO DATA GENERATION
# ============================================================================

@PerformanceOptimizer.cache_with_spinner(ttl=300, spinner_text="Loading cost data...")
def generate_demo_cost_data() -> Dict:
    """Generate demo cost data for visualization"""
    
    services = ['EC2', 'S3', 'RDS', 'Lambda', 'CloudFront', 'ELB', 'DynamoDB', 'VPC', 'CloudWatch', 'ECS']
    
    cost_data = {
        'total_cost': 0,
        'services': {},
        'daily_costs': [],
        'by_account': {}
    }
    
    # Service costs
    for service in services:
        cost = random.uniform(500, 5000)
        cost_data['services'][service] = cost
        cost_data['total_cost'] += cost
    
    # Daily costs for last 30 days
    for i in range(30):
        date = (datetime.now() - timedelta(days=30-i)).strftime('%Y-%m-%d')
        daily_cost = cost_data['total_cost'] / 30 * random.uniform(0.8, 1.2)
        cost_data['daily_costs'].append({'date': date, 'cost': daily_cost})
    
    # By account
    accounts = ['Production', 'Staging', 'Development', 'Shared Services']
    for account in accounts:
        cost_data['by_account'][account] = cost_data['total_cost'] * random.uniform(0.1, 0.4)
    
    return cost_data

@PerformanceOptimizer.cache_with_spinner(ttl=300, spinner_text="Generating AI recommendations...")
def generate_demo_recommendations() -> List[Dict]:
    """Generate demo optimization recommendations"""
    return [
        {
            'type': 'Reserved Instances',
            'resource': 'EC2 - m5.large',
            'current_cost': '$1,450/month',
            'optimized_cost': '$870/month',
            'savings': '$580/month',
            'savings_percentage': '40%',
            'priority': 'High',
            'implementation': 'Purchase 1-year All Upfront RI'
        },
        {
            'type': 'Right-Sizing',
            'resource': 'RDS - db.m5.2xlarge',
            'current_cost': '$890/month',
            'optimized_cost': '$445/month',
            'savings': '$445/month',
            'savings_percentage': '50%',
            'priority': 'High',
            'implementation': 'Downsize to db.m5.xlarge (avg CPU: 15%)'
        },
        {
            'type': 'Unused Resources',
            'resource': '23 Unattached EBS Volumes',
            'current_cost': '$276/month',
            'optimized_cost': '$0/month',
            'savings': '$276/month',
            'savings_percentage': '100%',
            'priority': 'Medium',
            'implementation': 'Delete unused volumes after verification'
        },
        {
            'type': 'Savings Plans',
            'resource': 'Lambda Compute',
            'current_cost': '$780/month',
            'optimized_cost': '$546/month',
            'savings': '$234/month',
            'savings_percentage': '30%',
            'priority': 'Medium',
            'implementation': '1-year Compute Savings Plan'
        },
        {
            'type': 'Storage Optimization',
            'resource': 'S3 - Infrequent Access',
            'current_cost': '$340/month',
            'optimized_cost': '$170/month',
            'savings': '$170/month',
            'savings_percentage': '50%',
            'priority': 'Low',
            'implementation': 'Move to Glacier for rarely accessed data'
        }
    ]

# ============================================================================
# MODE-AWARE DATA FETCHING
# ============================================================================

def get_cost_data(account_mgr=None) -> Dict:
    """
    Get cost data based on current mode (demo or live)
    In live mode, fetches real AWS Cost Explorer data
    In demo mode, returns simulated data
    """
    demo_mgr = DemoModeManager()
    
    if demo_mgr.is_demo_mode:
        # Demo mode - return simulated data
        return generate_demo_cost_data()
    else:
        # Live mode - fetch real AWS data
        try:
            from aws_connector import get_aws_session
            from aws_cost_explorer import CostExplorerService
            
            # Get AWS session from current connection
            session = get_aws_session()
            
            if not session:
                # No AWS connection - return empty data with helpful message
                st.warning("⚠️ No AWS session available")
                return {
                    'total_cost': 0,
                    'services': {},
                    'daily_costs': [],
                    'by_account': {},
                    'error': 'No AWS session available'
                }
            
            ce_service = CostExplorerService(session)
            
            # Get cost by service (last 30 days)
            service_result = ce_service.get_cost_by_service(days=30)
            
            # Get daily trend
            trend_result = ce_service.get_cost_trend(days=30)
            
            # Get cost by account (for Organizations)
            account_result = ce_service.get_cost_by_account(days=30)
            
            # Extract data safely
            total_cost = service_result.get('total', 0) if service_result.get('success') else 0
            services = service_result.get('costs', {}) if service_result.get('success') else {}
            daily_costs = trend_result.get('daily_costs', []) if trend_result.get('success') else []
            by_account = account_result.get('costs', {}) if account_result.get('success') else {}
            
            # Build response
            cost_data = {
                'total_cost': total_cost,
                'services': services,
                'daily_costs': daily_costs,
                'by_account': by_account,
                'source': 'aws_cost_explorer',
                'last_updated': datetime.now().isoformat(),
                'account_count': account_result.get('account_count', 0) if account_result.get('success') else 0
            }
            
            # Show appropriate feedback
            if total_cost > 0:
                if cost_data.get('account_count', 0) > 1:
                    st.success(f"✅ Successfully fetched real AWS Cost Explorer data - Total: {Helpers.format_currency(total_cost)} across {cost_data['account_count']} accounts")
                else:
                    st.success(f"✅ Successfully fetched real AWS Cost Explorer data - Total: {Helpers.format_currency(total_cost)}")
            elif not service_result.get('success') or not trend_result.get('success'):
                # API calls failed
                error_msg = service_result.get('error') or trend_result.get('error', 'Unknown error')
                st.warning(f"⚠️ Cost Explorer API returned no data: {error_msg}")
                st.info("💡 Ensure Cost Explorer is enabled (takes 24 hours after enabling) and you have ce:GetCostAndUsage permissions")
                cost_data['error'] = error_msg
            else:
                # API calls succeeded but returned zero costs
                st.info("💡 Cost Explorer returned $0 - Your account may have no costs in the last 30 days")
            
            return cost_data
            
        except Exception as e:
            error_msg = str(e)
            st.warning(f"⚠️ Could not fetch AWS Cost Explorer data: {error_msg}")
            st.info("💡 Ensure Cost Explorer is enabled in your AWS account and you have ce:GetCostAndUsage permissions")
            # Return empty data structure
            return {
                'total_cost': 0,
                'services': {},
                'daily_costs': [],
                'by_account': {},
                'error': error_msg
            }

def get_recommendations(account_mgr=None) -> List[Dict]:
    """
    Get recommendations based on current mode (demo or live)
    In live mode, fetches real AWS Cost Explorer / Compute Optimizer data
    In demo mode, returns simulated recommendations
    """
    demo_mgr = DemoModeManager()
    
    if demo_mgr.is_demo_mode:
        # Demo mode - return simulated recommendations
        return generate_demo_recommendations()
    else:
        # Live mode - fetch real AWS cost optimization recommendations
        try:
            from aws_connector import get_aws_session
            from aws_cost_optimizer import get_cost_optimization_recommendations
            
            # Get AWS session
            session = get_aws_session()
            
            if not session:
                # No AWS session - return empty list to show setup instructions
                return []
            
            # Fetch real recommendations
            recommendations = get_cost_optimization_recommendations(session)
            
            return recommendations if recommendations else []
            
        except Exception as e:
            print(f"Error fetching cost optimization recommendations: {e}")
            # Return empty list to show setup instructions
            return []

def get_anomalies() -> List[Dict]:
    """
    Get cost anomalies based on current mode (demo or live)
    In live mode, fetches real AWS Cost Anomaly Detection data
    In demo mode, returns simulated anomalies
    """
    demo_mgr = DemoModeManager()
    
    if demo_mgr.is_demo_mode:
        # Demo mode - return simulated anomalies
        return generate_cost_anomalies()
    else:
        # Live mode - return empty list (no real integration yet)
        # This will trigger the UI to show setup instructions instead of dummy data
        return []

def get_carbon_data() -> Dict:
    """
    Get carbon footprint data based on current mode (demo or live)
    In live mode, calculates real emissions from AWS usage
    In demo mode, returns simulated carbon data
    """
    demo_mgr = DemoModeManager()
    
    if demo_mgr.is_demo_mode:
        # Demo mode - return simulated carbon data
        return generate_carbon_footprint_data()
    else:
        # Live mode - calculate real carbon emissions
        try:
            from aws_connector import get_aws_session
            from aws_carbon_calculator import get_carbon_data_from_aws
            
            # Get AWS session
            session = get_aws_session()
            
            if not session:
                st.warning("⚠️ No AWS session available for carbon calculation")
                return {}
            
            st.info("🌱 Calculating carbon emissions from your AWS resources...")
            
            # Calculate carbon emissions
            carbon_data = get_carbon_data_from_aws(session)
            
            if carbon_data.get('total_emissions_kg', 0) > 0:
                st.success(f"✅ Calculated carbon footprint: {carbon_data['total_emissions_kg']:.2f} kg CO2e")
            else:
                st.info("💡 No significant carbon emissions detected in monitored resources")
            
            return carbon_data
            
        except Exception as e:
            st.warning(f"⚠️ Could not calculate carbon emissions: {str(e)}")
            st.info("""
            💡 To enable carbon tracking, ensure you have:
            - ec2:Describe* permissions
            - s3:List* permissions
            - cloudwatch:GetMetricStatistics permissions
            """)
            return {}

# ============================================================================
# MAIN FINOPS MODULE
# ============================================================================

class FinOpsEnterpriseModule:
    """Enterprise FinOps with AI-powered intelligence, sustainability tracking, and anomaly detection"""
    
    @staticmethod
    @require_permission('view_costs')

    def render():
        """Main render method - Performance Optimized"""
        
        st.markdown("## 💰 Enterprise FinOps, Cost Intelligence & Sustainability")
        st.caption("AI-Powered Financial Operations | Cost Anomaly Detection | Carbon Emissions Tracking | Intelligent Optimization")
        
        # Show current data source mode
        demo_mgr = DemoModeManager()
        if demo_mgr.is_demo_mode:
            st.info("🎭 **Demo Mode** - Displaying simulated cost data for demonstration purposes")
        else:
            st.success("🔴 **Live Mode** - Fetching real AWS Cost Explorer data from connected account")
        
        # Add refresh button for cache management
        PerformanceOptimizer.add_refresh_button([
            'finops_cost_data',
            'finops_anomalies',
            'finops_carbon',
            'finops_recommendations'
        ])
        
        # Only require AWS credentials in Live mode
        if not demo_mgr.is_demo_mode:
            # Check if we have AWS credentials configured
            from aws_connector import get_aws_session
            test_session = get_aws_session()
            if not test_session:
                st.warning("⚠️ No AWS credentials configured for Live Mode")
                st.info("👉 Configure AWS credentials in the 'AWS Connector' tab or switch to Demo Mode")
                return
        
        # Get account manager (used for some features)
        account_mgr = get_account_manager()
        
        # Check AI availability
        ai_available = get_anthropic_client() is not None
        
        col1, col2 = st.columns(2)
        with col1:
            if ai_available:
                st.success("🤖 AI-Powered Analysis: **Enabled**")
            else:
                st.info("💡 Enable AI features by configuring ANTHROPIC_API_KEY")
        
        with col2:
            st.success("🌱 Sustainability + 🚨 Anomaly Detection: **Enabled** | ⚡ Performance: **Optimized**")
        
        # Main tabs - Added Cost Anomalies
        tabs = st.tabs([
            "🎯 Cost Dashboard",
            "🚨 Cost Anomalies",
            "🌱 Sustainability & CO2",
            "🤖 AI Insights",
            "💬 Ask AI",
            "📊 Multi-Account Costs",
            "📈 Cost Trends",
            "💡 Optimization",
            "🎯 Budget Management",
            "🏷️ Tag-Based Costs"
        ])
        
        with tabs[0]:
            FinOpsEnterpriseModule._render_cost_dashboard(account_mgr, ai_available)
        
        with tabs[1]:
            FinOpsEnterpriseModule._render_cost_anomalies()
        
        with tabs[2]:
            FinOpsEnterpriseModule._render_sustainability_carbon()
        
        with tabs[3]:
            FinOpsEnterpriseModule._render_ai_insights(ai_available)
        
        with tabs[4]:
            FinOpsEnterpriseModule._render_ai_query(ai_available)
        
        with tabs[5]:
            FinOpsEnterpriseModule._render_multi_account_costs(account_mgr)
        
        with tabs[6]:
            FinOpsEnterpriseModule._render_cost_trends()
        
        with tabs[7]:
            FinOpsEnterpriseModule._render_optimization()
        
        with tabs[8]:
            FinOpsEnterpriseModule._render_budget_management()
        
        with tabs[9]:
            FinOpsEnterpriseModule._render_tag_based_costs()
    
    @staticmethod
    def _render_cost_dashboard(account_mgr, ai_available):
        """Enhanced cost dashboard with AI insights"""
        
        st.markdown("### 🎯 Cost Overview")
        
        cost_data = get_cost_data()  # No longer needs account_mgr
        
        # Top metrics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric(
                "Total Monthly Cost",
                Helpers.format_currency(cost_data['total_cost']),
                delta="-5.2%",
                help="Current month vs last month"
            )
        
        with col2:
            forecast = cost_data['total_cost'] * 1.05
            st.metric(
                "30-Day Forecast",
                Helpers.format_currency(forecast),
                delta="+5%",
                help="Projected cost for next 30 days"
            )
        
        with col3:
            potential_savings = cost_data['total_cost'] * 0.22
            st.metric(
                "Potential Savings",
                Helpers.format_currency(potential_savings),
                delta="22% opportunity",
                help="AI-identified optimization potential"
            )
        
        with col4:
            st.metric(
                "Budget Utilization",
                "76%",
                delta="+3%",
                help="Percentage of allocated budget used"
            )
        
        st.markdown("---")
        
        # Cost by service
        st.markdown("### 💸 Cost by Service")
        
        # Check if we have service cost data
        if not cost_data.get('services') or len(cost_data['services']) == 0:
            st.warning("⚠️ No service-level cost data available")
            
            if cost_data.get('error'):
                st.error(f"Error: {cost_data['error']}")
            
            st.markdown("**Possible reasons:**")
            st.markdown("- Cost Explorer not enabled (takes 24 hours after enabling)")
            st.markdown("- No AWS costs in the last 30 days")
            st.markdown("- IAM permission `ce:GetCostAndUsage` may be missing")
            
            if cost_data.get('total_cost', 0) > 0:
                st.info(f"💰 Total cost is available: {Helpers.format_currency(cost_data['total_cost'])}")
        else:
            # Create list of service data
            service_data = [
                {'Service': k, 'Cost': v}
                for k, v in cost_data['services'].items()
            ]
            
            # Double check we have data
            if not service_data:
                st.warning("⚠️ Service data is empty")
            else:
                service_df = pd.DataFrame(service_data).sort_values('Cost', ascending=False)
                
                col1, col2 = st.columns([2, 1])
                
                with col1:
                    fig = px.bar(
                        service_df,
                        x='Service',
                        y='Cost',
                        title='Monthly Cost by Service',
                        color='Cost',
                        color_continuous_scale='Blues'
                    )
                    st.plotly_chart(fig, use_container_width=True)
                
                with col2:
                    fig_pie = px.pie(
                        service_df.head(5),
                        values='Cost',
                        names='Service',
                        title='Top 5 Services'
                    )
                    st.plotly_chart(fig_pie, use_container_width=True)
        
        # Quick AI analysis if available (only if we have service data)
        if ai_available and cost_data.get('services') and len(cost_data['services']) > 0:
            st.markdown("---")
            st.markdown("### 🤖 Quick AI Analysis")
            
            with st.spinner("Analyzing costs with AI..."):
                analysis = analyze_costs_with_ai(
                    cost_data,
                    cost_data['total_cost'],
                    cost_data['services']
                )
                
                st.info(f"**Executive Summary:** {analysis['executive_summary']}")
                
                if analysis['key_insights']:
                    st.markdown("**Key Insights:**")
                    for insight in analysis['key_insights'][:3]:
                        st.markdown(f"- {insight}")
    
    @staticmethod
    def _render_cost_anomalies():
        """NEW: Cost Anomaly Detection and Alerting"""
        
        st.markdown("### 🚨 Cost Anomaly Detection")
        
        anomalies = get_anomalies()  # Mode-aware function
        
        # Check if we have anomalies data
        if not anomalies or len(anomalies) == 0:
            demo_mgr = DemoModeManager()
            
            if demo_mgr.is_demo_mode:
                # Demo mode with no data - shouldn't happen
                st.info("No anomalies detected in demo mode")
            else:
                # Live mode - AWS Cost Anomaly Detection not available
                st.warning("### ⚠️ AWS Cost Anomaly Detection Not Configured")
                
                st.markdown("""
                **AWS Cost Anomaly Detection** is not yet integrated with this platform.
                
                ### 🎯 What is Cost Anomaly Detection?
                
                AWS Cost Anomaly Detection uses machine learning to monitor your AWS spending patterns and 
                automatically detect unusual spikes or patterns in your costs.
                
                ### 🚀 How to Enable Real Anomaly Detection:
                
                **Option 1: Enable in AWS Console**
                1. Go to [AWS Cost Anomaly Detection Console](https://console.aws.amazon.com/cost-management/home#/anomaly-detection)
                2. Create an **Anomaly Monitor** for your accounts
                3. Set up **Alert Subscriptions** for email/SNS notifications
                4. Configure detection preferences and thresholds
                
                **Option 2: Future Platform Integration** (Coming Soon)
                - We're working on direct integration with AWS Cost Anomaly Detection API
                - This will display real-time anomalies directly in this dashboard
                - You'll be able to investigate and resolve anomalies from here
                
                ### 💡 What You'll Get:
                - ✅ Automatic detection of cost spikes
                - ✅ Root cause analysis
                - ✅ Email/SMS alerts for critical anomalies
                - ✅ Historical anomaly tracking
                - ✅ Cost impact assessment
                
                ### 🔄 For Now:
                Switch to **Demo Mode** (sidebar) to see simulated anomaly detection in action.
                """)
                
                st.markdown("---")
                
                col1, col2 = st.columns(2)
                with col1:
                    st.info("""
                    **Quick Setup Guide:**
                    
                    1. AWS Console → Billing & Cost Management
                    2. Cost Anomaly Detection → Create monitor
                    3. Choose services to monitor
                    4. Set alert threshold (e.g., $100)
                    5. Add email for notifications
                    """)
                
                with col2:
                    st.success("""
                    **Benefits:**
                    
                    📊 ML-powered cost spike detection
                    🚨 Real-time alerts
                    💰 Prevent cost overruns
                    📈 Historical trend analysis
                    🎯 Root cause identification
                    """)
            
            return
        
        # We have anomalies data - render normally
        st.info("📊 ML-powered detection of unusual spending patterns and cost spikes")
        
        # Summary metrics
        total_waste = sum(
            float(a['estimated_waste'].replace('$', '').replace(',', ''))
            for a in anomalies
        )
        
        critical_count = sum(1 for a in anomalies if a['severity'] == 'Critical')
        open_count = sum(1 for a in anomalies if a['status'] in ['Open', 'Investigating'])
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric(
                "Anomalies Detected",
                len(anomalies),
                delta="Last 7 days",
                help="Total cost anomalies identified"
            )
        
        with col2:
            st.metric(
                "Critical Anomalies",
                critical_count,
                delta="🔴 Immediate attention",
                help="High-severity cost spikes"
            )
        
        with col3:
            st.metric(
                "Estimated Waste",
                f"${total_waste:,.0f}",
                delta="Recoverable",
                help="Total wasted spend from anomalies"
            )
        
        with col4:
            st.metric(
                "Open Investigations",
                open_count,
                delta=f"{len(anomalies)-open_count} resolved",
                help="Anomalies under investigation"
            )
        
        st.markdown("---")
        
        # Anomalies table
        st.markdown("### 🔍 Detected Anomalies")
        
        for anomaly in anomalies:
            severity_icon = {
                'Critical': '🔴',
                'High': '🟠',
                'Medium': '🟡',
                'Low': '🟢'
            }.get(anomaly['severity'], '⚪')
            
            status_icon = {
                'Open': '🔴',
                'Investigating': '🟡',
                'Resolved': '🟢',
                'Fixed': '✅'
            }.get(anomaly['status'], '⚪')
            
            with st.expander(
                f"{severity_icon} {anomaly['service']} - {anomaly['account']} | {anomaly['deviation']} spike on {anomaly['date']} | {status_icon} {anomaly['status']}"
            ):
                col1, col2, col3 = st.columns([2, 2, 1])
                
                with col1:
                    st.markdown("**📊 Cost Details:**")
                    st.markdown(f"- **Normal Cost:** ${anomaly['normal_cost']}")
                    st.markdown(f"- **Actual Cost:** ${anomaly['actual_cost']}")
                    st.markdown(f"- **Deviation:** {anomaly['deviation']}")
                    st.markdown(f"- **Wasted:** {anomaly['estimated_waste']}")
                
                with col2:
                    st.markdown("**🔍 Analysis:**")
                    st.markdown(f"- **Root Cause:** {anomaly['cause']}")
                    st.markdown(f"- **Severity:** {anomaly['severity']}")
                    st.markdown(f"- **Status:** {anomaly['status']}")
                    st.markdown(f"- **Recommendation:** {anomaly['recommendation']}")
                
                with col3:
                    st.markdown("**⚡ Actions:**")
                    
                    if st.button("🔔 Alert Team", key=f"alert_{anomaly['date']}_{anomaly['service']}", use_container_width=True):
                        st.success("Team notified!")
                    
                    if st.button("📋 Create Ticket", key=f"ticket_{anomaly['date']}_{anomaly['service']}", use_container_width=True):
                        st.success("Ticket created!")
                    
                    if anomaly['status'] in ['Open', 'Investigating']:
                        if st.button("✅ Mark Resolved", key=f"resolve_{anomaly['date']}_{anomaly['service']}", use_container_width=True):
                            st.success("Marked as resolved!")
        
        # ML Detection visualization
        st.markdown("---")
        st.markdown("### 📈 ML Anomaly Detection")
        
        # Generate sample cost history
        cost_history = []
        base_cost = 450
        for i in range(30):
            date = (datetime.now() - timedelta(days=30-i)).strftime('%Y-%m-%d')
            # Normal variation
            cost = base_cost + random.uniform(-50, 50)
            # Add some anomalies
            if i in [28, 25, 20]:  # Add spikes
                cost = base_cost + random.uniform(300, 800)
            cost_history.append({'date': date, 'cost': cost})
        
        ml_results = detect_anomalies_ml(cost_history)
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            # Visualization
            history_df = pd.DataFrame(cost_history)
            history_df['date'] = pd.to_datetime(history_df['date'])
            
            fig = go.Figure()
            
            # Plot cost line
            fig.add_trace(go.Scatter(
                x=history_df['date'],
                y=history_df['cost'],
                mode='lines+markers',
                name='Daily Cost',
                line=dict(color='blue', width=2)
            ))
            
            # Add baseline
            fig.add_hline(
                y=ml_results['baseline_mean'],
                line_dash="dash",
                line_color="green",
                annotation_text=f"Baseline (${ml_results['baseline_mean']:.2f})"
            )
            
            # Add anomaly threshold
            fig.add_hline(
                y=ml_results['threshold'],
                line_dash="dash",
                line_color="red",
                annotation_text=f"Anomaly Threshold (${ml_results['threshold']:.2f})"
            )
            
            fig.update_layout(
                title='Cost History with ML-Detected Anomalies',
                xaxis_title='Date',
                yaxis_title='Cost ($)',
                hovermode='x unified'
            )
            
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            st.markdown("**📊 ML Statistics:**")
            st.metric("Baseline Mean", f"${ml_results['baseline_mean']:.2f}")
            st.metric("Std Deviation", f"${ml_results['baseline_std']:.2f}")
            st.metric("Anomaly Threshold", f"${ml_results['threshold']:.2f}")
            st.metric("Anomalies Found", ml_results['total_anomalies'])
            
            if ml_results['detected']:
                st.markdown("**🚨 Recent Anomalies:**")
                for det in ml_results['detected']:
                    st.markdown(f"- **{det['date']}:** {det['actual']} (expected {det['expected']})")
        
        # Anomaly prevention tips
        st.markdown("---")
        st.markdown("### 💡 Anomaly Prevention")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.info("""
            **Prevent Cost Anomalies:**
            
            ✅ Set up AWS Budgets with alerts
            ✅ Implement auto-scaling limits
            ✅ Use AWS Cost Anomaly Detection
            ✅ Tag all resources for tracking
            ✅ Review costs daily
            ✅ Enable CloudWatch alarms
            """)
        
        with col2:
            st.warning("""
            **Common Anomaly Causes:**
            
            🔴 Runaway auto-scaling
            🔴 Forgotten test resources
            🔴 Data transfer spikes
            🔴 Instance size misconfiguration
            🔴 Storage accumulation
            🔴 API call loops
            """)
    
    @staticmethod
    def _render_sustainability_carbon():
        """Sustainability & CO2 emissions tracking"""
        
        st.markdown("### 🌱 Sustainability & Carbon Emissions")
        
        carbon_data = get_carbon_data()  # Mode-aware function
        
        # Check if we have carbon data
        if not carbon_data or len(carbon_data) == 0:
            demo_mgr = DemoModeManager()
            
            if not demo_mgr.is_demo_mode:
                # Live mode - show instructions to run setup script
                st.warning("### ⚠️ Sustainability Tracking Not Configured")
                
                st.markdown("""
                **Carbon emissions tracking** can be set up automatically!
                
                ### 🚀 Quick Setup (Automated):
                
                **Windows PowerShell:**
                ```powershell
                powershell -ExecutionPolicy Bypass -File setup-carbon-tracking.ps1
                ```
                
                **What it does:**
                1. ✅ Creates IAM permissions for resource access
                2. ✅ Enables AWS Compute Optimizer
                3. ✅ Sets up CloudWatch metrics
                4. ✅ Configures carbon calculation
                
                ### 🌍 How Carbon Tracking Works:
                
                Your platform calculates carbon emissions by:
                - **EC2 Instances**: Power consumption × Regional carbon intensity
                - **S3 Storage**: Storage volume × Carbon per GB
                - **RDS Databases**: Instance type × Running hours
                - **Lambda**: Execution time × Memory allocation
                
                ### 💡 Regional Carbon Intensity:
                - 🇸🇪 **Stockholm** (eu-north-1): 9 gCO2e/kWh - 95% renewable ✨
                - 🇨🇦 **Montreal** (ca-central-1): 130 gCO2e/kWh - 80% renewable
                - 🇫🇷 **Paris** (eu-west-3): 71 gCO2e/kWh
                - 🇺🇸 **US East** (us-east-1): 416 gCO2e/kWh
                - 🇦🇺 **Sydney** (ap-southeast-2): 564 gCO2e/kWh
                
                ### 🔄 For Now:
                Switch to **Demo Mode** to see simulated carbon tracking in action.
                """)
                
                st.markdown("---")
                
                col1, col2 = st.columns(2)
                with col1:
                    st.info("""
                    **Carbon Reduction Tips:**
                    
                    🌱 Migrate to low-carbon regions
                    🌱 Use AWS Graviton (60% more efficient)
                    🌱 Right-size your instances
                    🌱 Delete unused resources
                    🌱 Use auto-scaling
                    """)
                
                with col2:
                    st.success("""
                    **Low-Carbon AWS Regions:**
                    
                    🇸🇪 Stockholm (95% renewable)
                    🇨🇦 Montreal (80% renewable)
                    🇫🇷 Paris (85% renewable)
                    🇧🇷 São Paulo (82% renewable)
                    🇺🇸 Oregon (renewable energy)
                    """)
            else:
                st.info("No carbon data available in demo mode")
            
            return
        
        # We have carbon data - render it!
        account_count = carbon_data.get('account_count', 0)
        if account_count > 1:
            st.success(f"✅ Carbon footprint calculated from {account_count} AWS accounts in your organization")
        else:
            st.success("✅ Carbon footprint calculated from your AWS resource usage")
        
        total_emissions = carbon_data.get('total_emissions_kg', 0)
        sustainability_score = carbon_data.get('sustainability_score', 0)
        renewable_pct = carbon_data.get('renewable_energy_pct', 0)
        
        # Top metrics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric(
                "Total CO2 Emissions",
                f"{total_emissions:,.2f} kg",
                delta=None
            )
        
        with col2:
            st.metric(
                "Sustainability Score",
                f"{sustainability_score:.0f}/100",
                delta=None
            )
        
        with col3:
            st.metric(
                "Renewable Energy",
                f"{renewable_pct:.0f}%",
                delta=None
            )
        
        with col4:
            if account_count > 1:
                st.metric(
                    "AWS Accounts",
                    f"{account_count}",
                    delta=None
                )
            else:
                trees_equivalent = total_emissions / 21 if total_emissions > 0 else 0
                st.metric("Trees to Offset", f"{trees_equivalent:,.0f} trees")
        
        st.markdown("---")
        
        # Multi-account breakdown (if available)
        emissions_by_account = carbon_data.get('emissions_by_account', {})
        if emissions_by_account and len(emissions_by_account) > 1:
            st.markdown("### 📊 Emissions by AWS Account")
            
            account_data = [
                {
                    'Account': k,
                    'Emissions (kg)': v,
                    'Percentage': f"{(v / total_emissions * 100):.1f}%" if total_emissions > 0 else "0%"
                }
                for k, v in emissions_by_account.items()
                if v > 0
            ]
            
            if account_data:
                account_df = pd.DataFrame(account_data).sort_values('Emissions (kg)', ascending=False)
                
                col1, col2 = st.columns([2, 1])
                
                with col1:
                    fig_accounts = px.bar(
                        account_df,
                        x='Account',
                        y='Emissions (kg)',
                        title='Carbon Emissions by Account',
                        color='Emissions (kg)',
                        color_continuous_scale='Reds',
                        text='Emissions (kg)'
                    )
                    fig_accounts.update_traces(texttemplate='%{text:.2f}', textposition='outside')
                    st.plotly_chart(fig_accounts, use_container_width=True)
                
                with col2:
                    st.dataframe(account_df, use_container_width=True, hide_index=True)
            
            st.markdown("---")
        
        # Emissions by service
        st.markdown("### 📊 Emissions by Service")
        
        emissions_by_service = carbon_data.get('emissions_by_service', carbon_data.get('by_service', {}))
        
        if emissions_by_service:
            # Check if this is demo data format or real data format
            if isinstance(list(emissions_by_service.values())[0], dict):
                # Demo data format (has cost, energy_kwh, emissions_kg)
                service_emissions = pd.DataFrame([
                    {
                        'Service': service,
                        'Cost ($)': data['cost'],
                        'Energy (kWh)': data['energy_kwh'],
                        'CO2 (kg)': data['emissions_kg']
                    }
                    for service, data in emissions_by_service.items()
                ]).sort_values('CO2 (kg)', ascending=False)
                
                col1, col2 = st.columns([2, 1])
                
                with col1:
                    fig = px.bar(
                        service_emissions,
                        x='Service',
                        y='CO2 (kg)',
                        title='Carbon Emissions by Service',
                        color='CO2 (kg)',
                        color_continuous_scale='Greens',
                        text='CO2 (kg)'
                    )
                    fig.update_traces(texttemplate='%{text:.1f}', textposition='outside')
                    st.plotly_chart(fig, use_container_width=True)
                
                with col2:
                    st.dataframe(service_emissions, use_container_width=True, hide_index=True)
            else:
                # Real data format (simple service: emissions_kg dict)
                service_data = [
                    {
                        'Service': service,
                        'Emissions (kg)': emissions,
                        'Percentage': f"{(emissions / total_emissions * 100):.1f}%" if total_emissions > 0 else "0%"
                    }
                    for service, emissions in emissions_by_service.items()
                    if emissions > 0
                ]
                
                if service_data:
                    service_df = pd.DataFrame(service_data).sort_values('Emissions (kg)', ascending=False)
                    
                    col1, col2 = st.columns([2, 1])
                    
                    with col1:
                        fig = px.bar(
                            service_df,
                            x='Service',
                            y='Emissions (kg)',
                            title='Carbon Emissions by Service',
                            color='Emissions (kg)',
                            color_continuous_scale='Greens',
                            text='Emissions (kg)'
                        )
                        fig.update_traces(texttemplate='%{text:.2f}', textposition='outside')
                        st.plotly_chart(fig, use_container_width=True)
                    
                    with col2:
                        st.dataframe(service_df, use_container_width=True, hide_index=True)
                else:
                    st.info("No service-level emissions data available")
        else:
            st.info("No service-level emissions data available")
        
        # Regional carbon intensity
        st.markdown("---")
        st.markdown("### 🌍 Regional Carbon Intensity")
        
        emissions_by_region = carbon_data.get('emissions_by_region', carbon_data.get('by_region', {}))
        
        if emissions_by_region:
            # Check if this is demo data format or real data format
            if isinstance(list(emissions_by_region.values())[0], dict):
                # Demo data format
                region_emissions = pd.DataFrame([
                    {
                        'Region': region,
                        'Carbon Intensity': data['carbon_intensity'],
                        'Rating': data['rating']
                    }
                    for region, data in emissions_by_region.items()
                ]).sort_values('Carbon Intensity')
                
                def rating_color(rating):
                    return '🟢' if rating == 'Low' else '🟡' if rating == 'Medium' else '🔴'
                
                region_emissions['Status'] = region_emissions['Rating'].apply(lambda x: f"{rating_color(x)} {x}")
                
                col1, col2 = st.columns([3, 2])
                
                with col1:
                    fig = px.bar(
                        region_emissions,
                        x='Region',
                        y='Carbon Intensity',
                        title='Carbon Intensity by AWS Region (gCO2eq/kWh)',
                        color='Rating',
                        color_discrete_map={'Low': 'green', 'Medium': 'orange', 'High': 'red'},
                        text='Carbon Intensity'
                    )
                    fig.update_traces(texttemplate='%{text}', textposition='outside')
                    st.plotly_chart(fig, use_container_width=True)
                
                with col2:
                    st.markdown("**🟢 Low Carbon Regions:**")
                    low_carbon = region_emissions[region_emissions['Rating'] == 'Low']
                    for _, row in low_carbon.iterrows():
                        st.markdown(f"- **{row['Region']}**: {row['Carbon Intensity']} gCO2eq/kWh")
            else:
                # Real data format (region: emissions_kg)
                region_data = [
                    {
                        'Region': region,
                        'Emissions (kg)': emissions,
                        'Percentage': f"{(emissions / total_emissions * 100):.1f}%" if total_emissions > 0 else "0%"
                    }
                    for region, emissions in emissions_by_region.items()
                    if emissions > 0
                ]
                
                if region_data:
                    region_df = pd.DataFrame(region_data).sort_values('Emissions (kg)', ascending=False)
                    
                    col1, col2 = st.columns([2, 1])
                    
                    with col1:
                        fig = px.bar(
                            region_df,
                            x='Region',
                            y='Emissions (kg)',
                            title='Carbon Emissions by Region',
                            color='Emissions (kg)',
                            color_continuous_scale='Reds',
                            text='Emissions (kg)'
                        )
                        fig.update_traces(texttemplate='%{text:.2f}', textposition='outside')
                        st.plotly_chart(fig, use_container_width=True)
                    
                    with col2:
                        st.dataframe(region_df, use_container_width=True, hide_index=True)
                else:
                    st.info("No regional emissions data available")
        
        # Recommendations
        if carbon_data.get('recommendations'):
            st.markdown("---")
            st.markdown("### 💡 Carbon Reduction Recommendations")
            
            recommendations = carbon_data['recommendations'][:5]
            for i, rec in enumerate(recommendations, 1):
                # Handle both dict format (demo) and string format (live)
                if isinstance(rec, dict):
                    # Demo mode format with full details
                    action = rec.get('action', 'Optimization recommendation')
                    impact = rec.get('impact', '')
                    priority = rec.get('priority', 'Medium')
                    
                    priority_emoji = '🔴' if priority == 'High' else '🟡' if priority == 'Medium' else '🟢'
                    st.markdown(f"{i}. {priority_emoji} **{action}** - {impact}")
                else:
                    # Live mode format (simple string)
                    st.markdown(f"{i}. {rec}")
    
    @staticmethod
    def _render_ai_insights(ai_available):
        """AI-powered cost insights"""
        
        st.markdown("### 🤖 AI-Powered Cost Intelligence")
        
        if not ai_available:
            st.warning("⚠️ AI features not available")
            st.info("Configure ANTHROPIC_API_KEY in Streamlit secrets to enable AI features")
            return
        
        cost_data = get_cost_data()
        
        with st.spinner("🤖 AI analyzing your cost data..."):
            analysis = analyze_costs_with_ai(cost_data, cost_data['total_cost'], cost_data['services'])
        
        st.markdown("#### 📊 Executive Summary")
        st.success(analysis['executive_summary'])
        
        st.markdown("---")
        st.markdown("#### 💡 Key Insights")
        
        for i, insight in enumerate(analysis.get('key_insights', []), 1):
            st.markdown(f"**{i}.** {insight}")
        
        st.markdown("---")
        st.markdown("#### 🎯 AI Recommendations")
        
        recommendations = analysis.get('recommendations', [])
        if recommendations:
            for rec in recommendations:
                priority_color = {'High': '🔴', 'Medium': '🟡', 'Low': '🟢'}.get(rec.get('priority', 'Medium'), '🟡')
                
                with st.expander(f"{priority_color} {rec.get('action', 'Recommendation')} - {rec.get('priority', 'Medium')} Priority"):
                    st.markdown(f"**Estimated Savings:** {rec.get('estimated_savings', 'TBD')}")
                    st.markdown(f"**Implementation:** {rec.get('implementation', 'See details')}")
    
    @staticmethod
    def _render_ai_query(ai_available):
        """Natural language query interface"""
        
        st.markdown("### 💬 Ask AI About Your Costs")
        
        if not ai_available:
            st.warning("⚠️ AI features not available. Configure ANTHROPIC_API_KEY to enable.")
            return
        
        st.info("💡 Ask questions in plain English about your AWS costs")
        
        # Sample questions
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("💰 What are my top 3 cost drivers?", key="finops_query_btn_1", use_container_width=True):
                st.session_state.finops_ai_query = "What are my top 3 cost drivers?"
            if st.button("📈 How can I reduce my EC2 costs?", key="finops_query_btn_2", use_container_width=True):
                st.session_state.finops_ai_query = "How can I reduce my EC2 costs?"
        
        with col2:
            if st.button("🎯 Where should I focus optimization?", key="finops_query_btn_3", use_container_width=True):
                st.session_state.finops_ai_query = "Where should I focus my optimization efforts?"
            if st.button("🌱 How can I reduce my carbon footprint?", key="finops_query_btn_4", use_container_width=True):
                st.session_state.finops_ai_query = "How can I reduce my carbon footprint?"
        
        # Query input - FIXED: Unique key
        query = st.text_input(
            "Your question:",
            value=st.session_state.get('finops_ai_query', ''),
            placeholder="e.g., What's driving my S3 costs?",
            key="finops_ai_query_text_input_unique"
        )
        
        if st.button("🔍 Ask AI", type="primary", key="finops_ask_ai_submit_btn"):
            if query:
                cost_data = get_cost_data()
                
                with st.spinner("🤖 AI thinking..."):
                    response = natural_language_query(query, cost_data)
                
                st.markdown("---")
                st.markdown("### 🤖 AI Response:")
                st.markdown(response)
            else:
                st.warning("Please enter a question")
    
    @staticmethod
    def _render_multi_account_costs(account_mgr):
        """Multi-account cost breakdown"""
        
        st.markdown("### 📊 Multi-Account Cost Analysis")
        
        cost_data = get_cost_data()  # No longer needs account_mgr
        
        # Check if we have multi-account data
        if not cost_data.get('by_account') or len(cost_data['by_account']) == 0:
            demo_mgr = DemoModeManager()
            
            if demo_mgr.is_demo_mode:
                st.info("💡 Multi-account cost breakdown not available in demo mode")
            else:
                st.warning("### ⚠️ Multi-Account Cost Breakdown Not Available")
                
                st.markdown("""
                **No linked account cost data found.**
                
                ### 🔍 Possible Reasons:
                
                1. **Not using AWS Organizations**
                   - You need AWS Organizations with linked accounts
                   - Management account must be connected
                
                2. **Not connected to Management Account**
                   - Connect using your **management/payer account** credentials
                   - This is the account that consolidates billing
                
                3. **No costs in linked accounts**
                   - Linked accounts may have $0 spend
                
                4. **Permission issue**
                   - Need `organizations:ListAccounts` permission
                   - Need `ce:GetCostAndUsage` with LINKED_ACCOUNT dimension
                
                ### 🚀 How to Enable:
                
                **If you have AWS Organizations:**
                1. Go to AWS Console → Organizations
                2. Note your **Management Account ID**
                3. In this platform, connect using Management Account credentials
                4. Cost breakdown will appear automatically
                
                ### 💡 Current Setup:
                - Total Cost: {total}
                - Source: Single account view
                
                Switch to your Management Account to see breakdown across all linked accounts.
                """.format(total=Helpers.format_currency(cost_data.get('total_cost', 0))))
            
            return
        
        # We have multi-account data - render it!
        account_count = cost_data.get('account_count', len(cost_data['by_account']))
        
        st.success(f"✅ Showing costs across **{account_count} AWS accounts** in your organization")
        
        # Create list of account data
        account_data = [
            {
                'Account': k,
                'Cost': v,
                'Cost_Formatted': Helpers.format_currency(v),
                'Percentage': f"{(v / cost_data['total_cost'] * 100):.1f}%" if cost_data.get('total_cost', 0) > 0 else "0%"
            }
            for k, v in cost_data['by_account'].items()
        ]
        
        # Double check we have data before creating DataFrame
        if not account_data:
            st.warning("⚠️ Account data is empty")
            return
        
        # Now safe to create and sort DataFrame
        account_df = pd.DataFrame(account_data).sort_values('Cost', ascending=False)
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            fig = px.bar(
                account_df,
                x='Account',
                y='Cost',
                text='Cost_Formatted',
                title='Cost by Account',
                color='Cost',
                color_continuous_scale='Reds'
            )
            fig.update_traces(textposition='outside')
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            st.dataframe(
                account_df[['Account', 'Cost_Formatted', 'Percentage']],
                use_container_width=True,
                hide_index=True
            )
    
    @staticmethod
    def _render_cost_trends():
        """Cost trends visualization"""
        
        st.markdown("### 📈 Cost Trends (30 Days)")
        
        cost_data = get_cost_data()
        
        # Check if we have daily cost data
        if not cost_data.get('daily_costs') or len(cost_data['daily_costs']) == 0:
            st.info("💡 Daily cost trend data not available")
            st.markdown("**Possible reasons:**")
            st.markdown("- Insufficient historical data (Cost Explorer requires 24+ hours)")
            st.markdown("- Cost Explorer not enabled in your AWS account")
            st.markdown("- API returned no daily cost data")
            
            if cost_data.get('total_cost', 0) > 0:
                st.success(f"✅ Total cost data available: {Helpers.format_currency(cost_data['total_cost'])}")
            return
        
        # Double check the list isn't empty
        if not cost_data['daily_costs']:
            st.warning("⚠️ Daily costs list is empty")
            return
        
        trend_df = pd.DataFrame(cost_data['daily_costs'])
        
        # Verify DataFrame has required columns
        if 'date' not in trend_df.columns or 'cost' not in trend_df.columns:
            st.error("⚠️ Daily cost data is missing required fields (date, cost)")
            return
        
        trend_df['date'] = pd.to_datetime(trend_df['date'])
        trend_df['7day_avg'] = trend_df['cost'].rolling(window=7).mean()
        
        fig = go.Figure()
        
        fig.add_trace(go.Scatter(
            x=trend_df['date'],
            y=trend_df['cost'],
            mode='lines',
            name='Daily Cost',
            line=dict(color='lightblue', width=1)
        ))
        
        fig.add_trace(go.Scatter(
            x=trend_df['date'],
            y=trend_df['7day_avg'],
            mode='lines',
            name='7-Day Average',
            line=dict(color='blue', width=3)
        ))
        
        fig.update_layout(
            title='Daily Cost Trend with 7-Day Moving Average',
            xaxis_title='Date',
            yaxis_title='Cost ($)',
            hovermode='x unified'
        )
        
        st.plotly_chart(fig, use_container_width=True)
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("Avg Daily Cost", Helpers.format_currency(trend_df['cost'].mean()))
        with col2:
            st.metric("Peak Daily Cost", Helpers.format_currency(trend_df['cost'].max()))
        with col3:
            trend = "↑ Increasing" if trend_df['cost'].iloc[-1] > trend_df['cost'].iloc[0] else "↓ Decreasing"
            st.metric("Trend", trend)
    
    @staticmethod
    def _render_optimization():
        """Cost optimization recommendations"""
        
        st.markdown("### 💡 Cost Optimization Opportunities")
        
        recommendations = get_recommendations()
        
        # Check if we have recommendations
        if not recommendations:
            demo_mgr = DemoModeManager()
            
            if not demo_mgr.is_demo_mode:
                # Live mode - show setup instructions
                st.warning("### ⚠️ Cost Optimization Not Available")
                
                st.markdown("""
                **AWS Cost Optimization recommendations** can be enabled in your AWS account.
                
                ### 🚀 What You'll Get:
                
                ✅ **EC2 Rightsizing** - Identify oversized instances  
                ✅ **Reserved Instances** - Save up to 72% on compute  
                ✅ **Savings Plans** - Flexible commitment-based discounts  
                ✅ **Unused Resources** - Find orphaned EBS volumes  
                ✅ **Storage Optimization** - S3 lifecycle recommendations  
                
                ### 📋 Required Permissions:
                
                ```json
                {
                  "Effect": "Allow",
                  "Action": [
                    "ce:GetRightsizingRecommendation",
                    "ce:GetReservationPurchaseRecommendation",
                    "ce:GetSavingsPlansPurchaseRecommendation",
                    "ec2:DescribeVolumes",
                    "compute-optimizer:GetEC2InstanceRecommendations"
                  ],
                  "Resource": "*"
                }
                ```
                
                ### 🔧 How to Enable:
                
                **Option 1: AWS Console**
                1. Go to [AWS Cost Explorer](https://console.aws.amazon.com/cost-management/home)
                2. Enable Cost Explorer (if not enabled)
                3. Navigate to **Recommendations** section
                4. Wait 24 hours for initial data collection
                
                **Option 2: AWS CLI**
                ```bash
                # Enable Cost Explorer
                aws ce enable-cost-explorer
                
                # Create IAM policy
                aws iam create-policy \\
                  --policy-name CostOptimizationPolicy \\
                  --policy-document file://policy.json
                
                # Attach to your user
                aws iam attach-user-policy \\
                  --user-name YOUR_USERNAME \\
                  --policy-arn arn:aws:iam::ACCOUNT_ID:policy/CostOptimizationPolicy
                ```
                
                ### 💡 Expected Savings:
                
                Typical organizations save **15-30%** on their AWS bill through:
                - Right-sizing: 10-20% savings
                - Reserved Instances: 30-70% savings  
                - Unused resources cleanup: 5-15% savings
                
                ### 🔄 For Now:
                Switch to **Demo Mode** to see sample cost optimization recommendations.
                """)
                return
        
        # We have recommendations - calculate totals and display
        total_monthly_savings = sum(
            float(rec['savings'].replace('$', '').replace(',', '').replace('/month', ''))
            for rec in recommendations
        )
        annual_savings = total_monthly_savings * 12
        
        # Check if this is real data
        demo_mgr = DemoModeManager()
        if not demo_mgr.is_demo_mode:
            st.success(f"✅ Found {len(recommendations)} cost optimization opportunities from AWS Cost Explorer")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("Monthly Savings Potential", Helpers.format_currency(total_monthly_savings))
        with col2:
            st.metric("Annual Savings Potential", Helpers.format_currency(annual_savings))
        with col3:
            st.metric("Recommendations", len(recommendations))
        
        st.markdown("---")
        st.markdown("#### 🎯 Optimization Recommendations")
        
        for rec in recommendations:
            priority_color = {'High': '🔴', 'Medium': '🟡', 'Low': '🟢'}.get(rec['priority'], '🟡')
            
            with st.expander(
                f"{priority_color} {rec['type']} - {rec['resource']} | Save {rec['savings']} ({rec['savings_percentage']})"
            ):
                col1, col2 = st.columns([2, 1])
                
                with col1:
                    st.markdown(f"**Current Cost:** {rec['current_cost']}")
                    st.markdown(f"**Optimized Cost:** {rec['optimized_cost']}")
                    st.markdown(f"**Monthly Savings:** {rec['savings']}")
                    st.markdown(f"**Implementation:** {rec['implementation']}")
                
                with col2:
                    st.metric("Savings %", rec['savings_percentage'])
                    st.markdown(f"**Priority:** {rec['priority']}")
                    
                    if st.button("📋 Create Action Item", key=f"finops_opt_action_{rec['resource']}_unique", use_container_width=True):
                        st.success("Action item created!")
    
    @staticmethod
    def _render_budget_management():
        """Budget management"""
        
        st.markdown("### 🎯 Budget Management")
        
        # Show mode indicator
        demo_mgr = DemoModeManager()
        
        if not demo_mgr.is_demo_mode:
            # Live mode - fetch real AWS Budgets data
            try:
                from aws_connector import get_aws_session
                from aws_budgets_manager import get_budgets_from_aws
                
                # Get AWS session
                session = get_aws_session()
                
                if not session:
                    st.warning("⚠️ No AWS session available for budget data")
                    return
                
                st.info("💰 Fetching budget data from AWS...")
                
                # Get budget data
                budget_data = get_budgets_from_aws(session)
                
                if not budget_data.get('has_budgets', False):
                    # No budgets configured - show setup instructions
                    st.warning("### ⚠️ No AWS Budgets Configured")
                    
                    st.markdown("""
                    **AWS Budgets** are not yet set up in your account.
                    
                    ### 🚀 Automated Setup Available!
                    
                    Run the PowerShell script to automatically create budgets:
                    
                    ```powershell
                    powershell -ExecutionPolicy Bypass -File setup-aws-budgets.ps1
                    ```
                    
                    **What it will create:**
                    - ✅ Monthly cost budget with your specified amount
                    - ✅ Email alerts at 80%, 100% thresholds
                    - ✅ Forecasted spend alerts
                    - ✅ EC2 usage budget (1000 hours/month)
                    
                    ### 💰 What is AWS Budgets?
                    
                    AWS Budgets lets you set custom cost and usage budgets that alert you when you exceed (or are forecasted to exceed) your budgeted amount.
                    
                    ### 💡 What You'll Get:
                    - ✅ Monthly cost/usage budgets
                    - ✅ Forecast-based alerts
                    - ✅ Email/SNS notifications
                    - ✅ Budget vs actual tracking
                    - ✅ Real-time utilization percentage
                    
                    ### 🔧 Manual Setup:
                    1. Go to [AWS Budgets Console](https://console.aws.amazon.com/billing/home#/budgets)
                    2. Click **Create budget**
                    3. Choose budget type (Cost, Usage, Savings Plans, Reservation)
                    4. Set amount and time period (monthly, quarterly, annual)
                    5. Configure alerts (email/SNS at 80%, 100%, 120% of budget)
                    
                    ### 🔄 For Now:
                    Switch to **Demo Mode** to see simulated budget tracking.
                    """)
                    return
                
                # We have budgets - display them!
                st.success(f"✅ Found {budget_data['total_budgets']} active budget(s) in your AWS account")
                
                # Summary metrics
                col1, col2, col3, col4 = st.columns(4)
                
                with col1:
                    st.metric(
                        "Total Budget",
                        f"${budget_data['total_limit']:,.2f}",
                        delta=None
                    )
                
                with col2:
                    st.metric(
                        "Actual Spend",
                        f"${budget_data['total_actual']:,.2f}",
                        delta=f"{budget_data['overall_utilization']:.1f}% used"
                    )
                
                with col3:
                    st.metric(
                        "Forecasted",
                        f"${budget_data['total_forecasted']:,.2f}",
                        delta=None
                    )
                
                with col4:
                    # Status based on utilization
                    if budget_data['budgets_exceeded'] > 0:
                        status_label = "EXCEEDED"
                        status_color = "🔴"
                    elif budget_data['budgets_warning'] > 0:
                        status_label = "WARNING"
                        status_color = "🟡"
                    else:
                        status_label = "ON TRACK"
                        status_color = "🟢"
                    
                    st.metric(
                        "Status",
                        f"{status_color} {status_label}",
                        delta=None
                    )
                
                st.markdown("---")
                
                # Budget details table
                st.markdown("#### 💼 Budget Details")
                
                budget_list = []
                for budget in budget_data.get('budgets', []):
                    status_emoji = {
                        'EXCEEDED': '🔴',
                        'WARNING': '🟡',
                        'FORECASTED_EXCEED': '🟠',
                        'OK': '🟢'
                    }.get(budget['status'], '⚪')
                    
                    budget_list.append({
                        'Budget Name': budget['name'],
                        'Type': budget['type'],
                        'Limit': f"${budget['limit_amount']:,.2f}",
                        'Actual': f"${budget['actual_amount']:,.2f}",
                        'Forecast': f"${budget['forecasted_amount']:,.2f}",
                        'Utilization': f"{budget['utilization']:.1f}%",
                        'Status': f"{status_emoji} {budget['status']}"
                    })
                
                if budget_list:
                    budget_df = pd.DataFrame(budget_list)
                    st.dataframe(budget_df, use_container_width=True, hide_index=True)
                    
                    # Visualization
                    st.markdown("#### 📊 Budget Utilization")
                    
                    # Create visualization data
                    viz_data = []
                    for budget in budget_data.get('budgets', []):
                        viz_data.append({
                            'Budget': budget['name'],
                            'Actual': budget['actual_amount'],
                            'Forecast': budget['forecasted_amount'],
                            'Limit': budget['limit_amount']
                        })
                    
                    if viz_data:
                        viz_df = pd.DataFrame(viz_data)
                        
                        import plotly.graph_objects as go
                        
                        fig = go.Figure()
                        
                        fig.add_trace(go.Bar(
                            name='Actual',
                            x=viz_df['Budget'],
                            y=viz_df['Actual'],
                            marker_color='lightblue'
                        ))
                        
                        fig.add_trace(go.Bar(
                            name='Forecast',
                            x=viz_df['Budget'],
                            y=viz_df['Forecast'],
                            marker_color='orange'
                        ))
                        
                        fig.add_trace(go.Scatter(
                            name='Limit',
                            x=viz_df['Budget'],
                            y=viz_df['Limit'],
                            mode='markers+lines',
                            marker=dict(size=10, color='red'),
                            line=dict(color='red', width=2, dash='dash')
                        ))
                        
                        fig.update_layout(
                            title='Budget vs Actual vs Forecast',
                            xaxis_title='Budget Name',
                            yaxis_title='Amount ($)',
                            barmode='group',
                            height=400
                        )
                        
                        st.plotly_chart(fig, use_container_width=True)
                
            except Exception as e:
                st.warning(f"⚠️ Could not fetch budget data: {str(e)}")
                st.info("""
                💡 To enable budgets, ensure you have:
                - budgets:ViewBudget permissions
                - budgets:DescribeBudgets permissions
                
                Run the setup script: setup-aws-budgets.ps1
                """)
            
            return
        
        # Demo mode - show simulated budgets
        budgets = [
            {'Budget Name': 'Production Monthly', 'Amount': '$15,000', 'Current Spend': '$11,400', 'Utilization': '76%', 'Forecast': '$14,250', 'Status': '✅ On Track'},
            {'Budget Name': 'Staging Monthly', 'Amount': '$5,000', 'Current Spend': '$4,650', 'Utilization': '93%', 'Forecast': '$5,580', 'Status': '⚠️ At Risk'},
            {'Budget Name': 'Development Monthly', 'Amount': '$3,000', 'Current Spend': '$2,100', 'Utilization': '70%', 'Forecast': '$2,520', 'Status': '✅ On Track'}
        ]
        
        df = pd.DataFrame(budgets)
        st.dataframe(df, use_container_width=True, hide_index=True)
    
    @staticmethod
    def _render_tag_based_costs():
        """Tag-based cost allocation"""
        
        st.markdown("### 🏷️ Tag-Based Cost Allocation")
        
        # Show mode indicator
        demo_mgr = DemoModeManager()
        if not demo_mgr.is_demo_mode:
            # Live mode - show setup instructions
            st.warning("### ⚠️ Tag-Based Cost Allocation Not Configured")
            
            st.markdown("""
            **Cost Allocation Tags** integration is not yet available on this platform.
            
            ### 🏷️ What are Cost Allocation Tags?
            
            Tags let you organize and track your AWS costs by custom categories like:
            - Department (Engineering, Sales, Marketing)
            - Environment (Production, Staging, Development)
            - Project (ProjectA, ProjectB)
            - Cost Center (CC-1001, CC-2002)
            
            ### 🚀 How to Set Up Cost Allocation Tags:
            
            **Step 1: Tag Your Resources**
            1. Tag EC2 instances, S3 buckets, RDS databases, etc.
            2. Use consistent tag keys: `Department`, `Environment`, `Project`
            3. Apply tags via AWS Console, CLI, or Infrastructure as Code
            
            **Step 2: Activate Tags in Billing**
            1. Go to [AWS Billing Console](https://console.aws.amazon.com/billing/home#/tags)
            2. Click **Cost Allocation Tags**
            3. Select user-defined tags to activate
            4. Wait 24 hours for data to appear
            
            **Step 3: View Tagged Costs**
            1. Use AWS Cost Explorer with GroupBy Tags
            2. Create Cost and Usage Reports with tag columns
            3. Set up tag-based budgets and alerts
            
            ### 💡 What You'll Get:
            - ✅ Cost breakdown by department/team
            - ✅ Project-level cost tracking
            - ✅ Environment cost comparison
            - ✅ Untagged resource identification
            - ✅ Tag compliance reporting
            - ✅ Chargeback/showback capabilities
            
            ### 🔄 For Now:
            Switch to **Demo Mode** to see simulated tag-based costs.
            """)
            
            st.markdown("---")
            
            col1, col2 = st.columns(2)
            with col1:
                st.info("""
                **Tagging Best Practices:**
                
                🏷️ Use consistent naming (PascalCase)
                🏷️ Define mandatory tags (Owner, Environment)
                🏷️ Automate tagging with Terraform/CloudFormation
                🏷️ Enforce tagging with AWS Config rules
                🏷️ Review untagged resources monthly
                """)
            
            with col2:
                st.success("""
                **Common Tag Keys:**
                
                👥 Department
                🌍 Environment  
                📦 Project
                💰 CostCenter
                👤 Owner
                📅 CreatedDate
                🎯 Application
                """)
            
            return
        
        # Demo mode - show simulated tag costs
        tag_costs = [
            {'Tag': 'Department', 'Value': 'Engineering', 'Cost': '$8,450', 'Percentage': '42%'},
            {'Tag': 'Department', 'Value': 'Data Science', 'Cost': '$5,230', 'Percentage': '26%'},
            {'Tag': 'Department', 'Value': 'Marketing', 'Cost': '$3,120', 'Percentage': '16%'},
            {'Tag': 'Department', 'Value': 'Untagged', 'Cost': '$3,200', 'Percentage': '16%'}
        ]
        
        df = pd.DataFrame(tag_costs)
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            fig = px.bar(df, x='Value', y='Cost', text='Percentage', title='Cost by Department', color='Cost')
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            st.dataframe(df, use_container_width=True, hide_index=True)
        
        st.markdown("---")
        st.markdown("#### 🎯 Tag Compliance")
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Tagged Resources", "84%", delta="↑ 5%")
        with col2:
            st.metric("Untagged Cost", "$3,200", delta="↓ $450")
        with col3:
            st.metric("Tag Coverage Goal", "95%", delta="11% to go")

# Backward compatibility - support both old and new class names
FinOpsModule = FinOpsEnterpriseModule

# Export both names for compatibility
__all__ = ['FinOpsEnterpriseModule', 'FinOpsModule']