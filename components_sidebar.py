"""
Multi-Cloud Global Sidebar Component
Supports AWS, Azure, and GCP with provider-specific filters
"""

import streamlit as st
from core_session_manager import SessionManager
from config_settings import AppConfig
from datetime import datetime

class GlobalSidebar:
    """Global sidebar with cloud provider-aware filters and controls"""
    
    @staticmethod
    def render(cloud_provider=None):
        """Render global sidebar based on selected cloud provider"""
        
        # Initialize session state first
        SessionManager.initialize()
        
        # Get cloud provider from parameter or session state
        if cloud_provider is None:
            cloud_provider = st.session_state.get('cloud_provider', 'AWS')
        
        with st.sidebar:
            # Cloud Provider Display
            cloud_icons = {"AWS": "☁️", "Azure": "🔷", "GCP": "🔴"}
            cloud_colors = {"AWS": "#FF9900", "Azure": "#0078D4", "GCP": "#4285F4"}
            
            st.markdown(f"""
            <div style="
                background: linear-gradient(135deg, {cloud_colors.get(cloud_provider, '#666')} 0%, #333 100%);
                padding: 15px;
                border-radius: 8px;
                text-align: center;
                margin-bottom: 20px;
            ">
                <h2 style="color: white; margin: 0; font-size: 1.5em;">
                    {cloud_icons.get(cloud_provider, '☁️')} {cloud_provider} Mode
                </h2>
            </div>
            """, unsafe_allow_html=True)
            
            # Demo/Live Mode Toggle
            st.markdown("### 🔄 Data Mode")
            mode = st.radio(
                "Select Mode",
                ["Live", "Demo"],
                index=0 if st.session_state.get('mode', 'Live') == 'Live' else 1,
                help=f"Live: Real {cloud_provider} data | Demo: Sample data for testing",
                horizontal=True
            )
            
            if mode != st.session_state.get('mode'):
                st.session_state.mode = mode
                st.rerun()
            
            if mode == "Demo":
                st.info(f"📊 Demo Mode - Using sample {cloud_provider} data")
            else:
                st.success(f"🔴 Live - Real {cloud_provider} data")
            
            st.markdown("---")
            
            st.markdown("### 🎛️ Global Filters")
            
            # Load appropriate accounts/subscriptions/projects based on cloud provider
            if cloud_provider == "AWS":
                accounts = AppConfig.load_aws_accounts()
                active_items = [acc for acc in accounts if acc.status == 'active']
                item_label = "Accounts"
                item_options = ['All Accounts'] + [f"{acc.account_name} ({acc.account_id})" for acc in active_items]
            elif cloud_provider == "Azure":
                subscriptions = AppConfig.load_azure_subscriptions()
                active_items = [sub for sub in subscriptions if sub.status == 'active']
                item_label = "Subscriptions"
                item_options = ['All Subscriptions'] + [f"{sub.subscription_name} ({sub.subscription_id[:8]}...)" for sub in active_items]
            else:  # GCP
                projects = AppConfig.load_gcp_projects()
                active_items = [proj for proj in projects if proj.status == 'active']
                item_label = "Projects"
                item_options = ['All Projects'] + [f"{proj.project_name} ({proj.project_id})" for proj in active_items]
            
            # Item selector
            selected_item = st.selectbox(
                item_label,
                options=item_options,
                help=f"Select {cloud_provider} {item_label.lower()} to filter resources"
            )
            
            # Update session state based on selection (cloud-agnostic)
            all_label = f'All {item_label}'
            if selected_item == all_label:
                st.session_state.selected_items = 'all'
            else:
                # Extract ID from selection (works for all cloud types)
                if '(' in selected_item and ')' in selected_item:
                    item_id = selected_item.split('(')[1].split(')')[0]
                    st.session_state.selected_items = item_id
            
            # Region selector (cloud-specific regions)
            if cloud_provider == "AWS":
                region_list = AppConfig.AWS_REGIONS
                region_help = "Select AWS region"
            elif cloud_provider == "Azure":
                region_list = AppConfig.AZURE_REGIONS
                region_help = "Select Azure region/location"
            else:  # GCP
                region_list = AppConfig.GCP_REGIONS
                region_help = "Select GCP region"
            
            region_options = ['All Regions'] + region_list
            selected_region = st.selectbox(
                "Region",
                options=region_options,
                help=region_help
            )
            
            # Update session state
            if selected_region == 'All Regions':
                st.session_state.selected_regions = 'all'
            else:
                st.session_state.selected_regions = selected_region
            
            # Environment filter
            env_options = ['All Environments', 'Production', 'Development', 'Staging', 'Sandbox']
            selected_env = st.selectbox(
                "Environment",
                options=env_options
            )
            
            st.session_state.selected_environment = 'all' if selected_env == 'All Environments' else selected_env.lower()
            
            st.markdown("---")
            
            # Time range for analytics
            st.markdown("### 📅 Time Range")
            time_range = st.selectbox(
                "Period",
                options=['Last 24 Hours', 'Last 7 Days', 'Last 30 Days', 'Last 90 Days'],
                index=2
            )
            
            st.session_state.time_range = time_range
            
            st.markdown("---")
            
            # Refresh controls
            st.markdown("### 🔄 Data Refresh")
            
            last_refresh = SessionManager.get('last_refresh', datetime.now())
            st.caption(f"Last refresh: {last_refresh.strftime('%H:%M:%S')}")
            
            if st.button("🔄 Refresh Now", use_container_width=True):
                SessionManager.trigger_refresh()
                st.cache_data.clear()
                st.rerun()
            
            auto_refresh = st.checkbox("Auto-refresh (5 min)", value=False)
            if auto_refresh:
                import time
                time.sleep(300)  # 5 minutes
                st.rerun()
            
            st.markdown("---")
            
            # Platform stats
            st.markdown("### 📊 Platform Stats")
            st.metric(f"Connected {item_label}", len(active_items))
            
            # Get regions based on cloud provider
            if cloud_provider == "AWS":
                regions = AppConfig.AWS_REGIONS
            elif cloud_provider == "Azure":
                regions = AppConfig.AZURE_REGIONS
            else:  # GCP
                regions = AppConfig.GCP_REGIONS
            
            st.metric("Active Regions", len(regions))
            
            # Health status
            health_label = "Account Health" if cloud_provider == "AWS" else "Subscription Health" if cloud_provider == "Azure" else "Project Health"
            st.markdown(f"### 🏥 {health_label}")
            for item in active_items[:3]:  # Show first 3
                status_icon = "✅" if item.status == "active" else "❌"
                # Get name based on cloud provider
                if cloud_provider == "AWS":
                    item_name = item.account_name
                elif cloud_provider == "Azure":
                    item_name = item.subscription_name
                else:  # GCP
                    item_name = item.project_name
                st.caption(f"{status_icon} {item_name}")
            
            if len(active_items) > 3:
                st.caption(f"... and {len(active_items) - 3} more")
