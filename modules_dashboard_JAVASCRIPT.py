"""
Module 0: Main Dashboard
Enterprise overview of multi-account AWS environment with AWS theming
JAVASCRIPT INJECTION VERSION - Forces white text after page load
"""

import streamlit as st
import pandas as pd
from typing import Dict, List
from datetime import datetime, timedelta
from config_settings import AppConfig
from core_account_manager import get_account_manager
from core_session_manager import SessionManager
from utils_helpers import Helpers
from aws_theme import AWSTheme

class DashboardModule:
    """Main dashboard with enterprise overview and AWS styling"""
    
    @staticmethod
    def render():
        """Render dashboard"""
        
        st.markdown("## 🏠 Enterprise Cloud Dashboard")
        st.caption("Multi-account AWS environment overview with real-time metrics")
        
        # Load account manager
        account_mgr = get_account_manager()
        if not account_mgr:
            st.error("❌ AWS account manager not configured. Please check secrets.toml")
            return
        
        # Load accounts
        accounts = AppConfig.load_aws_accounts()
        active_accounts = [acc for acc in accounts if acc.status == 'active']
        
        if not active_accounts:
            st.warning("⚠️ No active AWS accounts configured.")
            st.info("Go to **Account Lifecycle** → **Onboard Account** to add your first account.")
            return
        
        # Top metrics with AWS styling
        DashboardModule._render_top_metrics_aws(account_mgr, active_accounts)
        
        # ===== NUCLEAR JAVASCRIPT INJECTION - FORCES WHITE TEXT =====
        st.markdown("""
        <script>
        // Wait for page to load
        setTimeout(function() {
            // Target ALL metric elements and force white text
            const selectors = [
                '[data-testid="stMetric"]',
                '[data-testid="stMetric"] *',
                '[data-testid="stMetricLabel"]',
                '[data-testid="stMetricValue"]',
                '[data-testid="stMetricDelta"]',
                '[class*="metric"]',
                '[class*="Metric"]'
            ];
            
            selectors.forEach(function(selector) {
                try {
                    const elements = document.querySelectorAll(selector);
                    elements.forEach(function(el) {
                        el.style.color = 'white';
                        el.style.fill = 'white';
                        el.style.setProperty('color', 'white', 'important');
                        el.style.setProperty('fill', 'white', 'important');
                    });
                } catch(e) {
                    console.log('Selector failed:', selector);
                }
            });
            
            // Also target by position (first 4 columns in first row)
            const columns = document.querySelectorAll('[data-testid="column"]');
            if (columns.length >= 4) {
                for (let i = 0; i < 4; i++) {
                    const allElements = columns[i].querySelectorAll('*');
                    allElements.forEach(function(el) {
                        el.style.setProperty('color', 'white', 'important');
                        el.style.setProperty('fill', 'white', 'important');
                    });
                }
            }
            
            console.log('✅ White text injection complete!');
        }, 500);  // Wait 500ms for Streamlit to render
        
        // Run again after 2 seconds to catch late-loading elements
        setTimeout(function() {
            const allMetrics = document.querySelectorAll('[data-testid="stMetric"], [data-testid="stMetric"] *');
            allMetrics.forEach(function(el) {
                el.style.setProperty('color', 'white', 'important');
                el.style.setProperty('fill', 'white', 'important');
            });
            console.log('✅ Second white text injection complete!');
        }, 2000);
        </script>
        """, unsafe_allow_html=True)
        # ===== END JAVASCRIPT INJECTION =====
        
        st.markdown("---")
        
        # Charts row
        col1, col2 = st.columns(2)
        
        with col1:
            DashboardModule._render_cost_by_account(active_accounts)
        
        with col2:
            DashboardModule._render_resource_distribution(account_mgr, active_accounts)
        
        st.markdown("---")
        
        # Account status table
        DashboardModule._render_account_status_table(account_mgr, active_accounts)
        
        st.markdown("---")
        
        # Recent activity
        DashboardModule._render_recent_resources(account_mgr, active_accounts)
    
    @staticmethod
    def _render_top_metrics_aws(account_mgr, active_accounts):
        """Render top-level metrics with AWS theming"""
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            AWSTheme.aws_metric_card(
                label="Connected Accounts",
                value=str(len(active_accounts)),
                icon="🔗"
            )
        
        with col2:
            # Count total resources across accounts
            total_resources = 0
            for acc in active_accounts[:3]:  # Sample first 3 for performance
                try:
                    session = account_mgr.assume_role(
                        acc.account_id,
                        acc.account_name,
                        acc.role_arn
                    )
                    if session:
                        from aws_ec2 import EC2Service
                        ec2 = EC2Service(session.session, acc.regions[0])
                        result = ec2.list_instances()
                        total_resources += result.get('count', 0)
                except:
                    pass
            
            AWSTheme.aws_metric_card(
                label="Total Resources",
                value=Helpers.format_number(total_resources) if total_resources > 0 else "N/A",
                icon="📦"
            )
        
        with col3:
            # Estimated monthly cost
            estimated_cost = total_resources * 73  # $73/month per t3.micro
            AWSTheme.aws_metric_card(
                label="Est. Monthly Cost",
                value=Helpers.format_currency(estimated_cost),
                icon="💰"
            )
        
        with col4:
            # Compliance score (placeholder)
            AWSTheme.aws_metric_card(
                label="Compliance Score",
                value="N/A",
                icon="🛡️"
            )
    
    @staticmethod
    def _render_cost_by_account(active_accounts):
        """Render cost distribution by account"""
        
        st.markdown("### 💰 Cost by Account (Estimated)")
        
        # Generate sample data based on account names
        cost_data = []
        for acc in active_accounts:
            # Simulate different costs based on environment
            multiplier = {
                'production': 10,
                'staging': 3,
                'development': 2,
                'sandbox': 1
            }.get(acc.environment, 5)
            
            cost = 5000 * multiplier
            cost_data.append({
                'Account': acc.account_name,
                'Cost': cost
            })
        
        if cost_data:
            df = pd.DataFrame(cost_data)
            df = df.sort_values('Cost', ascending=False)
            
            # Create bar chart
            st.bar_chart(df.set_index('Account')['Cost'])
            
            # Show total
            total = df['Cost'].sum()
            st.caption(f"**Total:** {Helpers.format_currency(total)}")
        else:
            st.info("No cost data available")
    
    @staticmethod
    def _render_resource_distribution(account_mgr, active_accounts):
        """Render resource type distribution"""
        
        st.markdown("### 📦 Resource Distribution")
        
        # Sample data - in production, query all resource types
        resource_types = {
            'EC2 Instances': 45,
            'RDS Databases': 12,
            'S3 Buckets': 28,
            'Lambda Functions': 67,
            'DynamoDB Tables': 15
        }
        
        df = pd.DataFrame(list(resource_types.items()), columns=['Type', 'Count'])
        st.bar_chart(df.set_index('Type')['Count'])
    
    @staticmethod
    def _render_account_status_table(account_mgr, active_accounts):
        """Render account status table"""
        
        st.markdown("### 🏢 Account Status")
        
        table_data = []
        
        for acc in active_accounts:
            # Test connection
            success, error = account_mgr.test_account_connection(
                acc.account_id,
                acc.account_name,
                acc.role_arn
            )
            
            table_data.append({
                'Account Name': acc.account_name,
                'Account ID': acc.account_id,
                'Environment': acc.environment.upper(),
                'Regions': ', '.join(acc.regions),
                'Status': '✅ Connected' if success else '❌ Error',
                'Cost Center': acc.cost_center or 'N/A'
            })
        
        if table_data:
            df = pd.DataFrame(table_data)
            st.dataframe(df, use_container_width=True, hide_index=True)
        else:
            st.info("No accounts to display")
    
    @staticmethod
    def _render_recent_resources(account_mgr, active_accounts):
        """Render recent resources"""
        
        st.markdown("### 📋 Recent Resources")
        st.caption("Most recently created resources across accounts")
        
        resources = []
        
        # Fetch recent EC2 instances from first account
        if active_accounts:
            acc = active_accounts[0]
            try:
                session = account_mgr.assume_role(
                    acc.account_id,
                    acc.account_name,
                    acc.role_arn
                )
                
                if session:
                    from aws_ec2 import EC2Service
                    ec2 = EC2Service(session.session, acc.regions[0])
                    result = ec2.list_instances()
                    
                    if result['success']:
                        for inst in result['instances'][:10]:  # Latest 10
                            resources.append({
                                'Resource ID': inst['instance_id'],
                                'Type': 'EC2',
                                'Account': acc.account_name,
                                'Region': acc.regions[0],
                                'State': inst['state'],
                                'Created': Helpers.time_ago(inst['launch_time'])
                            })
            except:
                pass
        
        if resources:
            df = pd.DataFrame(resources)
            st.dataframe(df, use_container_width=True, hide_index=True)
        else:
            st.info("No recent resources found. Launch some EC2 instances to see them here!")
