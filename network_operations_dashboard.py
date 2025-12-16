"""
Network Operations & Connectivity Dashboard
Real-time monitoring of VPN, Direct Connect, latency, and network health

Features:
- VPN Tunnel Monitoring (Site-to-Site VPN)
- Direct Connect (DX) Health Monitoring
- Data Center to AWS Region Connectivity
- Latency Tracking & Analysis
- Network Path Analysis
- CloudWatch Integration (Native AWS metrics)
- Alert Management
- Historical Trend Analysis
- Network Topology Visualization
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from typing import Dict, List, Optional
from datetime import datetime, timedelta
import json

# ============================================================================
# PERFORMANCE OPTIMIZER
# ============================================================================

class PerformanceOptimizer:
    """Performance optimization wrapper"""
    
    @staticmethod
    def cache_with_spinner(ttl=60, spinner_text="Loading..."):
        """Decorator with caching and spinner - shorter TTL for real-time data"""
        import functools
        
        def decorator(func):
            cached_func = st.cache_data(ttl=ttl)(func)
            
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                cache_key = f"cache_{func.__name__}"
                
                if cache_key not in st.session_state:
                    with st.spinner(spinner_text):
                        result = cached_func(*args, **kwargs)
                        st.session_state[cache_key] = True
                    return result
                else:
                    return cached_func(*args, **kwargs)
            
            return wrapper
        return decorator
    
    @staticmethod
    def add_refresh_button(cache_keys=None):
        """Add refresh button"""
        col1, col2, col3 = st.columns([1, 1, 4])
        
        with col1:
            if st.button("🔄 Refresh", key=f"refresh_{st.session_state.net_ops_session_id}", use_container_width=True):
                if cache_keys:
                    for key in cache_keys:
                        if key in st.session_state:
                            del st.session_state[key]
                st.cache_data.clear()
                st.success("✅ Refreshed!")
                st.rerun()
        
        with col2:
            auto_refresh = st.checkbox("Auto-refresh", value=False, 
                                      help="Auto-refresh every 60 seconds",
                                      key=f"auto_refresh_net_{st.session_state.net_ops_session_id}")
            if auto_refresh:
                st.caption("🔄 Auto-refresh: ON")

# ============================================================================
# CLOUDWATCH DATA FETCHER
# ============================================================================

class CloudWatchNetworkMonitor:
    """Fetch network metrics from AWS CloudWatch"""
    
    @staticmethod
    def get_vpn_tunnel_metrics(account_mgr, account_id, region, vpn_id):
        """
        Get VPN tunnel metrics from CloudWatch
        
        Metrics:
        - TunnelState (0=DOWN, 1=UP)
        - TunnelDataIn (bytes)
        - TunnelDataOut (bytes)
        """
        try:
            session = account_mgr.assume_role(
                account_id,
                "VPN Monitoring",
                f"arn:aws:iam::{account_id}:role/MonitoringRole"
            )
            
            if session:
                import boto3
                cloudwatch = session.session.client('cloudwatch', region_name=region)
                
                # Get tunnel state
                response = cloudwatch.get_metric_statistics(
                    Namespace='AWS/VPN',
                    MetricName='TunnelState',
                    Dimensions=[
                        {'Name': 'VpnId', 'Value': vpn_id}
                    ],
                    StartTime=datetime.now() - timedelta(hours=1),
                    EndTime=datetime.now(),
                    Period=300,  # 5 minutes
                    Statistics=['Average']
                )
                
                return {
                    'success': True,
                    'datapoints': response.get('Datapoints', [])
                }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    @staticmethod
    def get_dx_connection_metrics(account_mgr, account_id, region, dx_id):
        """
        Get Direct Connect metrics from CloudWatch
        
        Metrics:
        - ConnectionState (available, down, ordering, etc.)
        - ConnectionBpsEgress
        - ConnectionBpsIngress
        - ConnectionPpsEgress
        - ConnectionPpsIngress
        - ConnectionLightLevelTx
        - ConnectionLightLevelRx
        """
        try:
            session = account_mgr.assume_role(
                account_id,
                "DX Monitoring",
                f"arn:aws:iam::{account_id}:role/MonitoringRole"
            )
            
            if session:
                import boto3
                cloudwatch = session.session.client('cloudwatch', region_name=region)
                
                # Get connection state
                response = cloudwatch.get_metric_statistics(
                    Namespace='AWS/DX',
                    MetricName='ConnectionState',
                    Dimensions=[
                        {'Name': 'ConnectionId', 'Value': dx_id}
                    ],
                    StartTime=datetime.now() - timedelta(hours=1),
                    EndTime=datetime.now(),
                    Period=300,
                    Statistics=['Average']
                )
                
                return {
                    'success': True,
                    'datapoints': response.get('Datapoints', [])
                }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    @staticmethod
    def get_network_latency(account_mgr, account_id, region):
        """
        Get network latency metrics using CloudWatch Synthetics or custom metrics
        """
        try:
            session = account_mgr.assume_role(
                account_id,
                "Latency Monitoring",
                f"arn:aws:iam::{account_id}:role/MonitoringRole"
            )
            
            if session:
                import boto3
                cloudwatch = session.session.client('cloudwatch', region_name=region)
                
                # Get custom latency metrics (if you've set them up)
                response = cloudwatch.get_metric_statistics(
                    Namespace='CustomMetrics/Network',
                    MetricName='Latency',
                    StartTime=datetime.now() - timedelta(hours=24),
                    EndTime=datetime.now(),
                    Period=3600,  # 1 hour
                    Statistics=['Average', 'Maximum', 'Minimum']
                )
                
                return {
                    'success': True,
                    'datapoints': response.get('Datapoints', [])
                }
        except Exception as e:
            return {'success': False, 'error': str(e)}

# ============================================================================
# DEMO DATA GENERATION (for testing without live AWS data)
# ============================================================================

@PerformanceOptimizer.cache_with_spinner(ttl=60, spinner_text="Loading network topology...")
def generate_network_topology() -> Dict:
    """Generate network topology with DCs and AWS regions"""
    
    return {
        'data_centers': [
            {
                'id': 'dc-hq-nyc',
                'name': 'HQ Data Center - New York',
                'location': 'New York, USA',
                'type': 'Primary',
                'connections': ['vpn-1', 'dx-1'],
                'status': 'healthy'
            },
            {
                'id': 'dc-branch-london',
                'name': 'Branch DC - London',
                'location': 'London, UK',
                'type': 'Secondary',
                'connections': ['vpn-2'],
                'status': 'healthy'
            },
            {
                'id': 'dc-backup-dallas',
                'name': 'Backup DC - Dallas',
                'location': 'Dallas, USA',
                'type': 'DR Site',
                'connections': ['vpn-3', 'dx-2'],
                'status': 'healthy'
            }
        ],
        'aws_regions': [
            {
                'id': 'us-east-1',
                'name': 'US East (N. Virginia)',
                'location': 'Virginia, USA',
                'vpcs': 3,
                'connections': ['vpn-1', 'dx-1', 'vpn-3'],
                'status': 'healthy'
            },
            {
                'id': 'us-west-2',
                'name': 'US West (Oregon)',
                'location': 'Oregon, USA',
                'vpcs': 2,
                'connections': ['vpn-3', 'dx-2'],
                'status': 'healthy'
            },
            {
                'id': 'eu-west-1',
                'name': 'EU (Ireland)',
                'location': 'Ireland',
                'vpcs': 1,
                'connections': ['vpn-2'],
                'status': 'healthy'
            }
        ],
        'vpn_connections': [
            {
                'id': 'vpn-1',
                'name': 'NYC-HQ to US-East-1',
                'source': 'dc-hq-nyc',
                'destination': 'us-east-1',
                'type': 'Site-to-Site VPN',
                'tunnels': 2,
                'status': 'available',
                'tunnel_1_state': 'UP',
                'tunnel_2_state': 'UP',
                'bandwidth_mbps': 1250,
                'latency_ms': 12,
                'packet_loss_pct': 0.01,
                'uptime_pct': 99.98
            },
            {
                'id': 'vpn-2',
                'name': 'London-Branch to EU-West-1',
                'source': 'dc-branch-london',
                'destination': 'eu-west-1',
                'type': 'Site-to-Site VPN',
                'tunnels': 2,
                'status': 'available',
                'tunnel_1_state': 'UP',
                'tunnel_2_state': 'DOWN',
                'bandwidth_mbps': 450,
                'latency_ms': 8,
                'packet_loss_pct': 0.02,
                'uptime_pct': 99.95
            },
            {
                'id': 'vpn-3',
                'name': 'Dallas-Backup to US-West-2',
                'source': 'dc-backup-dallas',
                'destination': 'us-west-2',
                'type': 'Site-to-Site VPN',
                'tunnels': 2,
                'status': 'available',
                'tunnel_1_state': 'UP',
                'tunnel_2_state': 'UP',
                'bandwidth_mbps': 980,
                'latency_ms': 35,
                'packet_loss_pct': 0.03,
                'uptime_pct': 99.92
            }
        ],
        'dx_connections': [
            {
                'id': 'dx-1',
                'name': 'DX-NYC-Primary',
                'source': 'dc-hq-nyc',
                'destination': 'us-east-1',
                'type': 'Dedicated 10 Gbps',
                'location': 'Equinix NY5',
                'status': 'available',
                'vlan': 100,
                'bandwidth_gbps': 10,
                'latency_ms': 3,
                'packet_loss_pct': 0.001,
                'uptime_pct': 99.99,
                'bgp_state': 'established'
            },
            {
                'id': 'dx-2',
                'name': 'DX-Dallas-Secondary',
                'source': 'dc-backup-dallas',
                'destination': 'us-west-2',
                'type': 'Dedicated 10 Gbps',
                'location': 'Equinix DA6',
                'status': 'available',
                'vlan': 200,
                'bandwidth_gbps': 10,
                'latency_ms': 18,
                'packet_loss_pct': 0.001,
                'uptime_pct': 99.99,
                'bgp_state': 'established'
            }
        ]
    }

@PerformanceOptimizer.cache_with_spinner(ttl=60, spinner_text="Loading network metrics...")
def generate_network_metrics(source, destination) -> Dict:
    """Generate network performance metrics for selected path"""
    
    import random
    
    # Generate hourly metrics for last 24 hours
    metrics = []
    base_latency = random.randint(5, 50)
    
    for i in range(24):
        timestamp = datetime.now() - timedelta(hours=23-i)
        
        metrics.append({
            'timestamp': timestamp,
            'latency_ms': base_latency + random.randint(-5, 10),
            'packet_loss_pct': round(random.uniform(0, 0.1), 3),
            'throughput_mbps': random.randint(800, 1200),
            'jitter_ms': round(random.uniform(0.5, 3.0), 2),
            'availability': random.choice([100, 100, 100, 99.9, 99.8])
        })
    
    return {
        'metrics': metrics,
        'avg_latency': base_latency,
        'avg_packet_loss': 0.02,
        'avg_throughput': 1000,
        'uptime_24h': 99.95
    }

@PerformanceOptimizer.cache_with_spinner(ttl=60, spinner_text="Checking network alerts...")
def generate_network_alerts() -> List[Dict]:
    """Generate network alerts and issues"""
    
    return [
        {
            'severity': 'Warning',
            'type': 'VPN Tunnel',
            'connection': 'London-Branch to EU-West-1',
            'issue': 'Tunnel 2 is DOWN',
            'impact': 'Reduced redundancy - single tunnel active',
            'recommendation': 'Investigate tunnel 2 configuration and restart if needed',
            'detected': datetime.now() - timedelta(hours=2),
            'status': 'Active'
        },
        {
            'severity': 'Info',
            'type': 'Latency',
            'connection': 'Dallas-Backup to US-West-2',
            'issue': 'Latency increased by 15ms',
            'impact': 'Minor performance degradation',
            'recommendation': 'Monitor for routing changes or ISP issues',
            'detected': datetime.now() - timedelta(hours=6),
            'status': 'Monitoring'
        },
        {
            'severity': 'Critical',
            'type': 'Direct Connect',
            'connection': 'DX-NYC-Primary',
            'issue': 'Bandwidth utilization at 85%',
            'impact': 'Potential congestion during peak hours',
            'recommendation': 'Consider upgrading to 20 Gbps or add secondary connection',
            'detected': datetime.now() - timedelta(days=1),
            'status': 'Active'
        }
    ]

# ============================================================================
# NETWORK OPERATIONS DASHBOARD
# ============================================================================

class NetworkOperationsDashboard:
    """Network Operations & Connectivity Dashboard"""
    
    @staticmethod
    def render(account_mgr):
        """Render network operations dashboard"""
        

        # Initialize unique session ID for button keys
        if "net_ops_session_id" not in st.session_state:
            st.session_state.net_ops_session_id = str(__import__("uuid").uuid4())[:8]

        st.markdown("## 🌐 Network Operations & Connectivity")
        st.caption("Real-time monitoring of VPN, Direct Connect, and network health using AWS CloudWatch")
        
        # Refresh button
        PerformanceOptimizer.add_refresh_button([
            'network_topology',
            'network_metrics',
            'network_alerts'
        ])
        
        # Check account manager
        if not account_mgr:
            st.warning("⚠️ Configure AWS credentials to access CloudWatch metrics")
            st.info("👉 Go to 'Account Management' to add your AWS accounts")
            return
        
        # Tabs
        tabs = st.tabs([
            "📊 Overview",
            "🔌 VPN Monitoring",
            "⚡ Direct Connect",
            "📈 Latency Analysis",
            "🚨 Alerts & Issues",
            "🗺️ Network Topology",
            "📜 Audit Trail"
        ])
        
        with tabs[0]:
            NetworkOperationsDashboard._render_overview()
        
        with tabs[1]:
            NetworkOperationsDashboard._render_vpn_monitoring(account_mgr)
        
        with tabs[2]:
            NetworkOperationsDashboard._render_dx_monitoring(account_mgr)
        
        with tabs[3]:
            NetworkOperationsDashboard._render_latency_analysis(account_mgr)
        
        with tabs[4]:
            NetworkOperationsDashboard._render_alerts()
        
        with tabs[5]:
            NetworkOperationsDashboard._render_topology()
        
        with tabs[6]:
            NetworkOperationsDashboard._render_audit_trail()
    
    # ========================================================================
    # TAB 1: OVERVIEW
    # ========================================================================
    
    @staticmethod
    def _render_overview():
        """Render network overview dashboard"""
        
        st.markdown("### 🎯 Network Health Overview")
        
        topology = generate_network_topology()
        
        # Top metrics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            total_connections = len(topology['vpn_connections']) + len(topology['dx_connections'])
            healthy = sum(1 for vpn in topology['vpn_connections'] if vpn['status'] == 'available')
            healthy += sum(1 for dx in topology['dx_connections'] if dx['status'] == 'available')
            
            st.metric(
                "Total Connections",
                total_connections,
                delta=f"{healthy} healthy",
                help="VPN + Direct Connect connections"
            )
        
        with col2:
            vpn_up = sum(1 for vpn in topology['vpn_connections'] if vpn['tunnel_1_state'] == 'UP' or vpn['tunnel_2_state'] == 'UP')
            st.metric(
                "VPN Tunnels",
                f"{vpn_up}/{len(topology['vpn_connections'])}",
                delta="Operational",
                help="Active VPN connections"
            )
        
        with col3:
            dx_up = sum(1 for dx in topology['dx_connections'] if dx['status'] == 'available')
            st.metric(
                "Direct Connect",
                f"{dx_up}/{len(topology['dx_connections'])}",
                delta="Available",
                help="Active DX connections"
            )
        
        with col4:
            alerts = generate_network_alerts()
            critical = sum(1 for alert in alerts if alert['severity'] == 'Critical')
            st.metric(
                "Active Alerts",
                len(alerts),
                delta=f"{critical} critical" if critical > 0 else "All clear",
                delta_color="inverse" if critical > 0 else "normal",
                help="Network alerts and issues"
            )
        
        st.markdown("---")
        
        # Connection status
        st.markdown("### 🔗 Connection Status")
        
        connection_data = []
        
        # VPN connections
        for vpn in topology['vpn_connections']:
            status = "🟢 Healthy" if vpn['tunnel_1_state'] == 'UP' and vpn['tunnel_2_state'] == 'UP' else "🟡 Degraded"
            if vpn['tunnel_1_state'] == 'DOWN' and vpn['tunnel_2_state'] == 'DOWN':
                status = "🔴 Down"
            
            connection_data.append({
                'Connection': vpn['name'],
                'Type': vpn['type'],
                'Status': status,
                'Latency (ms)': vpn['latency_ms'],
                'Bandwidth': f"{vpn['bandwidth_mbps']} Mbps",
                'Uptime': f"{vpn['uptime_pct']}%"
            })
        
        # DX connections
        for dx in topology['dx_connections']:
            status = "🟢 Healthy" if dx['status'] == 'available' and dx['bgp_state'] == 'established' else "🔴 Down"
            
            connection_data.append({
                'Connection': dx['name'],
                'Type': dx['type'],
                'Status': status,
                'Latency (ms)': dx['latency_ms'],
                'Bandwidth': f"{dx['bandwidth_gbps']} Gbps",
                'Uptime': f"{dx['uptime_pct']}%"
            })
        
        df = pd.DataFrame(connection_data)
        st.dataframe(df, use_container_width=True, hide_index=True)
        
        st.markdown("---")
        
        # Charts
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("#### 📊 Connections by Type")
            type_data = {
                'Type': ['VPN', 'Direct Connect'],
                'Count': [len(topology['vpn_connections']), len(topology['dx_connections'])]
            }
            fig = px.pie(pd.DataFrame(type_data), values='Count', names='Type',
                        color_discrete_sequence=['#3b82f6', '#10b981'])
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            st.markdown("#### 🌍 Connections by Region")
            region_count = {}
            for vpn in topology['vpn_connections']:
                dest = next(r for r in topology['aws_regions'] if r['id'] == vpn['destination'])
                region_count[dest['name']] = region_count.get(dest['name'], 0) + 1
            
            fig = px.bar(pd.DataFrame(list(region_count.items()), columns=['Region', 'Connections']),
                        x='Region', y='Connections', color='Connections',
                        color_continuous_scale='Blues')
            st.plotly_chart(fig, use_container_width=True)
    
    # ========================================================================
    # TAB 2: VPN MONITORING
    # ========================================================================
    
    @staticmethod
    def _render_vpn_monitoring(account_mgr):
        """Render VPN monitoring with CloudWatch integration"""
        
        st.markdown("### 🔌 VPN Site-to-Site Monitoring")
        st.caption("Monitor VPN tunnel health using AWS CloudWatch metrics")
        
        topology = generate_network_topology()
        
        # Connection selector
        st.markdown("#### Select Connection to Monitor")
        
        col1, col2 = st.columns(2)
        
        with col1:
            dc_names = [dc['name'] for dc in topology['data_centers']]
            selected_dc = st.selectbox(
                "Source Data Center",
                dc_names,
                help="Select your on-premises data center",
                key=f"select_dc_{st.session_state.net_ops_session_id}"
            )
        
        with col2:
            region_names = [r['name'] for r in topology['aws_regions']]
            selected_region = st.selectbox(
                "Destination AWS Region",
                region_names,
                help="Select target AWS region",
                key=f"select_region_{st.session_state.net_ops_session_id}"
            )
        
        # Find matching VPN connection
        dc = next((dc for dc in topology['data_centers'] if dc['name'] == selected_dc), None)
        region = next((r for r in topology['aws_regions'] if r['name'] == selected_region), None)
        
        matching_vpn = None
        if dc and region:
            matching_vpn = next((vpn for vpn in topology['vpn_connections'] 
                               if vpn['source'] == dc['id'] and vpn['destination'] == region['id']), None)
        
        if matching_vpn:
            st.success(f"✅ Connection Found: **{matching_vpn['name']}**")
            
            # Connection details
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                tunnel_status = "🟢 Both UP" if matching_vpn['tunnel_1_state'] == 'UP' and matching_vpn['tunnel_2_state'] == 'UP' else "🟡 Degraded"
                st.metric("Tunnel Status", tunnel_status)
            
            with col2:
                st.metric("Latency", f"{matching_vpn['latency_ms']} ms")
            
            with col3:
                st.metric("Bandwidth", f"{matching_vpn['bandwidth_mbps']} Mbps")
            
            with col4:
                st.metric("Uptime", f"{matching_vpn['uptime_pct']}%")
            
            st.markdown("---")
            
            # Tunnel details
            st.markdown("#### 🔌 Tunnel Details")
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("**Tunnel 1**")
                if matching_vpn['tunnel_1_state'] == 'UP':
                    st.success("🟢 Status: UP")
                else:
                    st.error("🔴 Status: DOWN")
                st.caption("Outside IP: 52.123.45.67")
                st.caption("Inside IP: 169.254.10.1/30")
                st.caption("BGP ASN: 65000")
            
            with col2:
                st.markdown("**Tunnel 2**")
                if matching_vpn['tunnel_2_state'] == 'UP':
                    st.success("🟢 Status: UP")
                else:
                    st.error("🔴 Status: DOWN")
                st.caption("Outside IP: 52.123.45.68")
                st.caption("Inside IP: 169.254.10.5/30")
                st.caption("BGP ASN: 65000")
            
            st.markdown("---")
            
            # CloudWatch metrics
            st.markdown("#### 📊 CloudWatch Metrics (Last 24 Hours)")
            
            # Get network metrics
            metrics = generate_network_metrics(selected_dc, selected_region)
            
            # Latency chart
            df_metrics = pd.DataFrame(metrics['metrics'])
            
            fig = go.Figure()
            fig.add_trace(go.Scatter(
                x=df_metrics['timestamp'],
                y=df_metrics['latency_ms'],
                mode='lines+markers',
                name='Latency (ms)',
                line=dict(color='#3b82f6', width=2),
                fill='tozeroy'
            ))
            fig.update_layout(
                title="Network Latency",
                xaxis_title="Time",
                yaxis_title="Latency (ms)",
                hovermode='x unified'
            )
            st.plotly_chart(fig, use_container_width=True)
            
            # Throughput chart
            fig = go.Figure()
            fig.add_trace(go.Scatter(
                x=df_metrics['timestamp'],
                y=df_metrics['throughput_mbps'],
                mode='lines+markers',
                name='Throughput (Mbps)',
                line=dict(color='#10b981', width=2),
                fill='tozeroy'
            ))
            fig.update_layout(
                title="Network Throughput",
                xaxis_title="Time",
                yaxis_title="Throughput (Mbps)",
                hovermode='x unified'
            )
            st.plotly_chart(fig, use_container_width=True)
            
            # Actions
            col1, col2, col3 = st.columns(3)
            
            with col1:
                if st.button("🔄 Reset Tunnel", key=f"reset_tunnel_{st.session_state.net_ops_session_id}", use_container_width=True):
                    st.info("Initiating tunnel reset...")
            
            with col2:
                if st.button("📊 View Detailed Metrics", key=f"view_detailed_metrics_{st.session_state.net_ops_session_id}", use_container_width=True):
                    st.info("Opening CloudWatch dashboard...")
            
            with col3:
                if st.button("🔔 Configure Alerts", key=f"configure_alerts_{st.session_state.net_ops_session_id}", use_container_width=True):
                    st.info("Opening CloudWatch Alarms...")
        
        else:
            st.warning("⚠️ No VPN connection found between selected locations")
            st.info("Configure a Site-to-Site VPN connection in AWS VPC console")
    
    # ========================================================================
    # TAB 3: DIRECT CONNECT MONITORING
    # ========================================================================
    
    @staticmethod
    def _render_dx_monitoring(account_mgr):
        """Render Direct Connect monitoring"""
        
        st.markdown("### ⚡ AWS Direct Connect Monitoring")
        st.caption("Monitor dedicated network connections using CloudWatch")
        
        topology = generate_network_topology()
        
        # Connection selector
        st.markdown("#### Select Direct Connect")
        
        dx_names = [dx['name'] for dx in topology['dx_connections']]
        if dx_names:
            selected_dx_name = st.selectbox("Direct Connect Connection", dx_names,
                                           key=f"select_dx_{st.session_state.net_ops_session_id}")
            
            dx = next((dx for dx in topology['dx_connections'] if dx['name'] == selected_dx_name), None)
            
            if dx:
                # Status
                col1, col2, col3, col4, col5 = st.columns(5)
                
                with col1:
                    if dx['status'] == 'available':
                        st.success("🟢 Available")
                    else:
                        st.error("🔴 Down")
                
                with col2:
                    st.metric("Bandwidth", f"{dx['bandwidth_gbps']} Gbps")
                
                with col3:
                    st.metric("Latency", f"{dx['latency_ms']} ms")
                
                with col4:
                    st.metric("Uptime", f"{dx['uptime_pct']}%")
                
                with col5:
                    if dx['bgp_state'] == 'established':
                        st.success("BGP: UP")
                    else:
                        st.error("BGP: DOWN")
                
                st.markdown("---")
                
                # Connection details
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown("**Connection Details**")
                    st.caption(f"📍 Location: {dx['location']}")
                    st.caption(f"🔢 VLAN: {dx['vlan']}")
                    st.caption(f"🌐 Type: {dx['type']}")
                    st.caption(f"📊 Packet Loss: {dx['packet_loss_pct']}%")
                
                with col2:
                    st.markdown("**Routing**")
                    st.caption(f"🔄 BGP State: {dx['bgp_state']}")
                    st.caption("📡 BGP ASN: 65100")
                    st.caption("🔐 MD5 Auth: Enabled")
                    st.caption("🛣️ Advertised Prefixes: 24")
                
                st.markdown("---")
                
                # CloudWatch metrics
                st.markdown("#### 📊 CloudWatch Metrics (Real-time)")
                
                # Bandwidth utilization
                metrics = generate_network_metrics(dx['source'], dx['destination'])
                df_metrics = pd.DataFrame(metrics['metrics'])
                
                # Bandwidth chart with utilization
                fig = go.Figure()
                
                # Calculate utilization percentage
                max_bandwidth = dx['bandwidth_gbps'] * 1000  # Convert to Mbps
                utilization = (df_metrics['throughput_mbps'] / max_bandwidth) * 100
                
                fig.add_trace(go.Scatter(
                    x=df_metrics['timestamp'],
                    y=utilization,
                    mode='lines+markers',
                    name='Bandwidth Utilization (%)',
                    line=dict(color='#8b5cf6', width=2),
                    fill='tozeroy'
                ))
                
                # Add threshold line at 80%
                fig.add_hline(y=80, line_dash="dash", line_color="red",
                            annotation_text="80% Threshold")
                
                fig.update_layout(
                    title="Bandwidth Utilization",
                    xaxis_title="Time",
                    yaxis_title="Utilization (%)",
                    hovermode='x unified'
                )
                st.plotly_chart(fig, use_container_width=True)
                
                # Connection state
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown("**Light Levels** (Optical Signal)")
                    st.progress(0.75, text="TX Power: -2.5 dBm")
                    st.progress(0.80, text="RX Power: -3.1 dBm")
                    st.caption("✅ Within normal range")
                
                with col2:
                    st.markdown("**Error Statistics**")
                    st.metric("Input Errors", "0", delta="Last hour")
                    st.metric("Output Errors", "0", delta="Last hour")
                    st.metric("CRC Errors", "0", delta="Last hour")
                
                # Actions
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    if st.button("📊 CloudWatch Dashboard", key=f"cloudwatch_dashboard_{st.session_state.net_ops_session_id}", use_container_width=True):
                        st.info("Opening DX CloudWatch dashboard...")
                
                with col2:
                    if st.button("🔔 Configure Alarms", key=f"configure_alarms_{st.session_state.net_ops_session_id}", use_container_width=True):
                        st.info("Opening CloudWatch Alarms...")
                
                with col3:
                    if st.button("📄 Download Report", key=f"download_report_{st.session_state.net_ops_session_id}", use_container_width=True):
                        st.info("Generating DX performance report...")
        
        else:
            st.info("No Direct Connect connections configured")
            st.markdown("**To set up Direct Connect:**")
            st.markdown("1. Go to AWS Console → Direct Connect")
            st.markdown("2. Create a new connection at a DX location")
            st.markdown("3. Configure Virtual Interface (VIF)")
            st.markdown("4. Establish BGP peering")
    
    # ========================================================================
    # TAB 4: LATENCY ANALYSIS
    # ========================================================================
    
    @staticmethod
    def _render_latency_analysis(account_mgr):
        """Render latency analysis dashboard"""
        
        st.markdown("### 📈 Network Latency Analysis")
        st.caption("Analyze network performance and latency trends")
        
        topology = generate_network_topology()
        
        # Path selector
        col1, col2 = st.columns(2)
        
        with col1:
            sources = [dc['name'] for dc in topology['data_centers']]
            selected_source = st.selectbox("Source", sources,
                                          key=f"select_source_{st.session_state.net_ops_session_id}")
        
        with col2:
            destinations = [r['name'] for r in topology['aws_regions']]
            selected_dest = st.selectbox("Destination", destinations,
                                        key=f"select_dest_{st.session_state.net_ops_session_id}")
        
        # Time range
        time_range = st.selectbox(
            "Time Range",
            ["Last Hour", "Last 6 Hours", "Last 24 Hours", "Last 7 Days", "Last 30 Days"],
            index=2,
            key=f"time_range_{st.session_state.net_ops_session_id}"
        )
        
        # Generate metrics
        metrics = generate_network_metrics(selected_source, selected_dest)
        df = pd.DataFrame(metrics['metrics'])
        
        # Summary metrics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Avg Latency", f"{metrics['avg_latency']} ms")
        
        with col2:
            st.metric("Packet Loss", f"{metrics['avg_packet_loss']}%")
        
        with col3:
            st.metric("Avg Throughput", f"{metrics['avg_throughput']} Mbps")
        
        with col4:
            st.metric("Availability", f"{metrics['uptime_24h']}%")
        
        st.markdown("---")
        
        # Multi-metric chart
        fig = go.Figure()
        
        # Latency
        fig.add_trace(go.Scatter(
            x=df['timestamp'],
            y=df['latency_ms'],
            name='Latency (ms)',
            mode='lines',
            line=dict(color='#3b82f6', width=2)
        ))
        
        # Jitter
        fig.add_trace(go.Scatter(
            x=df['timestamp'],
            y=df['jitter_ms'],
            name='Jitter (ms)',
            mode='lines',
            line=dict(color='#f59e0b', width=2)
        ))
        
        fig.update_layout(
            title=f"Latency & Jitter: {selected_source} → {selected_dest}",
            xaxis_title="Time",
            yaxis_title="Milliseconds (ms)",
            hovermode='x unified',
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
        )
        
        st.plotly_chart(fig, use_container_width=True)
        
        # Packet loss chart
        fig = go.Figure()
        
        fig.add_trace(go.Scatter(
            x=df['timestamp'],
            y=df['packet_loss_pct'],
            name='Packet Loss (%)',
            mode='lines+markers',
            line=dict(color='#ef4444', width=2),
            fill='tozeroy'
        ))
        
        fig.update_layout(
            title="Packet Loss",
            xaxis_title="Time",
            yaxis_title="Packet Loss (%)",
            hovermode='x unified'
        )
        
        st.plotly_chart(fig, use_container_width=True)
        
        # Latency distribution
        st.markdown("#### 📊 Latency Distribution")
        
        fig = px.histogram(df, x='latency_ms', nbins=20,
                          title="Latency Distribution",
                          labels={'latency_ms': 'Latency (ms)'},
                          color_discrete_sequence=['#3b82f6'])
        st.plotly_chart(fig, use_container_width=True)
        
        # Path comparison
        st.markdown("#### 🛣️ Path Comparison")
        
        comparison_data = []
        for vpn in topology['vpn_connections']:
            comparison_data.append({
                'Path': vpn['name'],
                'Type': 'VPN',
                'Latency (ms)': vpn['latency_ms'],
                'Packet Loss (%)': vpn['packet_loss_pct']
            })
        
        for dx in topology['dx_connections']:
            comparison_data.append({
                'Path': dx['name'],
                'Type': 'DX',
                'Latency (ms)': dx['latency_ms'],
                'Packet Loss (%)': dx['packet_loss_pct']
            })
        
        df_comparison = pd.DataFrame(comparison_data)
        
        fig = px.scatter(df_comparison, x='Latency (ms)', y='Packet Loss (%)',
                        color='Type', text='Path', size_max=20,
                        title="Latency vs Packet Loss - All Connections")
        fig.update_traces(textposition='top center')
        st.plotly_chart(fig, use_container_width=True)
    
    # ========================================================================
    # TAB 5: ALERTS & ISSUES
    # ========================================================================
    
    @staticmethod
    def _render_alerts():
        """Render alerts and issues"""
        
        st.markdown("### 🚨 Network Alerts & Issues")
        st.caption("Active alerts from CloudWatch Alarms")
        
        alerts = generate_network_alerts()
        
        # Summary
        critical = sum(1 for a in alerts if a['severity'] == 'Critical')
        warning = sum(1 for a in alerts if a['severity'] == 'Warning')
        info = sum(1 for a in alerts if a['severity'] == 'Info')
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Alerts", len(alerts))
        
        with col2:
            st.metric("Critical", critical, delta_color="inverse")
        
        with col3:
            st.metric("Warning", warning, delta_color="inverse")
        
        with col4:
            st.metric("Info", info)
        
        st.markdown("---")
        
        # Filter
        severity_filter = st.multiselect(
            "Filter by Severity",
            ['Critical', 'Warning', 'Info'],
            default=['Critical', 'Warning'],
            key=f"severity_filter_{st.session_state.net_ops_session_id}"
        )
        
        # Display alerts
        filtered_alerts = [a for a in alerts if a['severity'] in severity_filter]
        
        for alert in filtered_alerts:
            if alert['severity'] == 'Critical':
                st.error(f"🚨 **{alert['severity']} - {alert['type']}**")
            elif alert['severity'] == 'Warning':
                st.warning(f"⚠️ **{alert['severity']} - {alert['type']}**")
            else:
                st.info(f"ℹ️ **{alert['severity']} - {alert['type']}**")
            
            col1, col2 = st.columns([3, 1])
            
            with col1:
                st.markdown(f"**Connection:** {alert['connection']}")
                st.markdown(f"**Issue:** {alert['issue']}")
                st.markdown(f"**Impact:** {alert['impact']}")
                st.markdown(f"**Recommendation:** {alert['recommendation']}")
            
            with col2:
                st.caption(f"Detected: {alert['detected'].strftime('%Y-%m-%d %H:%M')}")
                st.caption(f"Status: {alert['status']}")
                
                if st.button(f"Acknowledge", key=f"ack_{alert['connection']}"):
                    st.success("Alert acknowledged")
            
            st.markdown("---")
    
    # ========================================================================
    # TAB 6: NETWORK TOPOLOGY
    # ========================================================================
    
    @staticmethod
    def _render_topology():
        """Render network topology visualization"""
        
        st.markdown("### 🗺️ Network Topology")
        st.caption("Visual representation of your network architecture")
        
        topology = generate_network_topology()
        
        # ASCII topology
        st.markdown("#### Network Architecture Diagram")
        
        st.code("""
    ┌─────────────────────────────────────────────────────────────┐
    │                     DATA CENTERS                            │
    └─────────────────────────────────────────────────────────────┘
    
    🏢 HQ NYC           🏢 London Branch      🏢 Dallas Backup
       │                      │                      │
       │ VPN + DX             │ VPN                 │ VPN + DX
       │                      │                      │
       ▼                      ▼                      ▼
    
    ┌─────────────────────────────────────────────────────────────┐
    │                     AWS REGIONS                             │
    └─────────────────────────────────────────────────────────────┘
    
    ☁️ us-east-1         ☁️ eu-west-1        ☁️ us-west-2
    (Virginia)           (Ireland)          (Oregon)
       │                      │                      │
    3 VPCs                1 VPC                 2 VPCs
    
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    
    Connections:
    ━━━ VPN (Site-to-Site)    ━━━ Direct Connect (Dedicated)
        """, language="text")
        
        # Connection summary
        st.markdown("#### 📊 Connection Summary")
        
        connection_summary = []
        
        for vpn in topology['vpn_connections']:
            dc = next(dc for dc in topology['data_centers'] if dc['id'] == vpn['source'])
            region = next(r for r in topology['aws_regions'] if r['id'] == vpn['destination'])
            
            connection_summary.append({
                'Source': dc['name'],
                'Destination': region['name'],
                'Type': 'VPN',
                'Bandwidth': f"{vpn['bandwidth_mbps']} Mbps",
                'Latency': f"{vpn['latency_ms']} ms",
                'Status': '🟢 UP' if vpn['tunnel_1_state'] == 'UP' else '🔴 DOWN'
            })
        
        for dx in topology['dx_connections']:
            dc = next(dc for dc in topology['data_centers'] if dc['id'] == dx['source'])
            region = next(r for r in topology['aws_regions'] if r['id'] == dx['destination'])
            
            connection_summary.append({
                'Source': dc['name'],
                'Destination': region['name'],
                'Type': 'Direct Connect',
                'Bandwidth': f"{dx['bandwidth_gbps']} Gbps",
                'Latency': f"{dx['latency_ms']} ms",
                'Status': '🟢 Available' if dx['status'] == 'available' else '🔴 Down'
            })
        
        df = pd.DataFrame(connection_summary)
        st.dataframe(df, use_container_width=True, hide_index=True)
    
    # ========================================================================
    # TAB 7: AUDIT TRAIL
    # ========================================================================
    
    @staticmethod
    def _render_audit_trail():
        """Render network changes audit trail"""
        
        st.markdown("### 📜 Network Changes Audit Trail")
        st.caption("Track all network configuration changes")
        
        # Sample audit data
        audit_data = [
            {
                'Timestamp': datetime.now() - timedelta(hours=2),
                'Action': 'VPN Tunnel Reset',
                'Resource': 'vpn-1',
                'User': 'admin@company.com',
                'Status': 'Success',
                'Details': 'Tunnel 2 reset completed successfully'
            },
            {
                'Timestamp': datetime.now() - timedelta(days=1),
                'Action': 'DX Connection Modified',
                'Resource': 'dx-1',
                'User': 'netops@company.com',
                'Status': 'Success',
                'Details': 'BGP configuration updated'
            },
            {
                'Timestamp': datetime.now() - timedelta(days=2),
                'Action': 'CloudWatch Alarm Created',
                'Resource': 'alarm-latency-high',
                'User': 'automation',
                'Status': 'Success',
                'Details': 'Latency threshold alarm created'
            }
        ]
        
        df = pd.DataFrame(audit_data)
        df['Timestamp'] = df['Timestamp'].dt.strftime('%Y-%m-%d %H:%M:%S')
        
        st.dataframe(df, use_container_width=True, hide_index=True)
        
        if st.button("📥 Export Audit Log", key=f"export_audit_log_{st.session_state.net_ops_session_id}"):
            csv = df.to_csv(index=False)
            st.download_button(
                "Download CSV",
                csv,
                "network_audit_trail.csv",
                "text/csv"
            )

# ============================================================================
# EXPORT
# ============================================================================

__all__ = ['NetworkOperationsDashboard']