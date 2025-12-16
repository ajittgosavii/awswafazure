"""
Network Management Module - VPC, Subnets, Security Groups
UI for AWS VPC and network infrastructure management
"""

import streamlit as st
import pandas as pd
from typing import Optional
from core_account_manager import get_account_manager, get_account_names
from aws_vpc import VPCManager

class NetworkManagementUI:
    """UI for VPC and Network Management"""
    
    @staticmethod
    def render():
        """Main render method for Network Management module"""
        st.title("🌐 Network Infrastructure Management")
        
        # Get account manager
        account_mgr = get_account_manager()
        
        if not account_mgr:
            st.warning("⚠️ Please configure AWS credentials in Account Management")
            st.info("👉 Go to the 'Account Management' tab to add your AWS accounts first.")
            return
        
        # Get account names
        account_names = get_account_names()
        
        if not account_names:
            st.warning("⚠️ No AWS accounts configured")
            st.info("👉 Go to the 'Account Management' tab to add your AWS accounts first.")
            return
        
        # Account selector
        selected_account = st.selectbox(
            "Select AWS Account",
            options=account_names,
            key="network_account_selector"
        )
        
        if not selected_account:
            st.info("Please select an account")
            return
        
        # Check if a specific region is selected
        selected_region = st.session_state.get('selected_regions', 'all')
        
        if selected_region == 'all':
            st.error("❌ Error loading Network Management: You must specify a region.")
            st.info("📍 Network resources (VPCs, Subnets, Security Groups) are region-specific. Please select a specific region from the sidebar to view network infrastructure.")
            return
        
        # Get region-specific session for selected account
        session = account_mgr.get_session_with_region(selected_account, selected_region)
        if not session:
            st.error(f"Failed to get session for {selected_account} in region {selected_region}")
            return
        
        # Initialize VPC Manager with region-specific session
        vpc_mgr = VPCManager(session)
        
        # Show selected region
        st.info(f"📍 Viewing network resources in **{selected_region}**")
        
        # Main tabs
        tabs = st.tabs([
            "📋 VPC Overview",
            "🏗️ Create VPC",
            "📡 Subnets",
            "🌐 Internet Gateways",
            "🔄 NAT Gateways",
            "🛣️ Route Tables",
            "🔒 Security Groups"
        ])
        
        # VPC Overview Tab
        with tabs[0]:
            NetworkManagementUI._render_vpc_overview(vpc_mgr)
        
        # Create VPC Tab
        with tabs[1]:
            NetworkManagementUI._render_create_vpc(vpc_mgr)
        
        # Subnets Tab
        with tabs[2]:
            NetworkManagementUI._render_subnets(vpc_mgr)
        
        # Internet Gateways Tab
        with tabs[3]:
            NetworkManagementUI._render_internet_gateways(vpc_mgr)
        
        # NAT Gateways Tab
        with tabs[4]:
            NetworkManagementUI._render_nat_gateways(vpc_mgr)
        
        # Route Tables Tab
        with tabs[5]:
            NetworkManagementUI._render_route_tables(vpc_mgr)
        
        # Security Groups Tab
        with tabs[6]:
            NetworkManagementUI._render_security_groups(vpc_mgr)
    
    @staticmethod
    def _render_vpc_overview(vpc_mgr: VPCManager):
        """Render VPC overview"""
        st.subheader("📋 VPC Overview")
        
        # List VPCs
        vpcs = vpc_mgr.list_vpcs()
        
        if not vpcs:
            st.info("No VPCs found in this account/region")
            return
        
        # Display metrics
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total VPCs", len(vpcs))
        with col2:
            default_vpcs = sum(1 for v in vpcs if v.get('is_default'))
            st.metric("Default VPCs", default_vpcs)
        with col3:
            custom_vpcs = len(vpcs) - default_vpcs
            st.metric("Custom VPCs", custom_vpcs)
        
        # VPC table
        st.markdown("### VPC List")
        vpc_df = pd.DataFrame(vpcs)
        st.dataframe(
            vpc_df[['vpc_id', 'cidr_block', 'state', 'is_default', 'dns_support', 'dns_hostnames']],
            use_container_width=True
        )
        
        # VPC Details
        if len(vpcs) > 0:
            st.markdown("### VPC Details")
            selected_vpc = st.selectbox(
                "Select VPC to view details",
                options=[v['vpc_id'] for v in vpcs],
                format_func=lambda x: f"{x} - {next((v['cidr_block'] for v in vpcs if v['vpc_id'] == x), '')}"
            )
            
            if selected_vpc:
                vpc_details = next((v for v in vpcs if v['vpc_id'] == selected_vpc), None)
                if vpc_details:
                    col1, col2 = st.columns(2)
                    with col1:
                        st.write("**VPC ID:**", vpc_details['vpc_id'])
                        st.write("**CIDR Block:**", vpc_details['cidr_block'])
                        st.write("**State:**", vpc_details['state'])
                    with col2:
                        st.write("**Default VPC:**", "Yes" if vpc_details['is_default'] else "No")
                        st.write("**DNS Support:**", "Enabled" if vpc_details['dns_support'] else "Disabled")
                        st.write("**DNS Hostnames:**", "Enabled" if vpc_details['dns_hostnames'] else "Disabled")
                    
                    # Tags
                    if vpc_details.get('tags'):
                        st.write("**Tags:**")
                        # Display tags as a nice table instead of JSON
                        tags_data = [{"Key": k, "Value": v} for k, v in vpc_details['tags'].items()]
                        tags_df = pd.DataFrame(tags_data)
                        st.dataframe(tags_df, hide_index=True, use_container_width=True)
    
    @staticmethod
    def _render_create_vpc(vpc_mgr: VPCManager):
        """Render VPC creation form"""
        st.subheader("🏗️ Create New VPC")
        
        with st.form("create_vpc_form"):
            vpc_name = st.text_input("VPC Name", placeholder="my-vpc")
            cidr_block = st.text_input("CIDR Block", value="10.0.0.0/16", 
                                      help="Example: 10.0.0.0/16 for 65,536 IPs")
            enable_dns = st.checkbox("Enable DNS Support", value=True)
            
            submit = st.form_submit_button("Create VPC")
            
            if submit:
                if not vpc_name or not cidr_block:
                    st.error("Please provide VPC name and CIDR block")
                else:
                    with st.spinner("Creating VPC..."):
                        result = vpc_mgr.create_vpc(cidr_block, vpc_name, enable_dns)
                        
                        if result.get('success'):
                            st.success(f"✅ {result.get('message', 'VPC created successfully')}")
                            st.info(f"VPC ID: {result.get('vpc_id')}")
                            st.rerun()
                        else:
                            st.error(f"❌ {result.get('error', 'Failed to create VPC')}")
    
    @staticmethod
    def _render_subnets(vpc_mgr: VPCManager):
        """Render subnets management"""
        st.subheader("📡 Subnet Management")
        
        # List all subnets
        subnets = vpc_mgr.list_subnets()
        
        if not subnets:
            st.info("No subnets found")
            return
        
        # Metrics
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Subnets", len(subnets))
        with col2:
            public_subnets = sum(1 for s in subnets if s.get('public'))
            st.metric("Public Subnets", public_subnets)
        with col3:
            private_subnets = len(subnets) - public_subnets
            st.metric("Private Subnets", private_subnets)
        
        # Subnet table
        subnet_df = pd.DataFrame(subnets)
        st.dataframe(
            subnet_df[['subnet_id', 'vpc_id', 'cidr_block', 'availability_zone', 'available_ips', 'state', 'public']],
            use_container_width=True
        )
        
        # Create subnet form
        st.markdown("### Create Subnet")
        with st.expander("Create New Subnet"):
            vpcs = vpc_mgr.list_vpcs()
            if vpcs:
                vpc_id = st.selectbox("Select VPC", options=[v['vpc_id'] for v in vpcs])
                subnet_name = st.text_input("Subnet Name", key="subnet_name")
                subnet_cidr = st.text_input("CIDR Block", value="10.0.1.0/24", key="subnet_cidr")
                az = st.text_input("Availability Zone", value="us-east-1a", key="subnet_az")
                is_public = st.checkbox("Public Subnet (auto-assign public IP)", key="subnet_public")
                
                if st.button("Create Subnet"):
                    if vpc_id and subnet_name and subnet_cidr and az:
                        result = vpc_mgr.create_subnet(vpc_id, subnet_cidr, az, subnet_name, is_public)
                        if result.get('success'):
                            st.success(f"✅ {result.get('message')}")
                            st.rerun()
                        else:
                            st.error(f"❌ {result.get('error')}")
    
    @staticmethod
    def _render_internet_gateways(vpc_mgr: VPCManager):
        """Render Internet Gateways"""
        st.subheader("🌐 Internet Gateways")
        
        igws = vpc_mgr.list_internet_gateways()
        
        if igws:
            igw_df = pd.DataFrame(igws)
            st.dataframe(igw_df, use_container_width=True)
        else:
            st.info("No Internet Gateways found")
        
        # Create IGW
        st.markdown("### Create Internet Gateway")
        with st.expander("Create New Internet Gateway"):
            vpcs = vpc_mgr.list_vpcs()
            if vpcs:
                vpc_id = st.selectbox("Select VPC", options=[v['vpc_id'] for v in vpcs], key="igw_vpc")
                igw_name = st.text_input("IGW Name", key="igw_name")
                
                if st.button("Create & Attach IGW"):
                    if vpc_id and igw_name:
                        result = vpc_mgr.create_internet_gateway(vpc_id, igw_name)
                        if result.get('success'):
                            st.success(f"✅ {result.get('message')}")
                            st.rerun()
                        else:
                            st.error(f"❌ {result.get('error')}")
    
    @staticmethod
    def _render_nat_gateways(vpc_mgr: VPCManager):
        """Render NAT Gateways"""
        st.subheader("🔄 NAT Gateways")
        
        nats = vpc_mgr.list_nat_gateways()
        
        if nats:
            nat_df = pd.DataFrame(nats)
            st.dataframe(nat_df[['nat_id', 'vpc_id', 'subnet_id', 'state', 'public_ip']], 
                        use_container_width=True)
        else:
            st.info("No NAT Gateways found")
        
        # Create NAT Gateway
        st.markdown("### Create NAT Gateway")
        with st.expander("Create New NAT Gateway"):
            st.warning("⚠️ NAT Gateways incur hourly charges (~$0.045/hour + data transfer)")
            
            subnets = vpc_mgr.list_subnets()
            public_subnets = [s for s in subnets if s.get('public')]
            
            if public_subnets:
                subnet_id = st.selectbox(
                    "Select Public Subnet",
                    options=[s['subnet_id'] for s in public_subnets],
                    key="nat_subnet"
                )
                nat_name = st.text_input("NAT Gateway Name", key="nat_name")
                
                if st.button("Create NAT Gateway"):
                    if subnet_id and nat_name:
                        result = vpc_mgr.create_nat_gateway(subnet_id, nat_name)
                        if result.get('success'):
                            st.success(f"✅ {result.get('message')}")
                            st.info(f"Elastic IP: {result.get('eip')}")
                            st.rerun()
                        else:
                            st.error(f"❌ {result.get('error')}")
            else:
                st.warning("No public subnets available. Create a public subnet first.")
    
    @staticmethod
    def _render_route_tables(vpc_mgr: VPCManager):
        """Render Route Tables"""
        st.subheader("🛣️ Route Tables")
        
        route_tables = vpc_mgr.list_route_tables()
        
        if not route_tables:
            st.info("No route tables found")
            return
        
        # Display route tables
        for rt in route_tables:
            with st.expander(f"Route Table: {rt['route_table_id']} {'(Main)' if rt['is_main'] else ''}"):
                col1, col2 = st.columns(2)
                with col1:
                    st.write("**Route Table ID:**", rt['route_table_id'])
                    st.write("**VPC ID:**", rt['vpc_id'])
                with col2:
                    st.write("**Main Route Table:**", "Yes" if rt['is_main'] else "No")
                    st.write("**Associations:**", len(rt.get('associations', [])))
                
                # Routes
                if rt.get('routes'):
                    st.write("**Routes:**")
                    routes_df = pd.DataFrame(rt['routes'])
                    st.dataframe(routes_df, use_container_width=True)
    
    @staticmethod
    def _render_security_groups(vpc_mgr: VPCManager):
        """Render Security Groups"""
        st.subheader("🔒 Security Groups")
        
        security_groups = vpc_mgr.list_security_groups()
        
        if not security_groups:
            st.info("No security groups found")
            return
        
        # Display security groups
        st.write(f"**Total Security Groups:** {len(security_groups)}")
        
        for sg in security_groups:
            with st.expander(f"{sg['group_name']} ({sg['group_id']})"):
                st.write("**Description:**", sg['description'])
                st.write("**VPC ID:**", sg.get('vpc_id', 'N/A'))
                
                col1, col2 = st.columns(2)
                with col1:
                    st.write("**Inbound Rules:**", len(sg.get('ingress_rules', [])))
                    if sg.get('ingress_rules'):
                        st.json(sg['ingress_rules'])
                with col2:
                    st.write("**Outbound Rules:**", len(sg.get('egress_rules', [])))
                    if sg.get('egress_rules'):
                        st.json(sg['egress_rules'])
        
        # Create security group
        st.markdown("### Create Security Group")
        with st.expander("Create New Security Group"):
            vpcs = vpc_mgr.list_vpcs()
            if vpcs:
                vpc_id = st.selectbox("Select VPC", options=[v['vpc_id'] for v in vpcs], key="sg_vpc")
                sg_name = st.text_input("Security Group Name", key="sg_name")
                sg_desc = st.text_input("Description", key="sg_desc")
                
                if st.button("Create Security Group"):
                    if vpc_id and sg_name and sg_desc:
                        result = vpc_mgr.create_security_group(vpc_id, sg_name, sg_desc)
                        if result.get('success'):
                            st.success(f"✅ {result.get('message')}")
                            st.rerun()
                        else:
                            st.error(f"❌ {result.get('error')}")