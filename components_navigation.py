"""
Multi-Cloud Navigation Component
Supports AWS, Azure, and GCP with provider-specific module routing
"""

import streamlit as st
from core_session_manager import SessionManager

class Navigation:
    """Main application navigation with multi-cloud support"""
    
    @staticmethod
    def render(cloud_provider=None):
        """Render main navigation with cloud provider awareness"""
        
        # Get cloud provider from parameter or session state
        if cloud_provider is None:
            cloud_provider = st.session_state.get('cloud_provider', 'AWS')
        
        # Initialize active module in session state
        if 'active_module' not in st.session_state:
            st.session_state.active_module = 'Dashboard'
        
        # Define navigation items based on cloud provider
        # Note: Using same module keys for now, will route to cloud-specific implementations
        nav_items = [
            {"key": "Dashboard", "icon": "🏠", "label": "Dashboard"},
            {"key": "Account Management", "icon": "👥", "label": "Account Mgmt" if cloud_provider == "AWS" else "Subscription Mgmt" if cloud_provider == "Azure" else "Project Mgmt"},
            {"key": "Resource Inventory", "icon": "📦", "label": "Resources"},
            {"key": "Network (VPC)", "icon": "🌐", "label": "Network"},
            {"key": "Organizations", "icon": "🏢", "label": "Organizations" if cloud_provider == "AWS" else "Management Groups" if cloud_provider == "Azure" else "Organization"},
            {"key": "Design & Planning", "icon": "📐", "label": "Design"},
            {"key": "Provisioning", "icon": "🚀", "label": "Provisioning"},
            {"key": "CI/CD", "icon": "📄", "label": "CI/CD"},
            {"key": "Operations", "icon": "⚙️", "label": "Operations"},
            {"key": "Advanced Operations", "icon": "⚡", "label": "Advanced Ops"},
            {"key": "Security", "icon": "🤖", "label": "Security & AI"},
            {"key": "EKS Management", "icon": "📌", "label": "EKS" if cloud_provider == "AWS" else "AKS" if cloud_provider == "Azure" else "GKE"},
            {"key": "FinOps & Cost", "icon": "💰", "label": "FinOps"},
            {"key": "Account Lifecycle", "icon": "📄", "label": "Lifecycle"},
            {"key": "Developer Experience", "icon": "👨‍💻", "label": "DevEx"},
            {"key": "AI Assistant", "icon": "🤖", "label": "AI Assistant"},
            {"key": "Admin Panel", "icon": "👨‍💼", "label": "Admin"}
        ]
        
        # Display current cloud provider mode
        cloud_icon = {"AWS": "☁️", "Azure": "🔷", "GCP": "🔴"}
        st.markdown(f"### 🧭 Navigation - {cloud_icon.get(cloud_provider, '☁️')} {cloud_provider} Mode")
        
        # Row 1: First 8 modules
        col1, col2, col3, col4, col5, col6, col7, col8 = st.columns(8)
        cols_row1 = [col1, col2, col3, col4, col5, col6, col7, col8]
        
        for idx, item in enumerate(nav_items[:8]):
            with cols_row1[idx]:
                button_type = "primary" if st.session_state.active_module == item['key'] else "secondary"
                if st.button(
                    f"{item['icon']} {item['label']}",
                    key=f"nav_{item['key']}",
                    use_container_width=True,
                    type=button_type
                ):
                    st.session_state.active_module = item['key']
                    st.rerun()
        
        # Row 2: Modules 8-15 (next 8 modules)
        col9, col10, col11, col12, col13, col14, col15, col16 = st.columns(8)
        cols_row2 = [col9, col10, col11, col12, col13, col14, col15, col16]
        
        for idx, item in enumerate(nav_items[8:16]):  # Only items 8-15
            with cols_row2[idx]:
                button_type = "primary" if st.session_state.active_module == item['key'] else "secondary"
                if st.button(
                    f"{item['icon']} {item['label']}",
                    key=f"nav_{item['key']}",
                    use_container_width=True,
                    type=button_type
                ):
                    st.session_state.active_module = item['key']
                    st.rerun()
        
        # Row 3: Remaining modules (16+)
        if len(nav_items) > 16:
            remaining_items = nav_items[16:]
            num_remaining = len(remaining_items)
            
            # Create columns for remaining items
            if num_remaining == 1:
                col17 = st.columns(1)[0]
                cols_row3 = [col17]
            elif num_remaining <= 8:
                cols_row3 = st.columns(num_remaining)
            else:
                # If more than 8, use 8 columns
                cols_row3 = st.columns(8)
            
            for idx, item in enumerate(remaining_items[:len(cols_row3)]):
                with cols_row3[idx]:
                    button_type = "primary" if st.session_state.active_module == item['key'] else "secondary"
                    if st.button(
                        f"{item['icon']} {item['label']}",
                        key=f"nav_{item['key']}",
                        use_container_width=True,
                        type=button_type
                    ):
                        st.session_state.active_module = item['key']
                        st.rerun()
        
        st.markdown("---")
        
        # Render the active module based on cloud provider
        active_module = st.session_state.active_module
        
        # Define module routing
        try:
            if cloud_provider == "AWS":
                # AWS Module routing (original v2.0 code)
                Navigation._render_aws_module(active_module)
            elif cloud_provider == "Azure":
                # Azure Module routing
                Navigation._render_azure_module(active_module)
            elif cloud_provider == "GCP":
                # GCP Module routing
                Navigation._render_gcp_module(active_module)
            else:
                st.error(f"Unknown cloud provider: {cloud_provider}")
        except Exception as e:
            st.error(f"Error loading {active_module} for {cloud_provider}: {str(e)}")
            st.exception(e)
    
    @staticmethod
    def _render_aws_module(active_module):
        """Render AWS modules (original v2.0 code)"""
        
        # Module 0: Dashboard
        if active_module == "Dashboard":
            from modules_dashboard import DashboardModule
            DashboardModule.render()
        
        # Module 1: Account Management
        elif active_module == "Account Management":
            try:
                from modules_account_management import AccountManagementModule
                AccountManagementModule.render()
            except Exception as e:
                st.error(f"Error loading Account Management: {str(e)}")
        
        # Module 2: Resource Inventory
        elif active_module == "Resource Inventory":
            try:
                from modules_resource_inventory import ResourceInventoryModule
                ResourceInventoryModule.render()
            except Exception as e:
                st.error(f"Error loading Resource Inventory: {str(e)}")
        
        # Module 3: Network Management (VPC)
        elif active_module == "Network (VPC)":
            try:
                from modules_network_management import NetworkManagementUI
                NetworkManagementUI.render()
            except Exception as e:
                st.error(f"Error loading Network Management: {str(e)}")
        
        # Module 4: Organizations
        elif active_module == "Organizations":
            try:
                from modules_organizations import OrganizationsManagementUI
                OrganizationsManagementUI.render()
            except Exception as e:
                st.error(f"Error loading Organizations: {str(e)}")
        
        # Module 5: Design & Planning
        elif active_module == "Design & Planning":
            try:
                from modules_design_planning import DesignPlanningModule
                DesignPlanningModule.render()
            except Exception as e:
                st.error(f"Error loading Design & Planning: {str(e)}")
        
        # Module 6: Provisioning & Deployment
        elif active_module == "Provisioning":
            try:
                from modules_provisioning import ProvisioningModule
                ProvisioningModule.render()
            except Exception as e:
                st.error(f"Error loading Provisioning: {str(e)}")
        
        # Module 7: CI/CD (Unified - All 3 Phases)
        elif active_module == "CI/CD":
            try:
                from modules_cicd_unified import UnifiedCICDModule
                UnifiedCICDModule.render()
            except Exception as e:
                st.error(f"Error loading CI/CD: {str(e)}")
        
        # Module 8: Operations
        elif active_module == "Operations":
            try:
                from modules_operations import OperationsModule
                OperationsModule.render()
            except Exception as e:
                st.error(f"Error loading Operations: {str(e)}")
        
        # Module 9: Advanced Operations
        elif active_module == "Advanced Operations":
            try:
                from modules_advanced_operations import AdvancedOperationsModule
                AdvancedOperationsModule.render()
            except Exception as e:
                st.error(f"Error loading Advanced Operations: {str(e)}")
        
        # Module 10: Security, Compliance & AI
        elif active_module == "Security":
            try:
                from modules_security_compliance import UnifiedSecurityComplianceModule
                UnifiedSecurityComplianceModule.render()
            except Exception as e:
                st.error(f"Error loading Security, Compliance & AI: {str(e)}")
        
        # Module 11: EKS Management
        elif active_module == "EKS Management":
            try:
                from modules_eks_management import EKSManagementModule
                EKSManagementModule.render()
            except Exception as e:
                st.error(f"Error loading EKS Management: {str(e)}")
        
        # Module 12: FinOps & Cost
        elif active_module == "FinOps & Cost":
            try:
                from modules_finops import FinOpsModule
                FinOpsModule.render()
            except Exception as e:
                st.error(f"Error loading FinOps: {str(e)}")
        
        # Module 13: Account Lifecycle
        elif active_module == "Account Lifecycle":
            try:
                from modules_account_lifecycle import AccountLifecycleModule
                AccountLifecycleModule.render()
            except Exception as e:
                st.error(f"Error loading Account Lifecycle: {str(e)}")
        
        # Module 14: Developer Experience
        elif active_module == "Developer Experience":
            try:
                from modules_devex import DevExModule
                DevExModule.render()
            except Exception as e:
                st.error(f"Error loading Developer Experience: {str(e)}")
        
        # Module 15: AI Assistant
        elif active_module == "AI Assistant":
            try:
                from modules_ai_assistant import AIAssistantModule
                AIAssistantModule.render()
            except Exception as e:
                st.error(f"Error loading AI Assistant: {str(e)}")
        
        # Module 16: Admin Panel
        elif active_module == "Admin Panel":
            try:
                from modules_admin_panel import AdminPanelModule
                AdminPanelModule.render()
            except Exception as e:
                st.error(f"Error loading Admin Panel: {str(e)}")
        
        # Default fallback
        else:
            st.warning(f"⚠️ Module '{active_module}' is under development for AWS")
    
    @staticmethod
    def _render_azure_module(active_module):
        """Render Azure modules"""
        
        # Map module names to Azure module files
        module_mapping = {
            "Dashboard": "azure_modules_dashboard",
            "Account Management": "azure_modules_subscription_management",
            "Resource Inventory": "azure_modules_resource_inventory_enhanced",
            "Network (VPC)": "azure_modules_network_enhanced",
            "Organizations": "azure_modules_organization_enhanced",
            "Design & Planning": "azure_modules_design_planning",
            "Provisioning": "azure_modules_provisioning",
            "CI/CD": "azure_modules_cicd_unified",
            "Operations": "azure_modules_operations_enhanced",
            "Advanced Operations": "azure_modules_advanced_operations",
            "Security": "azure_modules_security_and_compliance",
            "EKS Management": "azure_modules_aks_management",
            "FinOps & Cost": "azure_modules_finops_and_cost",
            "Account Lifecycle": "azure_modules_subscription_management",
            "Developer Experience": "azure_modules_developer_experience",
            "AI Assistant": "azure_modules_ai_assistant",
            "Admin Panel": "modules_admin_panel"  # Uses AWS module
        }
        
        # Get the appropriate module file
        module_file = module_mapping.get(active_module)
        
        if module_file:
            try:
                # Import and render the module
                module = __import__(module_file)
                module.render()
            except Exception as e:
                st.error(f"Error loading Azure module {active_module}: {str(e)}")
                st.info(f"🔷 Azure Module: {active_module}")
                st.write(f"Module file: {module_file}.py")
                st.exception(e)
        else:
            st.warning(f"⚠️ Azure module '{active_module}' mapping not found")
            st.info(f"Available Azure modules are being loaded. Please check back shortly.")
    
    @staticmethod
    def _render_gcp_module(active_module):
        """Render GCP modules"""
        
        # Map module names to GCP module files
        module_mapping = {
            "Dashboard": "gcp_modules_dashboard",
            "Account Management": "gcp_modules_project_management",
            "Resource Inventory": "gcp_modules_resource_inventory_enhanced",
            "Network (VPC)": "gcp_modules_network_enhanced",
            "Organizations": "gcp_modules_organization_enhanced",
            "Design & Planning": "gcp_modules_design_planning",
            "Provisioning": "gcp_modules_provisioning",
            "CI/CD": "gcp_modules_cicd_unified",
            "Operations": "gcp_modules_operations_enhanced",
            "Advanced Operations": "gcp_modules_advanced_operations",
            "Security": "gcp_modules_security_compliance",
            "EKS Management": "gcp_modules_gke_management",
            "FinOps & Cost": "gcp_modules_finops_cost",
            "Account Lifecycle": "gcp_modules_project_management",
            "Developer Experience": "gcp_modules_developer_experience",
            "AI Assistant": "gcp_modules_ai_assistant",
            "Admin Panel": "modules_admin_panel"  # Uses AWS module
        }
        
        # Get the appropriate module file
        module_file = module_mapping.get(active_module)
        
        if module_file:
            try:
                # Import and render the module
                module = __import__(module_file)
                module.render()
            except Exception as e:
                st.error(f"Error loading GCP module {active_module}: {str(e)}")
                st.info(f"🔴 GCP Module: {active_module}")
                st.write(f"Module file: {module_file}.py")
                st.exception(e)
        else:
            st.warning(f"⚠️ GCP module '{active_module}' mapping not found")
            st.info(f"Available GCP modules are being loaded. Please check back shortly.")