"""
EKS Sizing & Component Selection Framework
Comprehensive guide for capacity planning and technology decisions

This module adds to eks_modernization_v2.py:
1. 📊 EKS Sizing Calculator & Framework
2. 🔧 Component Selection Decision Trees
3. 🏗️ Integrated Transformation Guide
4. 📈 Capacity Planning Tools
"""

import streamlit as st
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
import math

# ============================================================================
# EKS SIZING FRAMEWORK
# ============================================================================

@dataclass
class WorkloadProfile:
    """Application workload profile for sizing"""
    name: str
    replicas: int
    cpu_request_millicores: int
    memory_request_mb: int
    cpu_limit_millicores: int
    memory_limit_mb: int
    is_critical: bool
    can_use_spot: bool
    requires_gpu: bool = False
    
    def get_total_cpu_request(self) -> float:
        """Total CPU request in cores"""
        return (self.replicas * self.cpu_request_millicores) / 1000
    
    def get_total_memory_request(self) -> float:
        """Total memory request in GB"""
        return (self.replicas * self.memory_request_mb) / 1024
    
    def get_total_cpu_limit(self) -> float:
        """Total CPU limit in cores"""
        return (self.replicas * self.cpu_limit_millicores) / 1000
    
    def get_total_memory_limit(self) -> float:
        """Total memory limit in GB"""
        return (self.replicas * self.memory_limit_mb) / 1024

@dataclass
class ClusterSizingResult:
    """Results of cluster sizing calculation"""
    total_cpu_needed: float
    total_memory_needed: float
    recommended_nodes: int
    recommended_instance_type: str
    estimated_monthly_cost: float
    overhead_percentage: float
    safety_buffer: float
    spot_eligible_percentage: float
    
    def get_cost_breakdown(self) -> Dict:
        """Detailed cost breakdown"""
        on_demand_cost = self.estimated_monthly_cost * (1 - self.spot_eligible_percentage/100)
        spot_cost = self.estimated_monthly_cost * (self.spot_eligible_percentage/100) * 0.3  # 70% savings
        return {
            'on_demand': on_demand_cost,
            'spot': spot_cost,
            'total': on_demand_cost + spot_cost,
            'savings': self.estimated_monthly_cost - (on_demand_cost + spot_cost)
        }

def render_eks_sizing_calculator():
    """Interactive EKS sizing calculator"""
    st.markdown("## 📊 EKS Cluster Sizing Calculator")
    
    st.markdown("""
    ### Why Sizing Matters
    
    **Over-provisioning (40-60% of organizations):**
    - 💸 Wasting $1000s per month
    - 🎯 Running at 20-30% utilization
    - 😰 Fear of running out of capacity
    
    **Under-provisioning (20-30% of organizations):**
    - 🔴 Application performance issues
    - 📈 Constant scaling events
    - 🚨 Production incidents
    
    **Right-sizing (Goal):**
    - ✅ 60-70% average utilization
    - 💰 Optimal cost efficiency
    - 📊 Room for burst traffic
    - 🎯 Predictable performance
    """)
    
    st.markdown("---")
    
    # Sizing method selection
    sizing_method = st.radio(
        "Choose Your Sizing Approach",
        [
            "🎯 Quick Estimate (Based on current infrastructure)",
            "📊 Detailed Workload Analysis (Recommended)",
            "🧮 Formula-Based Calculation (Advanced)"
        ]
    )
    
    if "Quick Estimate" in sizing_method:
        render_quick_sizing_estimate()
    elif "Detailed Workload" in sizing_method:
        render_detailed_workload_sizing()
    else:
        render_formula_based_sizing()

def render_quick_sizing_estimate():
    """Quick sizing based on current infrastructure"""
    st.markdown("### 🎯 Quick Estimate Method")
    
    st.info("""
    **Best for:** Initial planning when migrating from VMs/EC2
    
    **Accuracy:** ±30% (refine with actual usage data)
    """)
    
    col1, col2 = st.columns(2)
    
    with col1:
        current_vms = st.number_input("Number of Current VMs/Instances", min_value=1, value=10)
        avg_cpu_cores = st.number_input("Average vCPUs per VM", min_value=1, value=4)
        avg_memory_gb = st.number_input("Average Memory (GB) per VM", min_value=1, value=16)
    
    with col2:
        current_utilization = st.slider("Current Average Utilization %", 10, 90, 40)
        target_utilization = st.slider("Target EKS Utilization %", 50, 80, 65)
        growth_factor = st.slider("Expected Growth in 12 Months %", 0, 200, 20)
    
    if st.button("Calculate Cluster Size", use_container_width=True):
        # Calculate current capacity
        total_cpu = current_vms * avg_cpu_cores
        total_memory = current_vms * avg_memory_gb
        
        # Adjust for actual usage
        actual_cpu_used = total_cpu * (current_utilization / 100)
        actual_memory_used = total_memory * (current_utilization / 100)
        
        # Calculate needed capacity with growth
        needed_cpu = actual_cpu_used * (1 + growth_factor / 100)
        needed_memory = actual_memory_used * (1 + growth_factor / 100)
        
        # Account for target utilization
        required_cpu = needed_cpu / (target_utilization / 100)
        required_memory = needed_memory / (target_utilization / 100)
        
        # Add Kubernetes overhead (15-20%)
        overhead_factor = 1.20
        final_cpu = required_cpu * overhead_factor
        final_memory = required_memory * overhead_factor
        
        # Recommend instance type
        instance_recommendation = recommend_instance_type(final_cpu, final_memory)
        
        # Display results
        st.success("### 📈 Sizing Recommendations")
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Required CPU Cores", f"{final_cpu:.1f}")
            st.caption(f"Current: {total_cpu} → {actual_cpu_used:.1f} used")
        with col2:
            st.metric("Required Memory (GB)", f"{final_memory:.1f}")
            st.caption(f"Current: {total_memory} → {actual_memory_used:.1f} used")
        with col3:
            st.metric("Recommended Nodes", f"{instance_recommendation['node_count']}")
            st.caption(f"Instance: {instance_recommendation['instance_type']}")
        
        st.markdown("---")
        
        # Cost estimate
        cost_estimate = calculate_cost_estimate(
            instance_recommendation['instance_type'],
            instance_recommendation['node_count'],
            spot_percentage=50
        )
        
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("### 💰 Estimated Monthly Cost")
            st.metric("Total Cost", f"${cost_estimate['total']:,.0f}/month")
            st.caption(f"On-Demand: ${cost_estimate['on_demand']:,.0f} + Spot: ${cost_estimate['spot']:,.0f}")
        
        with col2:
            st.markdown("### 💡 Cost Optimization Potential")
            savings = calculate_potential_savings(cost_estimate['total'])
            st.metric("Potential Savings", f"${savings:,.0f}/month", delta="-40%")
            st.caption("With right-sizing + Spot + Karpenter")
        
        # Detailed breakdown
        with st.expander("📊 Detailed Breakdown"):
            st.markdown(f"""
            **Capacity Planning:**
            - Current VMs: {current_vms} × {avg_cpu_cores} vCPU × {avg_memory_gb} GB
            - Current Total: {total_cpu} vCPU, {total_memory} GB RAM
            - Actual Usage ({current_utilization}%): {actual_cpu_used:.1f} vCPU, {actual_memory_used:.1f} GB
            - With Growth ({growth_factor}%): {needed_cpu:.1f} vCPU, {needed_memory:.1f} GB
            - Target Utilization ({target_utilization}%): {required_cpu:.1f} vCPU, {required_memory:.1f} GB
            - With K8s Overhead (20%): {final_cpu:.1f} vCPU, {final_memory:.1f} GB
            
            **Architecture:**
            - Instance Type: {instance_recommendation['instance_type']}
            - Per-Instance: {instance_recommendation['vcpu']} vCPU, {instance_recommendation['memory_gb']} GB
            - Node Count: {instance_recommendation['node_count']} nodes
            - Distribution: 3 AZs ({instance_recommendation['node_count']//3} nodes per AZ)
            - Spot Eligible: ~50% (for non-critical workloads)
            
            **Cost Breakdown:**
            - Base Monthly (On-Demand): ${cost_estimate['base']:,.0f}
            - With 50% Spot (70% discount): ${cost_estimate['total']:,.0f}
            - Potential Optimizations: ${savings:,.0f} additional savings
            """)
        
        # Next steps
        st.markdown("### 🎯 Next Steps")
        st.info("""
        1. **Start Conservative:** Begin with these numbers, monitor for 2 weeks
        2. **Enable Monitoring:** Install metrics-server and Container Insights
        3. **Track Utilization:** Aim for 60-70% average, 80-85% peak
        4. **Right-size Weekly:** Review and adjust based on actual usage
        5. **Add Karpenter:** Automate sizing decisions (Month 2-3)
        """)

def render_detailed_workload_sizing():
    """Detailed workload-by-workload sizing"""
    st.markdown("### 📊 Detailed Workload Analysis")
    
    st.info("""
    **Best for:** Accurate capacity planning with known application requirements
    
    **Accuracy:** ±10% (high accuracy)
    """)
    
    st.markdown("#### Define Your Workloads")
    
    # Initialize session state for workloads
    if 'workloads' not in st.session_state:
        st.session_state.workloads = []
    
    # Add workload form
    with st.expander("➕ Add Workload", expanded=len(st.session_state.workloads) == 0):
        with st.form("add_workload"):
            col1, col2, col3 = st.columns(3)
            
            with col1:
                name = st.text_input("Workload Name", "web-app")
                replicas = st.number_input("Number of Replicas", 1, 100, 3)
                is_critical = st.checkbox("Critical Service", value=True)
            
            with col2:
                cpu_request = st.number_input("CPU Request (millicores)", 100, 8000, 500)
                cpu_limit = st.number_input("CPU Limit (millicores)", 100, 16000, 1000)
                can_use_spot = st.checkbox("Spot Eligible", value=not is_critical)
            
            with col3:
                memory_request = st.number_input("Memory Request (MB)", 128, 32768, 1024)
                memory_limit = st.number_input("Memory Limit (MB)", 128, 65536, 2048)
            
            if st.form_submit_button("Add Workload"):
                workload = WorkloadProfile(
                    name=name,
                    replicas=replicas,
                    cpu_request_millicores=cpu_request,
                    cpu_limit_millicores=cpu_limit,
                    memory_request_mb=memory_request,
                    memory_limit_mb=memory_limit,
                    is_critical=is_critical,
                    can_use_spot=can_use_spot
                )
                st.session_state.workloads.append(workload)
                st.success(f"Added {name}")
                st.rerun()
    
    # Display current workloads
    if st.session_state.workloads:
        st.markdown("#### Your Workloads")
        
        for i, workload in enumerate(st.session_state.workloads):
            col1, col2, col3, col4, col5 = st.columns([2, 1, 1, 1, 1])
            with col1:
                st.text(f"🔹 {workload.name}")
            with col2:
                st.text(f"{workload.replicas} replicas")
            with col3:
                st.text(f"{workload.get_total_cpu_request():.2f} CPU")
            with col4:
                st.text(f"{workload.get_total_memory_request():.2f} GB")
            with col5:
                if st.button("🗑️", key=f"delete_{i}"):
                    st.session_state.workloads.pop(i)
                    st.rerun()
        
        # Calculate cluster size
        if st.button("🧮 Calculate Required Cluster Size", use_container_width=True):
            result = calculate_cluster_from_workloads(st.session_state.workloads)
            display_sizing_results(result, st.session_state.workloads)

def calculate_cluster_from_workloads(workloads: List[WorkloadProfile]) -> ClusterSizingResult:
    """Calculate cluster size from workload profiles"""
    
    # Sum up all workload requirements
    total_cpu_request = sum(w.get_total_cpu_request() for w in workloads)
    total_memory_request = sum(w.get_total_memory_request() for w in workloads)
    
    # Add Kubernetes system overhead (15-20%)
    k8s_overhead = 0.20
    cpu_with_overhead = total_cpu_request * (1 + k8s_overhead)
    memory_with_overhead = total_memory_request * (1 + k8s_overhead)
    
    # Add safety buffer (15-20% for burst traffic)
    safety_buffer = 0.20
    final_cpu = cpu_with_overhead * (1 + safety_buffer)
    final_memory = memory_with_overhead * (1 + safety_buffer)
    
    # Calculate spot eligibility
    spot_eligible_cpu = sum(w.get_total_cpu_request() for w in workloads if w.can_use_spot)
    spot_percentage = (spot_eligible_cpu / total_cpu_request * 100) if total_cpu_request > 0 else 0
    
    # Recommend instance type and count
    instance_rec = recommend_instance_type(final_cpu, final_memory)
    
    # Calculate costs
    cost_est = calculate_cost_estimate(
        instance_rec['instance_type'],
        instance_rec['node_count'],
        spot_percentage
    )
    
    return ClusterSizingResult(
        total_cpu_needed=final_cpu,
        total_memory_needed=final_memory,
        recommended_nodes=instance_rec['node_count'],
        recommended_instance_type=instance_rec['instance_type'],
        estimated_monthly_cost=cost_est['total'],
        overhead_percentage=k8s_overhead * 100,
        safety_buffer=safety_buffer * 100,
        spot_eligible_percentage=spot_percentage
    )

def display_sizing_results(result: ClusterSizingResult, workloads: List[WorkloadProfile]):
    """Display detailed sizing results"""
    st.success("### ✅ Cluster Sizing Complete")
    
    # Top metrics
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total CPU", f"{result.total_cpu_needed:.1f} cores")
    with col2:
        st.metric("Total Memory", f"{result.total_memory_needed:.1f} GB")
    with col3:
        st.metric("Nodes Required", result.recommended_nodes)
    with col4:
        st.metric("Instance Type", result.recommended_instance_type)
    
    st.markdown("---")
    
    # Cost breakdown
    cost_breakdown = result.get_cost_breakdown()
    
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("### 💰 Cost Estimate")
        st.metric("Monthly Cost", f"${cost_breakdown['total']:,.0f}")
        st.caption(f"""
        On-Demand: ${cost_breakdown['on_demand']:,.0f}
        Spot ({result.spot_eligible_percentage:.0f}% workloads): ${cost_breakdown['spot']:,.0f}
        **Savings:** ${cost_breakdown['savings']:,.0f}/month from Spot
        """)
    
    with col2:
        st.markdown("### 📊 Capacity Breakdown")
        st.progress(result.spot_eligible_percentage / 100)
        st.caption(f"{result.spot_eligible_percentage:.0f}% Spot Eligible | {100-result.spot_eligible_percentage:.0f}% On-Demand")
    
    # Workload distribution
    with st.expander("📋 Workload Distribution Analysis"):
        st.markdown("**Critical vs Non-Critical:**")
        critical = [w for w in workloads if w.is_critical]
        non_critical = [w for w in workloads if not w.is_critical]
        
        col1, col2 = st.columns(2)
        with col1:
            st.markdown(f"**Critical ({len(critical)}):** On-Demand nodes")
            for w in critical:
                st.text(f"  • {w.name}: {w.get_total_cpu_request():.2f} CPU, {w.get_total_memory_request():.2f} GB")
        
        with col2:
            st.markdown(f"**Non-Critical ({len(non_critical)}):** Spot eligible")
            for w in non_critical:
                st.text(f"  • {w.name}: {w.get_total_cpu_request():.2f} CPU, {w.get_total_memory_request():.2f} GB")
    
    # Architecture recommendation
    with st.expander("🏗️ Recommended Architecture"):
        st.markdown(f"""
        **Node Configuration:**
        - Instance Type: {result.recommended_instance_type}
        - Total Nodes: {result.recommended_nodes}
        - Distribution: 3 AZs ({result.recommended_nodes // 3} nodes per AZ)
        
        **Node Groups:**
        1. **On-Demand Critical (30-40% capacity)**
           - For critical services (databases, auth, monitoring)
           - Instance Type: {result.recommended_instance_type}
           - Min: {max(3, result.recommended_nodes // 3)} nodes
        
        2. **Spot Best-Effort (60-70% capacity)**
           - For stateless workloads
           - Multiple instance types for diversification
           - Managed by Karpenter for optimal selection
        
        **Autoscaling:**
        - Use Karpenter for intelligent node provisioning
        - Set HPA for pod-level scaling
        - Configure PDB to protect critical services
        """)
    
    # Implementation guide
    st.markdown("### 🚀 Implementation Guide")
    
    tab1, tab2, tab3 = st.tabs(["Week 1: Setup", "Week 2: Deploy", "Week 3: Optimize"])
    
    with tab1:
        st.markdown("""
        **Week 1: Cluster Setup**
        
        ```bash
        # Create EKS cluster with your sizing
        eksctl create cluster \\
          --name production \\
          --version 1.28 \\
          --region us-east-1 \\
          --nodes {result.recommended_nodes} \\
          --node-type {result.recommended_instance_type} \\
          --nodes-min {max(3, result.recommended_nodes // 2)} \\
          --nodes-max {result.recommended_nodes * 2}
        
        # Install metrics-server
        kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml
        
        # Install Container Insights
        # Follow: https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Container-Insights-setup-EKS-quickstart.html
        ```
        
        **Deliverable:** Running EKS cluster with monitoring
        """)
    
    with tab2:
        st.markdown("""
        **Week 2: Deploy Workloads**
        
        Deploy your workloads one by one, monitoring resource usage:
        
        ```yaml
        # Example deployment with your calculated resources
        apiVersion: apps/v1
        kind: Deployment
        metadata:
          name: web-app
        spec:
          replicas: 3
          template:
            spec:
              containers:
              - name: app
                resources:
                  requests:
                    cpu: "500m"
                    memory: "1024Mi"
                  limits:
                    cpu: "1000m"
                    memory: "2048Mi"
        ```
        
        **Monitor:** CPU/Memory utilization should be 60-70%
        """)
    
    with tab3:
        st.markdown("""
        **Week 3: Right-size Based on Actuals**
        
        ```bash
        # Check actual resource usage
        kubectl top pods --all-namespaces
        kubectl top nodes
        
        # Get right-sizing recommendations
        kubectl describe vpa <vpa-name>
        ```
        
        **Actions:**
        - Reduce over-provisioned resources (< 50% usage)
        - Increase under-provisioned (> 80% usage)
        - Update deployment manifests with new values
        - Plan Karpenter adoption for dynamic sizing
        """)

def render_formula_based_sizing():
    """Advanced formula-based sizing"""
    st.markdown("### 🧮 Formula-Based Calculation")
    
    st.info("""
    **Best for:** Advanced users who understand their workload patterns
    
    **Use this when:** You have detailed metrics from existing systems
    """)
    
    st.markdown("""
    ### Sizing Formula
    
    ```
    Required_Capacity = (Workload_Demand × (1 + Growth_Factor)) / Target_Utilization × (1 + Overhead) × (1 + Buffer)
    
    Where:
    - Workload_Demand: Current actual usage
    - Growth_Factor: Expected growth (e.g., 0.20 for 20%)
    - Target_Utilization: Desired average utilization (e.g., 0.65 for 65%)
    - Overhead: Kubernetes system overhead (typically 0.15-0.20)
    - Buffer: Safety buffer for burst traffic (typically 0.15-0.20)
    ```
    """)
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### Input Parameters")
        workload_cpu = st.number_input("Current CPU Demand (cores)", 1.0, 1000.0, 50.0, 0.1)
        workload_memory = st.number_input("Current Memory Demand (GB)", 1.0, 2000.0, 100.0, 0.1)
        growth_factor = st.slider("Expected Growth %", 0, 100, 20) / 100
        target_util = st.slider("Target Utilization %", 50, 85, 65) / 100
    
    with col2:
        st.markdown("#### Advanced Settings")
        overhead = st.slider("K8s Overhead %", 10, 30, 20) / 100
        buffer = st.slider("Safety Buffer %", 10, 30, 20) / 100
        spot_percentage = st.slider("Spot Instance %", 0, 90, 60)
    
    # Calculate
    required_cpu = (workload_cpu * (1 + growth_factor)) / target_util * (1 + overhead) * (1 + buffer)
    required_memory = (workload_memory * (1 + growth_factor)) / target_util * (1 + overhead) * (1 + buffer)
    
    st.markdown("---")
    st.markdown("### 📊 Results")
    
    col1, col2 = st.columns(2)
    with col1:
        st.metric("Required CPU", f"{required_cpu:.1f} cores")
        st.caption(f"From: {workload_cpu} current demand")
    with col2:
        st.metric("Required Memory", f"{required_memory:.1f} GB")
        st.caption(f"From: {workload_memory} GB current demand")
    
    # Instance recommendation
    instance_rec = recommend_instance_type(required_cpu, required_memory)
    cost_est = calculate_cost_estimate(instance_rec['instance_type'], instance_rec['node_count'], spot_percentage)
    
    st.markdown(f"""
    **Recommended Configuration:**
    - Instance Type: {instance_rec['instance_type']}
    - Node Count: {instance_rec['node_count']}
    - Monthly Cost: ${cost_est['total']:,.0f}
    """)

def recommend_instance_type(cpu_cores: float, memory_gb: float) -> Dict:
    """Recommend AWS instance type based on requirements"""
    
    # Instance type catalog with pricing
    instances = [
        {'type': 't3.medium', 'vcpu': 2, 'memory': 4, 'price': 0.0416},
        {'type': 't3.large', 'vcpu': 2, 'memory': 8, 'price': 0.0832},
        {'type': 't3.xlarge', 'vcpu': 4, 'memory': 16, 'price': 0.1664},
        {'type': 't3.2xlarge', 'vcpu': 8, 'memory': 32, 'price': 0.3328},
        {'type': 'm5.large', 'vcpu': 2, 'memory': 8, 'price': 0.096},
        {'type': 'm5.xlarge', 'vcpu': 4, 'memory': 16, 'price': 0.192},
        {'type': 'm5.2xlarge', 'vcpu': 8, 'memory': 32, 'price': 0.384},
        {'type': 'm5.4xlarge', 'vcpu': 16, 'memory': 64, 'price': 0.768},
        {'type': 'm6i.large', 'vcpu': 2, 'memory': 8, 'price': 0.096},
        {'type': 'm6i.xlarge', 'vcpu': 4, 'memory': 16, 'price': 0.192},
        {'type': 'm6i.2xlarge', 'vcpu': 8, 'memory': 32, 'price': 0.384},
        {'type': 'c5.large', 'vcpu': 2, 'memory': 4, 'price': 0.085},
        {'type': 'c5.xlarge', 'vcpu': 4, 'memory': 8, 'price': 0.17},
        {'type': 'c5.2xlarge', 'vcpu': 8, 'memory': 16, 'price': 0.34},
        {'type': 'r5.large', 'vcpu': 2, 'memory': 16, 'price': 0.126},
        {'type': 'r5.xlarge', 'vcpu': 4, 'memory': 32, 'price': 0.252},
        {'type': 'r5.2xlarge', 'vcpu': 8, 'memory': 64, 'price': 0.504},
    ]
    
    # Calculate CPU-to-memory ratio
    ratio = cpu_cores / memory_gb if memory_gb > 0 else 1
    
    # Find best-fit instance
    best_instance = None
    min_nodes = float('inf')
    
    for instance in instances:
        # Accounting for system overhead, use 90% of instance capacity
        usable_cpu = instance['vcpu'] * 0.9
        usable_memory = instance['memory'] * 0.9
        
        # Calculate nodes needed
        nodes_for_cpu = math.ceil(cpu_cores / usable_cpu)
        nodes_for_memory = math.ceil(memory_gb / usable_memory)
        nodes_needed = max(nodes_for_cpu, nodes_for_memory)
        
        # Ensure at least 3 nodes for HA (1 per AZ)
        nodes_needed = max(nodes_needed, 3)
        
        # Find instance with minimum nodes needed
        if nodes_needed < min_nodes:
            min_nodes = nodes_needed
            best_instance = {
                'instance_type': instance['type'],
                'vcpu': instance['vcpu'],
                'memory_gb': instance['memory'],
                'node_count': nodes_needed,
                'hourly_price': instance['price'],
                'monthly_price': instance['price'] * 730  # hours per month
            }
    
    return best_instance

def calculate_cost_estimate(instance_type: str, node_count: int, spot_percentage: float) -> Dict:
    """Calculate estimated monthly cost"""
    
    # Get instance pricing (simplified)
    pricing = {
        't3.medium': 0.0416, 't3.large': 0.0832, 't3.xlarge': 0.1664, 't3.2xlarge': 0.3328,
        'm5.large': 0.096, 'm5.xlarge': 0.192, 'm5.2xlarge': 0.384, 'm5.4xlarge': 0.768,
        'm6i.large': 0.096, 'm6i.xlarge': 0.192, 'm6i.2xlarge': 0.384,
        'c5.large': 0.085, 'c5.xlarge': 0.17, 'c5.2xlarge': 0.34,
        'r5.large': 0.126, 'r5.xlarge': 0.252, 'r5.2xlarge': 0.504,
    }
    
    hourly_price = pricing.get(instance_type, 0.192)  # Default to m5.xlarge
    hours_per_month = 730
    
    # Calculate costs
    base_monthly = hourly_price * hours_per_month * node_count
    
    # With Spot instances (70% discount on Spot portion)
    on_demand_nodes = node_count * (1 - spot_percentage / 100)
    spot_nodes = node_count * (spot_percentage / 100)
    
    on_demand_cost = on_demand_nodes * hourly_price * hours_per_month
    spot_cost = spot_nodes * hourly_price * hours_per_month * 0.3  # 70% savings
    total_with_spot = on_demand_cost + spot_cost
    
    return {
        'base': base_monthly,
        'on_demand': on_demand_cost,
        'spot': spot_cost,
        'total': total_with_spot,
        'savings': base_monthly - total_with_spot
    }

def calculate_potential_savings(current_cost: float) -> float:
    """Calculate potential savings with full optimization"""
    # Right-sizing (20%), Spot (40%), Karpenter optimization (10%)
    return current_cost * 0.40

# ============================================================================
# COMPONENT SELECTION DECISION FRAMEWORK
# ============================================================================

def render_component_selection_guide():
    """Interactive decision tree for selecting EKS components"""
    st.markdown("## 🔧 Component Selection Framework")
    
    st.markdown("""
    ### Making Technology Decisions
    
    Selecting the right components is critical. Too many tools = operational burden.
    Too few tools = missing important capabilities.
    
    **This framework helps you decide WHEN to adopt each technology.**
    """)
    
    # Component categories
    component_type = st.selectbox(
        "What type of component are you evaluating?",
        [
            "📈 Autoscaling (Karpenter vs Cluster Autoscaler)",
            "🕸️ Service Mesh (Istio vs Linkerd vs App Mesh vs None)",
            "🔄 GitOps (ArgoCD vs FluxCD vs None)",
            "📊 Monitoring (Prometheus vs CloudWatch vs Both)",
            "🔐 Secrets Management (External Secrets vs Sealed Secrets vs Native)",
            "🌐 Ingress (ALB Controller vs NGINX vs Both)",
            "💾 Storage (EBS CSI vs EFS vs Both)",
        ]
    )
    
    if "Autoscaling" in component_type:
        render_autoscaling_decision()
    elif "Service Mesh" in component_type:
        render_service_mesh_decision()
    elif "GitOps" in component_type:
        render_gitops_decision()
    elif "Monitoring" in component_type:
        render_monitoring_decision()
    elif "Secrets" in component_type:
        render_secrets_decision()
    elif "Ingress" in component_type:
        render_ingress_decision()
    elif "Storage" in component_type:
        render_storage_decision()

def render_autoscaling_decision():
    """Decision framework for autoscaling"""
    st.markdown("### 📈 Autoscaling: Karpenter vs Cluster Autoscaler")
    
    st.markdown("#### Answer these questions:")
    
    workload_pattern = st.radio(
        "What's your workload pattern?",
        [
            "Stable and predictable (same load 24/7)",
            "Variable with some patterns (business hours)",
            "Highly variable and unpredictable (spiky traffic)"
        ]
    )
    
    team_experience = st.radio(
        "Team's Kubernetes experience?",
        [
            "Beginner (< 6 months with K8s)",
            "Intermediate (6-18 months)",
            "Advanced (18+ months, production experience)"
        ]
    )
    
    cost_priority = st.radio(
        "How important is cost optimization?",
        [
            "Critical - must minimize costs",
            "Important - want good cost/performance balance",
            "Secondary - features and reliability first"
        ]
    )
    
    if st.button("Get Recommendation", use_container_width=True):
        # Decision logic
        if team_experience == "Beginner (< 6 months with K8s)":
            recommendation = "cluster_autoscaler"
            reason = "Lower learning curve, well-documented, easier troubleshooting"
        elif cost_priority == "Critical - must minimize costs":
            recommendation = "karpenter"
            reason = "20-50% better cost optimization through intelligent provisioning"
        elif workload_pattern == "Highly variable and unpredictable (spiky traffic)":
            recommendation = "karpenter"
            reason = "Faster scaling (seconds vs minutes), better bin-packing"
        elif team_experience == "Intermediate (6-18 months)":
            recommendation = "start_ca_migrate_karpenter"
            reason = "Start with Cluster Autoscaler, migrate to Karpenter in 3-6 months"
        else:
            recommendation = "karpenter"
            reason = "You're ready for it, and benefits outweigh complexity"
        
        # Display recommendation
        if recommendation == "cluster_autoscaler":
            st.success("### ✅ Recommendation: Cluster Autoscaler")
            st.markdown(f"**Reason:** {reason}")
            
            st.markdown("""
            **Why Cluster Autoscaler for you:**
            - ✅ Easier to learn and operate
            - ✅ Extensive documentation and community support
            - ✅ Works well with managed node groups
            - ✅ Predictable behavior
            - ✅ Lower operational burden
            
            **Timeline:**
            - Week 1: Deploy Cluster Autoscaler
            - Week 2: Configure scaling policies
            - Month 2-3: Monitor and tune
            - Month 6+: Consider Karpenter migration
            
            **Setup Guide:** See "Cluster Autoscaler Setup" in Implementation tab
            """)
            
        elif recommendation == "karpenter":
            st.success("### ✅ Recommendation: Karpenter")
            st.markdown(f"**Reason:** {reason}")
            
            st.markdown("""
            **Why Karpenter for you:**
            - ✅ 20-50% better cost optimization
            - ✅ Sub-minute node provisioning
            - ✅ Automatic right-sizing
            - ✅ Better Spot instance support
            - ✅ No node groups required
            
            **Prerequisites:**
            - ✅ Team comfortable with Kubernetes concepts
            - ✅ Willingness to invest 2-3 weeks learning
            - ✅ Monitoring in place (to validate behavior)
            
            **Timeline:**
            - Week 1: Setup and configuration
            - Week 2-3: Testing and validation
            - Week 4: Production rollout
            - Ongoing: Fine-tuning and optimization
            
            **Setup Guide:** See "Karpenter Setup" in Implementation tab
            """)
            
        else:  # start_ca_migrate_karpenter
            st.success("### ✅ Recommendation: Start with Cluster Autoscaler, Migrate to Karpenter")
            st.markdown(f"**Reason:** {reason}")
            
            st.markdown("""
            **Phased Approach:**
            
            **Phase 1 (Months 0-3): Cluster Autoscaler**
            - Get familiar with autoscaling concepts
            - Build confidence with production operations
            - Establish monitoring and alerting
            - Document scaling patterns
            
            **Phase 2 (Months 3-6): Karpenter Preparation**
            - Team training on Karpenter concepts
            - Test Karpenter in dev environment
            - Plan migration strategy
            - Identify workloads for pilot
            
            **Phase 3 (Months 6-9): Karpenter Migration**
            - Deploy Karpenter alongside CA
            - Migrate non-critical workloads first
            - Validate cost savings and behavior
            - Complete migration, remove CA
            
            **Expected Outcome:** Smooth transition with minimal risk
            """)
        
        # Comparison table
        with st.expander("📊 Detailed Comparison"):
            st.markdown("""
            | Feature | Cluster Autoscaler | Karpenter |
            |---------|-------------------|-----------|
            | **Provisioning Speed** | 2-5 minutes | 15-30 seconds |
            | **Right-sizing** | Fixed node groups | Automatic per-pod |
            | **Spot Support** | Requires separate setup | Native with interruption handling |
            | **Learning Curve** | Gentle | Steeper |
            | **Cost Savings** | 10-30% | 20-50% |
            | **Complexity** | Low | Medium |
            | **Node Groups Required** | Yes | No |
            | **Multi-AZ** | Per node group | Automatic |
            | **Consolidation** | Manual | Automatic |
            | **AWS Lock-in** | No | Yes |
            """)

def render_service_mesh_decision():
    """Decision framework for service mesh"""
    st.markdown("### 🕸️ Service Mesh Decision Framework")
    
    st.markdown("#### Critical Question: Do you even need a service mesh?")
    
    microservices_count = st.select_slider(
        "How many microservices do you have?",
        options=["1-5", "6-20", "21-50", "51-100", "100+"]
    )
    
    traffic_requirements = st.multiselect(
        "What advanced traffic management do you need? (Select all)",
        [
            "Canary deployments with gradual traffic shifting",
            "A/B testing with header-based routing",
            "Circuit breaking and fault injection",
            "Automatic retry and timeout policies",
            "Cross-service distributed tracing",
            "None - basic load balancing is sufficient"
        ]
    )
    
    security_requirements = st.multiselect(
        "What security features do you need?",
        [
            "Mutual TLS (mTLS) between all services",
            "Fine-grained authorization policies",
            "Service-to-service authentication",
            "Encryption in transit (automatic)",
            "None - application-level security is sufficient"
        ]
    )
    
    team_size = st.radio(
        "What's your platform team size?",
        [
            "No dedicated platform team",
            "1-2 engineers",
            "3-5 engineers",
            "6+ engineers with specialized roles"
        ]
    )
    
    if st.button("Get Service Mesh Recommendation", use_container_width=True):
        # Decision logic
        services_numeric = {"1-5": 3, "6-20": 13, "21-50": 35, "51-100": 75, "100+": 150}
        num_services = services_numeric.get(microservices_count, 10)
        
        has_advanced_needs = len([r for r in traffic_requirements if r != "None - basic load balancing is sufficient"]) > 0
        has_security_needs = len([s for s in security_requirements if s != "None - application-level security is sufficient"]) > 0
        has_team = team_size in ["3-5 engineers", "6+ engineers with specialized roles"]
        
        # Decision tree
        if num_services < 20:
            recommendation = "none"
        elif num_services < 50 and not has_advanced_needs:
            recommendation = "wait"
        elif has_advanced_needs and has_security_needs and has_team:
            recommendation = "istio"
        elif has_team and num_services > 50:
            recommendation = "linkerd"
        elif has_advanced_needs:
            recommendation = "app_mesh"
        else:
            recommendation = "none"
        
        # Display recommendations
        if recommendation == "none":
            st.success("### ✅ Recommendation: No Service Mesh Needed")
            st.markdown("""
            **Why you don't need a service mesh:**
            - ✅ You have < 20 services (not enough complexity)
            - ✅ Basic load balancing meets your needs
            - ✅ Can achieve your goals with simpler tools
            
            **What to use instead:**
            - **Ingress Controller:** AWS Load Balancer Controller or NGINX
            - **Observability:** Prometheus + Grafana + CloudWatch
            - **Security:** Network Policies + TLS at ingress
            - **Traffic Management:** Kubernetes Services + Deployments
            
            **When to revisit:**
            - When you have 50+ microservices
            - When you need advanced traffic routing (canary, A/B)
            - When security requirements demand mTLS everywhere
            
            **Cost Saved:** $0 overhead (service mesh adds 10-15% resource cost)
            """)
            
        elif recommendation == "wait":
            st.warning("### ⏳ Recommendation: Wait, You're Not Ready Yet")
            st.markdown("""
            **Why wait:**
            - Your service count doesn't justify the complexity yet
            - You can achieve your goals with simpler tools
            - Service mesh adds 10-15% resource overhead
            - Requires dedicated platform engineering expertise
            
            **What to do instead:**
            1. **Build foundation first:** Get comfortable with basic K8s networking
            2. **Implement observability:** Prometheus, Grafana, distributed tracing
            3. **Use simple patterns:** Kubernetes native features
            4. **Grow gradually:** Revisit when you hit 50+ services
            
            **Revisit when:**
            - You reach 50+ microservices
            - Multiple teams managing different services
            - Advanced traffic management becomes critical
            - Dedicated platform team available (3+ engineers)
            """)
            
        elif recommendation == "istio":
            st.success("### ✅ Recommendation: Istio Service Mesh")
            st.markdown("""
            **Why Istio for you:**
            - ✅ 50+ microservices justify the investment
            - ✅ You need advanced traffic management (canary, A/B, circuit breaking)
            - ✅ Security requirements need mTLS and fine-grained policies
            - ✅ Platform team can manage the complexity
            
            **What you get:**
            - **Traffic Management:** Advanced routing, retries, timeouts, circuit breaking
            - **Security:** Automatic mTLS, authorization policies
            - **Observability:** Distributed tracing, service topology, metrics
            - **Policy Enforcement:** Rate limiting, quotas
            
            **Prerequisites:**
            - ✅ Platform team (3+ engineers)
            - ✅ Prometheus + Grafana already deployed
            - ✅ Team comfortable with Kubernetes networking
            - ✅ Budget for 10-15% resource overhead
            
            **Timeline:**
            - Week 1-2: Installation and basic configuration
            - Week 3-4: Pilot with 5-10 services
            - Week 5-8: Gradual rollout to all services
            - Month 3-6: Advanced features (canary, A/B testing)
            
            **Resource Impact:**
            - CPU: +10-15% (Envoy sidecars)
            - Memory: +50-100MB per pod
            - Latency: +1-2ms per hop
            
            **Setup Guide:** See "Istio Service Mesh" in Implementation tab
            """)
            
        elif recommendation == "linkerd":
            st.success("### ✅ Recommendation: Linkerd Service Mesh")
            st.markdown("""
            **Why Linkerd for you:**
            - ✅ You need a service mesh but want minimal complexity
            - ✅ Security (mTLS) is priority, advanced routing is secondary
            - ✅ Want lower resource overhead than Istio
            - ✅ CNCF graduated project with strong community
            
            **What you get:**
            - **Security:** Automatic mTLS (easiest to configure)
            - **Observability:** Built-in dashboard, metrics, tracing
            - **Lightweight:** Rust-based proxy (lower overhead than Istio)
            - **Simple:** Easier to learn and operate
            
            **Comparison to Istio:**
            - ✅ Simpler: Easier installation and operation
            - ✅ Lighter: 50% less resource overhead
            - ✅ Faster: Lower latency impact
            - ⚠️ Fewer features: Less advanced traffic routing
            
            **Timeline:**
            - Week 1: Installation (easier than Istio)
            - Week 2: Enable mTLS (automatic)
            - Week 3-4: Rollout to all services
            - Month 2+: Observability and optimization
            
            **Setup Guide:** See "Linkerd Setup" in Implementation tab
            """)
            
        elif recommendation == "app_mesh":
            st.success("### ✅ Recommendation: AWS App Mesh")
            st.markdown("""
            **Why AWS App Mesh for you:**
            - ✅ AWS-native solution with deep integration
            - ✅ Works across EKS, ECS, and EC2
            - ✅ Managed control plane (less operational burden)
            - ✅ No additional cost (pay for compute only)
            
            **What you get:**
            - **Native AWS:** Integrates with X-Ray, CloudWatch, IAM
            - **Managed:** AWS handles control plane updates
            - **Multi-compute:** Works with EKS, ECS, EC2
            - **Cost:** No additional service charges
            
            **Trade-offs:**
            - ✅ Simpler than Istio (managed by AWS)
            - ✅ Good AWS integration
            - ⚠️ AWS lock-in (less portable)
            - ⚠️ Fewer features than Istio
            - ⚠️ Smaller community
            
            **Timeline:**
            - Week 1-2: Setup and configuration
            - Week 3-4: Pilot with few services
            - Month 2-3: Full rollout
            
            **Setup Guide:** See "AWS App Mesh" in Implementation tab
            """)

def render_gitops_decision():
    """Decision framework for GitOps"""
    st.markdown("### 🔄 GitOps: ArgoCD vs FluxCD vs Manual")
    
    st.info("GitOps = Git as single source of truth for infrastructure and applications")
    
    team_size = st.radio(
        "How many people deploy to Kubernetes?",
        ["Just me (1)", "Small team (2-5)", "Multiple teams (6-15)", "Large organization (15+)"]
    )
    
    deployment_frequency = st.radio(
        "How often do you deploy?",
        ["Few times per month", "Weekly", "Multiple times per day"]
    )
    
    multi_cluster = st.radio(
        "How many clusters do you manage?",
        ["1 cluster", "2-3 clusters", "4-10 clusters", "10+ clusters"]
    )
    
    if st.button("Get GitOps Recommendation", use_container_width=True):
        # Simple decision logic
        if team_size == "Just me (1)" and deployment_frequency == "Few times per month":
            recommendation = "manual"
        elif team_size in ["Large organization (15+)"] or multi_cluster in ["4-10 clusters", "10+ clusters"]:
            recommendation = "argocd"
        elif deployment_frequency == "Multiple times per day":
            recommendation = "fluxcd"
        else:
            recommendation = "argocd"
        
        if recommendation == "manual":
            st.info("### 💡 Recommendation: Manual Deployments (For Now)")
            st.markdown("""
            **Why manual is OK for you:**
            - You deploy infrequently
            - Single developer/small team
            - GitOps adds complexity you don't need yet
            
            **What to do:**
            ```bash
            # Use kubectl apply
            kubectl apply -f manifests/
            
            # Or Helm
            helm upgrade --install myapp ./chart
            ```
            
            **Revisit GitOps when:**
            - Team grows to 5+ people
            - Deploying multiple times per day
            - Managing 2+ clusters
            - Need audit trail of changes
            """)
        elif recommendation == "argocd":
            st.success("### ✅ Recommendation: ArgoCD")
            st.markdown("""
            **Why ArgoCD for you:**
            - ✅ Rich UI for visibility
            - ✅ Better for multiple clusters
            - ✅ Strong RBAC for team collaboration
            - ✅ Application CRDs for complex deployments
            
            **Setup Guide:** See "ArgoCD GitOps" in Implementation tab
            """)
        else:  # fluxcd
            st.success("### ✅ Recommendation: FluxCD")
            st.markdown("""
            **Why FluxCD for you:**
            - ✅ Lightweight and simple
            - ✅ GitOps Toolkit approach
            - ✅ Great for automation (no UI dependency)
            - ✅ Native Kubernetes-style CRDs
            
            **Setup Guide:** FluxCD installation guide available
            """)

def render_monitoring_decision():
    """Monitoring stack decision"""
    st.info("Monitoring decision framework - Coming in full implementation")

def render_secrets_decision():
    """Secrets management decision"""
    st.info("Secrets management decision framework - Coming in full implementation")

def render_ingress_decision():
    """Ingress controller decision"""
    st.info("Ingress controller decision framework - Coming in full implementation")

def render_storage_decision():
    """Storage solution decision"""
    st.info("Storage solution decision framework - Coming in full implementation")

# ============================================================================
# INTEGRATED TRANSFORMATION GUIDE
# ============================================================================

def render_integrated_transformation():
    """Show how all components work together in a real transformation"""
    st.markdown("## 🏗️ Integrated Transformation: All Components Working Together")
    
    st.markdown("""
    ### Real-World Scenario
    
    Let's walk through a complete transformation showing how all components 
    integrate and work together.
    
    **Company:** E-commerce platform
    **Current State:** 30 microservices on VMs
    **Goal:** Migrate to EKS with cost optimization
    """)
    
    # Timeline view
    phase = st.selectbox(
        "Select Phase to See Component Integration",
        [
            "Phase 1: Foundation (Weeks 1-4)",
            "Phase 2: Platform Services (Weeks 5-8)",
            "Phase 3: Application Migration (Weeks 9-16)",
            "Phase 4: Optimization (Weeks 17-24)"
        ]
    )
    
    if "Phase 1" in phase:
        render_phase1_integration()
    elif "Phase 2" in phase:
        render_phase2_integration()
    elif "Phase 3" in phase:
        render_phase3_integration()
    else:
        render_phase4_integration()

def render_phase1_integration():
    """Phase 1: Foundation - sizing and initial setup"""
    st.markdown("### Phase 1: Foundation (Weeks 1-4)")
    
    st.markdown("#### Week 1-2: Sizing and Architecture")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        **Step 1: Size the Cluster**
        
        Using our sizing calculator:
        - Current: 30 VMs × 4 vCPU × 16 GB
        - Actual usage: 40% (over-provisioned)
        - Result: Need 50 vCPU, 100 GB
        
        **Decision:** 
        - 6x m5.xlarge nodes (4 vCPU, 16 GB each)
        - Total: 24 vCPU, 96 GB
        - Target: 60-70% utilization
        """)
    
    with col2:
        st.markdown("""
        **Step 2: Select Initial Components**
        
        Based on decision framework:
        - ✅ Cluster Autoscaler (team beginner)
        - ✅ ALB Controller (AWS native)
        - ✅ Container Insights (start simple)
        - ❌ Karpenter (wait 3 months)
        - ❌ Service Mesh (only 30 services)
        - ❌ Advanced monitoring (overkill)
        """)
    
    st.markdown("#### Week 3-4: Deploy Foundation")
    
    with st.expander("📋 Implementation Checklist"):
        st.markdown("""
        **Infrastructure:**
        - [x] VPC with 3 AZs
        - [x] EKS cluster with 6 nodes
        - [x] Cluster Autoscaler installed
        - [x] ALB Controller installed
        - [x] Container Insights enabled
        
        **Results:**
        - Cluster operational
        - Basic monitoring in place
        - Ready for applications
        
        **Cost:** $420/month (baseline)
        """)

def render_phase2_integration():
    """Phase 2: Platform services"""
    st.markdown("### Phase 2: Platform Services (Weeks 5-8)")
    
    st.markdown("""
    **Adding operational capabilities before applications**
    
    Components added:
    1. **ArgoCD** - For GitOps deployments
    2. **External Secrets Operator** - Integrates with AWS Secrets Manager
    3. **Cert-manager** - Automatic TLS certificates
    4. **Kyverno** - Policy enforcement
    """)
    
    st.markdown("#### How They Work Together:")
    
    st.code("""
# 1. ArgoCD watches Git repo for changes
# 2. External Secrets syncs from AWS Secrets Manager
# 3. Cert-manager gets TLS cert from Let's Encrypt
# 4. Kyverno ensures all pods have resource limits

# Application deployment flow:
Developer pushes code → Git
  ↓
ArgoCD detects change
  ↓
Creates Deployment + Service + Ingress
  ↓
External Secrets creates Secret from AWS
  ↓
Cert-manager provisions TLS certificate
  ↓
Kyverno validates policies
  ↓
ALB Controller creates Load Balancer
  ↓
Application accessible with HTTPS
    """, language="text")
    
    with st.expander("🔗 Component Integration Example"):
        st.code("""
# ArgoCD Application
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: web-app
spec:
  source:
    repoURL: https://github.com/company/app
    path: kubernetes/

---
# Deployment with External Secrets
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-app
spec:
  template:
    spec:
      containers:
      - name: app
        envFrom:
        - secretRef:
            name: app-secrets  # Synced from AWS by External Secrets
---
# External Secret definition
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: app-secrets
spec:
  secretStoreRef:
    name: aws-secrets-manager
  target:
    name: app-secrets
  data:
  - secretKey: DATABASE_URL
    remoteRef:
      key: prod/database/url

---
# Ingress with automatic TLS
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: web-app
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod  # Cert-manager handles this
    alb.ingress.kubernetes.io/scheme: internet-facing
spec:
  tls:
  - hosts:
    - app.example.com
    secretName: app-tls  # Created automatically by cert-manager
  rules:
  - host: app.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: web-app
            port:
              number: 80
        """, language="yaml")

def render_phase3_integration():
    """Phase 3: Application migration"""
    st.markdown("### Phase 3: Application Migration (Weeks 9-16)")
    
    st.markdown("""
    **Migrating 30 microservices in 3 waves**
    
    Now all components work together to enable smooth migration
    """)
    
    tab1, tab2, tab3 = st.tabs(["Wave 1: Quick Wins", "Wave 2: Core Services", "Wave 3: Complex Apps"])
    
    with tab1:
        st.markdown("""
        **Week 9-10: 10 Simple Services**
        
        Services: Static sites, simple APIs, background jobs
        
        **Component Usage:**
        - ✅ ArgoCD: Automated deployment from Git
        - ✅ Cluster Autoscaler: Adds nodes as needed
        - ✅ ALB Controller: Creates load balancers
        - ✅ Container Insights: Basic monitoring
        
        **Process:**
        1. Containerize application
        2. Create K8s manifests in Git
        3. Define ArgoCD Application
        4. ArgoCD deploys automatically
        5. Monitor in Container Insights
        
        **Outcome:**
        - 10 services migrated
        - Team confidence building
        - Patterns established
        """)
    
    with tab2:
        st.markdown("""
        **Week 11-14: 15 Core Services**
        
        Services: Main APIs, web frontends, user-facing services
        
        **Component Usage:**
        - ✅ All previous components
        - ✅ External Secrets: Database credentials
        - ✅ Cert-manager: TLS for all services
        - ✅ Kyverno: Enforce security policies
        
        **New Complexity:**
        - Inter-service communication
        - Shared databases
        - Caching layers
        - Background workers
        
        **Process:**
        1. Migrate services by domain/team
        2. Test inter-service communication
        3. Validate performance
        4. Cutover with blue-green
        
        **Outcome:**
        - 25/30 services on EKS
        - Production traffic flowing
        - Monitoring and alerting working
        """)
    
    with tab3:
        st.markdown("""
        **Week 15-16: 5 Complex Services**
        
        Services: Payment processing, order management, inventory
        
        **Component Usage:**
        - ✅ All components at full capacity
        - ✅ PodDisruptionBudgets for critical services
        - ✅ Advanced monitoring and alerting
        - ✅ Disaster recovery procedures
        
        **Extra Care:**
        - Extensive testing in staging
        - Gradual rollout with canary
        - Rollback procedures ready
        - 24/7 monitoring during cutover
        
        **Outcome:**
        - ✅ All 30 services migrated
        - ✅ Old VMs decommissioned
        - ✅ Cost reduced by 25%
        """)

def render_phase4_integration():
    """Phase 4: Optimization"""
    st.markdown("### Phase 4: Optimization (Weeks 17-24)")
    
    st.markdown("""
    **Adding advanced components for cost optimization and scale**
    
    Now that foundation is solid, add Karpenter and optimize
    """)
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        **Week 17-18: Deploy Karpenter**
        
        **Why now:**
        - ✅ Team experienced with K8s
        - ✅ Workload patterns understood
        - ✅ Monitoring in place to validate
        
        **Process:**
        1. Install Karpenter alongside Cluster Autoscaler
        2. Configure for Spot instances (60%)
        3. Test with non-critical services
        4. Migrate critical services
        5. Remove Cluster Autoscaler
        
        **Result:** 40% cost reduction
        """)
    
    with col2:
        st.markdown("""
        **Week 19-24: Continuous Optimization**
        
        **Activities:**
        - Right-size based on actual usage
        - Implement advanced HPA rules
        - Add VPA for automatic tuning
        - Optimize Spot instance strategy
        - Implement pod priority classes
        
        **Monitoring:**
        - Daily cost reviews
        - Weekly capacity planning
        - Monthly architecture reviews
        
        **Result:** 60% total cost reduction
        """)
    
    st.markdown("---")
    st.markdown("### 📊 Final Architecture - All Components Together")
    
    with st.expander("🏗️ View Complete Architecture Diagram"):
        st.code("""
┌─────────────────────────────────────────────────────┐
│                    USERS                            │
└───────────────────┬─────────────────────────────────┘
                    │
                    ↓
┌─────────────────────────────────────────────────────┐
│              ALB (AWS Load Balancer)                │
│  • Created by ALB Controller                        │
│  • TLS termination (cert from cert-manager)         │
└───────────────────┬─────────────────────────────────┘
                    │
                    ↓
┌─────────────────────────────────────────────────────┐
│               EKS CLUSTER                           │
│                                                     │
│  ┌──────────────────────────────────────────────┐  │
│  │  CONTROL PLANE (AWS Managed)                 │  │
│  │  • ArgoCD (GitOps automation)                │  │
│  │  • Karpenter (intelligent autoscaling)       │  │
│  │  • Kyverno (policy enforcement)              │  │
│  └──────────────────────────────────────────────┘  │
│                                                     │
│  ┌──────────────────────────────────────────────┐  │
│  │  WORKER NODES                                │  │
│  │                                              │  │
│  │  On-Demand (40%):                           │  │
│  │  • Critical services (payment, auth)        │  │
│  │  • Databases                                │  │
│  │  • Monitoring                               │  │
│  │                                              │  │
│  │  Spot (60%) - Managed by Karpenter:        │  │
│  │  • Web frontends                            │  │
│  │  • APIs                                     │  │
│  │  • Background workers                       │  │
│  │  • Batch jobs                               │  │
│  │                                              │  │
│  │  All pods have:                             │  │
│  │  • Resource requests/limits (enforced)      │  │
│  │  • Secrets from AWS (External Secrets)     │  │
│  │  • TLS certificates (cert-manager)          │  │
│  │  • Monitored (Container Insights)           │  │
│  └──────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
                    │
                    ↓
┌─────────────────────────────────────────────────────┐
│            AWS SERVICES                             │
│  • Secrets Manager (secrets)                        │
│  • Certificate Manager (TLS)                        │
│  • CloudWatch (logs & metrics)                      │
│  • S3 (backups & artifacts)                         │
│  • RDS (databases)                                  │
└─────────────────────────────────────────────────────┘

Component Interactions:
1. Developer pushes to Git
2. ArgoCD deploys to cluster
3. Karpenter provisions right-sized nodes
4. External Secrets syncs from AWS
5. Cert-manager handles TLS
6. ALB Controller creates load balancer
7. Kyverno enforces policies
8. Container Insights monitors everything
9. Spot instances reduce cost by 60%

Result: Production-ready, cost-optimized, automated platform
        """, language="text")
    
    st.success("""
    ### ✅ Transformation Complete!
    
    **Outcomes:**
    - ✅ All 30 microservices on EKS
    - ✅ 60% cost reduction
    - ✅ 99.9% availability
    - ✅ Automated deployments (GitOps)
    - ✅ Security hardened
    - ✅ Team trained and confident
    
    **Timeline:** 24 weeks (6 months)
    **Investment:** $420/month → $168/month (with optimizations)
    """)

# Export
__all__ = [
    'render_eks_sizing_calculator',
    'render_component_selection_guide',
    'render_integrated_transformation'
]
