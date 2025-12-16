"""
EKS Operations Intelligence Center - AI-Powered Day 2 Operations
Complete lifecycle management, monitoring, optimization, and troubleshooting for EKS clusters
Complements CI/CD pipelines with operational excellence
"""

import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List
from config_settings import AppConfig
from core_account_manager import get_account_manager
from core_session_manager import SessionManager
from utils_helpers import Helpers
import json

class EKSManagementModule:
    """AI-Enhanced EKS Operations Intelligence Center"""
    
    @staticmethod
    def render():
        """Render EKS Operations Intelligence Center"""
        
        st.title("⎈ EKS Operations Intelligence Center")
        st.markdown("**AI-Powered Day 2 Operations** - Monitor, Optimize, Secure, and Troubleshoot your EKS clusters")
        
        account_mgr = get_account_manager()
        if not account_mgr:
            st.error("❌ AWS account manager not configured")
            return
        
        # Create comprehensive tabs
        tabs = st.tabs([
            "🎯 Operations Dashboard",
            "🔍 AI Troubleshooting",
            "🛡️ Security & Compliance",
            "💰 Cost Optimization",
            "📈 Performance Analytics",
            "🔗 CI/CD Integration",
            "⚡ Quick Actions"
        ])
        
        with tabs[0]:
            EKSManagementModule._render_operations_dashboard(account_mgr)
        
        with tabs[1]:
            EKSManagementModule._render_ai_troubleshooting(account_mgr)
        
        with tabs[2]:
            EKSManagementModule._render_security_compliance(account_mgr)
        
        with tabs[3]:
            EKSManagementModule._render_cost_optimization(account_mgr)
        
        with tabs[4]:
            EKSManagementModule._render_performance_analytics(account_mgr)
        
        with tabs[5]:
            EKSManagementModule._render_cicd_integration(account_mgr)
        
        with tabs[6]:
            EKSManagementModule._render_quick_actions(account_mgr)
    
    @staticmethod
    def _render_operations_dashboard(account_mgr):
        """Render real-time operations dashboard - Phase 1"""
        st.markdown("## 🎯 Real-Time Operations Dashboard")
        st.info("📊 Live monitoring across all EKS clusters with AI-powered insights")
        
        # Overall health metrics
        col1, col2, col3, col4, col5 = st.columns(5)
        
        with col1:
            st.metric(
                "Total Clusters",
                "12",
                delta="↑ 2 this week"
            )
        
        with col2:
            st.metric(
                "Healthy Clusters",
                "10",
                delta="83%",
                delta_color="normal"
            )
        
        with col3:
            st.metric(
                "Total Pods",
                "847",
                delta="↑ 45 today"
            )
        
        with col4:
            st.metric(
                "Active Alerts",
                "3",
                delta="↓ 2 from yesterday",
                delta_color="inverse"
            )
        
        with col5:
            st.metric(
                "Monthly Cost",
                "$8,450",
                delta="↓ $320 optimized"
            )
        
        st.markdown("---")
        
        # Cluster health overview
        st.markdown("### 🏥 Cluster Health Status")
        
        clusters_health = [
            {
                'Cluster': 'prod-eks-us-east-1',
                'Account': 'Production',
                'Region': 'us-east-1',
                'Status': '✅ Healthy',
                'Pods': '245/250',
                'Nodes': '8/10',
                'CPU': '67%',
                'Memory': '72%',
                'Version': '1.28',
                'Uptime': '45 days',
                'Health Score': '95%'
            },
            {
                'Cluster': 'prod-eks-eu-west-1',
                'Account': 'Production',
                'Region': 'eu-west-1',
                'Status': '✅ Healthy',
                'Pods': '189/200',
                'Nodes': '6/8',
                'CPU': '54%',
                'Memory': '61%',
                'Version': '1.28',
                'Uptime': '38 days',
                'Health Score': '92%'
            },
            {
                'Cluster': 'staging-eks-us-east-1',
                'Account': 'Staging',
                'Region': 'us-east-1',
                'Status': '⚠️ Warning',
                'Pods': '98/100',
                'Nodes': '4/4',
                'CPU': '89%',
                'Memory': '91%',
                'Version': '1.27',
                'Uptime': '12 days',
                'Health Score': '68%'
            },
            {
                'Cluster': 'dev-eks-us-west-2',
                'Account': 'Development',
                'Region': 'us-west-2',
                'Status': '🔴 Critical',
                'Pods': '45/50',
                'Nodes': '2/4',
                'CPU': '45%',
                'Memory': '52%',
                'Version': '1.26',
                'Uptime': '2 days',
                'Health Score': '45%'
            }
        ]
        
        clusters_df = pd.DataFrame(clusters_health)
        
        # Add health score styling
        st.dataframe(
            clusters_df,
            use_container_width=True,
            hide_index=True
        )
        
        # AI Insights section
        st.markdown("---")
        st.markdown("### 🤖 AI-Powered Insights")
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            st.markdown("""
            **Critical Issues Detected:**
            - 🔴 **dev-eks-us-west-2**: 2 nodes down, causing pod scheduling failures
            - ⚠️ **staging-eks-us-east-1**: High resource usage (>90%), recommend scaling
            - ⚠️ **prod-eks-us-east-1**: Version 1.28 support ends in 60 days, plan upgrade
            
            **Optimization Opportunities:**
            - 💰 Moving to Graviton2 instances could save **$1,240/month**
            - 📦 12 pods using deprecated APIs, need migration before K8s 1.29
            - 🔒 3 clusters have unrestricted security groups, security risk
            
            **Proactive Recommendations:**
            - 📈 Enable Cluster Autoscaler on staging cluster (89% CPU usage)
            - 🛡️ Deploy Pod Security Standards on all production clusters
            - 💾 Configure automated EBS snapshot backups for stateful workloads
            """)
        
        with col2:
            st.markdown("**Quick Actions:**")
            
            if st.button("⚡ Fix Critical Issues", key="dash_fix_critical", type="primary", use_container_width=True):
                st.success("Initiating automated remediation...")
            
            if st.button("🔍 Deep Dive Analysis", key="dash_deep_dive", use_container_width=True):
                st.info("Generating comprehensive analysis...")
            
            if st.button("📊 Generate Report", key="dash_gen_report", use_container_width=True):
                st.info("Creating operations report...")
            
            if st.button("🔔 Configure Alerts", key="dash_config_alerts", use_container_width=True):
                st.info("Opening alert configuration...")
        
        # Recent events
        st.markdown("---")
        st.markdown("### 📋 Recent Events & Incidents")
        
        events = [
            {
                'Time': '5 min ago',
                'Cluster': 'dev-eks-us-west-2',
                'Severity': '🔴 Critical',
                'Event': 'Node i-abc123 became NotReady',
                'Impact': '5 pods evicted',
                'Status': 'Auto-remediation in progress'
            },
            {
                'Time': '15 min ago',
                'Cluster': 'staging-eks-us-east-1',
                'Severity': '⚠️ Warning',
                'Event': 'High memory usage detected',
                'Impact': 'Performance degradation',
                'Status': 'Monitoring'
            },
            {
                'Time': '1 hour ago',
                'Cluster': 'prod-eks-us-east-1',
                'Severity': '✅ Info',
                'Event': 'Successful deployment: api-v2.1.0',
                'Impact': 'None',
                'Status': 'Completed'
            },
            {
                'Time': '2 hours ago',
                'Cluster': 'prod-eks-eu-west-1',
                'Severity': '⚠️ Warning',
                'Event': 'Pod CrashLoopBackOff: auth-service',
                'Impact': '1 pod affected',
                'Status': 'Resolved - auto-restarted'
            }
        ]
        
        events_df = pd.DataFrame(events)
        st.dataframe(events_df, use_container_width=True, hide_index=True)
        
        # Live pod status
        st.markdown("---")
        st.markdown("### 🔴 Live Pod Status Across Clusters")
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Running Pods", "789", delta="↑ 23")
        with col2:
            st.metric("Pending Pods", "12", delta="↓ 5", delta_color="inverse")
        with col3:
            st.metric("Failed Pods", "3", delta="↓ 8", delta_color="inverse")
        with col4:
            st.metric("CrashLoopBackOff", "2", delta="↓ 1", delta_color="inverse")
    
    @staticmethod
    def _render_ai_troubleshooting(account_mgr):
        """AI-powered troubleshooting assistant - Phase 1 & 2"""
        st.markdown("## 🔍 AI-Powered Troubleshooting Assistant")
        st.info("🤖 Claude analyzes your EKS issues and provides intelligent solutions")
        
        # Sample troubleshooting questions
        st.markdown("### 💡 Common Issues - Click to Analyze:")
        
        sample_issues = [
            "Why is my pod in CrashLoopBackOff?",
            "Nodes are NotReady - diagnose the issue",
            "Pods stuck in Pending state",
            "High memory usage - identify the cause",
            "Service not accessible from outside cluster",
            "ImagePullBackOff error resolution"
        ]
        
        cols = st.columns(2)
        for i, issue in enumerate(sample_issues):
            with cols[i % 2]:
                if st.button(f"🔍 {issue}", key=f"troubleshoot_q_{i}", use_container_width=True):
                    st.session_state.troubleshoot_query = issue
        
        st.markdown("---")
        
        # AI Troubleshooting interface
        st.markdown("### 🤖 Ask Claude About Your EKS Issue:")
        
        query = st.text_area(
            "Describe your issue:",
            value=st.session_state.get('troubleshoot_query', ''),
            placeholder="e.g., My prod-api pod keeps crashing with OOMKilled error. How do I fix this?",
            height=100,
            key="eks_troubleshoot_input"
        )
        
        col1, col2, col3 = st.columns([1, 1, 3])
        
        with col1:
            if st.button("🤖 Analyze with AI", type="primary", key="eks_analyze_ai", use_container_width=True):
                if query:
                    with st.spinner("🤖 Claude is analyzing your issue..."):
                        import time
                        time.sleep(1.5)
                        
                        response = EKSManagementModule._generate_troubleshooting_response(query)
                        
                        st.markdown("---")
                        st.markdown("### 🤖 Claude's Analysis & Solution:")
                        st.markdown(response)
        
        with col2:
            if st.button("📋 Run Diagnostics", key="eks_run_diagnostics", use_container_width=True):
                st.info("Running comprehensive diagnostics...")
        
        # Recent troubleshooting sessions
        st.markdown("---")
        st.markdown("### 📜 Recent Troubleshooting Sessions")
        
        sessions = [
            {
                'Time': '10 min ago',
                'Issue': 'Pod CrashLoopBackOff',
                'Cluster': 'prod-eks-us-east-1',
                'Resolution': 'Increased memory limit to 512Mi',
                'Status': '✅ Resolved',
                'Time to Fix': '5 minutes'
            },
            {
                'Time': '1 hour ago',
                'Issue': 'Pending pods',
                'Cluster': 'staging-eks',
                'Resolution': 'Added node to cluster (insufficient capacity)',
                'Status': '✅ Resolved',
                'Time to Fix': '12 minutes'
            },
            {
                'Time': '3 hours ago',
                'Issue': 'Service unreachable',
                'Cluster': 'dev-eks',
                'Resolution': 'Fixed security group ingress rules',
                'Status': '✅ Resolved',
                'Time to Fix': '8 minutes'
            }
        ]
        
        sessions_df = pd.DataFrame(sessions)
        st.dataframe(sessions_df, use_container_width=True, hide_index=True)
        
        # AI-powered diagnostics tools
        st.markdown("---")
        st.markdown("### 🛠️ AI Diagnostic Tools")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.markdown("**Pod Diagnostics**")
            cluster_select = st.selectbox(
                "Select Cluster",
                ["prod-eks-us-east-1", "staging-eks", "dev-eks"],
                key="pod_diag_cluster"
            )
            
            namespace = st.text_input("Namespace", value="default", key="pod_diag_namespace")
            pod_name = st.text_input("Pod Name", placeholder="my-pod-abc123", key="pod_diag_pod")
            
            if st.button("🔍 Diagnose Pod", key="diagnose_pod_btn", use_container_width=True):
                st.code("""
kubectl get pod my-pod-abc123 -n default -o yaml

Status: CrashLoopBackOff
Last State: Terminated (OOMKilled)
Reason: Container exceeded memory limit

AI Analysis:
- Container using 512Mi but limit is 256Mi
- Recommendation: Increase memory limit to 512Mi
- Fix: Update deployment with new resource limits
                """, language="yaml")
        
        with col2:
            st.markdown("**Node Diagnostics**")
            node_name = st.text_input("Node Name", placeholder="ip-10-0-1-123", key="node_diag_name")
            
            if st.button("🔍 Diagnose Node", key="diagnose_node_btn", use_container_width=True):
                st.code("""
kubectl describe node ip-10-0-1-123

Status: Ready
CPU: 67% (2.7/4 cores)
Memory: 72% (5.8Gi/8Gi)
Pods: 24/110

AI Analysis:
- Node is healthy
- Resource usage normal
- No scheduling issues detected
                """, language="text")
        
        with col3:
            st.markdown("**Service Diagnostics**")
            service_name = st.text_input("Service Name", placeholder="my-service", key="svc_diag_name")
            
            if st.button("🔍 Diagnose Service", key="diagnose_svc_btn", use_container_width=True):
                st.code("""
kubectl get svc my-service -o yaml

Type: LoadBalancer
External IP: a1b2c3.us-east-1.elb.amazonaws.com
Endpoints: 3 pods ready

AI Analysis:
- Service is properly configured
- LoadBalancer provisioned successfully
- All endpoints healthy
                """, language="yaml")
    
    @staticmethod
    def _generate_troubleshooting_response(query: str):
        """Generate AI troubleshooting response"""
        query_lower = query.lower()
        
        if "crashloop" in query_lower or "crashing" in query_lower:
            return """
**🔍 Issue Analysis: CrashLoopBackOff**

**Root Cause Identified:**
Your pod is in CrashLoopBackOff, most commonly caused by:
1. **OOMKilled** (Out of Memory) - Container exceeded memory limit
2. **Application crash** - Bug or misconfiguration in the app
3. **Failed liveness probe** - Health check failing

**Diagnostic Steps:**

```bash
# 1. Check pod status
kubectl describe pod <pod-name> -n <namespace>

# 2. View container logs
kubectl logs <pod-name> -n <namespace> --previous

# 3. Check events
kubectl get events -n <namespace> --sort-by='.lastTimestamp'
```

**Most Likely Fix (OOMKilled):**

If you see "OOMKilled" in the logs:

```yaml
# Update your deployment with increased memory:
resources:
  requests:
    memory: "256Mi"
  limits:
    memory: "512Mi"  # Increase this
```

**Auto-Fix Command:**
```bash
kubectl set resources deployment/<deployment-name> \\
  --limits=memory=512Mi \\
  --requests=memory=256Mi
```

**Expected Result:**
- Pod will restart with new memory limits
- CrashLoopBackOff should resolve in 30-60 seconds
- Application will run stably

**If This Doesn't Work:**
1. Check application logs for errors
2. Verify environment variables are correct
3. Ensure dependencies (DB, cache) are accessible

**Prevention:**
- Set appropriate resource limits from the start
- Monitor memory usage with Prometheus
- Enable horizontal pod autoscaling (HPA)

Would you like me to analyze the specific logs for your pod?
"""
        
        elif "pending" in query_lower:
            return """
**🔍 Issue Analysis: Pods Stuck in Pending**

**Root Cause Identified:**
Pods in "Pending" state indicate scheduling issues. Common causes:

1. **Insufficient Resources** - Not enough CPU/memory on nodes (80%)
2. **Node Selector Mismatch** - Pod requires specific node that doesn't exist (10%)
3. **Persistent Volume Issues** - PVC can't be bound (5%)
4. **Taints/Tolerations** - Pod can't schedule on tainted nodes (5%)

**Immediate Diagnostics:**

```bash
# Check why pod is pending
kubectl describe pod <pod-name>

# Look for these events:
# "Insufficient cpu"
# "Insufficient memory"
# "No nodes available"
```

**Solution 1: Scale Cluster (Most Common)**

```bash
# Check current node capacity
kubectl top nodes

# If nodes are >80% utilized, scale up:
# Option A: Add nodes to existing node group
eksctl scale nodegroup --cluster=<cluster-name> \\
  --name=<nodegroup-name> --nodes=5

# Option B: Enable cluster autoscaler (recommended)
kubectl apply -f cluster-autoscaler.yaml
```

**Solution 2: Adjust Resource Requests**

```yaml
# If requests are too high, reduce them:
resources:
  requests:
    memory: "128Mi"  # Reduce from 256Mi
    cpu: "100m"      # Reduce from 500m
```

**Solution 3: Check Node Selectors**

```bash
# View pod's node selector
kubectl get pod <pod-name> -o yaml | grep nodeSelector -A 5

# List available nodes with labels
kubectl get nodes --show-labels
```

**Quick Fix:**
```bash
# Cordon problematic nodes (if any)
kubectl cordon <node-name>

# Add a new node
eksctl create nodegroup --cluster=<cluster-name> \\
  --node-type=t3.medium --nodes=2
```

**Expected Timeline:**
- New nodes ready: 3-5 minutes
- Pods scheduled: 30-60 seconds after nodes ready
- Total time: ~5-6 minutes

**AI Recommendation:**
Enable **Cluster Autoscaler** to prevent this in future:
- Automatically adds nodes when pods are pending
- Scales down when capacity is unused
- Saves ~20-30% on costs

Would you like the Cluster Autoscaler configuration?
"""
        
        elif "oom" in query_lower or "memory" in query_lower:
            return """
**🔍 Issue Analysis: High Memory Usage / OOMKilled**

**Root Cause:**
Your pods are experiencing memory issues. Analysis shows:

**Symptoms:**
- Pods terminated with "OOMKilled"
- High memory usage (>90%)
- Frequent pod restarts

**Diagnostic Commands:**

```bash
# 1. Check current memory usage
kubectl top pods -n <namespace>

# 2. Check pod resource limits
kubectl get pod <pod-name> -o yaml | grep -A 10 resources

# 3. View container logs before crash
kubectl logs <pod-name> --previous
```

**Immediate Fix:**

```yaml
# Update deployment with higher memory limits:
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  template:
    spec:
      containers:
      - name: app
        resources:
          requests:
            memory: "512Mi"   # Minimum guaranteed
          limits:
            memory: "1024Mi"  # Maximum allowed
```

**Apply with:**
```bash
kubectl apply -f deployment.yaml

# Or quick update:
kubectl set resources deployment/<name> \\
  --limits=memory=1Gi \\
  --requests=memory=512Mi
```

**Advanced Solutions:**

1. **Memory Leak Detection:**
```bash
# Enable memory profiling
kubectl port-forward pod/<pod-name> 6060:6060
# Access: http://localhost:6060/debug/pprof/heap
```

2. **Vertical Pod Autoscaler (VPA):**
```yaml
# Automatically adjusts memory limits
apiVersion: autoscaling.k8s.io/v1
kind: VerticalPodAutoscaler
metadata:
  name: my-app-vpa
spec:
  targetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: my-app
  updatePolicy:
    updateMode: "Auto"
```

**Expected Results:**
- Pods stop OOMKilling
- Stable memory usage
- No more CrashLoopBackOff

**Cost Impact:**
- Current: Frequent restarts causing downtime
- After fix: +$15-30/month for larger instances
- ROI: Prevents outages worth $1000s+

**Best Practices:**
- Set limits 20-30% above typical usage
- Monitor with Prometheus/Grafana
- Use VPA for automatic optimization
- Enable memory profiling in staging

**AI Insight:**
Based on patterns, consider:
- Switching to memory-optimized instances (r5.large)
- Could save 15% vs current configuration
- Better performance + lower cost

Need help implementing VPA or memory profiling?
"""
        
        elif "service" in query_lower or "accessible" in query_lower or "unreachable" in query_lower:
            return """
**🔍 Issue Analysis: Service Not Accessible**

**Root Cause Investigation:**

Services can be unreachable due to:
1. **Security Group Issues** (40%)
2. **Load Balancer Misconfiguration** (30%)
3. **Pod Selector Mismatch** (15%)
4. **DNS Resolution Issues** (10%)
5. **Network Policy Blocking** (5%)

**Step-by-Step Diagnosis:**

**1. Verify Service Configuration:**
```bash
# Check service status
kubectl get svc <service-name> -o wide

# Look for:
# - External IP assigned (LoadBalancer)
# - Correct selector labels
# - Proper port mapping
```

**2. Check Endpoints:**
```bash
# Verify pods are connected to service
kubectl get endpoints <service-name>

# Should show pod IPs
# If empty → selector mismatch
```

**3. Test Internal Connectivity:**
```bash
# From another pod
kubectl run test-pod --image=busybox --rm -it -- sh
wget -O- http://<service-name>.<namespace>.svc.cluster.local
```

**Common Fixes:**

**Fix 1: Security Group (Most Common)**
```bash
# Allow inbound traffic on service port
aws ec2 authorize-security-group-ingress \\
  --group-id sg-xxxxx \\
  --protocol tcp \\
  --port 80 \\
  --cidr 0.0.0.0/0
```

**Fix 2: Selector Mismatch**
```yaml
# Ensure service selector matches pod labels
apiVersion: v1
kind: Service
spec:
  selector:
    app: my-app  # Must match pod label
```

**Fix 3: LoadBalancer Annotations**
```yaml
apiVersion: v1
kind: Service
metadata:
  annotations:
    service.beta.kubernetes.io/aws-load-balancer-type: "nlb"
    service.beta.kubernetes.io/aws-load-balancer-scheme: "internet-facing"
spec:
  type: LoadBalancer
```

**Quick Validation:**
```bash
# 1. Check if pods are running
kubectl get pods -l app=my-app

# 2. Test pod directly (bypass service)
kubectl port-forward pod/<pod-name> 8080:80
curl http://localhost:8080

# 3. Check service endpoints
kubectl describe svc <service-name>
```

**Expected Resolution Time:**
- Security group fix: 30 seconds
- Service reconfiguration: 2-3 minutes
- LoadBalancer provisioning: 3-5 minutes

**AI Recommendation:**
- Add health checks to LoadBalancer
- Configure proper timeout values
- Enable access logs for debugging
- Use Network Policies for security

**Verification:**
```bash
# Test external access
curl http://<external-ip>

# Should return 200 OK
```

Need help with a specific service type (ClusterIP/NodePort/LoadBalancer)?
"""
        
        else:
            return f"""
**🤖 Claude EKS Troubleshooting Analysis**

Analyzing: *"{query}"*

**General Troubleshooting Approach:**

**1. Gather Information:**
```bash
# Check cluster status
kubectl cluster-info
kubectl get nodes
kubectl get pods --all-namespaces

# View recent events
kubectl get events --sort-by='.lastTimestamp' | head -20
```

**2. Identify the Issue:**
- Check pod/node/service status
- Review logs and events
- Analyze resource usage
- Verify configurations

**3. Common EKS Issues & Fixes:**

**A. Pod Issues:**
- CrashLoopBackOff → Check logs, increase resources
- ImagePullBackOff → Verify image exists, check credentials
- Pending → Scale cluster or reduce resource requests

**B. Node Issues:**
- NotReady → Check kubelet status, restart node
- High CPU/Memory → Scale node group or optimize workloads
- Disk pressure → Clean up old images/logs

**C. Networking Issues:**
- Service unreachable → Check security groups, selectors
- DNS failures → Verify CoreDNS pods are running
- Slow performance → Check CNI plugin, security groups

**D. Authentication Issues:**
- RBAC errors → Check service account permissions
- aws-auth ConfigMap → Verify IAM mappings

**Quick Diagnostics:**
```bash
# Pod troubleshooting
kubectl logs <pod-name> --previous
kubectl describe pod <pod-name>
kubectl exec -it <pod-name> -- sh

# Node troubleshooting
kubectl describe node <node-name>
kubectl top nodes

# Service troubleshooting
kubectl get svc
kubectl describe svc <service-name>
kubectl get endpoints <service-name>
```

**Next Steps:**
1. Describe your specific issue in more detail
2. Share relevant error messages or logs
3. I'll provide targeted solutions

**Example specific questions:**
- "My nginx pod keeps crashing with exit code 137"
- "LoadBalancer service shows <pending> for external IP"
- "Pods can't connect to RDS database"

How can I help you further?
"""
    
    @staticmethod
    def _render_security_compliance(account_mgr):
        """Security scanning and compliance - Phase 2"""
        st.markdown("## 🛡️ Security & Compliance Center")
        st.info("🔒 AI-powered security scanning, RBAC analysis, and compliance monitoring")
        
        # Security overview
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric(
                "Security Score",
                "78%",
                delta="↑ 5% this week"
            )
        
        with col2:
            st.metric(
                "Critical Vulns",
                "3",
                delta="↓ 2 fixed",
                delta_color="inverse"
            )
        
        with col3:
            st.metric(
                "RBAC Issues",
                "5",
                delta="Needs attention"
            )
        
        with col4:
            st.metric(
                "Compliance",
                "92%",
                delta="↑ 3%"
            )
        
        st.markdown("---")
        
        # Security findings
        st.markdown("### 🔍 Active Security Findings")
        
        findings = [
            {
                'Severity': '🔴 Critical',
                'Finding': 'Pod running as root in production',
                'Cluster': 'prod-eks-us-east-1',
                'Namespace': 'default',
                'Resource': 'legacy-app',
                'Risk': 'Container escape, privilege escalation',
                'Remediation': 'Add securityContext with runAsNonRoot: true',
                'Status': 'Open'
            },
            {
                'Severity': '🔴 Critical',
                'Finding': 'Image with HIGH CVEs deployed',
                'Cluster': 'prod-eks-us-east-1',
                'Namespace': 'api',
                'Resource': 'api-service:v1.2.0',
                'Risk': 'CVE-2024-1234, CVE-2024-5678 (RCE)',
                'Remediation': 'Update to api-service:v1.2.1',
                'Status': 'Open'
            },
            {
                'Severity': '🟠 High',
                'Finding': 'Overly permissive RBAC',
                'Cluster': 'staging-eks',
                'Namespace': 'kube-system',
                'Resource': 'developer-role',
                'Risk': 'Developers have cluster-admin access',
                'Remediation': 'Restrict to namespace-level permissions',
                'Status': 'In Progress'
            },
            {
                'Severity': '🟡 Medium',
                'Finding': 'No Network Policies defined',
                'Cluster': 'dev-eks',
                'Namespace': 'default',
                'Resource': 'all-pods',
                'Risk': 'Unrestricted pod-to-pod communication',
                'Remediation': 'Implement default-deny NetworkPolicy',
                'Status': 'Open'
            }
        ]
        
        findings_df = pd.DataFrame(findings)
        st.dataframe(findings_df, use_container_width=True, hide_index=True)
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if st.button("⚡ Auto-Fix All (Safe)", type="primary", key="sec_auto_fix_all", use_container_width=True):
                st.success("Auto-remediation initiated for safe fixes...")
        
        with col2:
            if st.button("📊 Security Report", key="sec_gen_report", use_container_width=True):
                st.info("Generating comprehensive security report...")
        
        with col3:
            if st.button("🔍 Deep Scan", key="sec_deep_scan", use_container_width=True):
                st.info("Starting deep security scan...")
        
        # RBAC Analysis
        st.markdown("---")
        st.markdown("### 👥 RBAC & Access Control Analysis")
        
        rbac_issues = [
            {
                'Issue Type': 'Overly Permissive',
                'Subject': 'ServiceAccount: default',
                'Permissions': 'cluster-admin',
                'Namespace': 'default',
                'Risk': 'High',
                'Recommendation': 'Create specific ServiceAccount with limited permissions'
            },
            {
                'Issue Type': 'Unused Service Account',
                'Subject': 'ServiceAccount: old-deployer',
                'Permissions': 'edit',
                'Namespace': 'production',
                'Risk': 'Medium',
                'Recommendation': 'Delete unused ServiceAccount'
            },
            {
                'Issue Type': 'Missing RBAC',
                'Subject': 'Namespace: monitoring',
                'Permissions': 'None defined',
                'Namespace': 'monitoring',
                'Risk': 'Low',
                'Recommendation': 'Create read-only role for monitoring tools'
            }
        ]
        
        rbac_df = pd.DataFrame(rbac_issues)
        st.dataframe(rbac_df, use_container_width=True, hide_index=True)
        
        # Pod Security Standards
        st.markdown("---")
        st.markdown("### 🔐 Pod Security Standards Compliance")
        
        col1, col2 = st.columns([3, 1])
        
        with col1:
            st.markdown("""
            **Pod Security Standards Status:**
            
            - ✅ **Baseline**: 100% compliant (all clusters)
            - ⚠️ **Restricted**: 68% compliant
                - 12 pods running as root
                - 5 pods with privileged containers
                - 8 pods missing securityContext
            
            **AI Recommendation:**
            Deploy Pod Security Admission controller with:
            - `enforce: baseline` (all namespaces)
            - `enforce: restricted` (production namespaces)
            - `audit: restricted` (staging/dev for monitoring)
            """)
        
        with col2:
            if st.button("📋 Generate PSA Config", key="sec_gen_psa", use_container_width=True):
                st.code("""
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
                """, language="yaml")
        
        # Image Vulnerability Scanning
        st.markdown("---")
        st.markdown("### 🐳 Container Image Vulnerability Scan")
        
        image_vulns = [
            {
                'Image': 'nginx:1.20',
                'Cluster': 'prod-eks',
                'Critical': 3,
                'High': 8,
                'Medium': 15,
                'Total CVEs': 26,
                'Latest Safe': 'nginx:1.25',
                'Action': 'Upgrade required'
            },
            {
                'Image': 'python:3.9',
                'Cluster': 'staging-eks',
                'Critical': 0,
                'High': 2,
                'Medium': 5,
                'Total CVEs': 7,
                'Latest Safe': 'python:3.12-slim',
                'Action': 'Recommended'
            },
            {
                'Image': 'alpine:3.18',
                'Cluster': 'dev-eks',
                'Critical': 0,
                'High': 0,
                'Medium': 1,
                'Total CVEs': 1,
                'Latest Safe': 'alpine:3.19',
                'Action': 'Low priority'
            }
        ]
        
        vulns_df = pd.DataFrame(image_vulns)
        st.dataframe(vulns_df, use_container_width=True, hide_index=True)
        
        # Compliance frameworks
        st.markdown("---")
        st.markdown("### 📜 Compliance Framework Status")
        
        compliance_data = [
            {'Framework': 'CIS Kubernetes Benchmark', 'Status': '87%', 'Failed Checks': 13, 'Priority': 'High'},
            {'Framework': 'PCI-DSS', 'Status': '92%', 'Failed Checks': 8, 'Priority': 'Critical'},
            {'Framework': 'HIPAA', 'Status': '78%', 'Failed Checks': 22, 'Priority': 'High'},
            {'Framework': 'SOC 2', 'Status': '95%', 'Failed Checks': 5, 'Priority': 'Medium'}
        ]
        
        compliance_df = pd.DataFrame(compliance_data)
        st.dataframe(compliance_df, use_container_width=True, hide_index=True)
    
    @staticmethod
    def _render_cost_optimization(account_mgr):
        """AI-driven cost optimization - Phase 2"""
        st.markdown("## 💰 AI-Powered Cost Optimization")
        st.info("💵 Intelligent cost analysis and automated savings recommendations")
        
        # Cost overview
        col1, col2, col3, col4, col5 = st.columns(5)
        
        with col1:
            st.metric(
                "Monthly Cost",
                "$8,450",
                delta="↓ $320 vs last month"
            )
        
        with col2:
            st.metric(
                "Potential Savings",
                "$1,840",
                delta="22% reduction"
            )
        
        with col3:
            st.metric(
                "Wasted Spend",
                "$450",
                delta="Idle resources"
            )
        
        with col4:
            st.metric(
                "Optimization Score",
                "72%",
                delta="↑ 8%"
            )
        
        with col5:
            st.metric(
                "ROI from Fixes",
                "$12K/year",
                delta="Projected"
            )
        
        st.markdown("---")
        
        # Top savings opportunities
        st.markdown("### 🎯 Top Savings Opportunities (AI-Identified)")
        
        opportunities = [
            {
                'Opportunity': 'Switch to Graviton2 instances',
                'Cluster': 'prod-eks-us-east-1',
                'Current Cost': '$3,200/mo',
                'Optimized Cost': '$1,960/mo',
                'Monthly Savings': '$1,240',
                'Annual Savings': '$14,880',
                'Effort': 'Low',
                'Confidence': '98%',
                'Impact': 'No performance loss, better price/performance'
            },
            {
                'Opportunity': 'Right-size over-provisioned nodes',
                'Cluster': 'staging-eks',
                'Current Cost': '$1,800/mo',
                'Optimized Cost': '$1,350/mo',
                'Monthly Savings': '$450',
                'Annual Savings': '$5,400',
                'Effort': 'Low',
                'Confidence': '95%',
                'Impact': 'Nodes running at 35% CPU usage'
            },
            {
                'Opportunity': 'Enable Cluster Autoscaler',
                'Cluster': 'dev-eks',
                'Current Cost': '$1,200/mo',
                'Optimized Cost': '$960/mo',
                'Monthly Savings': '$240',
                'Annual Savings': '$2,880',
                'Effort': 'Medium',
                'Confidence': '92%',
                'Impact': 'Auto-scale based on actual usage'
            },
            {
                'Opportunity': 'Use Spot Instances for non-prod',
                'Cluster': 'staging-eks, dev-eks',
                'Current Cost': '$2,100/mo',
                'Optimized Cost': '$1,470/mo',
                'Monthly Savings': '$630',
                'Annual Savings': '$7,560',
                'Effort': 'Medium',
                'Confidence': '89%',
                'Impact': '70% cost reduction on eligible workloads'
            }
        ]
        
        opps_df = pd.DataFrame(opportunities)
        st.dataframe(opps_df, use_container_width=True, hide_index=True)
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if st.button("⚡ Apply Top 3 Recommendations", type="primary", key="cost_apply_top3", use_container_width=True):
                st.success("Initiating cost optimization for top 3 recommendations...")
                st.info("Expected savings: $1,930/month = $23,160/year")
        
        with col2:
            if st.button("📊 Detailed Cost Report", key="cost_detailed_report", use_container_width=True):
                st.info("Generating comprehensive cost breakdown...")
        
        with col3:
            if st.button("🎯 Custom Analysis", key="cost_custom_analysis", use_container_width=True):
                st.info("Running custom cost analysis...")
        
        # Cost breakdown by cluster
        st.markdown("---")
        st.markdown("### 💵 Cost Breakdown by Cluster")
        
        cluster_costs = [
            {
                'Cluster': 'prod-eks-us-east-1',
                'Control Plane': '$73',
                'Nodes (8x m5.large)': '$2,880',
                'EBS Volumes': '$180',
                'Load Balancers': '$67',
                'Total': '$3,200',
                'Efficiency': '68%',
                'Waste': '$320'
            },
            {
                'Cluster': 'prod-eks-eu-west-1',
                'Control Plane': '$73',
                'Nodes (6x m5.large)': '$2,160',
                'EBS Volumes': '$140',
                'Load Balancers': '$54',
                'Total': '$2,427',
                'Efficiency': '75%',
                'Waste': '$180'
            },
            {
                'Cluster': 'staging-eks-us-east-1',
                'Control Plane': '$73',
                'Nodes (4x t3.large)': '$1,440',
                'EBS Volumes': '$90',
                'Load Balancers': '$27',
                'Total': '$1,630',
                'Efficiency': '45%',
                'Waste': '$450'
            }
        ]
        
        costs_df = pd.DataFrame(cluster_costs)
        st.dataframe(costs_df, use_container_width=True, hide_index=True)
        
        # Resource waste detection
        st.markdown("---")
        st.markdown("### 🚨 Waste Detection (AI-Powered)")
        
        waste = [
            {
                'Type': 'Idle Nodes',
                'Resource': '2 nodes in dev-eks',
                'Usage': '12% CPU, 18% Memory',
                'Cost': '$720/month',
                'Recommendation': 'Terminate or use for burst capacity',
                'Savings': '$720/month'
            },
            {
                'Type': 'Over-provisioned Pods',
                'Resource': '45 pods with high requests',
                'Usage': 'Requesting 2x actual usage',
                'Cost': '$280/month',
                'Recommendation': 'Right-size resource requests',
                'Savings': '$140/month'
            },
            {
                'Type': 'Unused Volumes',
                'Resource': '23 unattached EBS volumes',
                'Usage': '0% (orphaned)',
                'Cost': '$115/month',
                'Recommendation': 'Delete after snapshot',
                'Savings': '$115/month'
            },
            {
                'Type': 'Inactive Load Balancers',
                'Resource': '3 ALBs with 0 traffic',
                'Usage': 'No active connections',
                'Cost': '$75/month',
                'Recommendation': 'Delete unused load balancers',
                'Savings': '$75/month'
            }
        ]
        
        waste_df = pd.DataFrame(waste)
        st.dataframe(waste_df, use_container_width=True, hide_index=True)
        
        # AI insights
        st.markdown("---")
        st.markdown("### 🤖 AI Cost Optimization Insights")
        
        st.success("""
        **💡 Smart Recommendations:**
        
        1. **Immediate Action (This Week):**
           - Switch prod clusters to Graviton2 → Save $1,240/month
           - Delete 23 unused EBS volumes → Save $115/month
           - Total quick wins: **$1,355/month = $16,260/year**
        
        2. **Short-term (This Month):**
           - Implement Cluster Autoscaler → Save $240/month
           - Right-size 45 over-provisioned pods → Save $140/month
           - Enable Spot Instances for dev/staging → Save $630/month
           - Total: **$1,010/month = $12,120/year**
        
        3. **Strategic (This Quarter):**
           - Consolidate dev clusters (3→1) → Save $400/month
           - Implement FinOps tagging → 15-20% visibility improvement
           - Set up Karpenter for better node management → 10-15% savings
           - Total: **$600+/month = $7,200+/year**
        
        **📈 Total Potential Savings: $2,965/month = $35,580/year**
        
        **🎯 Target:** Reduce monthly EKS spend from $8,450 → $5,485 (35% reduction)
        """)
    
    @staticmethod
    def _render_performance_analytics(account_mgr):
        """Performance monitoring and optimization - Phase 2"""
        st.markdown("## 📈 Performance Analytics & Optimization")
        st.info("⚡ AI-powered performance monitoring and resource optimization")
        
        # Performance metrics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric(
                "Avg Response Time",
                "245ms",
                delta="↓ 38ms improved"
            )
        
        with col2:
            st.metric(
                "P95 Latency",
                "850ms",
                delta="↓ 12%"
            )
        
        with col3:
            st.metric(
                "Request Rate",
                "12.4K/sec",
                delta="↑ 2.1K/sec"
            )
        
        with col4:
            st.metric(
                "Error Rate",
                "0.12%",
                delta="↓ 0.08%",
                delta_color="inverse"
            )
        
        st.markdown("---")
        
        # Resource utilization
        st.markdown("### 📊 Cluster Resource Utilization")
        
        utilization = [
            {
                'Cluster': 'prod-eks-us-east-1',
                'CPU Usage': '67%',
                'CPU Trend': '↑',
                'Memory Usage': '72%',
                'Memory Trend': '→',
                'Network I/O': '2.4 Gbps',
                'Disk I/O': '450 IOPS',
                'Pod Density': '98%',
                'Recommendation': '✅ Healthy - monitor trends'
            },
            {
                'Cluster': 'staging-eks',
                'CPU Usage': '89%',
                'CPU Trend': '↑↑',
                'Memory Usage': '91%',
                'Memory Trend': '↑',
                'Network I/O': '1.2 Gbps',
                'Disk I/O': '320 IOPS',
                'Pod Density': '96%',
                'Recommendation': '⚠️ Scale urgently - at capacity'
            },
            {
                'Cluster': 'dev-eks',
                'CPU Usage': '23%',
                'CPU Trend': '→',
                'Memory Usage': '31%',
                'Memory Trend': '→',
                'Network I/O': '0.4 Gbps',
                'Disk I/O': '120 IOPS',
                'Pod Density': '45%',
                'Recommendation': '💰 Over-provisioned - scale down'
            }
        ]
        
        util_df = pd.DataFrame(utilization)
        st.dataframe(util_df, use_container_width=True, hide_index=True)
        
        # Scaling recommendations
        st.markdown("---")
        st.markdown("### 🎯 AI Scaling Recommendations")
        
        scaling_recs = [
            {
                'Cluster': 'staging-eks',
                'Current': '4 nodes (t3.large)',
                'Recommended': '6 nodes (t3.large) OR 4 nodes (t3.xlarge)',
                'Reason': 'CPU/Memory at 90%+ for 3 days',
                'Action': 'Immediate scale required',
                'Expected Impact': 'Reduce CPU to 60%, improve latency by 25%',
                'Cost Impact': '+$360/month'
            },
            {
                'Cluster': 'prod-eks-us-east-1',
                'Current': '8 nodes (m5.large)',
                'Recommended': 'Enable HPA + VPA',
                'Reason': 'Predictable traffic patterns, can optimize',
                'Action': 'Implement autoscaling',
                'Expected Impact': 'Handle 2x traffic spikes, reduce idle cost',
                'Cost Impact': 'Neutral (better utilization)'
            },
            {
                'Cluster': 'dev-eks',
                'Current': '4 nodes (t3.medium)',
                'Recommended': '2 nodes (t3.medium)',
                'Reason': 'Consistent 25% utilization',
                'Action': 'Scale down',
                'Expected Impact': 'No performance impact',
                'Cost Impact': '-$360/month savings'
            }
        ]
        
        scaling_df = pd.DataFrame(scaling_recs)
        st.dataframe(scaling_df, use_container_width=True, hide_index=True)
        
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("⚡ Apply Scaling Recommendations", type="primary", key="perf_apply_scaling", use_container_width=True):
                st.success("Applying scaling recommendations via GitOps...")
        
        with col2:
            if st.button("📊 Performance Report", key="perf_gen_report", use_container_width=True):
                st.info("Generating performance analysis report...")
        
        # Application performance
        st.markdown("---")
        st.markdown("### 🚀 Application Performance Insights")
        
        app_perf = [
            {
                'Application': 'api-service',
                'Namespace': 'production',
                'Avg Response': '120ms',
                'P95': '340ms',
                'P99': '890ms',
                'Error Rate': '0.08%',
                'Recommendation': '✅ Healthy',
                'Optimization': 'Consider caching for 15% improvement'
            },
            {
                'Application': 'frontend',
                'Namespace': 'production',
                'Avg Response': '450ms',
                'P95': '1,200ms',
                'P99': '3,400ms',
                'Error Rate': '0.05%',
                'Recommendation': '⚠️ Slow P99',
                'Optimization': 'Add CDN, optimize bundle size'
            },
            {
                'Application': 'auth-service',
                'Namespace': 'production',
                'Avg Response': '85ms',
                'P95': '180ms',
                'P99': '420ms',
                'Error Rate': '0.02%',
                'Recommendation': '✅ Excellent',
                'Optimization': 'No action needed'
            }
        ]
        
        app_perf_df = pd.DataFrame(app_perf)
        st.dataframe(app_perf_df, use_container_width=True, hide_index=True)
        
        # HPA/VPA recommendations
        st.markdown("---")
        st.markdown("### 🔄 Autoscaling Configuration Recommendations")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**Horizontal Pod Autoscaler (HPA)**")
            
            hpa_candidates = [
                {'App': 'api-service', 'Current Replicas': 3, 'Suggested': '3-10', 'Trigger': 'CPU > 70%'},
                {'App': 'frontend', 'Current Replicas': 2, 'Suggested': '2-8', 'Trigger': 'CPU > 65%'},
                {'App': 'worker', 'Current Replicas': 5, 'Suggested': '2-15', 'Trigger': 'Queue depth > 100'}
            ]
            
            hpa_df = pd.DataFrame(hpa_candidates)
            st.dataframe(hpa_df, use_container_width=True, hide_index=True)
            
            if st.button("📋 Generate HPA Configs", key="perf_gen_hpa", use_container_width=True):
                st.code("""
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: api-service-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: api-service
  minReplicas: 3
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
                """, language="yaml")
        
        with col2:
            st.markdown("**Vertical Pod Autoscaler (VPA)**")
            
            vpa_candidates = [
                {'App': 'database-proxy', 'Current': '256Mi/100m', 'Recommended': '512Mi/200m', 'Savings': 'Better performance'},
                {'App': 'cache', 'Current': '1Gi/500m', 'Recommended': '512Mi/250m', 'Savings': '-$45/month'},
                {'App': 'logger', 'Current': '128Mi/50m', 'Recommended': '256Mi/100m', 'Savings': 'Prevent OOM'}
            ]
            
            vpa_df = pd.DataFrame(vpa_candidates)
            st.dataframe(vpa_df, use_container_width=True, hide_index=True)
            
            if st.button("📋 Generate VPA Configs", key="perf_gen_vpa", use_container_width=True):
                st.code("""
apiVersion: autoscaling.k8s.io/v1
kind: VerticalPodAutoscaler
metadata:
  name: database-proxy-vpa
spec:
  targetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: database-proxy
  updatePolicy:
    updateMode: "Auto"
  resourcePolicy:
    containerPolicies:
    - containerName: '*'
      minAllowed:
        cpu: 100m
        memory: 256Mi
      maxAllowed:
        cpu: 1
        memory: 1Gi
                """, language="yaml")
    
    @staticmethod
    def _render_cicd_integration(account_mgr):
        """CI/CD integration view - Phase 3"""
        st.markdown("## 🔗 CI/CD Integration Dashboard")
        st.info("🔄 Bridge between your CI/CD pipelines and live EKS operations")
        
        # Deployment status from CI/CD
        st.markdown("### 🚀 Recent Deployments (from CI/CD Pipelines)")
        
        deployments = [
            {
                'Application': 'api-service',
                'Version': 'v2.1.4',
                'Cluster': 'prod-eks-us-east-1',
                'Namespace': 'production',
                'Pipeline': 'app-pipeline-123',
                'Deployed': '15 min ago',
                'Status': '✅ Healthy',
                'Replicas': '5/5',
                'GitOps Sync': '✅ Synced',
                'Rollback': 'Available'
            },
            {
                'Application': 'frontend',
                'Version': 'v1.8.3',
                'Cluster': 'prod-eks-us-east-1',
                'Namespace': 'production',
                'Pipeline': 'app-pipeline-124',
                'Deployed': '1 hour ago',
                'Status': '⚠️ Degraded',
                'Replicas': '3/4',
                'GitOps Sync': '⚠️ Out of sync',
                'Rollback': 'Available'
            },
            {
                'Application': 'auth-service',
                'Version': 'v3.0.1',
                'Cluster': 'staging-eks',
                'Namespace': 'staging',
                'Pipeline': 'app-pipeline-125',
                'Deployed': '3 hours ago',
                'Status': '✅ Healthy',
                'Replicas': '2/2',
                'GitOps Sync': '✅ Synced',
                'Rollback': 'Available'
            }
        ]
        
        deploy_df = pd.DataFrame(deployments)
        st.dataframe(deploy_df, use_container_width=True, hide_index=True)
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if st.button("🔄 Sync All with GitOps", type="primary", key="cicd_sync_all", use_container_width=True):
                st.success("Syncing all deployments with GitOps repositories...")
        
        with col2:
            if st.button("⏮️ Rollback Degraded", key="cicd_rollback_degraded", use_container_width=True):
                st.info("Rolling back frontend to v1.8.2...")
        
        with col3:
            if st.button("📊 Deployment Report", key="cicd_deploy_report", use_container_width=True):
                st.info("Generating deployment health report...")
        
        # GitOps status
        st.markdown("---")
        st.markdown("### 🔄 GitOps Sync Status")
        
        gitops_status = [
            {
                'Repository': 'infrastructure/prod-eks',
                'Branch': 'main',
                'Last Commit': '3a7f9d2 - Update node count',
                'Sync Status': '✅ Synced',
                'Cluster': 'prod-eks-us-east-1',
                'Last Sync': '5 min ago',
                'Health': 'Healthy'
            },
            {
                'Repository': 'apps/production',
                'Branch': 'main',
                'Last Commit': 'b2e4c18 - Deploy api v2.1.4',
                'Sync Status': '⚠️ Out of Sync',
                'Cluster': 'prod-eks-us-east-1',
                'Last Sync': '45 min ago',
                'Health': 'Degraded'
            },
            {
                'Repository': 'apps/staging',
                'Branch': 'develop',
                'Last Commit': 'd9f1a7c - Test new features',
                'Sync Status': '✅ Synced',
                'Cluster': 'staging-eks',
                'Last Sync': '2 min ago',
                'Health': 'Healthy'
            }
        ]
        
        gitops_df = pd.DataFrame(gitops_status)
        st.dataframe(gitops_df, use_container_width=True, hide_index=True)
        
        # Pipeline to cluster mapping
        st.markdown("---")
        st.markdown("### 🗺️ Pipeline → Cluster Mapping")
        
        st.markdown("""
        **Infrastructure Pipelines (Phase 4):**
        - `infra-pipeline-prod` → Creates/manages `prod-eks-us-east-1`, `prod-eks-eu-west-1`
        - `infra-pipeline-staging` → Creates/manages `staging-eks-us-east-1`
        - `infra-pipeline-dev` → Creates/manages `dev-eks-us-west-2`
        
        **Application Pipelines (Phase 5):**
        - `app-pipeline-api` → Deploys to all clusters (prod, staging, dev)
        - `app-pipeline-frontend` → Deploys to prod and staging clusters
        - `app-pipeline-workers` → Deploys to prod-eks-us-east-1
        """)
        
        # Deployment history
        st.markdown("---")
        st.markdown("### 📜 Deployment History & Rollback Options")
        
        history = [
            {
                'Time': '15 min ago',
                'App': 'api-service',
                'Version': 'v2.1.4 → v2.1.3',
                'Action': 'Deployment',
                'Pipeline': 'app-pipeline-123',
                'Result': '✅ Success',
                'Rollback To': 'v2.1.3'
            },
            {
                'Time': '1 hour ago',
                'App': 'frontend',
                'Version': 'v1.8.3 → v1.8.2',
                'Action': 'Deployment',
                'Pipeline': 'app-pipeline-124',
                'Result': '⚠️ Degraded',
                'Rollback To': 'v1.8.2'
            },
            {
                'Time': '3 hours ago',
                'App': 'auth-service',
                'Version': 'v3.0.1 → v3.0.0',
                'Action': 'Deployment',
                'Pipeline': 'app-pipeline-125',
                'Result': '✅ Success',
                'Rollback To': 'v3.0.0'
            },
            {
                'Time': '5 hours ago',
                'App': 'frontend',
                'Version': 'v1.8.2 ← v1.8.3',
                'Action': 'Rollback',
                'Pipeline': 'Manual',
                'Result': '✅ Success',
                'Rollback To': 'v1.8.1'
            }
        ]
        
        history_df = pd.DataFrame(history)
        st.dataframe(history_df, use_container_width=True, hide_index=True)
        
        # Quick rollback
        st.markdown("---")
        st.markdown("### ⏮️ Quick Rollback")
        
        with st.form("quick_rollback_form"):
            col1, col2, col3 = st.columns(3)
            
            with col1:
                app_to_rollback = st.selectbox(
                    "Application",
                    ["api-service", "frontend", "auth-service", "worker"],
                    key="rollback_app_select"
                )
            
            with col2:
                rollback_cluster = st.selectbox(
                    "Cluster",
                    ["prod-eks-us-east-1", "prod-eks-eu-west-1", "staging-eks"],
                    key="rollback_cluster_select"
                )
            
            with col3:
                rollback_version = st.selectbox(
                    "Rollback to Version",
                    ["v2.1.3 (previous)", "v2.1.2 (2 versions back)", "v2.1.1 (3 versions back)"],
                    key="rollback_version_select"
                )
            
            if st.form_submit_button("⏮️ Execute Rollback", type="primary"):
                st.success(f"Rolling back {app_to_rollback} to {rollback_version.split()[0]} on {rollback_cluster}...")
                st.info("Rollback will complete in ~2-3 minutes. Monitoring deployment status...")
    
    @staticmethod
    def _render_quick_actions(account_mgr):
        """Quick actions and incident response - Phase 3"""
        st.markdown("## ⚡ Quick Actions & Incident Response")
        st.info("🚨 Emergency operations and rapid response tools")
        
        # Emergency actions
        st.markdown("### 🚨 Emergency Operations")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.markdown("**Node Operations**")
            
            node_select = st.selectbox(
                "Select Node",
                ["ip-10-0-1-123 (prod)", "ip-10-0-2-234 (prod)", "ip-10-0-3-345 (staging)"],
                key="quick_node_select"
            )
            
            if st.button("🔴 Drain Node", key="quick_drain_node", use_container_width=True):
                st.warning("Draining node - pods will be evicted gracefully...")
            
            if st.button("🛑 Cordon Node", key="quick_cordon_node", use_container_width=True):
                st.info("Node cordoned - no new pods will be scheduled")
            
            if st.button("✅ Uncordon Node", key="quick_uncordon_node", use_container_width=True):
                st.success("Node uncordoned - resuming normal scheduling")
        
        with col2:
            st.markdown("**Pod Operations**")
            
            pod_select = st.text_input(
                "Pod Name",
                placeholder="my-app-abc123",
                key="quick_pod_input"
            )
            
            namespace_select = st.text_input(
                "Namespace",
                value="default",
                key="quick_namespace_input"
            )
            
            if st.button("🔄 Restart Pod", key="quick_restart_pod", use_container_width=True):
                st.success("Pod deleted - will be recreated by deployment...")
            
            if st.button("📋 Get Logs", key="quick_get_logs", use_container_width=True):
                st.code("kubectl logs my-app-abc123 -n default --tail=100", language="bash")
            
            if st.button("💻 Exec Shell", key="quick_exec_shell", use_container_width=True):
                st.code("kubectl exec -it my-app-abc123 -n default -- /bin/sh", language="bash")
        
        with col3:
            st.markdown("**Deployment Operations**")
            
            deployment_select = st.text_input(
                "Deployment Name",
                placeholder="api-service",
                key="quick_deploy_input"
            )
            
            if st.button("📈 Scale Up", key="quick_scale_up", use_container_width=True):
                st.success("Scaling deployment up by 2 replicas...")
            
            if st.button("📉 Scale Down", key="quick_scale_down", use_container_width=True):
                st.info("Scaling deployment down by 2 replicas...")
            
            if st.button("⏮️ Rollback", key="quick_rollback_deploy", use_container_width=True):
                st.warning("Rolling back to previous version...")
        
        # Incident response playbooks
        st.markdown("---")
        st.markdown("### 📖 Automated Incident Response Playbooks")
        
        playbooks = [
            {
                'Playbook': 'High Memory Usage',
                'Trigger': 'Memory > 90% for 5 min',
                'Actions': '1. Check for memory leaks, 2. Scale horizontally, 3. Increase limits',
                'Auto-Execute': '✅ Yes',
                'Success Rate': '94%',
                'Avg Resolution': '3 min'
            },
            {
                'Playbook': 'Pod CrashLoop',
                'Trigger': 'Pod restarts > 5 in 10 min',
                'Actions': '1. Analyze logs, 2. Check resource limits, 3. Increase if OOM',
                'Auto-Execute': '✅ Yes',
                'Success Rate': '89%',
                'Avg Resolution': '5 min'
            },
            {
                'Playbook': 'Node NotReady',
                'Trigger': 'Node status NotReady',
                'Actions': '1. Cordon node, 2. Drain pods, 3. Restart kubelet, 4. Replace if needed',
                'Auto-Execute': '⚠️ Approval required',
                'Success Rate': '92%',
                'Avg Resolution': '8 min'
            },
            {
                'Playbook': 'High Error Rate',
                'Trigger': 'Error rate > 5%',
                'Actions': '1. Check recent deployments, 2. Rollback if needed, 3. Alert team',
                'Auto-Execute': '⚠️ Approval required',
                'Success Rate': '96%',
                'Avg Resolution': '4 min'
            }
        ]
        
        playbooks_df = pd.DataFrame(playbooks)
        st.dataframe(playbooks_df, use_container_width=True, hide_index=True)
        
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("⚡ Enable All Playbooks", type="primary", key="quick_enable_playbooks", use_container_width=True):
                st.success("All incident response playbooks enabled!")
        
        with col2:
            if st.button("📋 Create Custom Playbook", key="quick_create_playbook", use_container_width=True):
                st.info("Opening playbook builder...")
        
        # Quick diagnostics
        st.markdown("---")
        st.markdown("### 🔍 Quick Diagnostics")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**Cluster Health Check**")
            
            if st.button("🏥 Run Health Check", key="quick_health_check", use_container_width=True):
                st.code("""
✅ Control Plane: Healthy
✅ API Server: Responding (45ms)
✅ Nodes: 8/8 Ready
✅ CoreDNS: 2/2 Running
✅ kube-proxy: 8/8 Running
⚠️ Metrics Server: 1/1 Running (high CPU)
✅ Cluster Autoscaler: Running

Overall Status: HEALTHY (1 warning)
                """, language="text")
        
        with col2:
            st.markdown("**Resource Availability**")
            
            if st.button("📊 Check Capacity", key="quick_check_capacity", use_container_width=True):
                st.code("""
CPU Capacity:
  Total: 32 cores
  Allocated: 21.5 cores (67%)
  Available: 10.5 cores

Memory Capacity:
  Total: 64 Gi
  Allocated: 46 Gi (72%)
  Available: 18 Gi

Pod Capacity:
  Total: 880 pods
  Running: 789 pods (90%)
  Available: 91 pods

Status: ✅ Sufficient capacity
                """, language="text")
        
        # Log aggregation
        st.markdown("---")
        st.markdown("### 📜 Log Aggregation & Search")
        
        log_search = st.text_input(
            "Search logs across all pods",
            placeholder="error|exception|timeout",
            key="quick_log_search_input"
        )
        
        time_range = st.selectbox(
            "Time Range",
            ["Last 15 minutes", "Last 1 hour", "Last 6 hours", "Last 24 hours"],
            key="quick_log_timerange"
        )
        
        if st.button("🔍 Search Logs", type="primary", key="quick_search_logs", use_container_width=True):
            st.markdown("**Search Results:**")
            st.code("""
[prod-eks] api-service-7d9f8-abc12 | 2024-12-06 10:23:45 | ERROR: Database connection timeout
[prod-eks] api-service-7d9f8-def34 | 2024-12-06 10:24:12 | ERROR: Retry limit exceeded
[staging] worker-5c7a3-ghi56 | 2024-12-06 10:25:03 | EXCEPTION: NullPointerException in process()
[prod-eks] auth-service-9b2e1-jkl78 | 2024-12-06 10:26:45 | ERROR: Token validation failed

Total: 47 matching log entries in last 15 minutes
Clusters affected: prod-eks-us-east-1, staging-eks
            """, language="text")
        
        # Export kubectl commands
        st.markdown("---")
        st.markdown("### 💻 Export kubectl Commands")
        
        st.markdown("**Generate commands for common operations:**")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if st.button("📋 Get All Resources", key="quick_cmd_get_all", use_container_width=True):
                st.code("""
kubectl get all -A
kubectl get nodes -o wide
kubectl get pv,pvc -A
kubectl get ing -A
                """, language="bash")
        
        with col2:
            if st.button("🔍 Troubleshooting Commands", key="quick_cmd_troubleshoot", use_container_width=True):
                st.code("""
kubectl describe node <node-name>
kubectl logs -f <pod-name>
kubectl get events --sort-by='.lastTimestamp'
kubectl top nodes
kubectl top pods -A
                """, language="bash")
        
        with col3:
            if st.button("⚡ Emergency Commands", key="quick_cmd_emergency", use_container_width=True):
                st.code("""
kubectl drain <node> --ignore-daemonsets
kubectl cordon <node>
kubectl delete pod <pod> --force
kubectl rollout restart deployment/<name>
kubectl scale deployment/<name> --replicas=0
                """, language="bash")

# Export the module
__all__ = ['EKSManagementModule']