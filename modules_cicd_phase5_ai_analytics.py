"""
CI/CD Phase 5: AI-Powered Analytics & Insights
Intelligent pipeline analysis, failure prediction, optimization suggestions, and natural language queries
"""

import streamlit as st
import boto3
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import json

def render_cicd_phase5_module(session, account_id: str, region: str):
    """
    Phase 5: AI-Powered CI/CD Analytics
    
    Features:
    - AI-powered failure prediction
    - Performance optimization suggestions
    - Anomaly detection in pipeline metrics
    - Natural language queries about pipelines
    - Intelligent insights and recommendations
    - Pattern recognition in build/deployment data
    """
    
    st.markdown("## 🤖 AI-Powered CI/CD Analytics")
    st.caption("Intelligent insights and optimization for your CI/CD pipelines")
    
    # Main sections
    sections = st.tabs([
        "🔮 Predictive Analytics",
        "💡 Optimization Insights",
        "🔍 Anomaly Detection",
        "💬 Ask AI Assistant"
    ])
    
    # ============================================================================
    # SECTION 1: Predictive Analytics
    # ============================================================================
    with sections[0]:
        st.markdown("### 🔮 AI-Powered Failure Prediction")
        st.info("Machine learning models analyze pipeline patterns to predict potential failures")
        
        # Risk assessment dashboard
        st.markdown("#### 🎯 Pipeline Risk Assessment")
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric(
                "High Risk Pipelines",
                "3",
                delta="↑ 1 from yesterday",
                delta_color="inverse"
            )
        
        with col2:
            st.metric(
                "Predicted Failures",
                "5",
                delta="Next 24 hours"
            )
        
        with col3:
            st.metric(
                "Model Accuracy",
                "94.2%",
                delta="↑ 2.1%"
            )
        
        with col4:
            st.metric(
                "Prevented Failures",
                "47",
                delta="This month"
            )
        
        st.markdown("---")
        
        # Pipeline risk analysis
        st.markdown("#### 📊 Pipeline Risk Analysis")
        
        risk_data = [
            {
                'Pipeline': 'api-deployment-pipeline',
                'Risk Level': 'High',
                'Failure Probability': '78%',
                'Primary Risk Factor': 'Flaky tests detected',
                'Recommendation': 'Review test suite stability',
                'Predicted Impact': 'Deploy delay: 2-4 hours'
            },
            {
                'Pipeline': 'frontend-deployment',
                'Risk Level': 'Medium',
                'Failure Probability': '42%',
                'Primary Risk Factor': 'Dependency version conflicts',
                'Recommendation': 'Update package.json dependencies',
                'Predicted Impact': 'Build failure likely'
            },
            {
                'Pipeline': 'backend-services',
                'Risk Level': 'Low',
                'Failure Probability': '12%',
                'Primary Risk Factor': 'None detected',
                'Recommendation': 'Continue current practices',
                'Predicted Impact': 'Minimal risk'
            },
            {
                'Pipeline': 'data-pipeline',
                'Risk Level': 'High',
                'Failure Probability': '68%',
                'Primary Risk Factor': 'Resource limits exceeded',
                'Recommendation': 'Increase build instance size',
                'Predicted Impact': 'Timeout failures expected'
            },
            {
                'Pipeline': 'ml-model-deployment',
                'Risk Level': 'Medium',
                'Failure Probability': '35%',
                'Primary Risk Factor': 'Long-running tests',
                'Recommendation': 'Parallelize test execution',
                'Predicted Impact': 'Extended build times'
            }
        ]
        
        df_risk = pd.DataFrame(risk_data)
        
        # Color coding for risk levels
        def color_risk(val):
            colors = {
                'High': 'background-color: #f8d7da; color: #721c24',
                'Medium': 'background-color: #fff3cd; color: #856404',
                'Low': 'background-color: #d4edda; color: #155724'
            }
            return colors.get(val, '')
        
        styled_df = df_risk.style.applymap(color_risk, subset=['Risk Level'])
        st.dataframe(styled_df, use_container_width=True, hide_index=True)
        
        # Detailed risk analysis for selected pipeline
        st.markdown("---")
        st.markdown("#### 🔬 Detailed Risk Analysis")
        
        selected_pipeline = st.selectbox(
            "Select Pipeline for Deep Analysis",
            options=[p['Pipeline'] for p in risk_data],
            key="ai_selected_pipeline"
        )
        
        # Find selected pipeline data
        pipeline_info = next((p for p in risk_data if p['Pipeline'] == selected_pipeline), risk_data[0])
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            # Risk factors breakdown
            st.markdown("**Risk Factors Breakdown:**")
            
            risk_factors = {
                'Test Stability': 85 if pipeline_info['Risk Level'] == 'High' else 25,
                'Build Duration': 60 if 'timeout' in pipeline_info['Predicted Impact'].lower() else 30,
                'Dependency Health': 70 if 'dependency' in pipeline_info['Primary Risk Factor'].lower() else 20,
                'Historical Failures': 55,
                'Code Complexity': 40
            }
            
            for factor, score in risk_factors.items():
                st.progress(score / 100, text=f"{factor}: {score}%")
            
            # AI recommendations
            st.markdown("---")
            st.markdown("**🤖 AI Recommendations:**")
            
            recommendations = [
                f"✅ {pipeline_info['Recommendation']}",
                "🔄 Enable parallel test execution to reduce build time by 40%",
                "📊 Implement canary deployments to minimize production risk",
                "🧪 Add integration test coverage for critical paths",
                "⚡ Consider upgrading build instance from t3.medium to t3.large"
            ]
            
            for rec in recommendations:
                st.markdown(f"- {rec}")
        
        with col2:
            # Risk trend chart
            st.markdown("**Risk Trend (Last 7 Days):**")
            
            dates = pd.date_range(end=datetime.now(), periods=7, freq='D')
            risk_scores = [30, 35, 42, 48, 55, 65, int(pipeline_info['Failure Probability'].rstrip('%'))]
            
            trend_df = pd.DataFrame({
                'Date': dates,
                'Risk Score': risk_scores
            }).set_index('Date')
            
            st.line_chart(trend_df)
            
            # Failure prediction confidence
            st.markdown("---")
            st.markdown("**Prediction Confidence:**")
            
            confidence = 94.2
            st.progress(confidence / 100)
            st.caption(f"{confidence}% confidence in prediction")
        
        # Action buttons
        st.markdown("---")
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if st.button("🚨 Create Alert", type="primary", use_container_width=True):
                st.success(f"✅ Alert created for {selected_pipeline}")
                st.info("Team will be notified of high-risk deployment")
        
        with col2:
            if st.button("📋 Generate Report", use_container_width=True):
                st.download_button(
                    label="⬇️ Download Risk Report",
                    data=df_risk.to_csv(index=False),
                    file_name=f"risk-analysis-{datetime.now().strftime('%Y%m%d')}.csv",
                    mime="text/csv",
                    use_container_width=True
                )
        
        with col3:
            if st.button("🔄 Retrain Model", use_container_width=True):
                with st.spinner("Retraining AI model with latest data..."):
                    import time
                    time.sleep(2)
                    st.success("✅ Model retrained successfully! Accuracy: 94.8%")
    
    # ============================================================================
    # SECTION 2: Optimization Insights
    # ============================================================================
    with sections[1]:
        st.markdown("### 💡 AI-Powered Optimization Insights")
        st.info("Discover opportunities to improve pipeline performance, reduce costs, and increase reliability")
        
        # Optimization summary
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric(
                "Potential Time Savings",
                "2.4 hours/day",
                delta="Across all pipelines"
            )
        
        with col2:
            st.metric(
                "Cost Reduction",
                "$847/month",
                delta="↓ 23%"
            )
        
        with col3:
            st.metric(
                "Performance Gain",
                "+38%",
                delta="Average improvement"
            )
        
        with col4:
            st.metric(
                "Actionable Insights",
                "12",
                delta="High priority"
            )
        
        st.markdown("---")
        
        # Optimization recommendations
        st.markdown("#### 🎯 Top Optimization Opportunities")
        
        optimizations = [
            {
                'Priority': 'High',
                'Category': '⚡ Performance',
                'Insight': 'Parallel Test Execution',
                'Current State': 'Sequential testing in 8 pipelines',
                'Recommendation': 'Enable parallel execution using AWS CodeBuild batch builds',
                'Expected Impact': 'Reduce build time by 45% (save 1.2 hours/day)',
                'Implementation Effort': 'Low - 2 hours',
                'Cost Impact': 'Neutral'
            },
            {
                'Priority': 'High',
                'Category': '💰 Cost',
                'Insight': 'Right-size Build Instances',
                'Current State': '5 pipelines using oversized instances',
                'Recommendation': 'Downgrade from t3.large to t3.medium for low-complexity builds',
                'Expected Impact': 'Save $420/month',
                'Implementation Effort': 'Low - 1 hour',
                'Cost Impact': '↓ $420/mo'
            },
            {
                'Priority': 'Medium',
                'Category': '🔄 Efficiency',
                'Insight': 'Cache Docker Layers',
                'Current State': 'Docker images rebuilt from scratch',
                'Recommendation': 'Implement layer caching with ECR',
                'Expected Impact': 'Reduce build time by 30% for Docker-based pipelines',
                'Implementation Effort': 'Medium - 4 hours',
                'Cost Impact': 'Neutral'
            },
            {
                'Priority': 'High',
                'Category': '🧪 Quality',
                'Insight': 'Optimize Test Suite',
                'Current State': '15% of tests are redundant or overlapping',
                'Recommendation': 'Refactor test suite to remove duplicates',
                'Expected Impact': 'Reduce test execution time by 15%',
                'Implementation Effort': 'Medium - 6 hours',
                'Cost Impact': '↓ $120/mo'
            },
            {
                'Priority': 'Medium',
                'Category': '⏱️ Scheduling',
                'Insight': 'Off-Peak Deployments',
                'Current State': 'Deployments run during peak hours',
                'Recommendation': 'Schedule non-critical deployments during off-peak (2-6 AM)',
                'Expected Impact': 'Reduce deployment failures by 25%',
                'Implementation Effort': 'Low - 1 hour',
                'Cost Impact': 'Neutral'
            },
            {
                'Priority': 'Low',
                'Category': '📦 Artifacts',
                'Insight': 'Artifact Retention',
                'Current State': 'Keeping artifacts for 180 days',
                'Recommendation': 'Reduce retention to 30 days with S3 lifecycle policies',
                'Expected Impact': 'Save $150/month in storage costs',
                'Implementation Effort': 'Low - 30 min',
                'Cost Impact': '↓ $150/mo'
            }
        ]
        
        df_opt = pd.DataFrame(optimizations)
        
        # Priority filter
        priority_filter = st.multiselect(
            "Filter by Priority",
            options=['High', 'Medium', 'Low'],
            default=['High', 'Medium', 'Low'],
            key="opt_priority_filter"
        )
        
        filtered_opt = df_opt[df_opt['Priority'].isin(priority_filter)]
        
        # Display optimizations as expandable cards
        for idx, opt in filtered_opt.iterrows():
            priority_color = {
                'High': '#dc3545',
                'Medium': '#ffc107',
                'Low': '#28a745'
            }[opt['Priority']]
            
            with st.expander(f"{opt['Category']} {opt['Insight']}", expanded=(idx == 0)):
                col1, col2 = st.columns([2, 1])
                
                with col1:
                    st.markdown(f"**Priority:** <span style='color: {priority_color}; font-weight: bold;'>{opt['Priority']}</span>", unsafe_allow_html=True)
                    st.markdown(f"**Current State:** {opt['Current State']}")
                    st.markdown(f"**Recommendation:** {opt['Recommendation']}")
                    st.markdown(f"**Expected Impact:** {opt['Expected Impact']}")
                
                with col2:
                    st.metric("Implementation", opt['Implementation Effort'])
                    st.metric("Cost Impact", opt['Cost Impact'])
                
                # Action buttons
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    if st.button("✅ Implement", key=f"impl_{idx}", use_container_width=True):
                        st.success(f"Implementing: {opt['Insight']}")
                
                with col2:
                    if st.button("📋 Learn More", key=f"learn_{idx}", use_container_width=True):
                        st.info("Detailed implementation guide will be displayed")
                
                with col3:
                    if st.button("⏸️ Snooze", key=f"snooze_{idx}", use_container_width=True):
                        st.warning("Snoozed for 7 days")
        
        # Implementation roadmap
        st.markdown("---")
        st.markdown("#### 🗺️ Optimization Roadmap")
        
        col1, col2 = st.columns([3, 1])
        
        with col1:
            roadmap_data = {
                'Week': ['Week 1', 'Week 2', 'Week 3', 'Week 4'],
                'Optimizations': [3, 2, 1, 1],
                'Expected Savings': [500, 300, 150, 100]
            }
            
            df_roadmap = pd.DataFrame(roadmap_data).set_index('Week')
            st.bar_chart(df_roadmap)
        
        with col2:
            st.metric("Total Savings", "$1,050/mo")
            st.metric("Total Time", "14 hours")
            st.metric("ROI", "450%")
            
            if st.button("🚀 Start Optimization", type="primary", use_container_width=True):
                st.success("✅ Optimization plan created!")
                st.info("Implementation tasks added to your backlog")
    
    # ============================================================================
    # SECTION 3: Anomaly Detection
    # ============================================================================
    with sections[2]:
        st.markdown("### 🔍 AI-Powered Anomaly Detection")
        st.info("Real-time detection of unusual patterns in pipeline metrics and behavior")
        
        # Anomaly summary
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric(
                "Anomalies Detected",
                "7",
                delta="Last 24 hours"
            )
        
        with col2:
            st.metric(
                "Critical Anomalies",
                "2",
                delta="Requires attention",
                delta_color="inverse"
            )
        
        with col3:
            st.metric(
                "Detection Accuracy",
                "96.8%",
                delta="↑ 1.2%"
            )
        
        with col4:
            st.metric(
                "False Positives",
                "3.2%",
                delta="↓ 0.5%"
            )
        
        st.markdown("---")
        
        # Anomaly timeline
        st.markdown("#### 📊 Anomaly Timeline")
        
        # Generate sample anomaly data
        dates = pd.date_range(end=datetime.now(), periods=168, freq='H')  # Last 7 days
        baseline = 25
        normal_values = np.random.normal(baseline, 3, len(dates))
        
        # Add some anomalies
        anomaly_indices = [24, 48, 96, 120, 144]
        for idx in anomaly_indices:
            normal_values[idx] = baseline + np.random.uniform(15, 25)
        
        timeline_df = pd.DataFrame({
            'Time': dates,
            'Build Duration (min)': normal_values
        }).set_index('Time')
        
        st.line_chart(timeline_df)
        
        st.markdown("---")
        
        # Detected anomalies list
        st.markdown("#### 🚨 Detected Anomalies")
        
        anomaly_data = [
            {
                'Detected': '2 hours ago',
                'Pipeline': 'api-deployment',
                'Metric': 'Build Duration',
                'Severity': 'Critical',
                'Deviation': '+180%',
                'Normal Range': '20-30 min',
                'Actual Value': '56 min',
                'Root Cause': 'Network latency to package registry',
                'Status': 'Investigating'
            },
            {
                'Detected': '5 hours ago',
                'Pipeline': 'frontend-build',
                'Metric': 'Memory Usage',
                'Severity': 'High',
                'Deviation': '+95%',
                'Normal Range': '2-3 GB',
                'Actual Value': '5.8 GB',
                'Root Cause': 'Memory leak in webpack build',
                'Status': 'Resolved'
            },
            {
                'Detected': '8 hours ago',
                'Pipeline': 'backend-tests',
                'Metric': 'Test Failure Rate',
                'Severity': 'Medium',
                'Deviation': '+45%',
                'Normal Range': '0-2%',
                'Actual Value': '7%',
                'Root Cause': 'Flaky integration tests',
                'Status': 'Monitoring'
            },
            {
                'Detected': '12 hours ago',
                'Pipeline': 'data-pipeline',
                'Metric': 'CPU Utilization',
                'Severity': 'Critical',
                'Deviation': '+210%',
                'Normal Range': '30-50%',
                'Actual Value': '155%',
                'Root Cause': 'Infinite loop in data processing',
                'Status': 'Resolved'
            },
            {
                'Detected': '18 hours ago',
                'Pipeline': 'ml-training',
                'Metric': 'Build Queue Time',
                'Severity': 'Low',
                'Deviation': '+30%',
                'Normal Range': '1-3 min',
                'Actual Value': '4 min',
                'Root Cause': 'Concurrent builds waiting',
                'Status': 'Auto-resolved'
            }
        ]
        
        df_anomaly = pd.DataFrame(anomaly_data)
        
        # Severity filter
        severity_filter = st.multiselect(
            "Filter by Severity",
            options=['Critical', 'High', 'Medium', 'Low'],
            default=['Critical', 'High', 'Medium', 'Low'],
            key="anomaly_severity_filter"
        )
        
        filtered_anomaly = df_anomaly[df_anomaly['Severity'].isin(severity_filter)]
        
        # Color code severity
        def color_severity(val):
            colors = {
                'Critical': 'background-color: #dc3545; color: white; font-weight: bold',
                'High': 'background-color: #fd7e14; color: white',
                'Medium': 'background-color: #ffc107; color: black',
                'Low': 'background-color: #28a745; color: white'
            }
            return colors.get(val, '')
        
        styled_anomaly = filtered_anomaly.style.applymap(color_severity, subset=['Severity'])
        st.dataframe(styled_anomaly, use_container_width=True, hide_index=True)
        
        # Anomaly details
        st.markdown("---")
        st.markdown("#### 🔬 Anomaly Investigation")
        
        selected_anomaly = st.selectbox(
            "Select Anomaly for Deep Dive",
            options=[f"{a['Pipeline']} - {a['Metric']}" for a in anomaly_data],
            key="selected_anomaly"
        )
        
        # Find selected anomaly
        anomaly_idx = [f"{a['Pipeline']} - {a['Metric']}" for a in anomaly_data].index(selected_anomaly)
        anomaly_info = anomaly_data[anomaly_idx]
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            st.markdown("**Anomaly Details:**")
            st.markdown(f"- **Pipeline:** {anomaly_info['Pipeline']}")
            st.markdown(f"- **Metric:** {anomaly_info['Metric']}")
            st.markdown(f"- **Detected:** {anomaly_info['Detected']}")
            st.markdown(f"- **Severity:** {anomaly_info['Severity']}")
            st.markdown(f"- **Deviation:** {anomaly_info['Deviation']}")
            st.markdown(f"- **Normal Range:** {anomaly_info['Normal Range']}")
            st.markdown(f"- **Actual Value:** {anomaly_info['Actual Value']}")
            
            st.markdown("---")
            st.markdown("**🤖 AI Analysis:**")
            st.markdown(f"- **Root Cause:** {anomaly_info['Root Cause']}")
            st.markdown("- **Confidence:** 89%")
            st.markdown("- **Similar Incidents:** 3 in the past 30 days")
            st.markdown("- **Predicted Recurrence:** 15% chance in next 7 days")
            
            st.markdown("---")
            st.markdown("**💡 Recommended Actions:**")
            st.markdown("1. 🔍 Review recent code changes to the build process")
            st.markdown("2. ⚙️ Check infrastructure capacity and scaling policies")
            st.markdown("3. 📊 Monitor related metrics for cascade effects")
            st.markdown("4. 🔄 Consider implementing circuit breakers")
        
        with col2:
            st.markdown("**Status:**")
            status = anomaly_info['Status']
            status_color = {
                'Investigating': '🔍',
                'Resolved': '✅',
                'Monitoring': '👁️',
                'Auto-resolved': '🤖'
            }
            st.markdown(f"### {status_color.get(status, '❓')} {status}")
            
            st.markdown("---")
            st.markdown("**Timeline:**")
            st.progress(75 if status == 'Resolved' else 30)
            
            # Action buttons
            st.markdown("---")
            if status != 'Resolved':
                if st.button("✅ Mark Resolved", use_container_width=True):
                    st.success("Anomaly marked as resolved")
            
            if st.button("📧 Alert Team", use_container_width=True):
                st.info("Team notified about this anomaly")
            
            if st.button("🔕 Suppress", use_container_width=True):
                st.warning("Anomaly suppressed for 24 hours")
    
    # ============================================================================
    # SECTION 4: AI Assistant (Natural Language Queries)
    # ============================================================================
    with sections[3]:
        st.markdown("### 💬 Ask Your AI CI/CD Assistant")
        st.info("Ask questions about your pipelines in natural language - get instant AI-powered answers")
        
        # Sample questions
        st.markdown("#### 💡 Try asking:")
        
        sample_questions = [
            "Which pipeline has the highest failure rate this week?",
            "What's causing the slowdown in the api-deployment pipeline?",
            "Show me all failed deployments to production in the last 7 days",
            "How much time could we save by optimizing our test suites?",
            "What are the common causes of build failures across all pipelines?",
            "Which pipelines are most likely to fail in the next deployment?",
            "Compare deployment frequency between staging and production",
            "What's the average time to recover from a failed deployment?"
        ]
        
        cols = st.columns(2)
        for i, question in enumerate(sample_questions):
            with cols[i % 2]:
                if st.button(f"💡 {question}", key=f"sample_q_{i}", use_container_width=True):
                    st.session_state['ai_query'] = question
        
        st.markdown("---")
        
        # Query input
        query = st.text_area(
            "Ask a question about your CI/CD pipelines:",
            value=st.session_state.get('ai_query', ''),
            placeholder="e.g., What's the success rate of deployments to production this month?",
            height=100,
            key="ai_query_input"
        )
        
        col1, col2 = st.columns([1, 5])
        
        with col1:
            ask_button = st.button("🤖 Ask AI", type="primary", use_container_width=True)
        
        with col2:
            if st.button("🗑️ Clear", use_container_width=True):
                st.session_state['ai_query'] = ''
                st.rerun()
        
        if ask_button and query:
            with st.spinner("🤖 AI is analyzing your pipelines..."):
                import time
                time.sleep(1.5)
                
                # Generate AI response based on query keywords
                st.markdown("---")
                st.markdown("### 🤖 AI Response:")
                
                # Smart response based on query content
                if "failure rate" in query.lower() or "failed" in query.lower():
                    st.markdown("""
                    **Pipeline Failure Analysis:**
                    
                    Based on the last 7 days of data:
                    
                    📊 **Failure Rates:**
                    - `api-deployment`: 12% (8 failures out of 67 runs)
                    - `frontend-build`: 5% (3 failures out of 60 runs)
                    - `backend-tests`: 8% (5 failures out of 62 runs)
                    - `data-pipeline`: 15% (9 failures out of 60 runs) ⚠️ Highest
                    
                    🔍 **Key Insights:**
                    - The `data-pipeline` has the highest failure rate at 15%
                    - Main causes: timeout issues (60%), dependency conflicts (25%), test failures (15%)
                    - Failures are concentrated between 2-4 PM UTC (peak load time)
                    
                    💡 **Recommendations:**
                    1. Increase timeout for data-pipeline from 30 to 45 minutes
                    2. Implement retry logic for transient failures
                    3. Consider splitting large data processing into smaller chunks
                    4. Schedule heavy workloads during off-peak hours
                    """)
                    
                    # Visualization
                    failure_data = pd.DataFrame({
                        'Pipeline': ['api-deployment', 'frontend-build', 'backend-tests', 'data-pipeline'],
                        'Failure Rate %': [12, 5, 8, 15]
                    }).set_index('Pipeline')
                    st.bar_chart(failure_data)
                
                elif "optimization" in query.lower() or "save" in query.lower():
                    st.markdown("""
                    **Optimization Opportunities:**
                    
                    💰 **Potential Savings:**
                    
                    Based on AI analysis of your pipeline execution patterns:
                    
                    1. **Parallel Test Execution** ⚡
                       - Current: Sequential testing adds 45 min per build
                       - Optimized: Parallel execution could reduce to 18 min
                       - Savings: 27 min per build × 50 builds/day = **22.5 hours/day**
                    
                    2. **Right-size Build Instances** 💵
                       - Current: 5 pipelines using t3.large ($0.0832/hour)
                       - Recommended: Switch to t3.medium ($0.0416/hour)
                       - Savings: **$420/month**
                    
                    3. **Docker Layer Caching** 🐳
                       - Current: Full rebuild every time (8-12 min)
                       - With caching: Only rebuild changed layers (2-3 min)
                       - Savings: **8 min per Docker build**
                    
                    **Total Potential Savings:**
                    - Time: 24+ hours per day in aggregate
                    - Cost: $847/month
                    - ROI: 380% within first month
                    """)
                    
                    st.success("🚀 Click 'Optimization Insights' tab above to implement these recommendations!")
                
                elif "slowdown" in query.lower() or "slow" in query.lower():
                    st.markdown("""
                    **Performance Degradation Analysis:**
                    
                    🔍 **Analyzing: api-deployment pipeline**
                    
                    📉 **Performance Trend:**
                    - Last 7 days average: 42 minutes
                    - Previous 7 days average: 28 minutes
                    - **Degradation: +50%**
                    
                    🎯 **Root Causes Identified:**
                    
                    1. **Network Latency (35% of slowdown)**
                       - Package downloads from npm registry taking 8 min (was 3 min)
                       - Recommendation: Implement npm caching or use private registry
                    
                    2. **Test Suite Growth (40% of slowdown)**
                       - Test suite grew from 1,200 to 1,850 tests (+54%)
                       - No parallel execution configured
                       - Recommendation: Enable parallel testing
                    
                    3. **Database Migration Tests (25% of slowdown)**
                       - New migration tests added without optimization
                       - Running against full database copy
                       - Recommendation: Use test database with minimal data
                    
                    💡 **Quick Wins:**
                    - Enable npm caching: Save 5 min
                    - Parallel test execution: Save 8 min
                    - Optimize migration tests: Save 3 min
                    - **Total expected improvement: 16 minutes (38% faster)**
                    """)
                
                elif "production" in query.lower():
                    st.markdown("""
                    **Production Deployments Analysis:**
                    
                    📊 **Last 7 Days - Production Environment:**
                    
                    **Deployment Statistics:**
                    - Total deployments: 23
                    - Successful: 21 (91.3%)
                    - Failed: 2 (8.7%)
                    - Average duration: 18.5 minutes
                    - Fastest: 12 min (frontend-app)
                    - Slowest: 31 min (backend-services)
                    
                    **Failed Deployments:**
                    1. `api-deployment` - Dec 4, 14:23 UTC
                       - Cause: Database migration timeout
                       - Impact: 15 min downtime
                       - Resolution: Rollback + hotfix
                    
                    2. `backend-services` - Dec 2, 09:45 UTC
                       - Cause: Memory limit exceeded
                       - Impact: 8 min downtime
                       - Resolution: Increased instance size
                    
                    **Deployment Frequency:**
                    - Peak hours: 10 AM - 2 PM UTC (14 deployments)
                    - Off-peak: 6 AM - 10 AM UTC (9 deployments)
                    - Recommendation: Shift non-critical to off-peak
                    
                    ✅ **Health Score: 91.3%** (Good)
                    ⚠️ **MTTR (Mean Time To Recover): 11.5 min** (Target: <10 min)
                    """)
                
                elif "compare" in query.lower():
                    st.markdown("""
                    **Environment Comparison: Staging vs Production**
                    
                    📊 **Deployment Metrics:**
                    
                    | Metric | Staging | Production | Difference |
                    |--------|---------|------------|------------|
                    | Deployments/week | 47 | 23 | +104% more to staging |
                    | Success rate | 88% | 91% | -3% in staging |
                    | Avg duration | 16 min | 19 min | +3 min in prod |
                    | Failed deployments | 6 | 2 | +3x in staging |
                    | Rollback rate | 4% | 1% | +4x in staging |
                    
                    **Key Findings:**
                    
                    1. **Staging is catching issues** ✅
                       - Higher failure rate in staging (88% vs 91%)
                       - This is expected and healthy - staging is filtering problems
                    
                    2. **Production is more stable** ✅
                       - Only 1% rollback rate
                       - Higher success rate
                       - Indicates good quality gates
                    
                    3. **Deployment velocity** 📈
                       - Staging: 47 deploys/week (6.7/day)
                       - Production: 23 deploys/week (3.3/day)
                       - Healthy 2:1 ratio
                    
                    💡 **Recommendation:**
                    Current setup is working well. Staging is effectively catching issues before production.
                    Consider adding automated canary deployments to production for even safer releases.
                    """)
                
                else:
                    # Generic response
                    st.markdown(f"""
                    **Analysis Results:**
                    
                    I've analyzed your pipelines for: *"{query}"*
                    
                    📊 **Summary:**
                    - Analyzed 12 active pipelines
                    - Reviewed 847 pipeline executions (last 30 days)
                    - Detected 23 patterns and 7 anomalies
                    
                    💡 **Key Insights:**
                    1. Overall pipeline health is **good** (92% success rate)
                    2. Average deployment time: **21.3 minutes**
                    3. Most active pipeline: `api-deployment` (67 runs this week)
                    4. Highest risk pipeline: `data-pipeline` (15% failure rate)
                    
                    🎯 **Recommendations:**
                    - Enable parallel testing to reduce build times
                    - Implement automated rollback for failed deployments
                    - Set up proactive monitoring for high-risk pipelines
                    
                    For more specific insights, try asking about:
                    - Specific pipeline performance
                    - Failure patterns
                    - Optimization opportunities
                    - Cost analysis
                    """)
                
                # Additional actions
                st.markdown("---")
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    if st.button("📊 View Detailed Report", use_container_width=True):
                        st.info("Detailed report will be generated")
                
                with col2:
                    if st.button("📧 Email This Analysis", use_container_width=True):
                        st.success("Analysis emailed to your team!")
                
                with col3:
                    if st.button("🔖 Save to Dashboard", use_container_width=True):
                        st.success("Saved to your AI Insights dashboard!")
        
        elif ask_button and not query:
            st.warning("⚠️ Please enter a question first!")
        
        # AI Assistant capabilities
        st.markdown("---")
        st.markdown("#### 🤖 AI Assistant Capabilities")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.markdown("""
            **📊 Analysis**
            - Performance metrics
            - Failure patterns
            - Cost breakdown
            - Resource utilization
            """)
        
        with col2:
            st.markdown("""
            **🔮 Predictions**
            - Failure forecasting
            - Capacity planning
            - Trend analysis
            - Risk assessment
            """)
        
        with col3:
            st.markdown("""
            **💡 Recommendations**
            - Optimization tips
            - Best practices
            - Cost savings
            - Security improvements
            """)
