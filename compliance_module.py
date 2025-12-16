"""
Compliance Module - Full WAF-to-Compliance Integration
Provides comprehensive compliance assessment based on WAF results
"""

import streamlit as st
from compliance import (
    get_all_mappings,
    get_framework_requirements,
    assess_compliance_status,
    identify_multi_framework_gaps,
    get_waf_question_compliance_impact,
    generate_compliance_report
)
from datetime import datetime

class ComplianceModule:
    """Comprehensive compliance assessment module"""
    
    @staticmethod
    def render():
        """Render compliance module with full WAF integration"""
        
        st.markdown("### 🔒 Compliance Framework Assessment")
        
        st.info("""
        **How This Works:**
        
        This module maps your WAF assessment results to compliance requirements:
        - ✅ **Green**: WAF controls satisfy compliance requirements
        - 🟡 **Yellow**: Partial compliance - some controls missing  
        - 🔴 **Red**: Gap - compliance requirement not met
        
        **Your WAF assessment serves as evidence for compliance!**
        """)
        
        # Check if WAF assessment has been completed
        waf_results = get_mock_waf_results()  # Replace with actual WAF results
        
        if not waf_results:
            st.warning("⚠️ Complete a WAF assessment first to see compliance status")
            
            with st.expander("📋 What You'll Get"):
                st.markdown("""
                Once you complete the WAF assessment, you'll see:
                
                **📊 Compliance Dashboard**
                - Overall compliance percentage for each framework
                - Number of requirements met/partial/gaps
                - Heat map showing WAF pillar coverage
                
                **🎯 Framework Details**
                - Detailed view of each compliance requirement
                - WAF questions that provide evidence
                - Current compliance status
                - Gap identification and remediation steps
                
                **🔗 WAF-to-Compliance Mapping**
                - See which compliance requirements each WAF question affects
                - Understand impact of WAF gaps on compliance
                - Prioritize fixes based on compliance needs
                
                **📋 Gap Analysis**
                - High-priority gaps affecting multiple frameworks
                - Effort vs impact assessment
                - Remediation roadmap
                
                **📄 Evidence Reports**
                - Generate compliance evidence packages
                - Export for auditors
                - PDF/Excel/CSV formats
                """)
            return
        
        # Main tabs
        tab1, tab2, tab3, tab4, tab5 = st.tabs([
            "📊 Dashboard",
            "🎯 Framework Details",
            "🔗 WAF Mapping",
            "📋 Gap Analysis",
            "📄 Reports"
        ])
        
        with tab1:
            ComplianceModule.render_dashboard(waf_results)
        
        with tab2:
            ComplianceModule.render_framework_details(waf_results)
        
        with tab3:
            ComplianceModule.render_waf_mapping(waf_results)
        
        with tab4:
            ComplianceModule.render_gap_analysis(waf_results)
        
        with tab5:
            ComplianceModule.render_reports(waf_results)
    
    @staticmethod
    def render_dashboard(waf_results):
        """Render compliance overview dashboard"""
        
        st.markdown("#### 📊 Compliance Overview")
        
        # Framework selection
        frameworks = ['PCI-DSS v4.0', 'HIPAA', 'SOC 2', 'ISO 27001:2022']
        selected_frameworks = st.multiselect(
            "Select Frameworks to Assess",
            frameworks,
            default=frameworks,
            help="Choose which frameworks to evaluate"
        )
        
        if not selected_frameworks:
            st.warning("Select at least one framework")
            return
        
        # Calculate compliance for each framework
        st.markdown("---")
        
        cols = st.columns(len(selected_frameworks))
        
        compliance_data = {}
        
        for idx, framework in enumerate(selected_frameworks):
            status = assess_compliance_status(framework, waf_results)
            compliance_data[framework] = status
            
            with cols[idx]:
                pct = status['compliance_percentage']
                
                if pct >= 90:
                    status_emoji = "🟢"
                elif pct >= 70:
                    status_emoji = "🟡"
                else:
                    status_emoji = "🔴"
                
                st.metric(
                    label=f"{status_emoji} {framework}",
                    value=f"{pct:.0f}%",
                    delta=f"{status['met']}/{status['total']}"
                )
                
                with st.expander("Details"):
                    st.markdown(f"""
                    **Total Requirements:** {status['total']}
                    
                    ✅ **Met:** {status['met']} ({status['met']/status['total']*100:.0f}%)
                    🟡 **Partial:** {status['partial']} ({status['partial']/status['total']*100:.0f}%)
                    🔴 **Gaps:** {status['gaps']} ({status['gaps']/status['total']*100:.0f}%)
                    """)
        
        # Heat map
        st.markdown("---")
        st.markdown("#### 🗺️ WAF Pillar Coverage by Framework")
        
        import pandas as pd
        
        pillars = ['Security', 'Ops Excellence', 'Reliability', 'Performance', 'Cost Opt']
        heat_data = {
            'Pillar': pillars,
        }
        
        for framework in selected_frameworks:
            # Mock data - replace with actual calculation
            heat_data[framework] = [95, 80, 75, 50, 40]
        
        df = pd.DataFrame(heat_data)
        st.dataframe(df, use_container_width=True, hide_index=True)
        
        # Priority gaps
        st.markdown("---")
        st.markdown("#### 🎯 High-Priority Gaps (Multiple Frameworks)")
        
        gaps = identify_multi_framework_gaps(waf_results)
        high_priority = [g for g in gaps if g.priority == 'high'][:5]
        
        if high_priority:
            for idx, gap in enumerate(high_priority):
                with st.expander(f"🔴 #{idx+1}: {gap.title} - Affects {len(gap.frameworks)} frameworks"):
                    st.markdown(f"**Frameworks:** {', '.join(gap.frameworks)}")
                    st.markdown(f"**Impact:** {gap.impact} | **Effort:** {gap.effort}")
                    
                    st.markdown("**Requirements Not Met:**")
                    for req in gap.requirements:
                        st.markdown(f"- **{req['framework']} {req['id']}:** {req['title']}")
        else:
            st.success("✅ No high-priority multi-framework gaps!")
    
    @staticmethod
    def render_framework_details(waf_results):
        """Render detailed view of specific framework"""
        
        st.markdown("#### 🎯 Framework Detailed Assessment")
        
        framework = st.selectbox(
            "Select Framework",
            ['PCI-DSS v4.0', 'HIPAA', 'SOC 2', 'ISO 27001:2022']
        )
        
        status = assess_compliance_status(framework, waf_results)
        
        # Summary metrics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Requirements", status['total'])
        with col2:
            st.metric("Met", status['met'], delta=f"{status['met']/status['total']*100:.0f}%")
        with col3:
            st.metric("Partial", status['partial'])
        with col4:
            st.metric("Gaps", status['gaps'], delta=f"-{status['gaps']/status['total']*100:.0f}%", delta_color="inverse")
        
        st.markdown("---")
        
        # Filter
        status_filter = st.selectbox(
            "Filter by Status",
            ["All", "Gaps Only", "Met", "Partially Met"]
        )
        
        # Display requirements
        for req_id, req_data in status['requirement_status'].items():
            req = req_data['requirement']
            req_status = req_data['status']
            
            # Apply filter
            if status_filter == "Gaps Only" and req_status != 'gap':
                continue
            elif status_filter == "Met" and req_status != 'met':
                continue
            elif status_filter == "Partially Met" and req_status != 'partial':
                continue
            
            status_icon = {
                'met': '✅',
                'partial': '🟡',
                'gap': '🔴',
                'unknown': '❓'
            }[req_status]
            
            with st.expander(f"{status_icon} {req.id}: {req.title}"):
                st.markdown(f"**Description:** {req.description}")
                st.markdown(f"**Priority:** {req.priority.upper()}")
                st.markdown(f"**Category:** {req.category}")
                
                st.markdown("---")
                st.markdown("**Evidence from WAF Assessment:**")
                
                for waf_q in req.waf_questions:
                    waf_result = req_data['waf_results'].get(waf_q, {})
                    compliant = waf_result.get('compliant', False)
                    q_icon = "✅" if compliant else "❌"
                    
                    st.markdown(f"{q_icon} **{waf_q}:** {waf_result.get('question', waf_q)}")
                    if not compliant:
                        st.caption(f"   Current: {waf_result.get('answer', 'Not assessed')}")
                
                if req_status == 'gap':
                    st.markdown("---")
                    st.error("**Gap:** This requirement is not satisfied")
                    
                    if st.button(f"📋 View Remediation", key=f"rem_{req_id}"):
                        st.info("Remediation steps will be shown here")
                
                elif req_status == 'met':
                    st.markdown("---")
                    st.success("✅ This requirement is fully satisfied")
    
    @staticmethod
    def render_waf_mapping(waf_results):
        """Show WAF to compliance mapping"""
        
        st.markdown("#### 🔗 WAF-to-Compliance Mapping")
        
        st.info("""
        Select a WAF question to see which compliance requirements it affects.
        This helps you understand the compliance impact of fixing WAF gaps.
        """)
        
        # Mock WAF questions - replace with actual
        waf_questions = {
            'SEC-IAM-04': 'Do you use MFA for privileged access?',
            'SEC-IAM-05': 'Is MFA enforced for console access?',
            'SEC-ENC-01': 'Is encryption at rest enabled for S3?',
            'SEC-ENC-02': 'Is encryption at rest enabled for EBS?',
            'SEC-LOG-01': 'Is CloudTrail enabled in all regions?',
            'SEC-LOG-02': 'Is CloudWatch logging configured?',
        }
        
        selected_q = st.selectbox(
            "Select WAF Question",
            list(waf_questions.keys()),
            format_func=lambda x: f"{x}: {waf_questions[x]}"
        )
        
        if selected_q:
            impact = get_waf_question_compliance_impact(selected_q)
            
            st.markdown("---")
            
            col1, col2 = st.columns([2, 1])
            
            with col1:
                st.markdown(f"**Question:** {waf_questions[selected_q]}")
                result = waf_results.get(selected_q, {})
                compliant = result.get('compliant', False)
                st.markdown(f"**Status:** {'✅ Compliant' if compliant else '❌ Non-compliant'}")
            
            with col2:
                st.metric("Affects Requirements", len(impact['requirements_affected']))
            
            st.markdown("---")
            st.markdown("**This WAF question provides evidence for:**")
            
            frameworks = list(set([r['framework'] for r in impact['requirements_affected']]))
            
            for framework in frameworks:
                reqs = [r for r in impact['requirements_affected'] if r['framework'] == framework]
                
                with st.expander(f"📋 {framework} ({len(reqs)} requirements)"):
                    for req in reqs:
                        status = "✅" if compliant else "❌"
                        st.markdown(f"{status} **{req['id']}:** {req['title']}")
                        st.caption(f"   {req['description']}")
                        st.markdown("")
    
    @staticmethod
    def render_gap_analysis(waf_results):
        """Render gap analysis"""
        
        st.markdown("#### 📋 Compliance Gap Analysis")
        
        st.info("""
        Gaps prioritized by:
        - Number of frameworks affected
        - Criticality of requirement
        - Implementation effort
        """)
        
        gaps = identify_multi_framework_gaps(waf_results)
        
        tab1, tab2, tab3 = st.tabs(["🔴 High Priority", "🟡 Medium Priority", "🟢 Low Priority"])
        
        with tab1:
            high = [g for g in gaps if g.priority == 'high']
            st.markdown(f"**{len(high)} high-priority gaps** (affect 3+ frameworks)")
            
            for idx, gap in enumerate(high):
                with st.expander(f"#{idx+1}: {gap.title}"):
                    st.markdown(f"**Frameworks:** {', '.join(gap.frameworks)}")
                    st.markdown(f"**Impact:** {gap.impact} | **Effort:** {gap.effort}")
                    st.markdown(f"**Risk:** {gap.risk_level}")
                    
                    st.markdown("**Requirements:**")
                    for req in gap.requirements:
                        st.markdown(f"- {req['framework']} {req['id']}: {req['title']}")
        
        with tab2:
            medium = [g for g in gaps if g.priority == 'medium']
            st.markdown(f"**{len(medium)} medium-priority gaps**")
            
            for idx, gap in enumerate(medium):
                with st.expander(f"#{idx+1}: {gap.title}"):
                    st.markdown(f"**Frameworks:** {', '.join(gap.frameworks)}")
                    st.markdown(f"**Impact:** {gap.impact} | **Effort:** {gap.effort}")
        
        with tab3:
            low = [g for g in gaps if g.priority == 'low']
            st.markdown(f"**{len(low)} low-priority gaps**")
            
            for idx, gap in enumerate(low):
                with st.expander(f"#{idx+1}: {gap.title}"):
                    st.markdown(f"**Frameworks:** {', '.join(gap.frameworks)}")
    
    @staticmethod
    def render_reports(waf_results):
        """Render report generation"""
        
        st.markdown("#### 📄 Compliance Evidence Reports")
        
        st.info("""
        Generate comprehensive evidence packages showing:
        - Compliance requirements
        - WAF assessment evidence
        - Control implementation status
        - Gaps and remediation plans
        """)
        
        col1, col2 = st.columns(2)
        
        with col1:
            framework = st.selectbox(
                "Select Framework",
                ["All Frameworks", "PCI-DSS v4.0", "HIPAA", "SOC 2", "ISO 27001:2022"]
            )
        
        with col2:
            report_type = st.selectbox(
                "Report Type",
                ["Full Evidence Package", "Gaps Only", "Met Controls Only", "Executive Summary"]
            )
        
        if st.button("🎯 Generate Report", type="primary"):
            with st.spinner("Generating report..."):
                if framework == "All Frameworks":
                    report_text = "Combined report for all frameworks\n\n"
                    for fw in ['PCI-DSS v4.0', 'HIPAA', 'SOC 2', 'ISO 27001:2022']:
                        status = assess_compliance_status(fw, waf_results)
                        report_text += generate_compliance_report(fw, status)
                        report_text += "\n" + "="*80 + "\n\n"
                else:
                    status = assess_compliance_status(framework, waf_results)
                    report_text = generate_compliance_report(framework, status)
                
                st.success("✅ Report generated!")
                
                st.download_button(
                    label="📥 Download Report",
                    data=report_text,
                    file_name=f"compliance_report_{framework.replace(' ', '_')}_{datetime.now().strftime('%Y%m%d')}.txt",
                    mime="text/plain"
                )
                
                with st.expander("📄 Preview Report"):
                    st.text(report_text)


def get_mock_waf_results():
    """Get mock WAF results for demonstration"""
    # This should be replaced with actual WAF assessment results
    return {
        'SEC-IAM-01': {'compliant': True, 'question': 'Do you use least privilege access?'},
        'SEC-IAM-02': {'compliant': True, 'question': 'Do you use role-based access control?'},
        'SEC-IAM-03': {'compliant': True, 'question': 'Do you regularly review access permissions?'},
        'SEC-IAM-04': {'compliant': False, 'question': 'Do you use MFA for privileged access?', 'answer': 'No'},
        'SEC-IAM-05': {'compliant': False, 'question': 'Is MFA enforced for console access?', 'answer': 'Partial'},
        'SEC-ENC-01': {'compliant': True, 'question': 'Is encryption at rest enabled for S3?'},
        'SEC-ENC-02': {'compliant': False, 'question': 'Is encryption at rest enabled for EBS?', 'answer': 'No'},
        'SEC-ENC-03': {'compliant': True, 'question': 'Is TLS 1.2+ enforced?'},
        'SEC-LOG-01': {'compliant': True, 'question': 'Is CloudTrail enabled in all regions?'},
        'SEC-LOG-02': {'compliant': True, 'question': 'Is CloudWatch logging configured?'},
        'SEC-LOG-03': {'compliant': False, 'question': 'Is log retention configured?', 'answer': 'No'},
        'SEC-DATA-01': {'compliant': True, 'question': 'Is data classified?'},
        'SEC-DATA-02': {'compliant': True, 'question': 'Is sensitive data tagged?'},
        'SEC-DETECT-01': {'compliant': True, 'question': 'Is GuardDuty enabled?'},
        'SEC-IR-01': {'compliant': True, 'question': 'Is incident response plan documented?'},
        'SEC-IR-02': {'compliant': True, 'question': 'Are IR procedures tested?'},
        'SEC-IR-03': {'compliant': True, 'question': 'Is IR team identified?'},
        'SEC-VPC-01': {'compliant': True, 'question': 'Is network segmentation implemented?'},
        'SEC-VPC-02': {'compliant': True, 'question': 'Are security groups configured?'},
        'SEC-VPC-03': {'compliant': True, 'question': 'Is VPC Flow Logs enabled?'},
        'SEC-POLICY-01': {'compliant': True, 'question': 'Are security policies documented?'},
        'OPS-01': {'compliant': True, 'question': 'Are operational procedures documented?'},
        'OPS-02': {'compliant': True, 'question': 'Is change management implemented?'},
        'OPS-POLICY-01': {'compliant': True, 'question': 'Are policies approved by management?'},
        'REL-BC-01': {'compliant': True, 'question': 'Is backup configured?'},
        'REL-BC-02': {'compliant': True, 'question': 'Is backup tested?'},
        'REL-HA-01': {'compliant': True, 'question': 'Is high availability configured?'},
    }

