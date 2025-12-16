"""
Migration & Disaster Recovery Module
Comprehensive Cloud Migration and DR Planning Platform

Features:
- 7Rs Migration Strategy Assessment
- Application Portfolio Analysis
- DR Pattern Selection
- RTO/RPO Calculator
- Migration Readiness Assessment
- TCO Analysis
"""

import streamlit as st
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass
import json

# ============================================================================
# MIGRATION STRATEGIES (7Rs)
# ============================================================================

MIGRATION_STRATEGIES = {
    "rehost": {
        "name": "Rehost (Lift & Shift)",
        "icon": "🏗️",
        "effort": "Low",
        "risk": "Low",
        "timeline": "Weeks",
        "cost_impact": "Neutral initially",
        "description": "Move applications to cloud without modifications",
        "best_for": [
            "Quick migration timelines",
            "Legacy applications",
            "Applications with complex dependencies",
            "Risk-averse organizations"
        ],
        "aws_services": ["EC2", "EBS", "Application Migration Service", "VM Import/Export"],
        "considerations": [
            "May not leverage cloud-native benefits",
            "Operating costs may be higher than on-premises",
            "Good first step before optimization"
        ],
        "implementation_phases": [
            {"phase": "Discovery", "duration": "1-2 weeks", "activities": ["Application inventory", "Dependency mapping", "Server assessment"]},
            {"phase": "Design", "duration": "1-2 weeks", "activities": ["Target architecture", "Network design", "Security groups"]},
            {"phase": "Migration", "duration": "2-4 weeks", "activities": ["Server replication", "Cutover planning", "Testing"]},
            {"phase": "Cutover", "duration": "1-2 days", "activities": ["Final sync", "DNS updates", "Validation"]}
        ]
    },
    "replatform": {
        "name": "Replatform (Lift & Reshape)",
        "icon": "🔧",
        "effort": "Medium",
        "risk": "Low-Medium",
        "timeline": "Weeks to Months",
        "cost_impact": "Moderate savings",
        "description": "Make targeted cloud optimizations during migration",
        "best_for": [
            "Applications needing minor cloud optimizations",
            "Database migrations to managed services",
            "Containerization candidates"
        ],
        "aws_services": ["RDS", "ElastiCache", "ECS", "Elastic Beanstalk"],
        "considerations": [
            "Balance between speed and optimization",
            "May require some code changes",
            "Good ROI for database migrations"
        ],
        "implementation_phases": [
            {"phase": "Assessment", "duration": "2-3 weeks", "activities": ["Platform evaluation", "Compatibility testing", "Performance baseline"]},
            {"phase": "Migration Design", "duration": "2-3 weeks", "activities": ["Target platform selection", "Schema conversion", "Application changes"]},
            {"phase": "Migration", "duration": "4-8 weeks", "activities": ["Data migration", "Application deployment", "Integration testing"]},
            {"phase": "Optimization", "duration": "2-4 weeks", "activities": ["Performance tuning", "Cost optimization", "Documentation"]}
        ]
    },
    "repurchase": {
        "name": "Repurchase (Drop & Shop)",
        "icon": "🛒",
        "effort": "Low-Medium",
        "risk": "Medium",
        "timeline": "Weeks to Months",
        "cost_impact": "Variable",
        "description": "Move to a different product, typically SaaS",
        "best_for": [
            "Commodity applications (CRM, HR, Email)",
            "Applications with good SaaS alternatives",
            "Reducing operational burden"
        ],
        "aws_services": ["AWS Marketplace", "SaaS integrations"],
        "considerations": [
            "Data migration complexity",
            "Feature gaps in new platform",
            "Change management required",
            "Subscription costs vs ownership"
        ],
        "implementation_phases": [
            {"phase": "Evaluation", "duration": "2-4 weeks", "activities": ["SaaS vendor selection", "Feature comparison", "Cost analysis"]},
            {"phase": "Planning", "duration": "2-3 weeks", "activities": ["Data migration strategy", "Integration design", "Training plan"]},
            {"phase": "Migration", "duration": "4-8 weeks", "activities": ["Data migration", "Configuration", "User training"]},
            {"phase": "Transition", "duration": "2-4 weeks", "activities": ["Parallel running", "Validation", "Cutover"]}
        ]
    },
    "refactor": {
        "name": "Refactor (Re-architect)",
        "icon": "⚙️",
        "effort": "High",
        "risk": "Medium-High",
        "timeline": "Months to Years",
        "cost_impact": "Significant long-term savings",
        "description": "Re-architect for cloud-native capabilities",
        "best_for": [
            "Applications requiring scalability",
            "Microservices transformation",
            "Long-term strategic applications"
        ],
        "aws_services": ["Lambda", "EKS", "DynamoDB", "API Gateway", "Step Functions"],
        "considerations": [
            "Highest investment but best cloud benefits",
            "Requires skilled development team",
            "Consider incremental approach"
        ],
        "implementation_phases": [
            {"phase": "Architecture Design", "duration": "4-8 weeks", "activities": ["Domain modeling", "Service decomposition", "API design"]},
            {"phase": "Foundation", "duration": "4-8 weeks", "activities": ["CI/CD pipeline", "Infrastructure as Code", "Observability"]},
            {"phase": "Incremental Migration", "duration": "3-12 months", "activities": ["Service by service migration", "Strangler fig pattern", "Testing"]},
            {"phase": "Optimization", "duration": "Ongoing", "activities": ["Performance tuning", "Cost optimization", "Feature enhancement"]}
        ]
    },
    "retire": {
        "name": "Retire",
        "icon": "🗑️",
        "effort": "Low",
        "risk": "Low",
        "timeline": "Weeks",
        "cost_impact": "Cost elimination",
        "description": "Decommission applications no longer needed",
        "best_for": [
            "Redundant applications",
            "Applications with better alternatives",
            "End-of-life systems"
        ],
        "aws_services": ["N/A - Decommission process"],
        "considerations": [
            "Verify no hidden dependencies",
            "Archive data for compliance",
            "Update integrations"
        ],
        "implementation_phases": [
            {"phase": "Assessment", "duration": "1-2 weeks", "activities": ["Usage analysis", "Dependency verification", "Data requirements"]},
            {"phase": "Planning", "duration": "1-2 weeks", "activities": ["Data archival plan", "Stakeholder communication", "Timeline"]},
            {"phase": "Decommission", "duration": "1-4 weeks", "activities": ["Data archival", "System shutdown", "Documentation"]}
        ]
    },
    "retain": {
        "name": "Retain (Revisit)",
        "icon": "📌",
        "effort": "None",
        "risk": "Low",
        "timeline": "N/A",
        "cost_impact": "Status quo",
        "description": "Keep applications on-premises for now",
        "best_for": [
            "Recently upgraded applications",
            "Compliance restrictions",
            "Applications requiring further assessment"
        ],
        "aws_services": ["Outposts (hybrid)", "Direct Connect"],
        "considerations": [
            "Document reasons for retention",
            "Reassess periodically",
            "Consider hybrid options"
        ],
        "implementation_phases": [
            {"phase": "Documentation", "duration": "1 week", "activities": ["Document retention reasons", "Define reassessment timeline"]},
            {"phase": "Hybrid Options", "duration": "As needed", "activities": ["Evaluate AWS Outposts", "Consider hybrid connectivity"]}
        ]
    },
    "relocate": {
        "name": "Relocate (Hypervisor-level)",
        "icon": "🚚",
        "effort": "Low",
        "risk": "Low",
        "timeline": "Days to Weeks",
        "cost_impact": "Minimal change",
        "description": "Move VMware workloads to VMware Cloud on AWS",
        "best_for": [
            "VMware environments",
            "Rapid data center exit",
            "Maintaining VMware investments"
        ],
        "aws_services": ["VMware Cloud on AWS", "VMware HCX"],
        "considerations": [
            "Requires VMware Cloud on AWS subscription",
            "Good for VMware-skilled teams",
            "Can be stepping stone to native AWS"
        ],
        "implementation_phases": [
            {"phase": "Setup", "duration": "1-2 weeks", "activities": ["VMware Cloud on AWS setup", "Network connectivity", "HCX configuration"]},
            {"phase": "Migration", "duration": "Days to weeks", "activities": ["VM replication", "Cutover", "Validation"]}
        ]
    }
}

# ============================================================================
# DR PATTERNS
# ============================================================================

DR_PATTERNS = {
    "backup_restore": {
        "name": "Backup & Restore",
        "icon": "💾",
        "rto": "24+ hours",
        "rpo": "Hours to 24 hours",
        "cost": "$ (Lowest)",
        "description": "Back up data and restore when disaster occurs",
        "architecture": [
            "Regular backups to S3 with cross-region replication",
            "AMIs copied to DR region",
            "Infrastructure as Code ready to deploy",
            "Restore from backups when needed"
        ],
        "aws_services": ["S3", "AWS Backup", "Glacier", "CloudFormation"],
        "best_for": ["Non-critical workloads", "Cost-sensitive applications", "Development environments"],
        "implementation": [
            "Enable cross-region S3 replication",
            "Create automated backup schedules",
            "Store IaC templates in version control",
            "Regular backup restoration testing"
        ]
    },
    "pilot_light": {
        "name": "Pilot Light",
        "icon": "🔥",
        "rto": "Hours (1-8)",
        "rpo": "Minutes to Hours",
        "cost": "$$ (Low-Moderate)",
        "description": "Core infrastructure running with minimal footprint",
        "architecture": [
            "Database replication to DR region",
            "Core networking always available",
            "Application servers can be started quickly",
            "DNS failover configured"
        ],
        "aws_services": ["RDS Read Replicas", "Route 53", "Auto Scaling", "Lambda"],
        "best_for": ["Business-critical applications", "Moderate recovery requirements"],
        "implementation": [
            "Set up RDS cross-region read replica",
            "Deploy VPC and networking in DR region",
            "Create launch templates for quick scaling",
            "Configure Route 53 health checks and failover"
        ]
    },
    "warm_standby": {
        "name": "Warm Standby",
        "icon": "🌡️",
        "rto": "Minutes to 1 hour",
        "rpo": "Seconds to Minutes",
        "cost": "$$$ (Moderate)",
        "description": "Scaled-down but fully functional environment",
        "architecture": [
            "Minimum viable production in DR region",
            "Continuous database replication",
            "Can scale up quickly when needed",
            "Active monitoring in both regions"
        ],
        "aws_services": ["Aurora Global Database", "ELB", "Auto Scaling", "CloudWatch"],
        "best_for": ["Critical applications", "SLA requirements < 1 hour RTO"],
        "implementation": [
            "Deploy scaled-down production in DR",
            "Enable Aurora Global Database",
            "Configure Auto Scaling for rapid expansion",
            "Set up automated failover procedures"
        ]
    },
    "active_active": {
        "name": "Active-Active (Multi-Site)",
        "icon": "🔄",
        "rto": "Near Zero",
        "rpo": "Near Zero",
        "cost": "$$$$ (Highest)",
        "description": "Full production in multiple regions simultaneously",
        "architecture": [
            "Traffic distributed across regions",
            "Synchronous or near-synchronous data replication",
            "No failover needed - automatic",
            "Global load balancing"
        ],
        "aws_services": ["Global Accelerator", "DynamoDB Global Tables", "Aurora Global Database", "Route 53"],
        "best_for": ["Mission-critical applications", "Zero downtime requirements", "Global user base"],
        "implementation": [
            "Deploy identical production in multiple regions",
            "Implement global data replication strategy",
            "Configure Global Accelerator or Route 53 latency routing",
            "Design for active-active data patterns"
        ]
    }
}

# ============================================================================
# RENDER FUNCTIONS
# ============================================================================

def render_migration_dr_tab():
    """Render comprehensive migration & DR tab"""
    
    st.markdown("""
    <div style="background: linear-gradient(135deg, #bf360c 0%, #e64a19 100%); padding: 2rem; border-radius: 12px; margin-bottom: 1.5rem;">
        <h2 style="color: #FFCCBC; margin: 0;">🔄 Migration & Disaster Recovery</h2>
        <p style="color: #FFAB91; margin: 0.5rem 0 0 0;">Comprehensive Migration Planning & DR Strategy</p>
    </div>
    """, unsafe_allow_html=True)
    
    tabs = st.tabs([
        "🚀 7Rs Assessment",
        "📊 Portfolio Analysis",
        "🛡️ DR Planning",
        "📈 RTO/RPO Calculator",
        "✅ Readiness Assessment"
    ])
    
    with tabs[0]:
        render_7rs_assessment()
    
    with tabs[1]:
        render_portfolio_analysis()
    
    with tabs[2]:
        render_dr_planning()
    
    with tabs[3]:
        render_rto_rpo_calculator()
    
    with tabs[4]:
        render_readiness_assessment()

def render_7rs_assessment():
    """Render 7Rs migration strategy assessment"""
    st.markdown("### 🚀 7Rs Migration Strategy Assessment")
    st.markdown("Evaluate and select the right migration strategy for each application")
    
    # Strategy overview
    st.markdown("#### Migration Strategies Overview")
    
    cols = st.columns(4)
    
    for idx, (key, strategy) in enumerate(MIGRATION_STRATEGIES.items()):
        if idx >= 4:  # Show first 4 in columns
            break
        with cols[idx]:
            st.markdown(f"""
            <div style="text-align: center; padding: 1rem; background: white; border-radius: 8px; margin-bottom: 0.5rem;">
                <div style="font-size: 2rem;">{strategy['icon']}</div>
                <div style="font-weight: bold;">{strategy['name'].split('(')[0]}</div>
                <div style="font-size: 0.8rem; color: #666;">Effort: {strategy['effort']}</div>
            </div>
            """, unsafe_allow_html=True)
    
    # Detailed strategy selection
    st.markdown("---")
    st.markdown("#### 📋 Strategy Details")
    
    selected_strategy = st.selectbox(
        "Select strategy to explore",
        list(MIGRATION_STRATEGIES.keys()),
        format_func=lambda x: f"{MIGRATION_STRATEGIES[x]['icon']} {MIGRATION_STRATEGIES[x]['name']}"
    )
    
    strategy = MIGRATION_STRATEGIES[selected_strategy]
    
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Effort", strategy['effort'])
    with col2:
        st.metric("Risk", strategy['risk'])
    with col3:
        st.metric("Timeline", strategy['timeline'])
    with col4:
        st.metric("Cost Impact", strategy['cost_impact'])
    
    st.markdown(f"**Description:** {strategy['description']}")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("**Best For:**")
        for item in strategy['best_for']:
            st.markdown(f"- {item}")
    
    with col2:
        st.markdown("**AWS Services:**")
        for svc in strategy['aws_services']:
            st.markdown(f"- {svc}")
    
    if strategy.get('considerations'):
        st.markdown("**Considerations:**")
        for item in strategy['considerations']:
            st.markdown(f"- ⚠️ {item}")
    
    # Implementation phases
    if strategy.get('implementation_phases'):
        st.markdown("#### 📅 Implementation Timeline")
        
        for phase in strategy['implementation_phases']:
            with st.expander(f"Phase: {phase['phase']} ({phase['duration']})"):
                for activity in phase['activities']:
                    st.markdown(f"- {activity}")

def render_portfolio_analysis():
    """Render application portfolio analysis"""
    st.markdown("### 📊 Application Portfolio Analysis")
    st.markdown("Analyze your application portfolio and get migration recommendations")
    
    st.info("💡 Enter information about an application to get a migration recommendation")
    
    col1, col2 = st.columns(2)
    
    with col1:
        app_name = st.text_input("Application Name", placeholder="e.g., Customer Portal")
        business_criticality = st.select_slider(
            "Business Criticality",
            options=["Low", "Medium", "High", "Critical"],
            value="Medium"
        )
        current_platform = st.selectbox(
            "Current Platform",
            ["Physical Server", "VMware", "Hyper-V", "Linux VMs", "Windows VMs", "Containers"]
        )
        architecture = st.selectbox(
            "Application Architecture",
            ["Monolithic", "Client-Server", "3-Tier", "Microservices", "Serverless"]
        )
    
    with col2:
        data_sensitivity = st.selectbox(
            "Data Sensitivity",
            ["Public", "Internal", "Confidential", "Highly Confidential"]
        )
        compliance_requirements = st.multiselect(
            "Compliance Requirements",
            ["None", "SOC 2", "HIPAA", "PCI DSS", "GDPR", "FedRAMP"]
        )
        technology_stack = st.multiselect(
            "Technology Stack",
            ["Java", ".NET", "Python", "Node.js", "PHP", "Ruby", "Go", "Legacy (COBOL, etc.)"]
        )
        migration_timeline = st.selectbox(
            "Desired Timeline",
            ["ASAP (< 1 month)", "Short (1-3 months)", "Medium (3-6 months)", "Long (6-12 months)", "Flexible"]
        )
    
    if st.button("🔍 Get Recommendation", type="primary"):
        st.markdown("---")
        st.markdown("### 📋 Migration Recommendation")
        
        # Simple recommendation logic
        if "Legacy" in technology_stack:
            recommended = "replatform"
            reason = "Legacy technology benefits from modernization during migration"
        elif architecture == "Monolithic" and business_criticality in ["High", "Critical"]:
            recommended = "rehost"
            reason = "Critical monolithic apps should migrate quickly, then optimize"
        elif architecture == "Microservices":
            recommended = "refactor"
            reason = "Microservices architecture is ready for cloud-native optimization"
        elif current_platform == "VMware":
            recommended = "relocate"
            reason = "VMware workloads can use VMware Cloud on AWS for rapid migration"
        elif business_criticality == "Low":
            recommended = "retire"
            reason = "Low criticality apps should be evaluated for retirement"
        else:
            recommended = "replatform"
            reason = "Balanced approach with targeted optimizations"
        
        strategy = MIGRATION_STRATEGIES[recommended]
        
        st.success(f"**Recommended Strategy:** {strategy['icon']} {strategy['name']}")
        st.markdown(f"**Reason:** {reason}")
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Expected Effort", strategy['effort'])
        with col2:
            st.metric("Risk Level", strategy['risk'])
        with col3:
            st.metric("Timeline", strategy['timeline'])

def render_dr_planning():
    """Render DR planning section"""
    st.markdown("### 🛡️ Disaster Recovery Planning")
    st.markdown("Select the right DR pattern based on your requirements")
    
    # DR Pattern comparison
    st.markdown("#### DR Pattern Comparison")
    
    comparison_data = []
    for key, pattern in DR_PATTERNS.items():
        comparison_data.append({
            "Pattern": f"{pattern['icon']} {pattern['name']}",
            "RTO": pattern['rto'],
            "RPO": pattern['rpo'],
            "Cost": pattern['cost'],
            "Best For": pattern['best_for'][0]
        })
    
    import pandas as pd
    df = pd.DataFrame(comparison_data)
    st.dataframe(df, use_container_width=True, hide_index=True)
    
    # Detailed pattern selection
    st.markdown("---")
    st.markdown("#### 📋 Pattern Details")
    
    selected_pattern = st.selectbox(
        "Select DR pattern to explore",
        list(DR_PATTERNS.keys()),
        format_func=lambda x: f"{DR_PATTERNS[x]['icon']} {DR_PATTERNS[x]['name']}"
    )
    
    pattern = DR_PATTERNS[selected_pattern]
    
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("RTO", pattern['rto'])
    with col2:
        st.metric("RPO", pattern['rpo'])
    with col3:
        st.metric("Cost", pattern['cost'])
    with col4:
        st.metric("Complexity", {"$": "Low", "$$": "Medium", "$$$": "High", "$$$$": "Very High"}.get(pattern['cost'], "Medium"))
    
    st.markdown(f"**Description:** {pattern['description']}")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("**Architecture:**")
        for item in pattern['architecture']:
            st.markdown(f"- {item}")
    
    with col2:
        st.markdown("**AWS Services:**")
        for svc in pattern['aws_services']:
            st.markdown(f"- {svc}")
    
    st.markdown("**Implementation Steps:**")
    for i, step in enumerate(pattern['implementation'], 1):
        st.markdown(f"{i}. {step}")

def render_rto_rpo_calculator():
    """Render RTO/RPO calculator"""
    st.markdown("### 📈 RTO/RPO Requirements Calculator")
    st.markdown("Determine your recovery requirements based on business impact")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("**Business Impact Assessment**")
        
        hourly_revenue = st.number_input("Hourly Revenue ($)", min_value=0, value=10000, step=1000)
        hourly_productivity = st.number_input("Hourly Productivity Loss ($)", min_value=0, value=5000, step=500)
        reputation_impact = st.selectbox(
            "Reputation Impact",
            ["Minimal", "Moderate", "Significant", "Severe"]
        )
        regulatory_impact = st.selectbox(
            "Regulatory/Compliance Impact",
            ["None", "Minor fines", "Major fines", "License at risk"]
        )
    
    with col2:
        st.markdown("**Data Characteristics**")
        
        transaction_volume = st.selectbox(
            "Transaction Volume",
            ["Low (< 100/hour)", "Medium (100-1000/hour)", "High (1000-10000/hour)", "Very High (> 10000/hour)"]
        )
        data_change_rate = st.selectbox(
            "Data Change Rate",
            ["Low (daily)", "Medium (hourly)", "High (minutes)", "Very High (seconds)"]
        )
        data_recreatable = st.selectbox(
            "Can data be recreated?",
            ["Yes, easily", "Yes, with effort", "Partially", "No"]
        )
    
    if st.button("📊 Calculate Requirements"):
        st.markdown("---")
        st.markdown("### 📋 Recommended Requirements")
        
        # Simple calculation logic
        hourly_cost = hourly_revenue + hourly_productivity
        
        # RTO recommendation
        if hourly_cost > 50000 or reputation_impact == "Severe":
            rto_rec = "< 1 hour"
            rto_pattern = "warm_standby"
        elif hourly_cost > 20000 or reputation_impact == "Significant":
            rto_rec = "1-4 hours"
            rto_pattern = "pilot_light"
        elif hourly_cost > 5000:
            rto_rec = "4-24 hours"
            rto_pattern = "pilot_light"
        else:
            rto_rec = "24+ hours"
            rto_pattern = "backup_restore"
        
        # RPO recommendation
        if transaction_volume.startswith("Very High") or data_change_rate.startswith("Very High"):
            rpo_rec = "< 1 minute"
            rpo_pattern = "active_active"
        elif transaction_volume.startswith("High") or data_change_rate.startswith("High"):
            rpo_rec = "< 15 minutes"
            rpo_pattern = "warm_standby"
        elif data_recreatable == "No":
            rpo_rec = "< 1 hour"
            rpo_pattern = "warm_standby"
        else:
            rpo_rec = "< 24 hours"
            rpo_pattern = "backup_restore"
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.metric("Recommended RTO", rto_rec)
            st.metric("Hourly Downtime Cost", f"${hourly_cost:,.0f}")
        
        with col2:
            st.metric("Recommended RPO", rpo_rec)
            st.metric("Daily Downtime Risk", f"${hourly_cost * 24:,.0f}")
        
        # Recommend pattern
        final_pattern = rpo_pattern if DR_PATTERNS[rpo_pattern]['cost'] > DR_PATTERNS[rto_pattern]['cost'] else rto_pattern
        pattern = DR_PATTERNS[final_pattern]
        
        st.success(f"**Recommended DR Pattern:** {pattern['icon']} {pattern['name']}")

def render_readiness_assessment():
    """Render migration readiness assessment"""
    st.markdown("### ✅ Migration Readiness Assessment")
    st.markdown("Evaluate your organization's readiness for cloud migration")
    
    categories = {
        "Business Readiness": [
            "Executive sponsorship secured",
            "Business case developed",
            "Budget allocated",
            "Success metrics defined"
        ],
        "Technical Readiness": [
            "Application inventory complete",
            "Dependency mapping done",
            "Cloud architecture designed",
            "Infrastructure as Code adopted"
        ],
        "Organizational Readiness": [
            "Cloud skills assessment done",
            "Training plan in place",
            "Operating model defined",
            "Change management planned"
        ],
        "Security & Compliance": [
            "Security requirements documented",
            "Compliance needs identified",
            "Security controls designed",
            "Audit requirements understood"
        ],
        "Operational Readiness": [
            "Monitoring strategy defined",
            "Incident response planned",
            "Backup/DR strategy designed",
            "Support model defined"
        ]
    }
    
    scores = {}
    
    for category, items in categories.items():
        st.markdown(f"**{category}**")
        category_score = 0
        cols = st.columns(2)
        
        for idx, item in enumerate(items):
            with cols[idx % 2]:
                if st.checkbox(item, key=f"ready_{category}_{item[:20]}"):
                    category_score += 25
        
        scores[category] = category_score
    
    st.markdown("---")
    
    # Results
    overall_score = sum(scores.values()) / len(scores)
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        color = "#388E3C" if overall_score >= 75 else "#FBC02D" if overall_score >= 50 else "#D32F2F"
        st.markdown(f"""
        <div style="text-align: center; padding: 1rem; background: white; border-radius: 10px;">
            <div style="font-size: 2.5rem; font-weight: bold; color: {color};">{overall_score:.0f}%</div>
            <div style="color: #666;">Overall Readiness</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        status = "Ready" if overall_score >= 75 else "Preparing" if overall_score >= 50 else "Early Stage"
        st.metric("Status", status)
    
    with col3:
        weeks = max(4, int((100 - overall_score) / 5))
        st.metric("Est. Prep Time", f"{weeks} weeks")
    
    # Category breakdown
    st.markdown("### Category Scores")
    
    for category, score in sorted(scores.items(), key=lambda x: x[1]):
        col1, col2 = st.columns([3, 1])
        with col1:
            st.progress(score / 100)
        with col2:
            st.markdown(f"**{category}:** {score}%")

# Export
__all__ = ['render_migration_dr_tab']
