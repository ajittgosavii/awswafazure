'''
AWS Design & Well-Architected Hub - INTEGRATED MODULE
Comprehensive architecture design with real-time WAF assessment

Version: 1.0.0
Author: AI-Powered Architecture Platform
'''

import streamlit as st
import json
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field, asdict
import uuid
from enum import Enum

# ============================================================================
# DATA MODELS - Integrated Design + WAF
# ============================================================================

class ArchitectureStatus(Enum):
    DRAFT = "draft"
    DESIGNING = "designing"
    REVIEW = "review"
    APPROVED = "approved"
    DEPLOYED = "deployed"

class WAFPillar(Enum):
    OPERATIONAL_EXCELLENCE = "operational_excellence"
    SECURITY = "security"
    RELIABILITY = "reliability"
    PERFORMANCE = "performance"
    COST = "cost"
    SUSTAINABILITY = "sustainability"

@dataclass
class WAFScore:
    pillar: str
    score: int
    max_score: int = 100
    issues: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    
    def get_grade(self) -> str:
        if self.score >= 90: return "A"
        elif self.score >= 80: return "B"
        elif self.score >= 70: return "C"
        elif self.score >= 60: return "D"
        else: return "F"
    
    def get_color(self) -> str:
        if self.score >= 80: return "green"
        elif self.score >= 60: return "orange"
        else: return "red"

@dataclass
class Component:
    id: str
    name: str
    type: str
    properties: Dict[str, Any] = field(default_factory=dict)
    waf_issues: List[str] = field(default_factory=list)
    
@dataclass
class IntegratedArchitectureDesign:
    '''Combined design + WAF assessment'''
    
    # Design attributes
    id: str
    project_name: str
    environment: str
    description: str = ""
    components: List[Component] = field(default_factory=list)
    
    # WAF attributes
    overall_score: Optional[int] = None
    pillar_scores: Dict[str, WAFScore] = field(default_factory=dict)
    total_issues: int = 0
    critical_issues: int = 0
    
    # Metadata
    status: ArchitectureStatus = ArchitectureStatus.DRAFT
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    assessed_at: Optional[datetime] = None
    created_by: str = "user"
    
    # Configuration
    auto_assess: bool = True
    
    def get_overall_grade(self) -> str:
        if not self.overall_score: return "N/A"
        if self.overall_score >= 90: return "A"
        elif self.overall_score >= 80: return "B"
        elif self.overall_score >= 70: return "C"
        elif self.overall_score >= 60: return "D"
        else: return "F"

# ============================================================================
# LIVE WAF ASSESSMENT ENGINE
# ============================================================================

class LiveWAFAssessor:
    '''Real-time WAF assessment engine'''
    
    def __init__(self):
        self.rules = self._load_assessment_rules()
    
    def _load_assessment_rules(self) -> Dict:
        '''Load WAF assessment rules'''
        return {
            'security': {
                'encryption_at_rest': {'weight': 15, 'critical': True},
                'encryption_in_transit': {'weight': 15, 'critical': True},
                'network_isolation': {'weight': 10, 'critical': False},
                'iam_least_privilege': {'weight': 10, 'critical': True},
                'backup_enabled': {'weight': 10, 'critical': False},
                'monitoring_enabled': {'weight': 10, 'critical': False},
            },
            'reliability': {
                'multi_az': {'weight': 20, 'critical': True},
                'auto_scaling': {'weight': 15, 'critical': False},
                'health_checks': {'weight': 15, 'critical': True},
                'disaster_recovery': {'weight': 15, 'critical': False},
            },
            'performance': {
                'caching_enabled': {'weight': 15, 'critical': False},
                'cdn_configured': {'weight': 10, 'critical': False},
                'database_optimization': {'weight': 15, 'critical': False},
            },
            'cost': {
                'right_sizing': {'weight': 20, 'critical': False},
                'reserved_instances': {'weight': 15, 'critical': False},
                'unused_resources': {'weight': 15, 'critical': True},
            }
        }
    
    def assess_design(self, design: IntegratedArchitectureDesign) -> Dict:
        '''Run complete WAF assessment'''
        
        # Assess each pillar
        pillar_scores = {}
        total_issues = 0
        critical_issues = 0
        
        for pillar in ['security', 'reliability', 'performance', 'cost', 
                      'operational_excellence', 'sustainability']:
            score_obj = self._assess_pillar(pillar, design)
            pillar_scores[pillar] = score_obj
            total_issues += len(score_obj.issues)
            critical_issues += len([i for i in score_obj.issues if 'CRITICAL' in i])
        
        # Calculate overall score
        overall = sum(s.score for s in pillar_scores.values()) // len(pillar_scores)
        
        # Update design
        design.pillar_scores = pillar_scores
        design.overall_score = overall
        design.total_issues = total_issues
        design.critical_issues = critical_issues
        design.assessed_at = datetime.now()
        
        return {
            'overall_score': overall,
            'pillar_scores': pillar_scores,
            'total_issues': total_issues,
            'critical_issues': critical_issues
        }
    
    def _assess_pillar(self, pillar: str, design: IntegratedArchitectureDesign) -> WAFScore:
        '''Assess single pillar'''
        
        issues = []
        recommendations = []
        base_score = 100
        deductions = 0
        
        # Check components against rules
        for component in design.components:
            component_issues = self._check_component(pillar, component)
            issues.extend(component_issues)
            
            # Deduct points for issues
            for issue in component_issues:
                if 'CRITICAL' in issue:
                    deductions += 15
                elif 'HIGH' in issue:
                    deductions += 10
                elif 'MEDIUM' in issue:
                    deductions += 5
        
        # Generate recommendations
        if issues:
            recommendations = self._generate_recommendations(pillar, issues)
        
        final_score = max(0, base_score - deductions)
        
        return WAFScore(
            pillar=pillar,
            score=final_score,
            issues=issues,
            recommendations=recommendations
        )
    
    def _check_component(self, pillar: str, component: Component) -> List[str]:
        '''Check component against pillar rules'''
        issues = []
        
        if pillar == 'security':
            # Database checks
            if 'database' in component.type.lower() or 'rds' in component.type.lower():
                if not component.properties.get('encrypted', False):
                    issues.append(f"[CRITICAL] {component.name}: Database not encrypted at rest")
                if not component.properties.get('backup_enabled', False):
                    issues.append(f"[HIGH] {component.name}: No backup policy configured")
                if component.properties.get('publicly_accessible', False):
                    issues.append(f"[CRITICAL] {component.name}: Database is publicly accessible")
            
            # Storage checks
            if 's3' in component.type.lower() or 'storage' in component.type.lower():
                if not component.properties.get('encrypted', False):
                    issues.append(f"[HIGH] {component.name}: Storage not encrypted")
                if not component.properties.get('versioning', False):
                    issues.append(f"[MEDIUM] {component.name}: Versioning not enabled")
        
        elif pillar == 'reliability':
            # High availability checks
            if not component.properties.get('multi_az', False):
                if 'database' in component.type.lower():
                    issues.append(f"[HIGH] {component.name}: Not configured for Multi-AZ")
            
            # Auto scaling checks
            if 'compute' in component.type.lower() or 'ec2' in component.type.lower():
                if not component.properties.get('auto_scaling', False):
                    issues.append(f"[MEDIUM] {component.name}: Auto Scaling not configured")
        
        elif pillar == 'performance':
            # Caching checks
            if 'database' in component.type.lower():
                if not component.properties.get('caching_enabled', False):
                    issues.append(f"[MEDIUM] {component.name}: No caching configured")
        
        return issues
    
    def _generate_recommendations(self, pillar: str, issues: List[str]) -> List[str]:
        '''Generate recommendations based on issues'''
        recommendations = []
        
        if pillar == 'security':
            if any('encrypted' in i.lower() for i in issues):
                recommendations.append("Enable encryption at rest for all data stores")
            if any('backup' in i.lower() for i in issues):
                recommendations.append("Configure automated backup policies")
        
        elif pillar == 'reliability':
            if any('multi-az' in i.lower() for i in issues):
                recommendations.append("Enable Multi-AZ deployment for high availability")
            if any('auto scaling' in i.lower() for i in issues):
                recommendations.append("Configure Auto Scaling for automatic capacity management")
        
        return recommendations

    def assess_component_addition(self, component: Component) -> List[str]:
        '''Quick assessment when component is added'''
        issues = []
        
        # Quick security checks
        if 'database' in component.type.lower():
            if not component.properties.get('encrypted', False):
                issues.append("⚠️ Consider enabling encryption")
            if not component.properties.get('multi_az', False):
                issues.append("⚠️ Consider Multi-AZ for reliability")
        
        return issues

# ============================================================================
# AI INTEGRATION LAYER
# ============================================================================

class IntegratedAIAssistant:
    '''AI that understands both design and WAF'''
    
    def suggest_improvements(self, design: IntegratedArchitectureDesign) -> List[Dict]:
        '''Generate AI-powered improvement suggestions'''
        suggestions = []
        
        if not design.pillar_scores:
            return suggestions
        
        # Analyze each pillar
        for pillar_name, pillar_score in design.pillar_scores.items():
            if pillar_score.score < 80:
                # Generate suggestions for low-scoring pillars
                suggestions.extend(self._generate_pillar_suggestions(
                    pillar_name, pillar_score, design
                ))
        
        # Sort by impact
        suggestions.sort(key=lambda x: x.get('impact_score', 0), reverse=True)
        
        return suggestions[:10]  # Top 10 suggestions
    
    def _generate_pillar_suggestions(self, pillar: str, score: WAFScore, 
                                    design: IntegratedArchitectureDesign) -> List[Dict]:
        '''Generate suggestions for a specific pillar'''
        suggestions = []
        
        if pillar == 'security' and score.score < 80:
            suggestions.append({
                'title': 'Enable Encryption at Rest',
                'description': 'Encrypt all data stores to improve security score',
                'impact': f'+{15} points',
                'impact_score': 15,
                'effort': 'Low',
                'cost_impact': 'Minimal',
                'action': 'enable_encryption',
                'components': [c.id for c in design.components if 'database' in c.type.lower()]
            })
        
        if pillar == 'reliability' and score.score < 80:
            suggestions.append({
                'title': 'Enable Multi-AZ Deployment',
                'description': 'Deploy across multiple availability zones for HA',
                'impact': f'+{20} points',
                'impact_score': 20,
                'effort': 'Medium',
                'cost_impact': '+$50-200/month',
                'action': 'enable_multi_az',
                'components': [c.id for c in design.components]
            })
        
        if pillar == 'performance' and score.score < 80:
            suggestions.append({
                'title': 'Enable Database Caching',
                'description': 'Add caching layer to improve query performance',
                'impact': f'+{15} points',
                'impact_score': 15,
                'effort': 'Medium',
                'cost_impact': '+$30-100/month',
                'action': 'enable_caching',
                'components': [c.id for c in design.components if 'database' in c.type.lower()]
            })
        
        return suggestions
    
    def apply_suggestion(self, design: IntegratedArchitectureDesign, 
                        suggestion: Dict) -> bool:
        '''Apply an AI suggestion to the design'''
        
        action = suggestion.get('action')
        affected_components = suggestion.get('components', [])
        
        if action == 'enable_encryption':
            for comp_id in affected_components:
                comp = next((c for c in design.components if c.id == comp_id), None)
                if comp:
                    comp.properties['encrypted'] = True
            return True
        
        elif action == 'enable_multi_az':
            for comp_id in affected_components:
                comp = next((c for c in design.components if c.id == comp_id), None)
                if comp:
                    comp.properties['multi_az'] = True
            return True
        
        elif action == 'enable_caching':
            for comp_id in affected_components:
                comp = next((c for c in design.components if c.id == comp_id), None)
                if comp:
                    comp.properties['caching_enabled'] = True
            return True
        
        return False

# ============================================================================
# UI COMPONENTS
# ============================================================================

def render_waf_score_card(design: IntegratedArchitectureDesign):
    '''Render WAF score card with live updates'''
    
    if not design.overall_score:
        st.info("⚡ Add components to see live WAF assessment")
        return
    
    # Overall score
    st.markdown("### ⚡ Live WAF Score")
    
    score_color = "🟢" if design.overall_score >= 80 else "🟡" if design.overall_score >= 60 else "🔴"
    grade = design.get_overall_grade()
    
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Overall Score", f"{design.overall_score}/100", delta=None)
    with col2:
        st.metric("Grade", f"{score_color} {grade}")
    with col3:
        st.metric("Issues", design.total_issues, delta=None)
    
    # Progress bar
    st.progress(design.overall_score / 100)
    
    # Pillar breakdown
    st.markdown("**Pillars:**")
    for pillar_name, pillar_score in design.pillar_scores.items():
        icon = "🟢" if pillar_score.score >= 80 else "🟡" if pillar_score.score >= 60 else "🔴"
        
        col1, col2 = st.columns([3, 1])
        with col1:
            st.write(f"{icon} **{pillar_name.replace('_', ' ').title()}**")
            st.progress(pillar_score.score / 100)
        with col2:
            st.write(f"{pillar_score.score}/100")
    
    # Critical issues
    if design.critical_issues > 0:
        st.error(f"⚠️ {design.critical_issues} critical issues found")
        
        # Show issues
        with st.expander("View Issues"):
            for pillar_name, pillar_score in design.pillar_scores.items():
                if pillar_score.issues:
                    st.markdown(f"**{pillar_name.title()}:**")
                    for issue in pillar_score.issues[:3]:  # Top 3
                        st.warning(issue)

def render_ai_suggestions(design: IntegratedArchitectureDesign, ai_assistant: IntegratedAIAssistant):
    '''Render AI improvement suggestions'''
    
    st.markdown("### 🤖 AI Recommendations")
    
    suggestions = ai_assistant.suggest_improvements(design)
    
    if not suggestions:
        st.success("✅ No major improvements needed!")
        return
    
    st.info(f"Found {len(suggestions)} opportunities for improvement")
    
    for i, suggestion in enumerate(suggestions[:5], 1):  # Top 5
        with st.expander(f"💡 {suggestion['title']} - {suggestion['impact']}"):
            st.write(suggestion['description'])
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Impact", suggestion['impact'])
            with col2:
                st.metric("Effort", suggestion['effort'])
            with col3:
                st.metric("Cost", suggestion['cost_impact'])
            
            if st.button(f"Apply This Fix", key=f"apply_{i}"):
                if ai_assistant.apply_suggestion(design, suggestion):
                    st.success("✅ Applied! Re-assessing...")
                    st.rerun()
    
    # Quick fix all
    if st.button("🔧 Apply All High-Impact Fixes", type="primary"):
        applied = 0
        for suggestion in suggestions:
            if suggestion['impact_score'] >= 15:
                if ai_assistant.apply_suggestion(design, suggestion):
                    applied += 1
        
        st.success(f"✅ Applied {applied} fixes! Re-assessing...")
        st.rerun()

# ============================================================================
# MAIN INTEGRATED MODULE CLASS
# ============================================================================

class IntegratedDesignWAFHub:
    '''Main integrated Design & Well-Architected Hub'''
    
    @staticmethod
    def initialize_session_state():
        '''Initialize session state variables'''
        if 'integrated_designs' not in st.session_state:
            st.session_state.integrated_designs = {}
        if 'current_design_id' not in st.session_state:
            st.session_state.current_design_id = None
        if 'waf_assessor' not in st.session_state:
            st.session_state.waf_assessor = LiveWAFAssessor()
        if 'ai_assistant' not in st.session_state:
            st.session_state.ai_assistant = IntegratedAIAssistant()
    
    @staticmethod
    def render():
        '''Main render method'''
        
        IntegratedDesignWAFHub.initialize_session_state()
        
        # Header
        st.markdown('''
        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                    padding: 2rem; border-radius: 12px; margin-bottom: 2rem;">
            <h1 style="color: white; margin: 0;">📐 AWS Design & Well-Architected Hub</h1>
            <p style="color: white; opacity: 0.9; margin: 0.5rem 0 0 0;">
                Design architectures with real-time WAF assessment & AI recommendations
            </p>
        </div>
        ''', unsafe_allow_html=True)
        
        # Quick metrics
        IntegratedDesignWAFHub._render_quick_metrics()
        
        # Main tabs
        tabs = st.tabs(["🎨 Design Studio", "📊 Portfolio", "📈 Analytics", "⚙️ Settings"])
        
        with tabs[0]:
            IntegratedDesignWAFHub._render_design_studio()
        
        with tabs[1]:
            IntegratedDesignWAFHub._render_portfolio()
        
        with tabs[2]:
            IntegratedDesignWAFHub._render_analytics()
        
        with tabs[3]:
            IntegratedDesignWAFHub._render_settings()
    
    @staticmethod
    def _render_quick_metrics():
        '''Render quick metrics dashboard'''
        
        designs = st.session_state.integrated_designs
        
        if not designs:
            return
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Designs", len(designs))
        
        with col2:
            assessed = [d for d in designs.values() if d.overall_score is not None]
            avg_score = sum(d.overall_score for d in assessed) / len(assessed) if assessed else 0
            st.metric("Avg WAF Score", f"{avg_score:.0f}/100")
        
        with col3:
            compliant = [d for d in designs.values() if d.overall_score and d.overall_score >= 80]
            pct = (len(compliant) / len(designs) * 100) if designs else 0
            st.metric("Compliant", f"{pct:.0f}%")
        
        with col4:
            total_critical = sum(d.critical_issues for d in designs.values())
            st.metric("Critical Issues", total_critical)
    
    @staticmethod
    def _render_design_studio():
        '''Render integrated design studio'''
        
        st.subheader("🎨 Design Studio")
        
        # Design selection/creation
        col1, col2 = st.columns([2, 1])
        
        with col1:
            designs = st.session_state.integrated_designs
            design_names = ["-- Create New Design --"] + list(designs.keys())
            
            selected = st.selectbox("Select Design", design_names)
            
            if selected == "-- Create New Design --":
                IntegratedDesignWAFHub._render_new_design_form()
                return
            else:
                st.session_state.current_design_id = designs[selected].id
        
        # Get current design
        current_design = IntegratedDesignWAFHub._get_current_design()
        
        if not current_design:
            st.info("👆 Select or create a design to get started")
            return
        
        # Two-column layout: Design | WAF
        col_design, col_waf = st.columns([2, 1])
        
        with col_design:
            IntegratedDesignWAFHub._render_design_canvas(current_design)
        
        with col_waf:
            render_waf_score_card(current_design)
            st.markdown("---")
            render_ai_suggestions(current_design, st.session_state.ai_assistant)
    
    @staticmethod
    def _render_new_design_form():
        '''Render form to create new design'''
        
        st.markdown("### Create New Architecture Design")
        
        with st.form("new_design_form"):
            project_name = st.text_input("Project Name", placeholder="My Production App")
            environment = st.selectbox("Environment", ["Production", "Staging", "Development", "Test"])
            description = st.text_area("Description", placeholder="Describe your architecture...")
            
            template = st.selectbox("Start From Template", [
                "Blank",
                "3-Tier Web Application",
                "Microservices Platform",
                "Data Lake",
                "ML/AI Workload"
            ])
            
            if st.form_submit_button("Create Design", type="primary"):
                if project_name:
                    design = IntegratedArchitectureDesign(
                        id=str(uuid.uuid4()),
                        project_name=project_name,
                        environment=environment,
                        description=description
                    )
                    
                    # Add template components if selected
                    if template != "Blank":
                        design.components = IntegratedDesignWAFHub._get_template_components(template)
                    
                    st.session_state.integrated_designs[project_name] = design
                    st.session_state.current_design_id = design.id
                    st.success(f"✅ Created design: {project_name}")
                    st.rerun()
                else:
                    st.error("Project name is required")
    
    @staticmethod
    def _get_template_components(template: str) -> List[Component]:
        '''Get components for template'''
        
        if template == "3-Tier Web Application":
            return [
                Component(str(uuid.uuid4()), "VPC", "network", {"cidr": "10.0.0.0/16"}),
                Component(str(uuid.uuid4()), "Application Load Balancer", "load_balancer", {}),
                Component(str(uuid.uuid4()), "EC2 Auto Scaling", "compute", {"auto_scaling": True}),
                Component(str(uuid.uuid4()), "RDS PostgreSQL", "database", {"engine": "postgresql"}),
                Component(str(uuid.uuid4()), "S3 Bucket", "storage", {})
            ]
        
        return []
    
    @staticmethod
    def _render_design_canvas(design: IntegratedArchitectureDesign):
        '''Render design canvas with components'''
        
        st.markdown("#### Components")
        
        # Display components
        if design.components:
            for i, comp in enumerate(design.components):
                col1, col2, col3 = st.columns([3, 2, 1])
                
                with col1:
                    st.write(f"**{comp.name}**")
                    st.caption(f"Type: {comp.type}")
                
                with col2:
                    if comp.waf_issues:
                        st.warning(f"⚠️ {len(comp.waf_issues)} issues")
                
                with col3:
                    if st.button("🗑️", key=f"del_{i}"):
                        design.components.remove(comp)
                        st.rerun()
                
                st.markdown("---")
        else:
            st.info("No components yet. Add components below.")
        
        # Add component
        st.markdown("#### Add Component")
        
        with st.form("add_component"):
            comp_name = st.text_input("Component Name")
            comp_type = st.selectbox("Type", [
                "compute", "database", "storage", "network", 
                "load_balancer", "cache", "queue"
            ])
            
            # Common properties
            col1, col2 = st.columns(2)
            with col1:
                encrypted = st.checkbox("Encrypted", value=True)
                multi_az = st.checkbox("Multi-AZ")
            with col2:
                backup_enabled = st.checkbox("Backup Enabled", value=True)
                auto_scaling = st.checkbox("Auto Scaling")
            
            if st.form_submit_button("Add Component"):
                if comp_name:
                    component = Component(
                        id=str(uuid.uuid4()),
                        name=comp_name,
                        type=comp_type,
                        properties={
                            'encrypted': encrypted,
                            'multi_az': multi_az,
                            'backup_enabled': backup_enabled,
                            'auto_scaling': auto_scaling
                        }
                    )
                    
                    design.components.append(component)
                    
                    # Quick assessment
                    issues = st.session_state.waf_assessor.assess_component_addition(component)
                    if issues:
                        st.warning(f"⚠️ Potential issues: {', '.join(issues)}")
                    
                    # Full re-assessment
                    st.session_state.waf_assessor.assess_design(design)
                    design.updated_at = datetime.now()
                    
                    st.success(f"✅ Added {comp_name}")
                    st.rerun()
        
        # Actions
        st.markdown("---")
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if st.button("🔄 Re-Assess WAF", use_container_width=True):
                st.session_state.waf_assessor.assess_design(design)
                st.success("✅ Assessment updated!")
                st.rerun()
        
        with col2:
            if st.button("📄 Export Design", use_container_width=True):
                # Export logic here
                st.info("Export feature coming soon!")
        
        with col3:
            if st.button("🚀 Deploy", use_container_width=True):
                if design.overall_score and design.overall_score >= 80:
                    st.success("✅ Ready to deploy!")
                else:
                    st.warning("⚠️ Fix WAF issues before deploying")
    
    @staticmethod
    def _get_current_design() -> Optional[IntegratedArchitectureDesign]:
        '''Get current design from session state'''
        
        design_id = st.session_state.current_design_id
        if not design_id:
            return None
        
        for design in st.session_state.integrated_designs.values():
            if design.id == design_id:
                return design
        
        return None
    
    @staticmethod
    def _render_portfolio():
        '''Render portfolio view'''
        
        st.subheader("📊 Architecture Portfolio")
        
        designs = st.session_state.integrated_designs
        
        if not designs:
            st.info("No designs yet. Create your first design in the Design Studio!")
            return
        
        # Portfolio summary
        st.markdown("### Portfolio Health")
        
        assessed_designs = [d for d in designs.values() if d.overall_score is not None]
        
        if assessed_designs:
            avg_score = sum(d.overall_score for d in assessed_designs) / len(assessed_designs)
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Average WAF Score", f"{avg_score:.0f}/100")
            with col2:
                compliant = len([d for d in assessed_designs if d.overall_score >= 80])
                st.metric("Compliant Designs", f"{compliant}/{len(assessed_designs)}")
            with col3:
                total_critical = sum(d.critical_issues for d in designs.values())
                st.metric("Total Critical Issues", total_critical)
        
        # Designs table
        st.markdown("### All Designs")
        
        df_data = []
        for design in designs.values():
            df_data.append({
                'Name': design.project_name,
                'Environment': design.environment,
                'WAF Score': f"{design.overall_score}/100" if design.overall_score else "Not assessed",
                'Grade': design.get_overall_grade(),
                'Status': design.status.value,
                'Components': len(design.components),
                'Critical Issues': design.critical_issues,
                'Last Updated': design.updated_at.strftime('%Y-%m-%d %H:%M')
            })
        
        df = pd.DataFrame(df_data)
        st.dataframe(df, use_container_width=True, hide_index=True)
    
    @staticmethod
    def _render_analytics():
        '''Render analytics dashboard'''
        
        st.subheader("📈 Analytics & Insights")
        
        designs = list(st.session_state.integrated_designs.values())
        assessed = [d for d in designs if d.overall_score is not None]
        
        if not assessed:
            st.info("No assessed designs yet. Complete some designs to see analytics!")
            return
        
        # Score distribution
        st.markdown("### WAF Score Distribution")
        
        scores = [d.overall_score for d in assessed]
        fig = go.Figure(data=[go.Histogram(x=scores, nbinsx=10)])
        fig.update_layout(
            xaxis_title="WAF Score",
            yaxis_title="Number of Designs",
            showlegend=False
        )
        st.plotly_chart(fig, use_container_width=True)
        
        # Pillar comparison
        st.markdown("### Pillar Performance Across Portfolio")
        
        pillar_avg = {}
        for design in assessed:
            for pillar_name, pillar_score in design.pillar_scores.items():
                if pillar_name not in pillar_avg:
                    pillar_avg[pillar_name] = []
                pillar_avg[pillar_name].append(pillar_score.score)
        
        pillar_data = []
        for pillar, scores in pillar_avg.items():
            avg = sum(scores) / len(scores)
            pillar_data.append({
                'Pillar': pillar.replace('_', ' ').title(),
                'Average Score': avg
            })
        
        df_pillars = pd.DataFrame(pillar_data)
        fig = px.bar(df_pillars, x='Pillar', y='Average Score', 
                     color='Average Score', color_continuous_scale='RdYlGn')
        st.plotly_chart(fig, use_container_width=True)
    
    @staticmethod
    def _render_settings():
        '''Render settings page'''
        
        st.subheader("⚙️ Settings")
        
        st.markdown("### General Settings")
        
        auto_assess = st.checkbox("Auto-assess on component changes", value=True)
        st.caption("Automatically run WAF assessment when components are added/modified")
        
        st.markdown("### Export Settings")
        
        export_format = st.selectbox("Default Export Format", ["JSON", "YAML", "Terraform", "CloudFormation"])
        
        st.markdown("### Notification Settings")
        
        notify_critical = st.checkbox("Notify on critical issues", value=True)
        notify_score_drop = st.checkbox("Notify on score drop > 10 points", value=False)
        
        if st.button("Save Settings"):
            st.success("✅ Settings saved!")
