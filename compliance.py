"""
Compliance Module - WAF to Compliance Framework Mapping
Maps AWS Well-Architected Framework questions to compliance requirements
Supports: PCI-DSS v4.0, HIPAA, SOC 2, ISO 27001:2022
"""

import streamlit as st
from typing import Dict, List, Tuple
from dataclasses import dataclass
from datetime import datetime

@dataclass
class ComplianceRequirement:
    """Single compliance requirement"""
    id: str
    title: str
    description: str
    framework: str
    waf_questions: List[str]  # WAF question IDs that provide evidence
    priority: str  # high, medium, low
    category: str

@dataclass
class ComplianceGap:
    """Identified compliance gap"""
    id: str
    title: str
    frameworks: List[str]
    requirements: List[Dict]
    waf_questions: List[str]
    impact: str
    effort: str
    risk_level: str
    remediation_steps: List[str]
    priority: str

# ============================================================================
# WAF TO COMPLIANCE MAPPINGS
# ============================================================================

# PCI-DSS v4.0 Requirements mapped to WAF questions
PCI_DSS_MAPPINGS = {
    'req_1': ComplianceRequirement(
        id='1.2.1',
        title='Firewall and Router Configuration Standards',
        description='Configuration standards for all network security controls',
        framework='PCI-DSS v4.0',
        waf_questions=['SEC-VPC-01', 'SEC-VPC-02', 'SEC-VPC-03'],
        priority='high',
        category='Network Security'
    ),
    'req_3': ComplianceRequirement(
        id='3.4.1',
        title='Protect Stored Cardholder Data',
        description='Cardholder data is rendered unreadable anywhere it is stored',
        framework='PCI-DSS v4.0',
        waf_questions=['SEC-ENC-01', 'SEC-ENC-02', 'SEC-DATA-01'],
        priority='high',
        category='Data Protection'
    ),
    'req_7': ComplianceRequirement(
        id='7.2.1',
        title='Restrict Access by Business Need to Know',
        description='Access control system with least privilege',
        framework='PCI-DSS v4.0',
        waf_questions=['SEC-IAM-01', 'SEC-IAM-02', 'SEC-IAM-03'],
        priority='high',
        category='Access Control'
    ),
    'req_8': ComplianceRequirement(
        id='8.3.1',
        title='Multi-factor Authentication',
        description='MFA for all access to cardholder data environment',
        framework='PCI-DSS v4.0',
        waf_questions=['SEC-IAM-04', 'SEC-IAM-05'],
        priority='high',
        category='Authentication'
    ),
    'req_10': ComplianceRequirement(
        id='10.2.1',
        title='Log and Monitor All Network Access',
        description='Automated audit trail for all user activities',
        framework='PCI-DSS v4.0',
        waf_questions=['SEC-LOG-01', 'SEC-LOG-02', 'SEC-LOG-03'],
        priority='high',
        category='Logging'
    ),
}

# HIPAA Safeguards mapped to WAF questions
HIPAA_MAPPINGS = {
    'admin_1': ComplianceRequirement(
        id='164.308(a)(1)',
        title='Security Management Process',
        description='Implement policies and procedures to prevent, detect, contain, and correct security violations',
        framework='HIPAA',
        waf_questions=['OPS-01', 'OPS-02', 'SEC-POLICY-01'],
        priority='high',
        category='Administrative Safeguards'
    ),
    'admin_3': ComplianceRequirement(
        id='164.308(a)(3)',
        title='Workforce Security',
        description='Implement policies and procedures to ensure workforce has appropriate access',
        framework='HIPAA',
        waf_questions=['SEC-IAM-01', 'SEC-IAM-02', 'SEC-IAM-06'],
        priority='high',
        category='Administrative Safeguards'
    ),
    'admin_4': ComplianceRequirement(
        id='164.308(a)(4)',
        title='Information Access Management',
        description='Implement policies for authorizing access to ePHI',
        framework='HIPAA',
        waf_questions=['SEC-IAM-03', 'SEC-IAM-07', 'SEC-DATA-01'],
        priority='high',
        category='Administrative Safeguards'
    ),
    'tech_1': ComplianceRequirement(
        id='164.312(a)(1)',
        title='Access Control',
        description='Implement technical policies and procedures for access to ePHI',
        framework='HIPAA',
        waf_questions=['SEC-IAM-01', 'SEC-IAM-04', 'SEC-IAM-05'],
        priority='high',
        category='Technical Safeguards'
    ),
    'tech_2': ComplianceRequirement(
        id='164.312(a)(2)(iv)',
        title='Encryption and Decryption',
        description='Implement mechanism to encrypt and decrypt ePHI',
        framework='HIPAA',
        waf_questions=['SEC-ENC-01', 'SEC-ENC-02', 'SEC-ENC-03'],
        priority='high',
        category='Technical Safeguards'
    ),
}

# SOC 2 Trust Service Criteria mapped to WAF questions
SOC2_MAPPINGS = {
    'cc6_1': ComplianceRequirement(
        id='CC6.1',
        title='Logical and Physical Access Controls',
        description='Restrict logical and physical access to authorized users',
        framework='SOC 2',
        waf_questions=['SEC-IAM-01', 'SEC-IAM-02', 'SEC-IAM-04'],
        priority='high',
        category='Common Criteria'
    ),
    'cc6_2': ComplianceRequirement(
        id='CC6.2',
        title='User Identification and Authentication',
        description='Identify and authenticate users before granting access',
        framework='SOC 2',
        waf_questions=['SEC-IAM-03', 'SEC-IAM-04', 'SEC-IAM-05'],
        priority='high',
        category='Common Criteria'
    ),
    'cc7_1': ComplianceRequirement(
        id='CC7.1',
        title='Detection of Security Events',
        description='Detect and identify security events in a timely manner',
        framework='SOC 2',
        waf_questions=['SEC-DETECT-01', 'SEC-LOG-01', 'SEC-LOG-02'],
        priority='high',
        category='Common Criteria'
    ),
    'cc7_2': ComplianceRequirement(
        id='CC7.2',
        title='Response to Security Incidents',
        description='Respond to security incidents in a timely manner',
        framework='SOC 2',
        waf_questions=['SEC-IR-01', 'SEC-IR-02', 'SEC-IR-03'],
        priority='high',
        category='Common Criteria'
    ),
    'a1_2': ComplianceRequirement(
        id='A1.2',
        title='Availability - System Recovery',
        description='System can restore operations after disruption',
        framework='SOC 2',
        waf_questions=['REL-BC-01', 'REL-BC-02', 'REL-HA-01'],
        priority='high',
        category='Availability'
    ),
}

# ISO 27001:2022 Controls mapped to WAF questions
ISO27001_MAPPINGS = {
    'a5_1': ComplianceRequirement(
        id='A.5.1',
        title='Policies for Information Security',
        description='Information security policy approved by management',
        framework='ISO 27001:2022',
        waf_questions=['OPS-POLICY-01', 'SEC-POLICY-01'],
        priority='high',
        category='Organizational Controls'
    ),
    'a8_2': ComplianceRequirement(
        id='A.8.2',
        title='Information Classification',
        description='Information classified according to security requirements',
        framework='ISO 27001:2022',
        waf_questions=['SEC-DATA-01', 'SEC-DATA-02'],
        priority='high',
        category='Asset Management'
    ),
    'a9_2': ComplianceRequirement(
        id='A.9.2',
        title='User Access Management',
        description='Access to systems granted according to policy',
        framework='ISO 27001:2022',
        waf_questions=['SEC-IAM-01', 'SEC-IAM-02', 'SEC-IAM-03'],
        priority='high',
        category='Access Control'
    ),
    'a9_4': ComplianceRequirement(
        id='A.9.4.2',
        title='Secure Log-on Procedures',
        description='Access to systems controlled by secure log-on procedure',
        framework='ISO 27001:2022',
        waf_questions=['SEC-IAM-04', 'SEC-IAM-05'],
        priority='high',
        category='Access Control'
    ),
    'a12_4': ComplianceRequirement(
        id='A.12.4',
        title='Logging and Monitoring',
        description='Event logs recording user activities maintained and reviewed',
        framework='ISO 27001:2022',
        waf_questions=['SEC-LOG-01', 'SEC-LOG-02', 'SEC-LOG-03'],
        priority='high',
        category='Operations Security'
    ),
}

# ============================================================================
# COMPLIANCE ASSESSMENT FUNCTIONS
# ============================================================================

def get_all_mappings() -> Dict:
    """Get all compliance framework mappings"""
    return {
        'PCI-DSS v4.0': PCI_DSS_MAPPINGS,
        'HIPAA': HIPAA_MAPPINGS,
        'SOC 2': SOC2_MAPPINGS,
        'ISO 27001:2022': ISO27001_MAPPINGS
    }

def get_framework_requirements(framework: str) -> List[ComplianceRequirement]:
    """Get all requirements for a specific framework"""
    mappings = get_all_mappings()
    if framework in mappings:
        return list(mappings[framework].values())
    return []

def assess_compliance_status(framework: str, waf_results: Dict) -> Dict:
    """
    Assess compliance status based on WAF assessment results
    
    Args:
        framework: Framework name (e.g., 'PCI-DSS v4.0')
        waf_results: Dict of WAF question results {question_id: {'compliant': bool}}
    
    Returns:
        Dict with compliance status
    """
    requirements = get_framework_requirements(framework)
    
    total = len(requirements)
    met = 0
    partial = 0
    gaps = 0
    
    requirement_status = {}
    
    for req in requirements:
        # Check if all mapped WAF questions are compliant
        waf_q_results = []
        for q_id in req.waf_questions:
            if q_id in waf_results:
                waf_q_results.append(waf_results[q_id].get('compliant', False))
        
        if not waf_q_results:
            status = 'unknown'
        elif all(waf_q_results):
            status = 'met'
            met += 1
        elif any(waf_q_results):
            status = 'partial'
            partial += 1
        else:
            status = 'gap'
            gaps += 1
        
        requirement_status[req.id] = {
            'requirement': req,
            'status': status,
            'waf_questions': req.waf_questions,
            'waf_results': {q: waf_results.get(q, {}) for q in req.waf_questions}
        }
    
    compliance_pct = (met / total * 100) if total > 0 else 0
    
    return {
        'framework': framework,
        'total': total,
        'met': met,
        'partial': partial,
        'gaps': gaps,
        'compliance_percentage': compliance_pct,
        'requirement_status': requirement_status
    }

def identify_multi_framework_gaps(waf_results: Dict) -> List[ComplianceGap]:
    """
    Identify gaps that affect multiple compliance frameworks
    
    Returns list of gaps sorted by priority (high impact first)
    """
    # Track which WAF questions affect which requirements
    waf_to_requirements = {}
    
    all_mappings = get_all_mappings()
    
    for framework_name, requirements in all_mappings.items():
        for req_id, req in requirements.items():
            for waf_q in req.waf_questions:
                if waf_q not in waf_to_requirements:
                    waf_to_requirements[waf_q] = []
                waf_to_requirements[waf_q].append({
                    'framework': framework_name,
                    'requirement': req
                })
    
    # Find gaps (non-compliant WAF questions)
    gaps = []
    
    for waf_q, req_list in waf_to_requirements.items():
        # Check if this WAF question is non-compliant
        if waf_q in waf_results and not waf_results[waf_q].get('compliant', True):
            # This is a gap affecting multiple requirements
            frameworks = list(set([r['framework'] for r in req_list]))
            
            # Determine priority based on number of frameworks affected
            if len(frameworks) >= 3:
                priority = 'high'
            elif len(frameworks) == 2:
                priority = 'medium'
            else:
                priority = 'low'
            
            gap = ComplianceGap(
                id=waf_q,
                title=waf_results[waf_q].get('question', waf_q),
                frameworks=frameworks,
                requirements=[{
                    'framework': r['framework'],
                    'id': r['requirement'].id,
                    'title': r['requirement'].title
                } for r in req_list],
                waf_questions=[waf_q],
                impact='High' if len(frameworks) >= 3 else 'Medium',
                effort=waf_results[waf_q].get('effort', 'Medium'),
                risk_level='Critical' if len(frameworks) >= 3 else 'High',
                remediation_steps=waf_results[waf_q].get('remediation', []),
                priority=priority
            )
            
            gaps.append(gap)
    
    # Sort by priority (high first)
    priority_order = {'high': 0, 'medium': 1, 'low': 2}
    gaps.sort(key=lambda x: (priority_order[x.priority], -len(x.frameworks)))
    
    return gaps

def get_waf_question_compliance_impact(waf_question_id: str) -> Dict:
    """
    Get compliance impact of a specific WAF question
    
    Returns dict showing which compliance requirements are affected
    """
    impact = {
        'waf_question_id': waf_question_id,
        'frameworks_affected': [],
        'requirements_affected': []
    }
    
    all_mappings = get_all_mappings()
    
    for framework_name, requirements in all_mappings.items():
        framework_reqs = []
        
        for req_id, req in requirements.items():
            if waf_question_id in req.waf_questions:
                framework_reqs.append({
                    'id': req.id,
                    'title': req.title,
                    'description': req.description,
                    'priority': req.priority
                })
        
        if framework_reqs:
            impact['frameworks_affected'].append(framework_name)
            impact['requirements_affected'].extend([{
                'framework': framework_name,
                **req
            } for req in framework_reqs])
    
    return impact

def generate_compliance_report(framework: str, compliance_status: Dict) -> str:
    """Generate compliance evidence report"""
    
    report = f"""
COMPLIANCE EVIDENCE REPORT
{'='*80}

Framework: {framework}
Assessment Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Based on: AWS Well-Architected Framework Assessment

EXECUTIVE SUMMARY
{'-'*80}
Overall Compliance: {compliance_status['compliance_percentage']:.0f}%
Total Requirements: {compliance_status['total']}
Fully Met: {compliance_status['met']} ({compliance_status['met']/compliance_status['total']*100:.0f}%)
Partially Met: {compliance_status['partial']} ({compliance_status['partial']/compliance_status['total']*100:.0f}%)
Gaps: {compliance_status['gaps']} ({compliance_status['gaps']/compliance_status['total']*100:.0f}%)

"""
    
    # Add detailed findings
    report += "\nDETAILED FINDINGS\n"
    report += "="*80 + "\n\n"
    
    for req_id, req_data in compliance_status['requirement_status'].items():
        req = req_data['requirement']
        status = req_data['status']
        
        status_symbol = {
            'met': '✅',
            'partial': '🟡',
            'gap': '❌',
            'unknown': '❓'
        }[status]
        
        report += f"{status_symbol} {req.id}: {req.title}\n"
        report += f"   Status: {status.upper()}\n"
        report += f"   Description: {req.description}\n"
        report += f"   Priority: {req.priority.upper()}\n"
        
        # Add WAF evidence
        report += "   Evidence from WAF Assessment:\n"
        for waf_q in req.waf_questions:
            waf_result = req_data['waf_results'].get(waf_q, {})
            compliant = waf_result.get('compliant', False)
            result_symbol = '✅' if compliant else '❌'
            report += f"      {result_symbol} {waf_q}: {waf_result.get('question', 'N/A')}\n"
        
        report += "\n"
    
    return report

