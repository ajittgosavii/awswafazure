"""
AI Insights Generator for WAF Assessments
Generates comprehensive, pillar-wise insights using Claude AI

Features:
- Pillar-wise analysis
- Strengths and weaknesses identification
- Actionable recommendations
- Risk prioritization
- Implementation guidance
"""

import streamlit as st
from typing import Dict, List, Tuple
import json

def generate_comprehensive_insights(assessment: Dict, questions: List) -> Dict:
    """
    Generate comprehensive AI insights for the assessment
    
    Args:
        assessment: Assessment data with responses
        questions: List of all Question objects
        
    Returns:
        Dictionary with insights organized by pillar
    """
    
    # Check if Anthropic is available and get API key
    try:
        import anthropic
        
        # Try multiple locations for API key (support different formats)
        api_key = None
        
        # Format 1: Root level ANTHROPIC_API_KEY
        if "ANTHROPIC_API_KEY" in st.secrets:
            api_key = st.secrets["ANTHROPIC_API_KEY"]
        
        # Format 2: Under [anthropic] section
        elif "anthropic" in st.secrets:
            if "ANTHROPIC_API_KEY" in st.secrets["anthropic"]:
                api_key = st.secrets["anthropic"]["ANTHROPIC_API_KEY"]
            elif "api_key" in st.secrets["anthropic"]:
                api_key = st.secrets["anthropic"]["api_key"]
        
        # Format 3: Check environment variable as fallback
        if not api_key:
            import os
            api_key = os.environ.get("ANTHROPIC_API_KEY")
        
        if not api_key:
            return {"error": "Anthropic API key not configured. Add ANTHROPIC_API_KEY to Streamlit secrets."}
        
        client = anthropic.Anthropic(api_key=api_key)
    except Exception as e:
        return {"error": f"Anthropic API error: {str(e)}"}
    
    # Prepare assessment data for AI analysis
    analysis_data = prepare_assessment_data(assessment, questions)
    
    # Generate insights using Claude
    try:
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=4000,
            messages=[{
                "role": "user",
                "content": f"""You are an AWS Well-Architected Framework expert. Analyze this assessment and provide comprehensive insights.

Assessment Data:
{json.dumps(analysis_data, indent=2)}

Provide a detailed analysis in the following JSON format:
{{
    "executive_summary": "2-3 paragraph summary of overall assessment",
    "overall_strengths": ["list of 3-5 key strengths"],
    "overall_weaknesses": ["list of 3-5 critical areas needing attention"],
    "pillars": {{
        "Operational Excellence": {{
            "score": {analysis_data['pillar_scores'].get('Operational Excellence', 0)},
            "status": "Excellent/Good/Needs Improvement/Critical",
            "strengths": ["specific strengths in this pillar"],
            "weaknesses": ["specific weaknesses in this pillar"],
            "recommendations": [
                {{
                    "title": "Recommendation title",
                    "description": "Detailed description",
                    "impact": "High/Medium/Low",
                    "effort": "High/Medium/Low",
                    "priority": "Critical/High/Medium/Low"
                }}
            ]
        }},
        "Security": {{ ... similar structure ... }},
        "Reliability": {{ ... }},
        "Performance Efficiency": {{ ... }},
        "Cost Optimization": {{ ... }},
        "Sustainability": {{ ... }}
    }},
    "quick_wins": ["list of 3-5 quick wins that can be implemented immediately"],
    "long_term_initiatives": ["list of 3-5 strategic initiatives"],
    "risk_summary": {{
        "critical_risks": ["list of critical risks identified"],
        "high_risks": ["list of high priority risks"],
        "medium_risks": ["list of medium priority risks"]
    }}
}}

Focus on:
1. Specific findings based on the actual responses
2. Actionable recommendations with clear next steps
3. Business impact and technical rationale
4. AWS best practices and services that can help
5. Prioritization based on risk and impact

Respond ONLY with valid JSON, no other text."""
            }]
        )
        
        # Parse the response
        insights_text = response.content[0].text
        
        # Extract JSON from response (in case there's any wrapper text)
        start_idx = insights_text.find('{')
        end_idx = insights_text.rfind('}') + 1
        if start_idx != -1 and end_idx > start_idx:
            insights_json = insights_text[start_idx:end_idx]
            insights = json.loads(insights_json)
            return insights
        else:
            return {"error": "Failed to parse AI response"}
            
    except Exception as e:
        return {"error": f"AI generation failed: {str(e)}"}


def prepare_assessment_data(assessment: Dict, questions: List) -> Dict:
    """
    Prepare assessment data for AI analysis
    
    Args:
        assessment: Assessment data
        questions: List of questions
        
    Returns:
        Structured data for AI analysis
    """
    
    responses = assessment.get('responses', {})
    
    # Organize responses by pillar
    pillar_data = {}
    
    for question in questions:
        pillar_name = question.pillar.value
        
        if pillar_name not in pillar_data:
            pillar_data[pillar_name] = {
                'total_questions': 0,
                'answered_questions': 0,
                'high_risk_answers': 0,
                'medium_risk_answers': 0,
                'low_risk_answers': 0,
                'sample_answers': []
            }
        
        pillar_data[pillar_name]['total_questions'] += 1
        
        if question.id in responses:
            pillar_data[pillar_name]['answered_questions'] += 1
            response = responses[question.id]
            
            # Get the choice text
            choice_index = response.get('choice_index', 0)
            if 0 <= choice_index < len(question.choices):
                choice = question.choices[choice_index]
                risk_level = choice.risk_level.label if hasattr(choice.risk_level, 'label') else str(choice.risk_level)
                
                # Count risk levels
                if 'High' in risk_level or 'Critical' in risk_level:
                    pillar_data[pillar_name]['high_risk_answers'] += 1
                elif 'Medium' in risk_level:
                    pillar_data[pillar_name]['medium_risk_answers'] += 1
                else:
                    pillar_data[pillar_name]['low_risk_answers'] += 1
                
                # Add sample (first 3 high-risk questions per pillar)
                if len(pillar_data[pillar_name]['sample_answers']) < 3:
                    if 'High' in risk_level or 'Medium' in risk_level:
                        pillar_data[pillar_name]['sample_answers'].append({
                            'question': question.text[:100] + '...' if len(question.text) > 100 else question.text,
                            'answer': choice.text[:100] + '...' if len(choice.text) > 100 else choice.text,
                            'risk': risk_level
                        })
    
    return {
        'assessment_name': assessment.get('name', 'Unnamed Assessment'),
        'workload_name': assessment.get('workload_name', 'N/A'),
        'environment': assessment.get('environment', 'N/A'),
        'progress': assessment.get('progress', 0),
        'overall_score': assessment.get('overall_score', 0),
        'pillar_scores': assessment.get('scores', {}),
        'total_responses': len(responses),
        'pillar_data': pillar_data,
        'assessment_type': assessment.get('type', 'Standard')
    }


def format_insights_for_display(insights: Dict) -> None:
    """
    Format and display AI insights in Streamlit
    
    Args:
        insights: Insights dictionary from AI
    """
    
    if 'error' in insights:
        st.error(f"❌ {insights['error']}")
        return
    
    # Executive Summary
    st.markdown("## 📊 Executive Summary")
    st.markdown(insights.get('executive_summary', 'No summary available'))
    
    st.divider()
    
    # Overall Assessment
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### ✅ Key Strengths")
        for strength in insights.get('overall_strengths', []):
            st.success(f"✓ {strength}")
    
    with col2:
        st.markdown("### ⚠️ Areas for Improvement")
        for weakness in insights.get('overall_weaknesses', []):
            st.warning(f"→ {weakness}")
    
    st.divider()
    
    # Pillar-wise Analysis
    st.markdown("## 🎯 Pillar-wise Deep Dive")
    
    pillars = insights.get('pillars', {})
    
    for pillar_name, pillar_data in pillars.items():
        with st.expander(f"### {get_pillar_emoji(pillar_name)} {pillar_name} - {pillar_data.get('status', 'N/A')}", expanded=False):
            
            # Pillar score and status
            col_score, col_status = st.columns([1, 2])
            with col_score:
                score = pillar_data.get('score', 0)
                st.metric("Pillar Score", f"{score}/100")
            with col_status:
                status = pillar_data.get('status', 'Unknown')
                status_color = get_status_color(status)
                st.markdown(f"**Status:** :{status_color}[{status}]")
            
            st.markdown("---")
            
            # Strengths
            if pillar_data.get('strengths'):
                st.markdown("**💪 Strengths:**")
                for strength in pillar_data['strengths']:
                    st.markdown(f"- ✓ {strength}")
            
            # Weaknesses
            if pillar_data.get('weaknesses'):
                st.markdown("**⚠️ Areas Needing Attention:**")
                for weakness in pillar_data['weaknesses']:
                    st.markdown(f"- → {weakness}")
            
            # Recommendations
            if pillar_data.get('recommendations'):
                st.markdown("**🎯 Recommendations:**")
                for idx, rec in enumerate(pillar_data['recommendations'], 1):
                    with st.container():
                        priority_emoji = {
                            'Critical': '🔴',
                            'High': '🟠',
                            'Medium': '🟡',
                            'Low': '🟢'
                        }.get(rec.get('priority', 'Medium'), '🟡')
                        
                        st.markdown(f"{priority_emoji} **{idx}. {rec.get('title', 'Recommendation')}**")
                        st.markdown(f"   {rec.get('description', 'No description')}")
                        
                        col_i, col_e, col_p = st.columns(3)
                        with col_i:
                            st.caption(f"Impact: **{rec.get('impact', 'N/A')}**")
                        with col_e:
                            st.caption(f"Effort: **{rec.get('effort', 'N/A')}**")
                        with col_p:
                            st.caption(f"Priority: **{rec.get('priority', 'N/A')}**")
    
    st.divider()
    
    # Quick Wins
    st.markdown("## ⚡ Quick Wins (Start Here!)")
    st.info("These can be implemented quickly with high impact:")
    quick_wins = insights.get('quick_wins', [])
    for idx, win in enumerate(quick_wins, 1):
        st.markdown(f"{idx}. ✨ {win}")
    
    st.divider()
    
    # Long-term Initiatives
    st.markdown("## 🚀 Strategic Initiatives")
    st.info("Plan these for long-term improvement:")
    initiatives = insights.get('long_term_initiatives', [])
    for idx, initiative in enumerate(initiatives, 1):
        st.markdown(f"{idx}. 🎯 {initiative}")
    
    st.divider()
    
    # Risk Summary
    st.markdown("## ⚠️ Risk Summary")
    risk_summary = insights.get('risk_summary', {})
    
    col_r1, col_r2, col_r3 = st.columns(3)
    
    with col_r1:
        st.markdown("### 🔴 Critical Risks")
        critical = risk_summary.get('critical_risks', [])
        if critical:
            for risk in critical:
                st.error(f"→ {risk}")
        else:
            st.success("✓ No critical risks")
    
    with col_r2:
        st.markdown("### 🟠 High Priority")
        high = risk_summary.get('high_risks', [])
        if high:
            for risk in high:
                st.warning(f"→ {risk}")
        else:
            st.success("✓ No high risks")
    
    with col_r3:
        st.markdown("### 🟡 Medium Priority")
        medium = risk_summary.get('medium_risks', [])
        if medium:
            for risk in medium:
                st.info(f"→ {risk}")
        else:
            st.success("✓ No medium risks")


def get_pillar_emoji(pillar_name: str) -> str:
    """Get emoji for pillar"""
    emoji_map = {
        'Operational Excellence': '⚙️',
        'Security': '🔒',
        'Reliability': '🛡️',
        'Performance Efficiency': '⚡',
        'Cost Optimization': '💰',
        'Sustainability': '🌱'
    }
    return emoji_map.get(pillar_name, '📊')


def get_status_color(status: str) -> str:
    """Get color for status"""
    color_map = {
        'Excellent': 'green',
        'Good': 'blue',
        'Needs Improvement': 'orange',
        'Critical': 'red'
    }
    return color_map.get(status, 'gray')