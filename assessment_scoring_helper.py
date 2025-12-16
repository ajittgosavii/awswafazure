"""
Assessment Scoring Helper Module
Calculates scores and updates assessment after each response

This fixes the issue where responses are saved but scores show as 0
"""

from typing import Dict, List
from datetime import datetime


def calculate_assessment_scores(assessment: Dict, questions: List) -> None:
    """
    Calculate and update all scores in the assessment
    
    This function:
    1. Calculates overall score based on responses
    2. Calculates pillar scores
    3. Updates progress percentage (correctly!)
    4. Generates action items based on risk levels
    
    Args:
        assessment: The assessment dictionary
        questions: List of all Question objects
    """
    responses = assessment.get('responses', {})
    
    if not responses:
        assessment['overall_score'] = 0
        assessment['progress'] = 0
        assessment['scores'] = {}
        assessment['action_items'] = []
        return
    
    # ============================================================================
    # 1. CALCULATE OVERALL SCORE
    # ============================================================================
    total_points = 0
    max_points = 0
    
    for question in questions:
        if question.id in responses:
            response = responses[question.id]
            # Response has 'points' directly stored
            total_points += response.get('points', 0)
        max_points += 100  # Each question is worth 100 points max
    
    overall_score = (total_points / max_points * 100) if max_points > 0 else 0
    assessment['overall_score'] = round(overall_score, 1)
    
    # ============================================================================
    # 2. CALCULATE PILLAR SCORES - FIXED!
    # ============================================================================
    # Import Pillar enum
    try:
        from waf_review_module import Pillar
    except:
        # Fallback if import fails
        class Pillar:
            class Enum:
                pass
            OPERATIONAL_EXCELLENCE = "Operational Excellence"
            SECURITY = "Security"
            RELIABILITY = "Reliability"
            PERFORMANCE_EFFICIENCY = "Performance Efficiency"
            COST_OPTIMIZATION = "Cost Optimization"
            SUSTAINABILITY = "Sustainability"
    
    pillar_scores = {}
    
    # FIX: Iterate through Pillar enum properly
    for pillar in Pillar:
        # Get questions for this pillar - compare by value, not object
        pillar_questions = [q for q in questions if q.pillar.value == pillar.value]
        
        if not pillar_questions:
            pillar_scores[pillar.value] = 0
            continue
        
        pillar_points = 0
        pillar_max = 0
        
        for question in pillar_questions:
            if question.id in responses:
                response = responses[question.id]
                pillar_points += response.get('points', 0)
            pillar_max += 100
        
        pillar_score = (pillar_points / pillar_max * 100) if pillar_max > 0 else 0
        pillar_scores[pillar.value] = round(pillar_score, 1)
    
    assessment['scores'] = pillar_scores
    
    # ============================================================================
    # 3. CALCULATE CORRECT PROGRESS
    # ============================================================================
    total_questions = len(questions)
    answered_questions = len(responses)
    
    progress = (answered_questions / total_questions * 100) if total_questions > 0 else 0
    assessment['progress'] = round(progress, 1)
    
    # ============================================================================
    # 4. UPDATE METADATA
    # ============================================================================
    assessment['questions_answered'] = answered_questions
    assessment['questions_total'] = total_questions
    assessment['updated_at'] = datetime.now().isoformat()
    
    # ============================================================================
    # 5. GENERATE ACTION ITEMS - FIXED LOGIC!
    # ============================================================================
    # ALWAYS generate action items if assessment is complete or near-complete
    # Don't restrict based on overall score - risk items exist regardless of score
    if progress > 80:  # If >80% done, generate action items
        generate_action_items(assessment, questions)


def generate_action_items(assessment: Dict, questions: List) -> None:
    """
    Generate action items based on responses
    
    Generates action items for:
    - CRITICAL risks (priority 1)
    - HIGH risks (priority 2)  
    - MEDIUM risks (priority 3)
    
    Args:
        assessment: The assessment dictionary
        questions: List of all Question objects
    """
    responses = assessment.get('responses', {})
    action_items = []
    
    for question in questions:
        if question.id in responses:
            response = responses[question.id]
            risk_level = response.get('risk_level', 'NONE')
            
            # FIX: Use case-insensitive comparison (risk_level is stored as "High", not "HIGH")
            risk_level_upper = risk_level.upper() if isinstance(risk_level, str) else str(risk_level).upper()
            
            # Generate action items for CRITICAL, HIGH, and MEDIUM risks
            if risk_level_upper in ['CRITICAL', 'HIGH', 'MEDIUM']:
                # Get question details
                question_text = question.text if hasattr(question, 'text') else 'Unknown Question'
                question_desc = question.description if hasattr(question, 'description') else ''
                question_pillar = question.pillar.value if hasattr(question, 'pillar') else 'Unknown'
                
                # Determine priority
                if risk_level_upper == 'CRITICAL':
                    priority = 1
                    effort = '1-2 weeks'
                    cost = '$$$$'
                elif risk_level_upper == 'HIGH':
                    priority = 2
                    effort = '1 week'
                    cost = '$$$'
                else:  # MEDIUM
                    priority = 3
                    effort = '2-3 days'
                    cost = '$$'
                
                action_item = {
                    'id': f"action_{question.id}",
                    'question_id': question.id,
                    'title': f"Improve: {question_text[:60]}..." if len(question_text) > 60 else f"Improve: {question_text}",
                    'description': question_desc,
                    'risk_level': risk_level,
                    'pillar': question_pillar,
                    'status': 'Open',
                    'priority': priority,
                    'estimated_effort': effort,
                    'estimated_cost': cost,
                    'choice_selected': response.get('choice_text', ''),
                    'notes': response.get('notes', ''),
                    'created_at': datetime.now().isoformat()
                }
                action_items.append(action_item)
    
    # Sort by priority (CRITICAL first)
    action_items.sort(key=lambda x: x['priority'])
    
    # Update assessment
    assessment['action_items'] = action_items
    
    # Add summary statistics
    assessment['action_items_summary'] = {
        'total': len(action_items),
        'critical': sum(1 for item in action_items if item['risk_level'] == 'CRITICAL'),
        'high': sum(1 for item in action_items if item['risk_level'] == 'HIGH'),
        'medium': sum(1 for item in action_items if item['risk_level'] == 'MEDIUM')
    }


def get_score_color(score: float) -> str:
    """Get color for score display"""
    if score >= 80:
        return '#28a745'  # Green
    elif score >= 60:
        return '#ffc107'  # Yellow
    elif score >= 40:
        return '#fd7e14'  # Orange
    else:
        return '#dc3545'  # Red


def get_score_status(score: float) -> str:
    """Get status text for score"""
    if score >= 80:
        return 'EXCELLENT'
    elif score >= 60:
        return 'GOOD'
    elif score >= 40:
        return 'NEEDS IMPROVEMENT'
    else:
        return 'CRITICAL'


# Export all functions
__all__ = [
    'calculate_assessment_scores',
    'generate_action_items',
    'get_score_color',
    'get_score_status'
]