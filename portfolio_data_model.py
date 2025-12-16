"""
Portfolio Assessment Data Model and Utilities
Handles multi-account assessment structure and operations
"""

from typing import Dict, List, Optional
from datetime import datetime
import streamlit as st


def create_portfolio_assessment(
    name: str,
    workload_name: str,
    accounts: List[Dict],
    environment: str = "Production",
    assessment_type: str = "Comprehensive"
) -> Dict:
    """
    Create a new portfolio assessment for multiple AWS accounts
    
    Args:
        name: Assessment name (e.g., "Q4 2024 Production Portfolio")
        workload_name: Workload description
        accounts: List of account configurations
        environment: Environment type
        assessment_type: Assessment type
    
    Returns:
        Portfolio assessment dictionary
    """
    
    assessment_id = f"portfolio_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    return {
        # Basic metadata
        'id': assessment_id,
        'name': name,
        'workload_name': workload_name,
        'type': assessment_type,
        'environment': environment,
        'created_at': datetime.now().isoformat(),
        'updated_at': datetime.now().isoformat(),
        
        # Portfolio flag
        'is_portfolio': True,
        
        # Multiple accounts configuration
        'accounts': accounts,
        
        # AWS scan results per account
        'scan_results_by_account': {},
        'auto_detected_by_account': {},
        
        # Scoring
        'overall_score': 0,
        'progress': 0,
        'scores': {},  # Pillar scores (aggregated)
        'scores_by_account': {},  # Overall score per account
        'pillar_scores_by_account': {},  # Pillar scores per account
        
        # Responses (user answers)
        'responses': {},
        'responses_by_account': {},
        
        # Action items
        'action_items': [],  # Portfolio-wide items
        'action_items_by_account': {},  # Account-specific items
        
        # Auto-detection
        'auto_detected': {},  # Merged auto-detected answers
        'scan_completed_at': None,
        
        # Notes and metadata
        'notes': '',
        'tags': ['portfolio', 'multi-account'],
    }


def add_account_to_portfolio(
    assessment: Dict,
    account_id: str,
    account_name: str,
    role_arn: Optional[str] = None,
    regions: Optional[List[str]] = None,
    priority: str = 'medium'
) -> Dict:
    """
    Add an AWS account to a portfolio assessment
    
    Args:
        assessment: Portfolio assessment dictionary
        account_id: AWS account ID (12 digits)
        account_name: Human-readable account name
        role_arn: IAM role ARN for cross-account access
        regions: List of regions to scan
        priority: Account priority (high/medium/low)
    
    Returns:
        Updated assessment dictionary
    """
    
    if 'accounts' not in assessment:
        assessment['accounts'] = []
    
    # Validate account_id format
    if not account_id.isdigit() or len(account_id) != 12:
        raise ValueError(f"Invalid account ID: {account_id}. Must be 12 digits.")
    
    # Check for duplicates
    existing_ids = [acc['account_id'] for acc in assessment['accounts']]
    if account_id in existing_ids:
        raise ValueError(f"Account {account_id} already exists in portfolio")
    
    account_config = {
        'account_id': account_id,
        'account_name': account_name,
        'priority': priority.lower(),
        'added_at': datetime.now().isoformat(),
    }
    
    if role_arn:
        account_config['role_arn'] = role_arn
    
    if regions:
        account_config['regions'] = regions
    else:
        account_config['regions'] = ['us-east-1']  # Default
    
    assessment['accounts'].append(account_config)
    assessment['updated_at'] = datetime.now().isoformat()
    assessment['is_portfolio'] = True
    
    return assessment


def remove_account_from_portfolio(assessment: Dict, account_id: str) -> Dict:
    """Remove an account from portfolio"""
    
    if 'accounts' not in assessment:
        return assessment
    
    # Remove from accounts list
    assessment['accounts'] = [
        acc for acc in assessment['accounts'] 
        if acc['account_id'] != account_id
    ]
    
    # Clean up account-specific data
    for key in ['scan_results_by_account', 'auto_detected_by_account', 
                'scores_by_account', 'pillar_scores_by_account',
                'action_items_by_account', 'responses_by_account']:
        if key in assessment and account_id in assessment[key]:
            del assessment[key][account_id]
    
    assessment['updated_at'] = datetime.now().isoformat()
    
    # Update portfolio flag
    if len(assessment.get('accounts', [])) <= 1:
        assessment['is_portfolio'] = False
    
    return assessment


def merge_auto_detected_answers(
    auto_detected_by_account: Dict[str, Dict],
    accounts: List[Dict]
) -> Dict:
    """
    Merge auto-detected answers across multiple accounts
    
    Strategy:
    - For each question, select the answer from the highest-priority account
    - If same priority, select answer with highest confidence
    - Scoring: (priority_score * 100) + confidence
    
    Args:
        auto_detected_by_account: Dict mapping account_id -> auto_detected answers
        accounts: List of account configurations with priorities
    
    Returns:
        Merged auto-detected answers dictionary
    """
    
    merged = {}
    
    # Create priority and confidence scoring
    priority_scores = {'high': 3, 'medium': 2, 'low': 1}
    priority_map = {
        acc['account_id']: priority_scores.get(acc.get('priority', 'medium'), 2)
        for acc in accounts
    }
    
    # Get all question IDs across all accounts
    all_question_ids = set()
    for auto_detected in auto_detected_by_account.values():
        if isinstance(auto_detected, dict):
            all_question_ids.update(auto_detected.keys())
    
    # For each question, select best answer
    for qid in all_question_ids:
        best_answer = None
        best_score = -1
        best_account_id = None
        
        for account_id, auto_detected in auto_detected_by_account.items():
            if not isinstance(auto_detected, dict):
                continue
                
            if qid in auto_detected:
                answer = auto_detected[qid]
                
                # Calculate composite score
                priority_score = priority_map.get(account_id, 2)
                confidence = answer.get('confidence', 0)
                total_score = (priority_score * 100) + confidence
                
                if total_score > best_score:
                    best_score = total_score
                    best_answer = answer.copy()
                    best_account_id = account_id
        
        if best_answer:
            # Add source tracking
            best_answer['source_account'] = best_account_id
            best_answer['merged_from_accounts'] = len([
                aid for aid, ad in auto_detected_by_account.items()
                if isinstance(ad, dict) and qid in ad
            ])
            merged[qid] = best_answer
    
    return merged


def calculate_portfolio_scores(
    assessment: Dict,
    scores_by_account: Dict[str, float],
    pillar_scores_by_account: Dict[str, Dict[str, float]]
) -> Dict:
    """
    Calculate aggregated portfolio scores from individual account scores
    
    Uses weighted average based on account priority
    
    Args:
        assessment: Portfolio assessment
        scores_by_account: Dict mapping account_id -> overall score
        pillar_scores_by_account: Dict mapping account_id -> pillar scores
    
    Returns:
        Updated assessment with aggregated scores
    """
    
    accounts = assessment.get('accounts', [])
    if not accounts:
        return assessment
    
    # Priority weights
    priority_weights = {'high': 3, 'medium': 2, 'low': 1}
    
    # Calculate weighted average overall score
    total_weight = 0
    weighted_score_sum = 0
    
    for account in accounts:
        account_id = account['account_id']
        if account_id in scores_by_account:
            weight = priority_weights.get(account.get('priority', 'medium'), 2)
            score = scores_by_account[account_id]
            weighted_score_sum += score * weight
            total_weight += weight
    
    if total_weight > 0:
        assessment['overall_score'] = weighted_score_sum / total_weight
    
    # Calculate weighted pillar scores
    pillar_names = [
        'Operational Excellence',
        'Security',
        'Reliability',
        'Performance Efficiency',
        'Cost Optimization',
        'Sustainability'
    ]
    
    aggregated_pillar_scores = {}
    
    for pillar in pillar_names:
        total_weight = 0
        weighted_pillar_sum = 0
        
        for account in accounts:
            account_id = account['account_id']
            if account_id in pillar_scores_by_account:
                account_pillars = pillar_scores_by_account[account_id]
                if pillar in account_pillars:
                    weight = priority_weights.get(account.get('priority', 'medium'), 2)
                    score = account_pillars[pillar]
                    weighted_pillar_sum += score * weight
                    total_weight += weight
        
        if total_weight > 0:
            aggregated_pillar_scores[pillar] = weighted_pillar_sum / total_weight
    
    assessment['scores'] = aggregated_pillar_scores
    assessment['scores_by_account'] = scores_by_account
    assessment['pillar_scores_by_account'] = pillar_scores_by_account
    assessment['updated_at'] = datetime.now().isoformat()
    
    return assessment


def is_portfolio_assessment(assessment: Dict) -> bool:
    """Check if assessment is a portfolio (multi-account) assessment"""
    
    # Check explicit flag
    if assessment.get('is_portfolio', False):
        return True
    
    # Check accounts array
    accounts = assessment.get('accounts', [])
    if len(accounts) > 1:
        return True
    
    return False


def get_account_names(assessment: Dict) -> List[str]:
    """Get list of account names in portfolio"""
    
    accounts = assessment.get('accounts', [])
    return [acc.get('account_name', acc.get('account_id', 'Unknown')) 
            for acc in accounts]


def get_account_summary(assessment: Dict) -> Dict:
    """Get summary statistics for portfolio"""
    
    accounts = assessment.get('accounts', [])
    scores_by_account = assessment.get('scores_by_account', {})
    
    summary = {
        'total_accounts': len(accounts),
        'high_priority': len([a for a in accounts if a.get('priority') == 'high']),
        'medium_priority': len([a for a in accounts if a.get('priority') == 'medium']),
        'low_priority': len([a for a in accounts if a.get('priority') == 'low']),
        'scanned_accounts': len([aid for aid in scores_by_account if scores_by_account[aid] > 0]),
        'pending_accounts': len(accounts) - len([aid for aid in scores_by_account if scores_by_account[aid] > 0]),
    }
    
    return summary


# Example Usage
if __name__ == "__main__":
    # Create portfolio
    accounts = [
        {
            'account_id': '123456789012',
            'account_name': 'Production Main',
            'role_arn': 'arn:aws:iam::123456789012:role/WAFAdvisorRole',
            'regions': ['us-east-1', 'us-west-2'],
            'priority': 'high'
        },
        {
            'account_id': '234567890123',
            'account_name': 'Production DR',
            'role_arn': 'arn:aws:iam::234567890123:role/WAFAdvisorRole',
            'regions': ['eu-west-1'],
            'priority': 'medium'
        },
    ]
    
    portfolio = create_portfolio_assessment(
        name="Q4 2024 Production Portfolio",
        workload_name="Multi-Account Production Environment",
        accounts=accounts,
        environment="Production"
    )
    
    print(f"Created portfolio: {portfolio['name']}")
    print(f"Accounts: {len(portfolio['accounts'])}")
