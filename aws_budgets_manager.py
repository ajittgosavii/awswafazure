import streamlit as st
"""
AWS Budgets Integration
Fetches budget data and utilization from AWS Budgets API
"""

import boto3
from typing import Dict, List
from datetime import datetime
from botocore.exceptions import ClientError
from decimal import Decimal


class AWSBudgetsManager:
    """Manage AWS Budgets integration"""
    
    def __init__(self, session: boto3.Session):
        """Initialize budgets manager"""
        self.session = session
        self.account_id = session.client('sts').get_caller_identity()['Account']
        self.budgets_client = session.client('budgets', region_name='us-east-1')
    
    def get_all_budgets(self) -> List[Dict]:
        """Get all budgets for the account"""
        try:
            response = self.budgets_client.describe_budgets(
                AccountId=self.account_id
            )
            
            budgets = []
            for budget in response.get('Budgets', []):
                budget_data = self._process_budget(budget)
                budgets.append(budget_data)
            
            return budgets
            
        except ClientError as e:
            print(f"Error fetching budgets: {e}")
            return []
    
    def _process_budget(self, budget: Dict) -> Dict:
        """Process raw budget data into usable format"""
        budget_name = budget.get('BudgetName', 'Unknown')
        budget_type = budget.get('BudgetType', 'COST')
        time_unit = budget.get('TimeUnit', 'MONTHLY')
        
        # Get budget limit
        budget_limit = budget.get('BudgetLimit', {})
        limit_amount = float(budget_limit.get('Amount', 0))
        limit_unit = budget_limit.get('Unit', 'USD')
        
        # Get calculated spend
        calculated_spend = budget.get('CalculatedSpend', {})
        actual_spend = calculated_spend.get('ActualSpend', {})
        forecasted_spend = calculated_spend.get('ForecastedSpend', {})
        
        actual_amount = float(actual_spend.get('Amount', 0))
        forecasted_amount = float(forecasted_spend.get('Amount', 0))
        
        # Calculate utilization
        utilization = (actual_amount / limit_amount * 100) if limit_amount > 0 else 0
        forecasted_utilization = (forecasted_amount / limit_amount * 100) if limit_amount > 0 else 0
        
        # Determine status
        if utilization >= 100:
            status = 'EXCEEDED'
            status_color = 'red'
        elif utilization >= 80:
            status = 'WARNING'
            status_color = 'orange'
        elif forecasted_utilization >= 100:
            status = 'FORECASTED_EXCEED'
            status_color = 'yellow'
        else:
            status = 'OK'
            status_color = 'green'
        
        return {
            'name': budget_name,
            'type': budget_type,
            'time_unit': time_unit,
            'limit_amount': limit_amount,
            'limit_unit': limit_unit,
            'actual_amount': actual_amount,
            'forecasted_amount': forecasted_amount,
            'utilization': utilization,
            'forecasted_utilization': forecasted_utilization,
            'status': status,
            'status_color': status_color,
            'remaining': max(0, limit_amount - actual_amount),
            'over_budget': max(0, actual_amount - limit_amount)
        }
    
    def get_budget_alerts(self, budget_name: str) -> List[Dict]:
        """Get alerts configured for a specific budget"""
        try:
            response = self.budgets_client.describe_notifications_for_budget(
                AccountId=self.account_id,
                BudgetName=budget_name
            )
            
            alerts = []
            for notification in response.get('Notifications', []):
                alert = {
                    'type': notification.get('NotificationType', 'ACTUAL'),
                    'comparison': notification.get('ComparisonOperator', 'GREATER_THAN'),
                    'threshold': notification.get('Threshold', 0),
                    'threshold_type': notification.get('ThresholdType', 'PERCENTAGE')
                }
                alerts.append(alert)
            
            return alerts
            
        except ClientError as e:
            print(f"Error fetching alerts for {budget_name}: {e}")
            return []
    
    def get_budget_summary(self) -> Dict:
        """Get summary of all budgets"""
        budgets = self.get_all_budgets()
        
        if not budgets:
            return {
                'total_budgets': 0,
                'total_limit': 0,
                'total_actual': 0,
                'total_forecasted': 0,
                'budgets_exceeded': 0,
                'budgets_warning': 0,
                'budgets_ok': 0,
                'overall_utilization': 0
            }
        
        total_limit = sum(b['limit_amount'] for b in budgets if b['type'] == 'COST')
        total_actual = sum(b['actual_amount'] for b in budgets if b['type'] == 'COST')
        total_forecasted = sum(b['forecasted_amount'] for b in budgets if b['type'] == 'COST')
        
        budgets_exceeded = len([b for b in budgets if b['status'] == 'EXCEEDED'])
        budgets_warning = len([b for b in budgets if b['status'] == 'WARNING'])
        budgets_ok = len([b for b in budgets if b['status'] == 'OK'])
        
        overall_utilization = (total_actual / total_limit * 100) if total_limit > 0 else 0
        
        return {
            'total_budgets': len(budgets),
            'total_limit': total_limit,
            'total_actual': total_actual,
            'total_forecasted': total_forecasted,
            'budgets_exceeded': budgets_exceeded,
            'budgets_warning': budgets_warning,
            'budgets_ok': budgets_ok,
            'overall_utilization': overall_utilization,
            'budgets': budgets
        }


@st.cache_data(ttl=300)  # 5 min cache for Live mode
def get_budgets_from_aws(session: boto3.Session) -> Dict:
    """
    Main function to get budget data from AWS
    This replaces the "not integrated" message in Live mode
    """
    manager = AWSBudgetsManager(session)
    summary = manager.get_budget_summary()
    
    return {
        'has_budgets': summary['total_budgets'] > 0,
        'total_budgets': summary['total_budgets'],
        'total_limit': summary['total_limit'],
        'total_actual': summary['total_actual'],
        'total_forecasted': summary['total_forecasted'],
        'budgets_exceeded': summary['budgets_exceeded'],
        'budgets_warning': summary['budgets_warning'],
        'budgets_ok': summary['budgets_ok'],
        'overall_utilization': summary['overall_utilization'],
        'budgets': summary.get('budgets', []),
        'last_updated': datetime.now().isoformat()
    }
