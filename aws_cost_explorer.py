"""
AWS Cost Explorer Service Integration
"""

import streamlit as st
from typing import Dict, List, Optional
from datetime import datetime, timedelta
import boto3
from botocore.exceptions import ClientError

class CostExplorerService:
    """Cost Explorer operations"""
    
    def __init__(self, session: boto3.Session):
        """Initialize Cost Explorer service"""
        self.session = session
        # Cost Explorer is always in us-east-1
        self.client = session.client('ce', region_name='us-east-1')
    
    def get_monthly_cost(_self, months: int = 1) -> Dict:
        """Get monthly cost"""
        try:
            end_date = datetime.now().date()
            start_date = end_date - timedelta(days=30 * months)
            
            response = _self.client.get_cost_and_usage(
                TimePeriod={
                    'Start': start_date.isoformat(),
                    'End': end_date.isoformat()
                },
                Granularity='MONTHLY',
                Metrics=['UnblendedCost']
            )
            
            total_cost = 0
            for result in response['ResultsByTime']:
                amount = float(result['Total']['UnblendedCost']['Amount'])
                total_cost += amount
            
            return {
                'success': True,
                'total_cost': total_cost,
                'currency': 'USD',
                'period': f"Last {months} month(s)"
            }
            
        except ClientError as e:
            return {
                'success': False,
                'error': str(e),
                'total_cost': 0
            }
    
    def get_cost_by_service(_self, days: int = 30) -> Dict:
        """Get cost breakdown by service"""
        try:
            end_date = datetime.now().date()
            start_date = end_date - timedelta(days=days)
            
            response = _self.client.get_cost_and_usage(
                TimePeriod={
                    'Start': start_date.isoformat(),
                    'End': end_date.isoformat()
                },
                Granularity='MONTHLY',
                Metrics=['UnblendedCost'],
                GroupBy=[
                    {'Type': 'DIMENSION', 'Key': 'SERVICE'}
                ]
            )
            
            costs_by_service = {}
            for result in response['ResultsByTime']:
                for group in result['Groups']:
                    service = group['Keys'][0]
                    amount = float(group['Metrics']['UnblendedCost']['Amount'])
                    costs_by_service[service] = costs_by_service.get(service, 0) + amount
            
            # Sort by cost descending
            sorted_costs = dict(sorted(costs_by_service.items(), key=lambda x: x[1], reverse=True))
            
            return {
                'success': True,
                'costs': sorted_costs,
                'total': sum(sorted_costs.values())
            }
            
        except ClientError as e:
            return {
                'success': False,
                'error': str(e),
                'costs': {}
            }
    
    def get_cost_trend(_self, days: int = 30) -> Dict:
        """Get daily cost trend"""
        try:
            end_date = datetime.now().date()
            start_date = end_date - timedelta(days=days)
            
            response = _self.client.get_cost_and_usage(
                TimePeriod={
                    'Start': start_date.isoformat(),
                    'End': end_date.isoformat()
                },
                Granularity='DAILY',
                Metrics=['UnblendedCost']
            )
            
            daily_costs = []
            for result in response['ResultsByTime']:
                daily_costs.append({
                    'date': result['TimePeriod']['Start'],
                    'cost': float(result['Total']['UnblendedCost']['Amount'])
                })
            
            return {
                'success': True,
                'daily_costs': daily_costs
            }
            
        except ClientError as e:
            return {
                'success': False,
                'error': str(e),
                'daily_costs': []
            }
    
    def get_cost_forecast(_self, days: int = 30) -> Dict:
        """Get cost forecast"""
        try:
            start_date = datetime.now().date()
            end_date = start_date + timedelta(days=days)
            
            response = _self.client.get_cost_forecast(
                TimePeriod={
                    'Start': start_date.isoformat(),
                    'End': end_date.isoformat()
                },
                Metric='UNBLENDED_COST',
                Granularity='MONTHLY'
            )
            
            forecast = float(response['Total']['Amount'])
            
            return {
                'success': True,
                'forecast': forecast,
                'currency': 'USD'
            }
            
        except ClientError as e:
            return {
                'success': False,
                'error': str(e),
                'forecast': 0
            }
    
    def get_cost_by_account(_self, days: int = 30) -> Dict:
        """
        Get cost breakdown by linked account (for AWS Organizations)
        This will show costs for all accounts in the organization
        """
        try:
            end_date = datetime.now().date()
            start_date = end_date - timedelta(days=days)
            
            response = _self.client.get_cost_and_usage(
                TimePeriod={
                    'Start': start_date.isoformat(),
                    'End': end_date.isoformat()
                },
                Granularity='MONTHLY',
                Metrics=['UnblendedCost'],
                GroupBy=[
                    {'Type': 'DIMENSION', 'Key': 'LINKED_ACCOUNT'}
                ]
            )
            
            costs_by_account = {}
            account_names = {}  # Map account IDs to friendly names
            
            for result in response['ResultsByTime']:
                for group in result['Groups']:
                    account_id = group['Keys'][0]
                    amount = float(group['Metrics']['UnblendedCost']['Amount'])
                    
                    if amount > 0:  # Only include accounts with costs
                        costs_by_account[account_id] = costs_by_account.get(account_id, 0) + amount
            
            # Try to get account names from Organizations API
            try:
                org_client = _self.session.client('organizations', region_name='us-east-1')
                accounts_response = org_client.list_accounts()
                
                for account in accounts_response['Accounts']:
                    account_id = account['Id']
                    account_name = account['Name']
                    if account_id in costs_by_account:
                        account_names[account_id] = f"{account_name} ({account_id})"
            except Exception as org_error:
                # If Organizations API not available, just use account IDs
                st.warning(f"Could not fetch account names from Organizations API: {org_error}")
                for account_id in costs_by_account.keys():
                    account_names[account_id] = account_id
            
            # Create final dict with account names
            costs_with_names = {}
            for account_id, cost in costs_by_account.items():
                name = account_names.get(account_id, account_id)
                costs_with_names[name] = cost
            
            # Sort by cost descending
            sorted_costs = dict(sorted(costs_with_names.items(), key=lambda x: x[1], reverse=True))
            
            return {
                'success': True,
                'costs': sorted_costs,
                'total': sum(sorted_costs.values()),
                'account_count': len(sorted_costs)
            }
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            
            # If this is not an Organizations account, return helpful message
            if error_code == 'InvalidDimensionValue':
                return {
                    'success': False,
                    'error': 'This account is not part of AWS Organizations or does not have linked accounts',
                    'costs': {},
                    'total': 0
                }
            
            return {
                'success': False,
                'error': str(e),
                'costs': {},
                'total': 0
            }
