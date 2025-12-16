"""
AWS CloudWatch Integration - Observability & Monitoring
Supports metrics, logs, alarms, dashboards, and insights
"""

import streamlit as st
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from core_account_manager import get_account_manager

class CloudWatchManager:
    """AWS CloudWatch Monitoring and Logging"""
    
    def __init__(self, session):
        """Initialize CloudWatch manager with boto3 session"""
        self.cloudwatch = session.client('cloudwatch')
        self.logs = session.client('logs')
        self.events = session.client('events')
    
    # ============= METRICS =============
    
    def list_metrics(self, namespace: Optional[str] = None, 
                    metric_name: Optional[str] = None) -> List[Dict[str, Any]]:
        """List CloudWatch metrics"""
        try:
            params = {}
            if namespace:
                params['Namespace'] = namespace
            if metric_name:
                params['MetricName'] = metric_name
            
            metrics = []
            paginator = self.cloudwatch.get_paginator('list_metrics')
            
            for page in paginator.paginate(**params):
                for metric in page['Metrics']:
                    metrics.append({
                        'namespace': metric['Namespace'],
                        'metric_name': metric['MetricName'],
                        'dimensions': metric.get('Dimensions', [])
                    })
            
            return metrics
        except Exception as e:
            st.error(f"Error listing metrics: {str(e)}")
            return []
    
    def get_metric_statistics(self, namespace: str, metric_name: str,
                             start_time: datetime, end_time: datetime,
                             period: int = 300, statistics: List[str] = ['Average'],
                             dimensions: List[Dict] = None) -> Dict[str, Any]:
        """Get metric statistics over a time period"""
        try:
            params = {
                'Namespace': namespace,
                'MetricName': metric_name,
                'StartTime': start_time,
                'EndTime': end_time,
                'Period': period,
                'Statistics': statistics
            }
            
            if dimensions:
                params['Dimensions'] = dimensions
            
            response = self.cloudwatch.get_metric_statistics(**params)
            
            datapoints = sorted(response.get('Datapoints', []), 
                              key=lambda x: x['Timestamp'])
            
            return {
                'label': response.get('Label', metric_name),
                'datapoints': [{
                    'timestamp': dp['Timestamp'].strftime('%Y-%m-%d %H:%M:%S'),
                    'average': dp.get('Average', 0),
                    'sum': dp.get('Sum', 0),
                    'minimum': dp.get('Minimum', 0),
                    'maximum': dp.get('Maximum', 0),
                    'sample_count': dp.get('SampleCount', 0),
                    'unit': dp.get('Unit', 'None')
                } for dp in datapoints]
            }
        except Exception as e:
            st.error(f"Error getting metric statistics: {str(e)}")
            return {'label': '', 'datapoints': []}
    
    def put_metric_data(self, namespace: str, metric_name: str, 
                       value: float, unit: str = 'None',
                       dimensions: List[Dict] = None) -> Dict[str, Any]:
        """Put custom metric data"""
        try:
            metric_data = {
                'MetricName': metric_name,
                'Value': value,
                'Unit': unit,
                'Timestamp': datetime.utcnow()
            }
            
            if dimensions:
                metric_data['Dimensions'] = dimensions
            
            self.cloudwatch.put_metric_data(
                Namespace=namespace,
                MetricData=[metric_data]
            )
            
            return {
                'success': True,
                'message': f'Metric {metric_name} published'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    # ============= ALARMS =============
    
    def list_alarms(self, state_value: Optional[str] = None) -> List[Dict[str, Any]]:
        """List CloudWatch alarms"""
        try:
            params = {}
            if state_value:
                params['StateValue'] = state_value
            
            alarms = []
            paginator = self.cloudwatch.get_paginator('describe_alarms')
            
            for page in paginator.paginate(**params):
                for alarm in page['MetricAlarms']:
                    alarms.append({
                        'alarm_name': alarm['AlarmName'],
                        'alarm_arn': alarm['AlarmArn'],
                        'description': alarm.get('AlarmDescription', ''),
                        'state': alarm['StateValue'],
                        'state_reason': alarm.get('StateReason', ''),
                        'metric_name': alarm.get('MetricName', ''),
                        'namespace': alarm.get('Namespace', ''),
                        'statistic': alarm.get('Statistic', ''),
                        'threshold': alarm.get('Threshold', 0),
                        'comparison_operator': alarm.get('ComparisonOperator', ''),
                        'evaluation_periods': alarm.get('EvaluationPeriods', 0),
                        'actions_enabled': alarm.get('ActionsEnabled', False)
                    })
            
            return alarms
        except Exception as e:
            st.error(f"Error listing alarms: {str(e)}")
            return []
    
    def create_alarm(self, alarm_name: str, metric_name: str, namespace: str,
                    statistic: str, period: int, evaluation_periods: int,
                    threshold: float, comparison_operator: str,
                    alarm_actions: List[str] = None,
                    dimensions: List[Dict] = None) -> Dict[str, Any]:
        """Create a CloudWatch alarm"""
        try:
            params = {
                'AlarmName': alarm_name,
                'MetricName': metric_name,
                'Namespace': namespace,
                'Statistic': statistic,
                'Period': period,
                'EvaluationPeriods': evaluation_periods,
                'Threshold': threshold,
                'ComparisonOperator': comparison_operator,
                'ActionsEnabled': True
            }
            
            if alarm_actions:
                params['AlarmActions'] = alarm_actions
            if dimensions:
                params['Dimensions'] = dimensions
            
            self.cloudwatch.put_metric_alarm(**params)
            
            return {
                'success': True,
                'message': f'Alarm {alarm_name} created'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def delete_alarm(self, alarm_name: str) -> Dict[str, Any]:
        """Delete a CloudWatch alarm"""
        try:
            self.cloudwatch.delete_alarms(AlarmNames=[alarm_name])
            return {
                'success': True,
                'message': f'Alarm {alarm_name} deleted'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def set_alarm_state(self, alarm_name: str, state_value: str, 
                       state_reason: str) -> Dict[str, Any]:
        """Manually set alarm state (for testing)"""
        try:
            self.cloudwatch.set_alarm_state(
                AlarmName=alarm_name,
                StateValue=state_value,
                StateReason=state_reason
            )
            return {
                'success': True,
                'message': f'Alarm state set to {state_value}'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    # ============= LOG GROUPS & STREAMS =============
    
    def list_log_groups(self, prefix: Optional[str] = None) -> List[Dict[str, Any]]:
        """List CloudWatch Log Groups"""
        try:
            params = {}
            if prefix:
                params['logGroupNamePrefix'] = prefix
            
            log_groups = []
            paginator = self.logs.get_paginator('describe_log_groups')
            
            for page in paginator.paginate(**params):
                for lg in page['logGroups']:
                    log_groups.append({
                        'log_group_name': lg['logGroupName'],
                        'arn': lg.get('arn', ''),
                        'creation_time': datetime.fromtimestamp(lg['creationTime']/1000).strftime('%Y-%m-%d %H:%M:%S'),
                        'retention_days': lg.get('retentionInDays', 'Never expire'),
                        'stored_bytes': lg.get('storedBytes', 0),
                        'metric_filter_count': lg.get('metricFilterCount', 0)
                    })
            
            return log_groups
        except Exception as e:
            st.error(f"Error listing log groups: {str(e)}")
            return []
    
    def create_log_group(self, log_group_name: str, 
                        retention_days: Optional[int] = None) -> Dict[str, Any]:
        """Create a log group"""
        try:
            self.logs.create_log_group(logGroupName=log_group_name)
            
            if retention_days:
                self.logs.put_retention_policy(
                    logGroupName=log_group_name,
                    retentionInDays=retention_days
                )
            
            return {
                'success': True,
                'message': f'Log group {log_group_name} created'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def delete_log_group(self, log_group_name: str) -> Dict[str, Any]:
        """Delete a log group"""
        try:
            self.logs.delete_log_group(logGroupName=log_group_name)
            return {
                'success': True,
                'message': f'Log group {log_group_name} deleted'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def list_log_streams(self, log_group_name: str, limit: int = 50) -> List[Dict[str, Any]]:
        """List log streams in a log group"""
        try:
            response = self.logs.describe_log_streams(
                logGroupName=log_group_name,
                orderBy='LastEventTime',
                descending=True,
                limit=limit
            )
            
            streams = []
            for stream in response.get('logStreams', []):
                streams.append({
                    'log_stream_name': stream['logStreamName'],
                    'creation_time': datetime.fromtimestamp(stream['creationTime']/1000).strftime('%Y-%m-%d %H:%M:%S'),
                    'last_event_time': datetime.fromtimestamp(stream.get('lastEventTimestamp', stream['creationTime'])/1000).strftime('%Y-%m-%d %H:%M:%S'),
                    'stored_bytes': stream.get('storedBytes', 0)
                })
            
            return streams
        except Exception as e:
            st.error(f"Error listing log streams: {str(e)}")
            return []
    
    def get_log_events(self, log_group_name: str, log_stream_name: str,
                      start_time: Optional[datetime] = None,
                      limit: int = 100) -> List[Dict[str, Any]]:
        """Get log events from a stream"""
        try:
            params = {
                'logGroupName': log_group_name,
                'logStreamName': log_stream_name,
                'limit': limit,
                'startFromHead': False
            }
            
            if start_time:
                params['startTime'] = int(start_time.timestamp() * 1000)
            
            response = self.logs.get_log_events(**params)
            
            events = []
            for event in response.get('events', []):
                events.append({
                    'timestamp': datetime.fromtimestamp(event['timestamp']/1000).strftime('%Y-%m-%d %H:%M:%S'),
                    'message': event['message']
                })
            
            return events
        except Exception as e:
            st.error(f"Error getting log events: {str(e)}")
            return []
    
    def filter_log_events(self, log_group_name: str, filter_pattern: str,
                         start_time: Optional[datetime] = None,
                         end_time: Optional[datetime] = None,
                         limit: int = 100) -> List[Dict[str, Any]]:
        """Filter log events across all streams"""
        try:
            params = {
                'logGroupName': log_group_name,
                'filterPattern': filter_pattern,
                'limit': limit
            }
            
            if start_time:
                params['startTime'] = int(start_time.timestamp() * 1000)
            if end_time:
                params['endTime'] = int(end_time.timestamp() * 1000)
            
            response = self.logs.filter_log_events(**params)
            
            events = []
            for event in response.get('events', []):
                events.append({
                    'timestamp': datetime.fromtimestamp(event['timestamp']/1000).strftime('%Y-%m-%d %H:%M:%S'),
                    'log_stream_name': event['logStreamName'],
                    'message': event['message']
                })
            
            return events
        except Exception as e:
            st.error(f"Error filtering log events: {str(e)}")
            return []
    
    # ============= INSIGHTS QUERIES =============
    
    def start_insights_query(self, log_group_name: str, query_string: str,
                            start_time: datetime, end_time: datetime) -> Dict[str, Any]:
        """Start a CloudWatch Insights query"""
        try:
            response = self.logs.start_query(
                logGroupName=log_group_name,
                startTime=int(start_time.timestamp()),
                endTime=int(end_time.timestamp()),
                queryString=query_string
            )
            
            return {
                'success': True,
                'query_id': response['queryId']
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def get_insights_query_results(self, query_id: str) -> Dict[str, Any]:
        """Get results of an Insights query"""
        try:
            response = self.logs.get_query_results(queryId=query_id)
            
            return {
                'status': response['status'],
                'results': response.get('results', []),
                'statistics': response.get('statistics', {})
            }
        except Exception as e:
            st.error(f"Error getting query results: {str(e)}")
            return {'status': 'Failed', 'results': []}
    
    # ============= DASHBOARDS =============
    
    def list_dashboards(self) -> List[Dict[str, Any]]:
        """List CloudWatch dashboards"""
        try:
            dashboards = []
            paginator = self.cloudwatch.get_paginator('list_dashboards')
            
            for page in paginator.paginate():
                for dashboard in page['DashboardEntries']:
                    dashboards.append({
                        'dashboard_name': dashboard['DashboardName'],
                        'dashboard_arn': dashboard['DashboardArn'],
                        'last_modified': dashboard['LastModified'].strftime('%Y-%m-%d %H:%M:%S'),
                        'size': dashboard.get('Size', 0)
                    })
            
            return dashboards
        except Exception as e:
            st.error(f"Error listing dashboards: {str(e)}")
            return []
    
    def create_dashboard(self, dashboard_name: str, 
                        dashboard_body: str) -> Dict[str, Any]:
        """Create a CloudWatch dashboard"""
        try:
            self.cloudwatch.put_dashboard(
                DashboardName=dashboard_name,
                DashboardBody=dashboard_body
            )
            
            return {
                'success': True,
                'message': f'Dashboard {dashboard_name} created'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def get_dashboard(self, dashboard_name: str) -> Optional[Dict[str, Any]]:
        """Get dashboard definition"""
        try:
            response = self.cloudwatch.get_dashboard(
                DashboardName=dashboard_name
            )
            
            return {
                'dashboard_name': response['DashboardName'],
                'dashboard_arn': response['DashboardArn'],
                'dashboard_body': response['DashboardBody']
            }
        except Exception as e:
            st.error(f"Error getting dashboard: {str(e)}")
            return None
    
    def delete_dashboard(self, dashboard_name: str) -> Dict[str, Any]:
        """Delete a dashboard"""
        try:
            self.cloudwatch.delete_dashboards(
                DashboardNames=[dashboard_name]
            )
            return {
                'success': True,
                'message': f'Dashboard {dashboard_name} deleted'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    # ============= EVENTBRIDGE (CloudWatch Events) =============
    
    def list_rules(self) -> List[Dict[str, Any]]:
        """List EventBridge rules"""
        try:
            rules = []
            paginator = self.events.get_paginator('list_rules')
            
            for page in paginator.paginate():
                for rule in page['Rules']:
                    rules.append({
                        'name': rule['Name'],
                        'arn': rule['Arn'],
                        'state': rule.get('State', 'ENABLED'),
                        'description': rule.get('Description', ''),
                        'schedule_expression': rule.get('ScheduleExpression', ''),
                        'event_pattern': rule.get('EventPattern', '')
                    })
            
            return rules
        except Exception as e:
            st.error(f"Error listing rules: {str(e)}")
            return []
    
    def create_rule(self, rule_name: str, schedule_expression: str = None,
                   event_pattern: str = None, description: str = '') -> Dict[str, Any]:
        """Create an EventBridge rule"""
        try:
            params = {
                'Name': rule_name,
                'State': 'ENABLED',
                'Description': description
            }
            
            if schedule_expression:
                params['ScheduleExpression'] = schedule_expression
            elif event_pattern:
                params['EventPattern'] = event_pattern
            else:
                return {'success': False, 'error': 'Either schedule or event pattern required'}
            
            response = self.events.put_rule(**params)
            
            return {
                'success': True,
                'rule_arn': response['RuleArn'],
                'message': f'Rule {rule_name} created'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
