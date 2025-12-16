"""
AWS S3 and Lambda Service Integrations
"""

import streamlit as st
from typing import List, Dict, Optional
import boto3
from botocore.exceptions import ClientError

class S3Service:
    """S3 operations"""
    
    def __init__(self, session: boto3.Session):
        """Initialize S3 service"""
        self.session = session
        self.client = session.client('s3')
    
    def list_buckets(_self) -> Dict:
        """List all S3 buckets"""
        try:
            response = _self.client.list_buckets()
            
            buckets = []
            for bucket in response.get('Buckets', []):
                bucket_name = bucket['Name']
                
                # Get bucket region
                try:
                    location = _self.client.get_bucket_location(Bucket=bucket_name)
                    # LocationConstraint is None for us-east-1
                    region = location.get('LocationConstraint') or 'us-east-1'
                except ClientError as e:
                    error_code = e.response['Error']['Code']
                    if error_code == 'AccessDenied':
                        region = 'Access Denied'
                    else:
                        region = f'Error: {error_code}'
                except Exception as e:
                    region = 'unknown'
                
                # Get bucket size (simplified - would need CloudWatch in production)
                buckets.append({
                    'bucket_name': bucket_name,
                    'creation_date': bucket['CreationDate'],
                    'region': region
                })
            
            return {
                'success': True,
                'count': len(buckets),
                'buckets': buckets
            }
        except ClientError as e:
            return {
                'success': False,
                'error': str(e),
                'count': 0,
                'buckets': []
            }


class LambdaService:
    """Lambda operations"""
    
    def __init__(self, session: boto3.Session, region: str = 'us-east-1'):
        """Initialize Lambda service"""
        self.session = session
        self.region = region
        self.client = session.client('lambda', region_name=region)
    
    def list_functions(_self) -> Dict:
        """List all Lambda functions"""
        try:
            functions = []
            paginator = _self.client.get_paginator('list_functions')
            
            for page in paginator.paginate():
                for func in page['Functions']:
                    functions.append({
                        'function_name': func['FunctionName'],
                        'runtime': func.get('Runtime', 'N/A'),
                        'handler': func.get('Handler', 'N/A'),
                        'memory_size': func.get('MemorySize', 0),
                        'timeout': func.get('Timeout', 0),
                        'last_modified': func.get('LastModified', 'N/A'),
                        'code_size': func.get('CodeSize', 0),
                        'description': func.get('Description', '')
                    })
            
            return {
                'success': True,
                'count': len(functions),
                'functions': functions,
                'region': _self.region
            }
        except ClientError as e:
            return {
                'success': False,
                'error': str(e),
                'count': 0,
                'functions': []
            }


class DynamoDBService:
    """DynamoDB operations"""
    
    def __init__(self, session: boto3.Session, region: str = 'us-east-1'):
        """Initialize DynamoDB service"""
        self.session = session
        self.region = region
        self.client = session.client('dynamodb', region_name=region)
    
    def list_tables(_self) -> Dict:
        """List all DynamoDB tables"""
        try:
            tables = []
            paginator = _self.client.get_paginator('list_tables')
            
            for page in paginator.paginate():
                for table_name in page['TableNames']:
                    # Get table details
                    try:
                        table_info = _self.client.describe_table(TableName=table_name)
                        table = table_info['Table']
                        
                        tables.append({
                            'table_name': table['TableName'],
                            'status': table['TableStatus'],
                            'item_count': table.get('ItemCount', 0),
                            'size_bytes': table.get('TableSizeBytes', 0),
                            'creation_date': table.get('CreationDateTime'),
                            'billing_mode': table.get('BillingModeSummary', {}).get('BillingMode', 'PROVISIONED')
                        })
                    except:
                        pass
            
            return {
                'success': True,
                'count': len(tables),
                'tables': tables,
                'region': _self.region
            }
        except ClientError as e:
            return {
                'success': False,
                'error': str(e),
                'count': 0,
                'tables': []
            }
