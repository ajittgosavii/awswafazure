"""
AWS Service Catalog Integration
Supports portfolio management, product deployment, and self-service provisioning
"""

import streamlit as st
from typing import Dict, List, Optional, Any
from datetime import datetime
from core_account_manager import get_account_manager

class ServiceCatalogManager:
    """AWS Service Catalog Management"""
    
    def __init__(self, session):
        """Initialize Service Catalog manager with boto3 session"""
        self.sc = session.client('servicecatalog')
    
    # ============= PORTFOLIOS =============
    
    def list_portfolios(self) -> List[Dict[str, Any]]:
        """List all portfolios"""
        try:
            portfolios = []
            paginator = self.sc.get_paginator('list_portfolios')
            
            for page in paginator.paginate():
                for portfolio in page['PortfolioDetails']:
                    portfolios.append({
                        'id': portfolio['Id'],
                        'arn': portfolio['ARN'],
                        'display_name': portfolio['DisplayName'],
                        'description': portfolio.get('Description', ''),
                        'provider_name': portfolio.get('ProviderName', ''),
                        'created_time': portfolio.get('CreatedTime', datetime.now()).strftime('%Y-%m-%d %H:%M:%S')
                    })
            
            return portfolios
        except Exception as e:
            st.error(f"Error listing portfolios: {str(e)}")
            return []
    
    def create_portfolio(self, display_name: str, provider_name: str,
                        description: str = '') -> Dict[str, Any]:
        """Create a new portfolio"""
        try:
            response = self.sc.create_portfolio(
                DisplayName=display_name,
                ProviderName=provider_name,
                Description=description
            )
            
            portfolio = response['PortfolioDetail']
            return {
                'success': True,
                'portfolio_id': portfolio['Id'],
                'message': f'Portfolio {display_name} created'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def delete_portfolio(self, portfolio_id: str) -> Dict[str, Any]:
        """Delete a portfolio"""
        try:
            self.sc.delete_portfolio(Id=portfolio_id)
            return {
                'success': True,
                'message': f'Portfolio {portfolio_id} deleted'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    # ============= PRODUCTS =============
    
    def list_products(self, portfolio_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """List products, optionally filtered by portfolio"""
        try:
            products = []
            
            if portfolio_id:
                # List products for a specific portfolio
                paginator = self.sc.get_paginator('search_products_as_admin')
                for page in paginator.paginate(PortfolioId=portfolio_id):
                    for product in page['ProductViewDetails']:
                        pv = product['ProductViewSummary']
                        products.append({
                            'product_id': pv['ProductId'],
                            'name': pv['Name'],
                            'type': pv.get('Type', ''),
                            'owner': pv.get('Owner', ''),
                            'short_description': pv.get('ShortDescription', ''),
                            'distributor': pv.get('Distributor', '')
                        })
            else:
                # List all products
                paginator = self.sc.get_paginator('search_products_as_admin')
                for page in paginator.paginate():
                    for product in page['ProductViewDetails']:
                        pv = product['ProductViewSummary']
                        products.append({
                            'product_id': pv['ProductId'],
                            'name': pv['Name'],
                            'type': pv.get('Type', ''),
                            'owner': pv.get('Owner', ''),
                            'short_description': pv.get('ShortDescription', '')
                        })
            
            return products
        except Exception as e:
            st.error(f"Error listing products: {str(e)}")
            return []
    
    def create_product(self, name: str, owner: str, product_type: str,
                      description: str = '',
                      distributor: str = '',
                      support_description: str = '') -> Dict[str, Any]:
        """Create a new product"""
        try:
            response = self.sc.create_product(
                Name=name,
                Owner=owner,
                ProductType=product_type,
                Description=description,
                Distributor=distributor,
                SupportDescription=support_description
            )
            
            return {
                'success': True,
                'product_id': response['ProductViewDetail']['ProductViewSummary']['ProductId'],
                'message': f'Product {name} created'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def associate_product_with_portfolio(self, product_id: str,
                                        portfolio_id: str) -> Dict[str, Any]:
        """Associate a product with a portfolio"""
        try:
            self.sc.associate_product_with_portfolio(
                ProductId=product_id,
                PortfolioId=portfolio_id
            )
            
            return {
                'success': True,
                'message': f'Product associated with portfolio'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def disassociate_product_from_portfolio(self, product_id: str,
                                           portfolio_id: str) -> Dict[str, Any]:
        """Disassociate a product from a portfolio"""
        try:
            self.sc.disassociate_product_from_portfolio(
                ProductId=product_id,
                PortfolioId=portfolio_id
            )
            
            return {
                'success': True,
                'message': f'Product disassociated from portfolio'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    # ============= PROVISIONING ARTIFACTS (VERSIONS) =============
    
    def list_provisioning_artifacts(self, product_id: str) -> List[Dict[str, Any]]:
        """List provisioning artifacts (versions) for a product"""
        try:
            response = self.sc.list_provisioning_artifacts(
                ProductId=product_id
            )
            
            artifacts = []
            for artifact in response.get('ProvisioningArtifactDetails', []):
                artifacts.append({
                    'id': artifact['Id'],
                    'name': artifact.get('Name', ''),
                    'description': artifact.get('Description', ''),
                    'type': artifact.get('Type', ''),
                    'created_time': artifact.get('CreatedTime', datetime.now()).strftime('%Y-%m-%d %H:%M:%S'),
                    'active': artifact.get('Active', False)
                })
            
            return artifacts
        except Exception as e:
            st.error(f"Error listing provisioning artifacts: {str(e)}")
            return []
    
    def create_provisioning_artifact(self, product_id: str, name: str,
                                    parameters: Dict[str, Any],
                                    artifact_type: str = 'CLOUD_FORMATION_TEMPLATE') -> Dict[str, Any]:
        """Create a provisioning artifact (product version)"""
        try:
            response = self.sc.create_provisioning_artifact(
                ProductId=product_id,
                Parameters={
                    'Name': name,
                    'Type': artifact_type,
                    'Info': parameters
                }
            )
            
            return {
                'success': True,
                'artifact_id': response['ProvisioningArtifactDetail']['Id'],
                'message': f'Provisioning artifact {name} created'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    # ============= PROVISIONED PRODUCTS =============
    
    def list_provisioned_products(self) -> List[Dict[str, Any]]:
        """List provisioned products"""
        try:
            products = []
            paginator = self.sc.get_paginator('search_provisioned_products')
            
            for page in paginator.paginate():
                for product in page['ProvisionedProducts']:
                    products.append({
                        'id': product['Id'],
                        'name': product['Name'],
                        'type': product.get('Type', ''),
                        'status': product.get('Status', ''),
                        'status_message': product.get('StatusMessage', ''),
                        'created_time': product.get('CreatedTime', datetime.now()).strftime('%Y-%m-%d %H:%M:%S'),
                        'last_record_id': product.get('LastRecordId', '')
                    })
            
            return products
        except Exception as e:
            st.error(f"Error listing provisioned products: {str(e)}")
            return []
    
    def provision_product(self, product_id: str, provisioning_artifact_id: str,
                         provisioned_product_name: str,
                         provisioning_parameters: List[Dict] = None) -> Dict[str, Any]:
        """Provision a product"""
        try:
            params = {
                'ProductId': product_id,
                'ProvisioningArtifactId': provisioning_artifact_id,
                'ProvisionedProductName': provisioned_product_name
            }
            
            if provisioning_parameters:
                params['ProvisioningParameters'] = provisioning_parameters
            
            response = self.sc.provision_product(**params)
            
            return {
                'success': True,
                'record_id': response['RecordDetail']['RecordId'],
                'message': f'Product provisioning initiated'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def terminate_provisioned_product(self, provisioned_product_id: str) -> Dict[str, Any]:
        """Terminate a provisioned product"""
        try:
            response = self.sc.terminate_provisioned_product(
                ProvisionedProductId=provisioned_product_id
            )
            
            return {
                'success': True,
                'record_id': response['RecordDetail']['RecordId'],
                'message': 'Product termination initiated'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def update_provisioned_product(self, provisioned_product_id: str,
                                   provisioning_artifact_id: Optional[str] = None,
                                   provisioning_parameters: List[Dict] = None) -> Dict[str, Any]:
        """Update a provisioned product"""
        try:
            params = {
                'ProvisionedProductId': provisioned_product_id
            }
            
            if provisioning_artifact_id:
                params['ProvisioningArtifactId'] = provisioning_artifact_id
            if provisioning_parameters:
                params['ProvisioningParameters'] = provisioning_parameters
            
            response = self.sc.update_provisioned_product(**params)
            
            return {
                'success': True,
                'record_id': response['RecordDetail']['RecordId'],
                'message': 'Product update initiated'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    # ============= LAUNCH PATHS & CONSTRAINTS =============
    
    def list_launch_paths(self, product_id: str) -> List[Dict[str, Any]]:
        """List launch paths for a product"""
        try:
            response = self.sc.list_launch_paths(ProductId=product_id)
            
            paths = []
            for path in response.get('LaunchPathSummaries', []):
                paths.append({
                    'id': path.get('Id', ''),
                    'name': path.get('Name', ''),
                    'constraint_summaries': path.get('ConstraintSummaries', [])
                })
            
            return paths
        except Exception as e:
            st.error(f"Error listing launch paths: {str(e)}")
            return []
    
    def create_constraint(self, portfolio_id: str, product_id: str,
                         constraint_type: str, parameters: str = '') -> Dict[str, Any]:
        """
        Create a constraint
        
        Args:
            constraint_type: 'LAUNCH', 'NOTIFICATION', 'RESOURCE_UPDATE', 'STACKSET', or 'TEMPLATE'
        """
        try:
            params = {
                'PortfolioId': portfolio_id,
                'ProductId': product_id,
                'Type': constraint_type
            }
            
            if parameters:
                params['Parameters'] = parameters
            
            response = self.sc.create_constraint(**params)
            
            return {
                'success': True,
                'constraint_id': response['ConstraintDetail']['ConstraintId'],
                'message': f'Constraint created'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    # ============= PORTFOLIO SHARING =============
    
    def create_portfolio_share(self, portfolio_id: str, account_id: str = None,
                              organization_node_id: str = None) -> Dict[str, Any]:
        """Share a portfolio with an account or organizational unit"""
        try:
            params = {
                'PortfolioId': portfolio_id
            }
            
            if account_id:
                params['AccountId'] = account_id
            elif organization_node_id:
                params['OrganizationNode'] = {
                    'Type': 'ORGANIZATIONAL_UNIT',
                    'Value': organization_node_id
                }
            else:
                return {'success': False, 'error': 'Either account_id or organization_node_id required'}
            
            response = self.sc.create_portfolio_share(**params)
            
            return {
                'success': True,
                'share_token': response.get('PortfolioShareToken', ''),
                'message': 'Portfolio shared successfully'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def delete_portfolio_share(self, portfolio_id: str, account_id: str = None,
                              organization_node_id: str = None) -> Dict[str, Any]:
        """Remove portfolio sharing"""
        try:
            params = {
                'PortfolioId': portfolio_id
            }
            
            if account_id:
                params['AccountId'] = account_id
            elif organization_node_id:
                params['OrganizationNode'] = {
                    'Type': 'ORGANIZATIONAL_UNIT',
                    'Value': organization_node_id
                }
            
            response = self.sc.delete_portfolio_share(**params)
            
            return {
                'success': True,
                'share_token': response.get('PortfolioShareToken', ''),
                'message': 'Portfolio share removed'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
