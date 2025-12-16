"""
AWS EKS (Elastic Kubernetes Service) Integration
Complete EKS cluster management and provisioning
"""

import streamlit as st
from typing import List, Dict, Optional, Tuple
import boto3
from botocore.exceptions import ClientError
from datetime import datetime
import json

class EKSService:
    """EKS operations across accounts and regions"""
    
    def __init__(self, session: boto3.Session, region: str = 'us-east-1'):
        """Initialize EKS service"""
        self.session = session
        self.region = region
        self.eks_client = session.client('eks', region_name=region)
        self.ec2_client = session.client('ec2', region_name=region)
        self.iam_client = session.client('iam')
    
    def list_clusters(_self) -> Dict:
        """List all EKS clusters"""
        try:
            clusters = []
            paginator = _self.eks_client.get_paginator('list_clusters')
            
            for page in paginator.paginate():
                for cluster_name in page['clusters']:
                    try:
                        # Get cluster details
                        cluster_info = _self.eks_client.describe_cluster(name=cluster_name)
                        cluster = cluster_info['cluster']
                        
                        # Get node groups
                        nodegroups = _self.list_nodegroups(cluster_name)
                        
                        clusters.append({
                            'cluster_name': cluster['name'],
                            'status': cluster['status'],
                            'version': cluster['version'],
                            'endpoint': cluster.get('endpoint', 'N/A'),
                            'created_at': cluster.get('createdAt'),
                            'role_arn': cluster['roleArn'],
                            'vpc_id': cluster['resourcesVpcConfig']['vpcId'],
                            'subnet_ids': cluster['resourcesVpcConfig']['subnetIds'],
                            'security_group_ids': cluster['resourcesVpcConfig'].get('securityGroupIds', []),
                            'nodegroup_count': len(nodegroups),
                            'platform_version': cluster.get('platformVersion', 'N/A'),
                            'tags': cluster.get('tags', {})
                        })
                    except ClientError:
                        pass
            
            return {
                'success': True,
                'count': len(clusters),
                'clusters': clusters,
                'region': _self.region
            }
            
        except ClientError as e:
            return {
                'success': False,
                'error': str(e),
                'count': 0,
                'clusters': []
            }
    
    def list_nodegroups(self, cluster_name: str) -> List[Dict]:
        """List node groups for a cluster"""
        try:
            nodegroups = []
            response = self.eks_client.list_nodegroups(clusterName=cluster_name)
            
            for ng_name in response.get('nodegroups', []):
                try:
                    ng_info = self.eks_client.describe_nodegroup(
                        clusterName=cluster_name,
                        nodegroupName=ng_name
                    )
                    ng = ng_info['nodegroup']
                    
                    nodegroups.append({
                        'nodegroup_name': ng['nodegroupName'],
                        'status': ng['status'],
                        'instance_types': ng.get('instanceTypes', []),
                        'desired_size': ng['scalingConfig']['desiredSize'],
                        'min_size': ng['scalingConfig']['minSize'],
                        'max_size': ng['scalingConfig']['maxSize'],
                        'ami_type': ng.get('amiType', 'N/A'),
                        'disk_size': ng.get('diskSize', 0),
                        'created_at': ng.get('createdAt')
                    })
                except ClientError:
                    pass
            
            return nodegroups
            
        except ClientError:
            return []
    
    def get_cluster_details(self, cluster_name: str) -> Optional[Dict]:
        """Get detailed information about a cluster"""
        try:
            response = self.eks_client.describe_cluster(name=cluster_name)
            cluster = response['cluster']
            
            # Get addons
            addons = self.list_addons(cluster_name)
            
            # Get node groups
            nodegroups = self.list_nodegroups(cluster_name)
            
            # Get Fargate profiles
            fargate_profiles = self.list_fargate_profiles(cluster_name)
            
            return {
                'cluster_name': cluster['name'],
                'arn': cluster['arn'],
                'status': cluster['status'],
                'version': cluster['version'],
                'endpoint': cluster.get('endpoint'),
                'created_at': cluster.get('createdAt'),
                'role_arn': cluster['roleArn'],
                'vpc_config': {
                    'vpc_id': cluster['resourcesVpcConfig']['vpcId'],
                    'subnet_ids': cluster['resourcesVpcConfig']['subnetIds'],
                    'security_group_ids': cluster['resourcesVpcConfig'].get('securityGroupIds', []),
                    'endpoint_public_access': cluster['resourcesVpcConfig'].get('endpointPublicAccess', False),
                    'endpoint_private_access': cluster['resourcesVpcConfig'].get('endpointPrivateAccess', False)
                },
                'logging': cluster.get('logging', {}),
                'identity': cluster.get('identity', {}),
                'platform_version': cluster.get('platformVersion'),
                'tags': cluster.get('tags', {}),
                'addons': addons,
                'nodegroups': nodegroups,
                'fargate_profiles': fargate_profiles,
                'encryption_config': cluster.get('encryptionConfig', [])
            }
            
        except ClientError:
            return None
    
    def list_addons(self, cluster_name: str) -> List[Dict]:
        """List EKS addons for a cluster"""
        try:
            addons = []
            response = self.eks_client.list_addons(clusterName=cluster_name)
            
            for addon_name in response.get('addons', []):
                try:
                    addon_info = self.eks_client.describe_addon(
                        clusterName=cluster_name,
                        addonName=addon_name
                    )
                    addon = addon_info['addon']
                    
                    addons.append({
                        'addon_name': addon['addonName'],
                        'addon_version': addon['addonVersion'],
                        'status': addon['status'],
                        'created_at': addon.get('createdAt')
                    })
                except ClientError:
                    pass
            
            return addons
            
        except ClientError:
            return []
    
    def list_fargate_profiles(self, cluster_name: str) -> List[str]:
        """List Fargate profiles for a cluster"""
        try:
            response = self.eks_client.list_fargate_profiles(clusterName=cluster_name)
            return response.get('fargateProfileNames', [])
        except ClientError:
            return []
    
    def create_cluster(
        self,
        cluster_name: str,
        kubernetes_version: str,
        role_arn: str,
        vpc_config: Dict,
        enable_logging: bool = True,
        tags: Optional[Dict] = None
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Create a new EKS cluster
        
        Returns:
            (success, cluster_arn, error_message)
        """
        try:
            params = {
                'name': cluster_name,
                'version': kubernetes_version,
                'roleArn': role_arn,
                'resourcesVpcConfig': vpc_config
            }
            
            if enable_logging:
                params['logging'] = {
                    'clusterLogging': [
                        {
                            'types': ['api', 'audit', 'authenticator', 'controllerManager', 'scheduler'],
                            'enabled': True
                        }
                    ]
                }
            
            if tags:
                params['tags'] = tags
            
            response = self.eks_client.create_cluster(**params)
            
            return True, response['cluster']['arn'], None
            
        except ClientError as e:
            return False, None, str(e)
    
    def create_nodegroup(
        self,
        cluster_name: str,
        nodegroup_name: str,
        node_role_arn: str,
        subnets: List[str],
        instance_types: List[str],
        scaling_config: Dict,
        disk_size: int = 20,
        ami_type: str = 'AL2_x86_64',
        tags: Optional[Dict] = None
    ) -> Tuple[bool, Optional[str]]:
        """
        Create a managed node group
        
        Returns:
            (success, error_message)
        """
        try:
            params = {
                'clusterName': cluster_name,
                'nodegroupName': nodegroup_name,
                'scalingConfig': scaling_config,
                'diskSize': disk_size,
                'subnets': subnets,
                'instanceTypes': instance_types,
                'amiType': ami_type,
                'nodeRole': node_role_arn
            }
            
            if tags:
                params['tags'] = tags
            
            self.eks_client.create_nodegroup(**params)
            
            return True, None
            
        except ClientError as e:
            return False, str(e)
    
    def delete_cluster(self, cluster_name: str) -> Tuple[bool, Optional[str]]:
        """Delete an EKS cluster"""
        try:
            # First, delete all node groups
            nodegroups = self.list_nodegroups(cluster_name)
            for ng in nodegroups:
                try:
                    self.eks_client.delete_nodegroup(
                        clusterName=cluster_name,
                        nodegroupName=ng['nodegroup_name']
                    )
                except ClientError:
                    pass
            
            # Delete the cluster
            self.eks_client.delete_cluster(name=cluster_name)
            
            return True, None
            
        except ClientError as e:
            return False, str(e)
    
    def update_cluster_version(self, cluster_name: str, version: str) -> Tuple[bool, Optional[str]]:
        """Update cluster Kubernetes version"""
        try:
            self.eks_client.update_cluster_version(
                name=cluster_name,
                version=version
            )
            return True, None
            
        except ClientError as e:
            return False, str(e)
    
    def get_cluster_cost_estimate(self, cluster_name: str) -> Dict:
        """Estimate monthly cost for EKS cluster"""
        try:
            # EKS Control Plane: $0.10/hour = $73/month
            control_plane_cost = 73.0
            
            # Get node groups
            nodegroups = self.list_nodegroups(cluster_name)
            
            nodegroup_cost = 0
            total_nodes = 0
            
            for ng in nodegroups:
                desired_size = ng['desired_size']
                instance_type = ng['instance_types'][0] if ng['instance_types'] else 't3.medium'
                
                # Simplified instance pricing
                instance_pricing = {
                    't3.small': 0.0208,
                    't3.medium': 0.0416,
                    't3.large': 0.0832,
                    't3.xlarge': 0.1664,
                    'm5.large': 0.096,
                    'm5.xlarge': 0.192,
                    'm5.2xlarge': 0.384,
                    'c5.large': 0.085,
                    'c5.xlarge': 0.17,
                    'r5.large': 0.126,
                    'r5.xlarge': 0.252
                }
                
                hourly_rate = instance_pricing.get(instance_type, 0.10)
                ng_cost = hourly_rate * 730 * desired_size  # 730 hours/month
                nodegroup_cost += ng_cost
                total_nodes += desired_size
            
            total_cost = control_plane_cost + nodegroup_cost
            
            return {
                'success': True,
                'total_monthly_cost': total_cost,
                'control_plane_cost': control_plane_cost,
                'nodegroup_cost': nodegroup_cost,
                'total_nodes': total_nodes
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'total_monthly_cost': 0
            }
    
    def get_available_kubernetes_versions(self) -> List[str]:
        """Get available Kubernetes versions"""
        # Current EKS versions (as of 2024)
        return ['1.28', '1.29', '1.30']
    
    def get_recommended_instance_types(self) -> Dict[str, List[str]]:
        """Get recommended instance types by use case"""
        return {
            'General Purpose': ['t3.medium', 't3.large', 't3.xlarge', 'm5.large', 'm5.xlarge', 'm5.2xlarge'],
            'Compute Optimized': ['c5.large', 'c5.xlarge', 'c5.2xlarge', 'c5.4xlarge'],
            'Memory Optimized': ['r5.large', 'r5.xlarge', 'r5.2xlarge', 'r5.4xlarge'],
            'GPU Instances': ['p3.2xlarge', 'p3.8xlarge', 'g4dn.xlarge', 'g4dn.2xlarge']
        }
