"""
AWS VPC Integration - Complete Network Infrastructure Management
Supports VPC, Subnets, Route Tables, Internet Gateways, NAT Gateways, Security Groups, NACLs
"""

import streamlit as st
from typing import Dict, List, Optional, Any
from core_account_manager import get_account_manager

class VPCManager:
    """AWS VPC and Network Infrastructure Management"""
    
    def __init__(self, session):
        """Initialize VPC manager with boto3 session"""
        self.ec2_client = session.client('ec2')
        self.ec2_resource = session.resource('ec2')
    
    # ============= VPC OPERATIONS =============
    
    def list_vpcs(self) -> List[Dict[str, Any]]:
        """List all VPCs in the account"""
        try:
            response = self.ec2_client.describe_vpcs()
            
            vpcs = []
            for vpc in response['Vpcs']:
                vpc_info = {
                    'vpc_id': vpc['VpcId'],
                    'cidr_block': vpc['CidrBlock'],
                    'state': vpc['State'],
                    'is_default': vpc.get('IsDefault', False),
                    'dns_support': vpc.get('EnableDnsSupport', False),
                    'dns_hostnames': vpc.get('EnableDnsHostnames', False),
                    'tags': {tag['Key']: tag['Value'] for tag in vpc.get('Tags', [])}
                }
                vpcs.append(vpc_info)
            
            return vpcs
        except Exception as e:
            st.error(f"Error listing VPCs: {str(e)}")
            return []
    
    def create_vpc(self, cidr_block: str, name: str, enable_dns: bool = True) -> Dict[str, Any]:
        """Create a new VPC"""
        try:
            # Create VPC
            response = self.ec2_client.create_vpc(
                CidrBlock=cidr_block,
                AmazonProvidedIpv6CidrBlock=False
            )
            vpc_id = response['Vpc']['VpcId']
            
            # Tag VPC
            self.ec2_client.create_tags(
                Resources=[vpc_id],
                Tags=[
                    {'Key': 'Name', 'Value': name},
                    {'Key': 'ManagedBy', 'Value': 'CloudIDP'}
                ]
            )
            
            # Enable DNS
            if enable_dns:
                self.ec2_client.modify_vpc_attribute(
                    VpcId=vpc_id,
                    EnableDnsHostnames={'Value': True}
                )
                self.ec2_client.modify_vpc_attribute(
                    VpcId=vpc_id,
                    EnableDnsSupport={'Value': True}
                )
            
            return {
                'success': True,
                'vpc_id': vpc_id,
                'cidr_block': cidr_block,
                'message': f'VPC {vpc_id} created successfully'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def delete_vpc(self, vpc_id: str) -> Dict[str, Any]:
        """Delete a VPC"""
        try:
            self.ec2_client.delete_vpc(VpcId=vpc_id)
            return {'success': True, 'message': f'VPC {vpc_id} deleted'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    # ============= SUBNET OPERATIONS =============
    
    def list_subnets(self, vpc_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """List subnets, optionally filtered by VPC"""
        try:
            filters = []
            if vpc_id:
                filters.append({'Name': 'vpc-id', 'Values': [vpc_id]})
            
            response = self.ec2_client.describe_subnets(Filters=filters)
            
            subnets = []
            for subnet in response['Subnets']:
                subnet_info = {
                    'subnet_id': subnet['SubnetId'],
                    'vpc_id': subnet['VpcId'],
                    'cidr_block': subnet['CidrBlock'],
                    'availability_zone': subnet['AvailabilityZone'],
                    'available_ips': subnet['AvailableIpAddressCount'],
                    'state': subnet['State'],
                    'public': subnet.get('MapPublicIpOnLaunch', False),
                    'tags': {tag['Key']: tag['Value'] for tag in subnet.get('Tags', [])}
                }
                subnets.append(subnet_info)
            
            return subnets
        except Exception as e:
            st.error(f"Error listing subnets: {str(e)}")
            return []
    
    def create_subnet(self, vpc_id: str, cidr_block: str, 
                     availability_zone: str, name: str, 
                     public: bool = False) -> Dict[str, Any]:
        """Create a subnet"""
        try:
            response = self.ec2_client.create_subnet(
                VpcId=vpc_id,
                CidrBlock=cidr_block,
                AvailabilityZone=availability_zone
            )
            subnet_id = response['Subnet']['SubnetId']
            
            # Tag subnet
            self.ec2_client.create_tags(
                Resources=[subnet_id],
                Tags=[
                    {'Key': 'Name', 'Value': name},
                    {'Key': 'Type', 'Value': 'Public' if public else 'Private'},
                    {'Key': 'ManagedBy', 'Value': 'CloudIDP'}
                ]
            )
            
            # Enable auto-assign public IP for public subnets
            if public:
                self.ec2_client.modify_subnet_attribute(
                    SubnetId=subnet_id,
                    MapPublicIpOnLaunch={'Value': True}
                )
            
            return {
                'success': True,
                'subnet_id': subnet_id,
                'message': f'Subnet {subnet_id} created'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    # ============= INTERNET GATEWAY =============
    
    def create_internet_gateway(self, vpc_id: str, name: str) -> Dict[str, Any]:
        """Create and attach Internet Gateway"""
        try:
            # Create IGW
            response = self.ec2_client.create_internet_gateway()
            igw_id = response['InternetGateway']['InternetGatewayId']
            
            # Tag IGW
            self.ec2_client.create_tags(
                Resources=[igw_id],
                Tags=[
                    {'Key': 'Name', 'Value': name},
                    {'Key': 'ManagedBy', 'Value': 'CloudIDP'}
                ]
            )
            
            # Attach to VPC
            self.ec2_client.attach_internet_gateway(
                InternetGatewayId=igw_id,
                VpcId=vpc_id
            )
            
            return {
                'success': True,
                'igw_id': igw_id,
                'message': f'Internet Gateway {igw_id} created and attached'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def list_internet_gateways(self, vpc_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """List Internet Gateways"""
        try:
            filters = []
            if vpc_id:
                filters.append({'Name': 'attachment.vpc-id', 'Values': [vpc_id]})
            
            response = self.ec2_client.describe_internet_gateways(Filters=filters)
            
            igws = []
            for igw in response['InternetGateways']:
                igw_info = {
                    'igw_id': igw['InternetGatewayId'],
                    'attachments': igw.get('Attachments', []),
                    'tags': {tag['Key']: tag['Value'] for tag in igw.get('Tags', [])}
                }
                igws.append(igw_info)
            
            return igws
        except Exception as e:
            st.error(f"Error listing IGWs: {str(e)}")
            return []
    
    # ============= NAT GATEWAY =============
    
    def create_nat_gateway(self, subnet_id: str, name: str) -> Dict[str, Any]:
        """Create NAT Gateway (requires EIP allocation)"""
        try:
            # Allocate Elastic IP
            eip_response = self.ec2_client.allocate_address(Domain='vpc')
            allocation_id = eip_response['AllocationId']
            
            # Create NAT Gateway
            response = self.ec2_client.create_nat_gateway(
                SubnetId=subnet_id,
                AllocationId=allocation_id
            )
            nat_id = response['NatGateway']['NatGatewayId']
            
            # Tag NAT Gateway
            self.ec2_client.create_tags(
                Resources=[nat_id],
                Tags=[
                    {'Key': 'Name', 'Value': name},
                    {'Key': 'ManagedBy', 'Value': 'CloudIDP'}
                ]
            )
            
            return {
                'success': True,
                'nat_id': nat_id,
                'eip': eip_response['PublicIp'],
                'message': f'NAT Gateway {nat_id} created'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def list_nat_gateways(self, vpc_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """List NAT Gateways"""
        try:
            filters = []
            if vpc_id:
                filters.append({'Name': 'vpc-id', 'Values': [vpc_id]})
            
            response = self.ec2_client.describe_nat_gateways(Filters=filters)
            
            nats = []
            for nat in response['NatGateways']:
                nat_info = {
                    'nat_id': nat['NatGatewayId'],
                    'vpc_id': nat['VpcId'],
                    'subnet_id': nat['SubnetId'],
                    'state': nat['State'],
                    'public_ip': nat['NatGatewayAddresses'][0]['PublicIp'] if nat.get('NatGatewayAddresses') else None,
                    'tags': {tag['Key']: tag['Value'] for tag in nat.get('Tags', [])}
                }
                nats.append(nat_info)
            
            return nats
        except Exception as e:
            st.error(f"Error listing NAT Gateways: {str(e)}")
            return []
    
    # ============= ROUTE TABLES =============
    
    def list_route_tables(self, vpc_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """List route tables"""
        try:
            filters = []
            if vpc_id:
                filters.append({'Name': 'vpc-id', 'Values': [vpc_id]})
            
            response = self.ec2_client.describe_route_tables(Filters=filters)
            
            route_tables = []
            for rt in response['RouteTables']:
                rt_info = {
                    'route_table_id': rt['RouteTableId'],
                    'vpc_id': rt['VpcId'],
                    'routes': rt.get('Routes', []),
                    'associations': rt.get('Associations', []),
                    'is_main': any(a.get('Main', False) for a in rt.get('Associations', [])),
                    'tags': {tag['Key']: tag['Value'] for tag in rt.get('Tags', [])}
                }
                route_tables.append(rt_info)
            
            return route_tables
        except Exception as e:
            st.error(f"Error listing route tables: {str(e)}")
            return []
    
    def create_route_table(self, vpc_id: str, name: str) -> Dict[str, Any]:
        """Create route table"""
        try:
            response = self.ec2_client.create_route_table(VpcId=vpc_id)
            rt_id = response['RouteTable']['RouteTableId']
            
            # Tag route table
            self.ec2_client.create_tags(
                Resources=[rt_id],
                Tags=[
                    {'Key': 'Name', 'Value': name},
                    {'Key': 'ManagedBy', 'Value': 'CloudIDP'}
                ]
            )
            
            return {
                'success': True,
                'route_table_id': rt_id,
                'message': f'Route table {rt_id} created'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def add_route(self, route_table_id: str, destination: str, 
                 gateway_id: Optional[str] = None,
                 nat_gateway_id: Optional[str] = None) -> Dict[str, Any]:
        """Add route to route table"""
        try:
            params = {
                'RouteTableId': route_table_id,
                'DestinationCidrBlock': destination
            }
            
            if gateway_id:
                params['GatewayId'] = gateway_id
            elif nat_gateway_id:
                params['NatGatewayId'] = nat_gateway_id
            
            self.ec2_client.create_route(**params)
            
            return {
                'success': True,
                'message': f'Route to {destination} added'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    # ============= SECURITY GROUPS =============
    
    def list_security_groups(self, vpc_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """List security groups"""
        try:
            filters = []
            if vpc_id:
                filters.append({'Name': 'vpc-id', 'Values': [vpc_id]})
            
            response = self.ec2_client.describe_security_groups(Filters=filters)
            
            security_groups = []
            for sg in response['SecurityGroups']:
                sg_info = {
                    'group_id': sg['GroupId'],
                    'group_name': sg['GroupName'],
                    'description': sg['Description'],
                    'vpc_id': sg.get('VpcId'),
                    'ingress_rules': sg.get('IpPermissions', []),
                    'egress_rules': sg.get('IpPermissionsEgress', []),
                    'tags': {tag['Key']: tag['Value'] for tag in sg.get('Tags', [])}
                }
                security_groups.append(sg_info)
            
            return security_groups
        except Exception as e:
            st.error(f"Error listing security groups: {str(e)}")
            return []
    
    def create_security_group(self, vpc_id: str, name: str, description: str) -> Dict[str, Any]:
        """Create security group"""
        try:
            response = self.ec2_client.create_security_group(
                GroupName=name,
                Description=description,
                VpcId=vpc_id
            )
            sg_id = response['GroupId']
            
            # Tag security group
            self.ec2_client.create_tags(
                Resources=[sg_id],
                Tags=[
                    {'Key': 'Name', 'Value': name},
                    {'Key': 'ManagedBy', 'Value': 'CloudIDP'}
                ]
            )
            
            return {
                'success': True,
                'group_id': sg_id,
                'message': f'Security group {sg_id} created'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def add_ingress_rule(self, group_id: str, protocol: str, 
                        from_port: int, to_port: int, 
                        cidr: str) -> Dict[str, Any]:
        """Add ingress rule to security group"""
        try:
            self.ec2_client.authorize_security_group_ingress(
                GroupId=group_id,
                IpPermissions=[{
                    'IpProtocol': protocol,
                    'FromPort': from_port,
                    'ToPort': to_port,
                    'IpRanges': [{'CidrIp': cidr}]
                }]
            )
            
            return {
                'success': True,
                'message': f'Ingress rule added to {group_id}'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    # ============= NETWORK ACLs =============
    
    def list_network_acls(self, vpc_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """List Network ACLs"""
        try:
            filters = []
            if vpc_id:
                filters.append({'Name': 'vpc-id', 'Values': [vpc_id]})
            
            response = self.ec2_client.describe_network_acls(Filters=filters)
            
            nacls = []
            for nacl in response['NetworkAcls']:
                nacl_info = {
                    'nacl_id': nacl['NetworkAclId'],
                    'vpc_id': nacl['VpcId'],
                    'is_default': nacl.get('IsDefault', False),
                    'entries': nacl.get('Entries', []),
                    'associations': nacl.get('Associations', []),
                    'tags': {tag['Key']: tag['Value'] for tag in nacl.get('Tags', [])}
                }
                nacls.append(nacl_info)
            
            return nacls
        except Exception as e:
            st.error(f"Error listing NACLs: {str(e)}")
            return []
