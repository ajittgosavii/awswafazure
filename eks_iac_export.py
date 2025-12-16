"""
EKS Infrastructure as Code (IaC) Export Module
Part of the AI-Enhanced EKS Architecture Design Wizard

Features:
- Terraform Configuration Generator
- CloudFormation Template Generator
- Pulumi Configuration Generator
- CDK (TypeScript) Generator
- Module-based Structure
- Best Practices Implementation

Author: Infosys Cloud Architecture Team
Version: 2.0.0
"""

import streamlit as st
import json
import yaml
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import os
import re

# ============================================================================
# IAC ENUMS
# ============================================================================

class IaCTool(Enum):
    """Infrastructure as Code Tools"""
    TERRAFORM = "terraform"
    CLOUDFORMATION = "cloudformation"
    PULUMI = "pulumi"
    CDK = "cdk"

class IaCModuleType(Enum):
    """IaC Module Types"""
    VPC = "vpc"
    EKS = "eks"
    NODE_GROUPS = "node_groups"
    ADDONS = "addons"
    IAM = "iam"
    SECURITY = "security"
    OBSERVABILITY = "observability"


# ============================================================================
# TERRAFORM GENERATOR
# ============================================================================

class TerraformGenerator:
    """
    Generates production-ready Terraform configurations for EKS clusters.
    """
    
    def generate_terraform(self, cluster_config: Dict) -> Dict[str, str]:
        """
        Generate complete Terraform configuration.
        
        Args:
            cluster_config: EKS cluster configuration
            
        Returns:
            Dict of filename -> content
        """
        files = {}
        
        # Main configuration files
        files["versions.tf"] = self._generate_versions()
        files["providers.tf"] = self._generate_providers(cluster_config)
        files["variables.tf"] = self._generate_variables(cluster_config)
        files["terraform.tfvars"] = self._generate_tfvars(cluster_config)
        files["locals.tf"] = self._generate_locals(cluster_config)
        
        # Infrastructure modules
        files["vpc.tf"] = self._generate_vpc(cluster_config)
        files["eks.tf"] = self._generate_eks(cluster_config)
        files["node_groups.tf"] = self._generate_node_groups(cluster_config)
        files["iam.tf"] = self._generate_iam(cluster_config)
        files["addons.tf"] = self._generate_addons(cluster_config)
        files["karpenter.tf"] = self._generate_karpenter(cluster_config)
        
        # Security
        files["security_groups.tf"] = self._generate_security_groups(cluster_config)
        
        # Outputs
        files["outputs.tf"] = self._generate_outputs(cluster_config)
        
        # Helper files
        files["README.md"] = self._generate_readme(cluster_config)
        files["Makefile"] = self._generate_makefile()
        
        return files
    
    def _generate_versions(self) -> str:
        """Generate versions.tf"""
        
        return '''terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.30"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.24"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.12"
    }
    kubectl = {
      source  = "gavinbunney/kubectl"
      version = "~> 1.14"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }

  backend "s3" {
    # Configure your backend
    # bucket         = "your-terraform-state-bucket"
    # key            = "eks/terraform.tfstate"
    # region         = "us-east-1"
    # dynamodb_table = "terraform-locks"
    # encrypt        = true
  }
}
'''
    
    def _generate_providers(self, config: Dict) -> str:
        """Generate providers.tf"""
        
        region = config.get("region", "us-east-1")
        
        return f'''# AWS Provider
provider "aws" {{
  region = var.region

  default_tags {{
    tags = local.common_tags
  }}
}}

# Kubernetes Provider
provider "kubernetes" {{
  host                   = module.eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)

  exec {{
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args        = ["eks", "get-token", "--cluster-name", module.eks.cluster_name]
  }}
}}

# Helm Provider
provider "helm" {{
  kubernetes {{
    host                   = module.eks.cluster_endpoint
    cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)

    exec {{
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "aws"
      args        = ["eks", "get-token", "--cluster-name", module.eks.cluster_name]
    }}
  }}
}}

# Kubectl Provider
provider "kubectl" {{
  apply_retry_count      = 5
  host                   = module.eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
  load_config_file       = false

  exec {{
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args        = ["eks", "get-token", "--cluster-name", module.eks.cluster_name]
  }}
}}
'''
    
    def _generate_variables(self, config: Dict) -> str:
        """Generate variables.tf"""
        
        return '''# General Variables
variable "region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "production"
}

variable "project" {
  description = "Project name"
  type        = string
  default     = "eks-cluster"
}

# VPC Variables
variable "vpc_cidr" {
  description = "VPC CIDR block"
  type        = string
  default     = "10.0.0.0/16"
}

variable "availability_zones" {
  description = "Number of availability zones"
  type        = number
  default     = 3
}

# EKS Variables
variable "cluster_name" {
  description = "EKS cluster name"
  type        = string
}

variable "cluster_version" {
  description = "Kubernetes version"
  type        = string
  default     = "1.29"
}

variable "cluster_endpoint_public_access" {
  description = "Enable public API endpoint"
  type        = bool
  default     = false
}

variable "cluster_endpoint_private_access" {
  description = "Enable private API endpoint"
  type        = bool
  default     = true
}

# Node Group Variables
variable "node_groups" {
  description = "EKS node groups configuration"
  type = map(object({
    instance_types = list(string)
    capacity_type  = string
    min_size       = number
    max_size       = number
    desired_size   = number
    labels         = map(string)
    taints         = list(object({
      key    = string
      value  = string
      effect = string
    }))
  }))
  default = {}
}

# Karpenter Variables
variable "enable_karpenter" {
  description = "Enable Karpenter autoscaler"
  type        = bool
  default     = true
}

# Add-ons Variables
variable "enable_cluster_autoscaler" {
  description = "Enable Cluster Autoscaler"
  type        = bool
  default     = false
}

variable "enable_metrics_server" {
  description = "Enable Metrics Server"
  type        = bool
  default     = true
}

variable "enable_aws_load_balancer_controller" {
  description = "Enable AWS Load Balancer Controller"
  type        = bool
  default     = true
}

variable "enable_external_secrets" {
  description = "Enable External Secrets Operator"
  type        = bool
  default     = true
}

variable "enable_cert_manager" {
  description = "Enable cert-manager"
  type        = bool
  default     = true
}

# Tags
variable "tags" {
  description = "Additional tags"
  type        = map(string)
  default     = {}
}
'''
    
    def _generate_tfvars(self, config: Dict) -> str:
        """Generate terraform.tfvars"""
        
        cluster_name = config.get("cluster_name", "eks-cluster")
        region = config.get("region", "us-east-1")
        environment = config.get("environment", "production")
        k8s_version = config.get("kubernetes_version", "1.29")
        vpc_cidr = config.get("network", {}).get("vpc_cidr", "10.0.0.0/16")
        azs = config.get("network", {}).get("availability_zones", 3)
        
        # Node groups
        node_groups_config = {}
        for ng in config.get("node_groups", []):
            ng_name = ng.get("name", "default")
            node_groups_config[ng_name] = {
                "instance_types": ng.get("instance_types", ["m6i.xlarge"]),
                "capacity_type": ng.get("capacity_type", "ON_DEMAND"),
                "min_size": ng.get("min_size", 1),
                "max_size": ng.get("max_size", 10),
                "desired_size": ng.get("desired_size", 2),
                "labels": ng.get("labels", {}),
                "taints": ng.get("taints", [])
            }
        
        security = config.get("security", {})
        
        tfvars = f'''# Environment Configuration
region      = "{region}"
environment = "{environment}"
project     = "{cluster_name}"

# VPC Configuration
vpc_cidr           = "{vpc_cidr}"
availability_zones = {azs}

# EKS Configuration
cluster_name                    = "{cluster_name}"
cluster_version                 = "{k8s_version}"
cluster_endpoint_public_access  = {str(security.get("public_endpoint", False)).lower()}
cluster_endpoint_private_access = {str(security.get("private_endpoint", True)).lower()}

# Node Groups
node_groups = {{
'''
        
        for ng_name, ng_config in node_groups_config.items():
            tfvars += f'''  {ng_name} = {{
    instance_types = {json.dumps(ng_config["instance_types"])}
    capacity_type  = "{ng_config["capacity_type"]}"
    min_size       = {ng_config["min_size"]}
    max_size       = {ng_config["max_size"]}
    desired_size   = {ng_config["desired_size"]}
    labels         = {json.dumps(ng_config.get("labels", {}))}
    taints         = {json.dumps(ng_config.get("taints", []))}
  }}
'''
        
        tfvars += '''}

# Karpenter
enable_karpenter = true

# Add-ons
enable_cluster_autoscaler           = false
enable_metrics_server               = true
enable_aws_load_balancer_controller = true
enable_external_secrets             = true
enable_cert_manager                 = true

# Tags
tags = {
  "ManagedBy"   = "Terraform"
  "Environment" = "''' + environment + '''"
  "Project"     = "''' + cluster_name + '''"
}
'''
        
        return tfvars
    
    def _generate_locals(self, config: Dict) -> str:
        """Generate locals.tf"""
        
        return '''locals {
  cluster_name = var.cluster_name
  region       = var.region

  azs = slice(data.aws_availability_zones.available.names, 0, var.availability_zones)

  common_tags = merge(
    {
      Environment = var.environment
      Project     = var.project
      ManagedBy   = "Terraform"
      Cluster     = var.cluster_name
    },
    var.tags
  )

  # VPC CIDR calculations
  vpc_cidr = var.vpc_cidr

  # Subnet CIDR calculations
  private_subnets = [for i in range(var.availability_zones) : cidrsubnet(var.vpc_cidr, 4, i)]
  public_subnets  = [for i in range(var.availability_zones) : cidrsubnet(var.vpc_cidr, 8, i + 48)]
  intra_subnets   = [for i in range(var.availability_zones) : cidrsubnet(var.vpc_cidr, 8, i + 52)]
}

data "aws_availability_zones" "available" {
  state = "available"

  filter {
    name   = "opt-in-status"
    values = ["opt-in-not-required"]
  }
}

data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}
'''
    
    def _generate_vpc(self, config: Dict) -> str:
        """Generate vpc.tf"""
        
        return '''#------------------------------------------------------------------------------
# VPC Module
#------------------------------------------------------------------------------

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.4"

  name = "${local.cluster_name}-vpc"
  cidr = local.vpc_cidr

  azs             = local.azs
  private_subnets = local.private_subnets
  public_subnets  = local.public_subnets
  intra_subnets   = local.intra_subnets

  enable_nat_gateway     = true
  single_nat_gateway     = var.environment != "production"
  one_nat_gateway_per_az = var.environment == "production"

  enable_dns_hostnames = true
  enable_dns_support   = true

  # VPC Flow Logs
  enable_flow_log                      = true
  create_flow_log_cloudwatch_log_group = true
  create_flow_log_cloudwatch_iam_role  = true
  flow_log_max_aggregation_interval    = 60

  # Subnet tags for EKS
  public_subnet_tags = {
    "kubernetes.io/role/elb"                      = 1
    "kubernetes.io/cluster/${local.cluster_name}" = "owned"
  }

  private_subnet_tags = {
    "kubernetes.io/role/internal-elb"             = 1
    "kubernetes.io/cluster/${local.cluster_name}" = "owned"
    "karpenter.sh/discovery"                      = local.cluster_name
  }

  tags = local.common_tags
}

#------------------------------------------------------------------------------
# VPC Endpoints
#------------------------------------------------------------------------------

module "vpc_endpoints" {
  source  = "terraform-aws-modules/vpc/aws//modules/vpc-endpoints"
  version = "~> 5.4"

  vpc_id = module.vpc.vpc_id

  endpoints = {
    s3 = {
      service         = "s3"
      service_type    = "Gateway"
      route_table_ids = module.vpc.private_route_table_ids
      tags            = { Name = "${local.cluster_name}-s3-endpoint" }
    }
    ecr_api = {
      service             = "ecr.api"
      private_dns_enabled = true
      subnet_ids          = module.vpc.private_subnets
      security_group_ids  = [aws_security_group.vpc_endpoints.id]
      tags                = { Name = "${local.cluster_name}-ecr-api-endpoint" }
    }
    ecr_dkr = {
      service             = "ecr.dkr"
      private_dns_enabled = true
      subnet_ids          = module.vpc.private_subnets
      security_group_ids  = [aws_security_group.vpc_endpoints.id]
      tags                = { Name = "${local.cluster_name}-ecr-dkr-endpoint" }
    }
    sts = {
      service             = "sts"
      private_dns_enabled = true
      subnet_ids          = module.vpc.private_subnets
      security_group_ids  = [aws_security_group.vpc_endpoints.id]
      tags                = { Name = "${local.cluster_name}-sts-endpoint" }
    }
    logs = {
      service             = "logs"
      private_dns_enabled = true
      subnet_ids          = module.vpc.private_subnets
      security_group_ids  = [aws_security_group.vpc_endpoints.id]
      tags                = { Name = "${local.cluster_name}-logs-endpoint" }
    }
    ssm = {
      service             = "ssm"
      private_dns_enabled = true
      subnet_ids          = module.vpc.private_subnets
      security_group_ids  = [aws_security_group.vpc_endpoints.id]
      tags                = { Name = "${local.cluster_name}-ssm-endpoint" }
    }
  }

  tags = local.common_tags
}
'''
    
    def _generate_eks(self, config: Dict) -> str:
        """Generate eks.tf"""
        
        security = config.get("security", {})
        
        return '''#------------------------------------------------------------------------------
# EKS Cluster
#------------------------------------------------------------------------------

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.2"

  cluster_name    = local.cluster_name
  cluster_version = var.cluster_version

  # Networking
  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  # Cluster endpoint access
  cluster_endpoint_public_access  = var.cluster_endpoint_public_access
  cluster_endpoint_private_access = var.cluster_endpoint_private_access

  # Cluster addons
  cluster_addons = {
    coredns = {
      most_recent = true
      configuration_values = jsonencode({
        computeType = "Fargate"
        replicaCount = 2
      })
    }
    kube-proxy = {
      most_recent = true
    }
    vpc-cni = {
      most_recent    = true
      before_compute = true
      configuration_values = jsonencode({
        env = {
          ENABLE_PREFIX_DELEGATION = "true"
          WARM_PREFIX_TARGET       = "1"
        }
      })
    }
    aws-ebs-csi-driver = {
      most_recent              = true
      service_account_role_arn = module.ebs_csi_irsa.iam_role_arn
    }
  }

  # Encryption
  cluster_encryption_config = {
    provider_key_arn = aws_kms_key.eks.arn
    resources        = ["secrets"]
  }

  # Logging
  cluster_enabled_log_types = [
    "api",
    "audit",
    "authenticator",
    "controllerManager",
    "scheduler"
  ]

  # IAM
  enable_irsa = true

  # Node security group
  node_security_group_additional_rules = {
    ingress_self_all = {
      description = "Node to node all ports/protocols"
      protocol    = "-1"
      from_port   = 0
      to_port     = 0
      type        = "ingress"
      self        = true
    }
  }

  # Access configuration
  authentication_mode                      = "API_AND_CONFIG_MAP"
  enable_cluster_creator_admin_permissions = true

  access_entries = {
    # Add additional access entries as needed
  }

  tags = local.common_tags
}

#------------------------------------------------------------------------------
# KMS Key for EKS Encryption
#------------------------------------------------------------------------------

resource "aws_kms_key" "eks" {
  description             = "KMS key for EKS cluster encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = merge(local.common_tags, {
    Name = "${local.cluster_name}-eks-key"
  })
}

resource "aws_kms_alias" "eks" {
  name          = "alias/${local.cluster_name}-eks"
  target_key_id = aws_kms_key.eks.key_id
}
'''
    
    def _generate_node_groups(self, config: Dict) -> str:
        """Generate node_groups.tf"""
        
        return '''#------------------------------------------------------------------------------
# EKS Managed Node Groups
#------------------------------------------------------------------------------

module "eks_managed_node_groups" {
  source  = "terraform-aws-modules/eks/aws//modules/eks-managed-node-group"
  version = "~> 20.2"

  for_each = var.node_groups

  name            = each.key
  cluster_name    = module.eks.cluster_name
  cluster_version = module.eks.cluster_version

  subnet_ids = module.vpc.private_subnets

  # Node group configuration
  instance_types = each.value.instance_types
  capacity_type  = each.value.capacity_type

  min_size     = each.value.min_size
  max_size     = each.value.max_size
  desired_size = each.value.desired_size

  # Labels and taints
  labels = merge(
    each.value.labels,
    {
      "nodegroup" = each.key
    }
  )

  taints = [for taint in each.value.taints : {
    key    = taint.key
    value  = taint.value
    effect = taint.effect
  }]

  # Launch template configuration
  use_custom_launch_template = true

  block_device_mappings = {
    xvda = {
      device_name = "/dev/xvda"
      ebs = {
        volume_size           = 100
        volume_type           = "gp3"
        iops                  = 3000
        throughput            = 150
        encrypted             = true
        kms_key_id            = aws_kms_key.eks.arn
        delete_on_termination = true
      }
    }
  }

  # IMDSv2
  metadata_options = {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "disabled"
  }

  # Security
  cluster_primary_security_group_id = module.eks.cluster_primary_security_group_id
  vpc_security_group_ids            = [module.eks.node_security_group_id]

  # IAM
  iam_role_additional_policies = {
    AmazonSSMManagedInstanceCore = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
  }

  tags = merge(local.common_tags, {
    "karpenter.sh/discovery" = local.cluster_name
  })
}
'''
    
    def _generate_iam(self, config: Dict) -> str:
        """Generate iam.tf"""
        
        return '''#------------------------------------------------------------------------------
# IAM Roles for Service Accounts (IRSA)
#------------------------------------------------------------------------------

# EBS CSI Driver IRSA
module "ebs_csi_irsa" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "~> 5.32"

  role_name             = "${local.cluster_name}-ebs-csi-driver"
  attach_ebs_csi_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:ebs-csi-controller-sa"]
    }
  }

  tags = local.common_tags
}

# AWS Load Balancer Controller IRSA
module "aws_lb_controller_irsa" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "~> 5.32"

  role_name                              = "${local.cluster_name}-aws-lb-controller"
  attach_load_balancer_controller_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:aws-load-balancer-controller"]
    }
  }

  tags = local.common_tags
}

# External Secrets IRSA
module "external_secrets_irsa" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "~> 5.32"

  role_name                             = "${local.cluster_name}-external-secrets"
  attach_external_secrets_policy        = true
  external_secrets_secrets_manager_arns = ["arn:aws:secretsmanager:${local.region}:${data.aws_caller_identity.current.account_id}:secret:*"]
  external_secrets_ssm_parameter_arns   = ["arn:aws:ssm:${local.region}:${data.aws_caller_identity.current.account_id}:parameter/*"]

  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["external-secrets:external-secrets"]
    }
  }

  tags = local.common_tags
}

# Cert Manager IRSA
module "cert_manager_irsa" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "~> 5.32"

  role_name                     = "${local.cluster_name}-cert-manager"
  attach_cert_manager_policy    = true
  cert_manager_hosted_zone_arns = ["arn:aws:route53:::hostedzone/*"]

  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["cert-manager:cert-manager"]
    }
  }

  tags = local.common_tags
}

# CloudWatch Agent IRSA
module "cloudwatch_agent_irsa" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "~> 5.32"

  role_name = "${local.cluster_name}-cloudwatch-agent"

  role_policy_arns = {
    CloudWatchAgentServerPolicy = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
  }

  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["amazon-cloudwatch:cloudwatch-agent"]
    }
  }

  tags = local.common_tags
}
'''
    
    def _generate_addons(self, config: Dict) -> str:
        """Generate addons.tf"""
        
        return '''#------------------------------------------------------------------------------
# Kubernetes Add-ons (Helm)
#------------------------------------------------------------------------------

# AWS Load Balancer Controller
resource "helm_release" "aws_load_balancer_controller" {
  count = var.enable_aws_load_balancer_controller ? 1 : 0

  name       = "aws-load-balancer-controller"
  repository = "https://aws.github.io/eks-charts"
  chart      = "aws-load-balancer-controller"
  namespace  = "kube-system"
  version    = "1.6.2"

  set {
    name  = "clusterName"
    value = module.eks.cluster_name
  }

  set {
    name  = "serviceAccount.create"
    value = "true"
  }

  set {
    name  = "serviceAccount.name"
    value = "aws-load-balancer-controller"
  }

  set {
    name  = "serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = module.aws_lb_controller_irsa.iam_role_arn
  }

  set {
    name  = "region"
    value = local.region
  }

  set {
    name  = "vpcId"
    value = module.vpc.vpc_id
  }

  depends_on = [module.eks_managed_node_groups]
}

# Metrics Server
resource "helm_release" "metrics_server" {
  count = var.enable_metrics_server ? 1 : 0

  name       = "metrics-server"
  repository = "https://kubernetes-sigs.github.io/metrics-server/"
  chart      = "metrics-server"
  namespace  = "kube-system"
  version    = "3.11.0"

  set {
    name  = "args[0]"
    value = "--kubelet-preferred-address-types=InternalIP"
  }

  depends_on = [module.eks_managed_node_groups]
}

# External Secrets Operator
resource "helm_release" "external_secrets" {
  count = var.enable_external_secrets ? 1 : 0

  name             = "external-secrets"
  repository       = "https://charts.external-secrets.io"
  chart            = "external-secrets"
  namespace        = "external-secrets"
  create_namespace = true
  version          = "0.9.9"

  set {
    name  = "serviceAccount.create"
    value = "true"
  }

  set {
    name  = "serviceAccount.name"
    value = "external-secrets"
  }

  set {
    name  = "serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = module.external_secrets_irsa.iam_role_arn
  }

  depends_on = [module.eks_managed_node_groups]
}

# Cert Manager
resource "helm_release" "cert_manager" {
  count = var.enable_cert_manager ? 1 : 0

  name             = "cert-manager"
  repository       = "https://charts.jetstack.io"
  chart            = "cert-manager"
  namespace        = "cert-manager"
  create_namespace = true
  version          = "1.13.3"

  set {
    name  = "installCRDs"
    value = "true"
  }

  set {
    name  = "serviceAccount.create"
    value = "true"
  }

  set {
    name  = "serviceAccount.name"
    value = "cert-manager"
  }

  set {
    name  = "serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = module.cert_manager_irsa.iam_role_arn
  }

  depends_on = [module.eks_managed_node_groups]
}
'''
    
    def _generate_karpenter(self, config: Dict) -> str:
        """Generate karpenter.tf"""
        
        return '''#------------------------------------------------------------------------------
# Karpenter
#------------------------------------------------------------------------------

module "karpenter" {
  source  = "terraform-aws-modules/eks/aws//modules/karpenter"
  version = "~> 20.2"

  count = var.enable_karpenter ? 1 : 0

  cluster_name = module.eks.cluster_name

  irsa_oidc_provider_arn = module.eks.oidc_provider_arn

  # IAM role policies
  enable_irsa                     = true
  irsa_namespace_service_accounts = ["karpenter:karpenter"]

  # Node IAM role
  node_iam_role_additional_policies = {
    AmazonSSMManagedInstanceCore = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
  }

  tags = local.common_tags
}

# Karpenter Helm Release
resource "helm_release" "karpenter" {
  count = var.enable_karpenter ? 1 : 0

  name       = "karpenter"
  repository = "oci://public.ecr.aws/karpenter"
  chart      = "karpenter"
  namespace  = "karpenter"
  version    = "0.33.1"

  create_namespace = true

  set {
    name  = "settings.clusterName"
    value = module.eks.cluster_name
  }

  set {
    name  = "settings.clusterEndpoint"
    value = module.eks.cluster_endpoint
  }

  set {
    name  = "settings.interruptionQueue"
    value = module.karpenter[0].queue_name
  }

  set {
    name  = "serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = module.karpenter[0].iam_role_arn
  }

  set {
    name  = "controller.resources.requests.cpu"
    value = "1"
  }

  set {
    name  = "controller.resources.requests.memory"
    value = "1Gi"
  }

  set {
    name  = "controller.resources.limits.cpu"
    value = "1"
  }

  set {
    name  = "controller.resources.limits.memory"
    value = "1Gi"
  }

  depends_on = [
    module.eks_managed_node_groups,
    module.karpenter
  ]
}

# Karpenter NodePool
resource "kubectl_manifest" "karpenter_nodepool" {
  count = var.enable_karpenter ? 1 : 0

  yaml_body = <<-YAML
    apiVersion: karpenter.sh/v1beta1
    kind: NodePool
    metadata:
      name: default
    spec:
      template:
        spec:
          nodeClassRef:
            name: default
          requirements:
            - key: kubernetes.io/arch
              operator: In
              values: ["amd64", "arm64"]
            - key: kubernetes.io/os
              operator: In
              values: ["linux"]
            - key: karpenter.sh/capacity-type
              operator: In
              values: ["spot", "on-demand"]
            - key: karpenter.k8s.aws/instance-category
              operator: In
              values: ["c", "m", "r"]
            - key: karpenter.k8s.aws/instance-generation
              operator: Gt
              values: ["5"]
          expireAfter: 720h
      limits:
        cpu: 1000
        memory: 2000Gi
      disruption:
        consolidationPolicy: WhenEmptyOrUnderutilized
        consolidateAfter: 1m
  YAML

  depends_on = [helm_release.karpenter]
}

# Karpenter EC2NodeClass
resource "kubectl_manifest" "karpenter_ec2nodeclass" {
  count = var.enable_karpenter ? 1 : 0

  yaml_body = <<-YAML
    apiVersion: karpenter.k8s.aws/v1beta1
    kind: EC2NodeClass
    metadata:
      name: default
    spec:
      role: ${module.karpenter[0].node_iam_role_name}
      amiFamily: AL2023
      subnetSelectorTerms:
        - tags:
            karpenter.sh/discovery: ${module.eks.cluster_name}
      securityGroupSelectorTerms:
        - tags:
            karpenter.sh/discovery: ${module.eks.cluster_name}
      blockDeviceMappings:
        - deviceName: /dev/xvda
          ebs:
            volumeSize: 100Gi
            volumeType: gp3
            iops: 3000
            throughput: 125
            encrypted: true
            kmsKeyId: ${aws_kms_key.eks.arn}
            deleteOnTermination: true
      metadataOptions:
        httpEndpoint: enabled
        httpProtocolIPv6: disabled
        httpPutResponseHopLimit: 1
        httpTokens: required
      tags:
        Environment: ${var.environment}
        ManagedBy: karpenter
  YAML

  depends_on = [helm_release.karpenter]
}
'''
    
    def _generate_security_groups(self, config: Dict) -> str:
        """Generate security_groups.tf"""
        
        return '''#------------------------------------------------------------------------------
# Security Groups
#------------------------------------------------------------------------------

# VPC Endpoints Security Group
resource "aws_security_group" "vpc_endpoints" {
  name        = "${local.cluster_name}-vpc-endpoints"
  description = "Security group for VPC endpoints"
  vpc_id      = module.vpc.vpc_id

  ingress {
    description = "HTTPS from VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [module.vpc.vpc_cidr_block]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name = "${local.cluster_name}-vpc-endpoints"
  })
}
'''
    
    def _generate_outputs(self, config: Dict) -> str:
        """Generate outputs.tf"""
        
        return '''#------------------------------------------------------------------------------
# Outputs
#------------------------------------------------------------------------------

# VPC Outputs
output "vpc_id" {
  description = "VPC ID"
  value       = module.vpc.vpc_id
}

output "private_subnets" {
  description = "Private subnet IDs"
  value       = module.vpc.private_subnets
}

output "public_subnets" {
  description = "Public subnet IDs"
  value       = module.vpc.public_subnets
}

# EKS Outputs
output "cluster_name" {
  description = "EKS cluster name"
  value       = module.eks.cluster_name
}

output "cluster_endpoint" {
  description = "EKS cluster endpoint"
  value       = module.eks.cluster_endpoint
}

output "cluster_certificate_authority_data" {
  description = "EKS cluster CA certificate"
  value       = module.eks.cluster_certificate_authority_data
  sensitive   = true
}

output "cluster_oidc_issuer_url" {
  description = "OIDC issuer URL"
  value       = module.eks.cluster_oidc_issuer_url
}

output "cluster_oidc_provider_arn" {
  description = "OIDC provider ARN"
  value       = module.eks.oidc_provider_arn
}

output "cluster_security_group_id" {
  description = "Cluster security group ID"
  value       = module.eks.cluster_security_group_id
}

output "node_security_group_id" {
  description = "Node security group ID"
  value       = module.eks.node_security_group_id
}

# Karpenter Outputs
output "karpenter_irsa_role_arn" {
  description = "Karpenter IRSA role ARN"
  value       = var.enable_karpenter ? module.karpenter[0].iam_role_arn : null
}

output "karpenter_node_role_name" {
  description = "Karpenter node IAM role name"
  value       = var.enable_karpenter ? module.karpenter[0].node_iam_role_name : null
}

# KMS Key
output "kms_key_arn" {
  description = "KMS key ARN for EKS encryption"
  value       = aws_kms_key.eks.arn
}

# Configure kubectl
output "configure_kubectl" {
  description = "Command to configure kubectl"
  value       = "aws eks update-kubeconfig --region ${local.region} --name ${module.eks.cluster_name}"
}
'''
    
    def _generate_readme(self, config: Dict) -> str:
        """Generate README.md"""
        
        cluster_name = config.get("cluster_name", "eks-cluster")
        
        return f'''# {cluster_name} - Terraform Configuration

This Terraform configuration deploys a production-ready EKS cluster with best practices.

## Features

- ✅ EKS cluster with managed node groups
- ✅ VPC with public/private subnets across multiple AZs
- ✅ VPC endpoints for AWS services
- ✅ Karpenter for autoscaling
- ✅ AWS Load Balancer Controller
- ✅ External Secrets Operator
- ✅ Cert Manager
- ✅ KMS encryption for secrets
- ✅ IRSA for all add-ons
- ✅ VPC Flow Logs

## Prerequisites

- Terraform >= 1.5.0
- AWS CLI configured
- kubectl installed

## Quick Start

1. Initialize Terraform:
   ```bash
   terraform init
   ```

2. Review the plan:
   ```bash
   terraform plan
   ```

3. Apply the configuration:
   ```bash
   terraform apply
   ```

4. Configure kubectl:
   ```bash
   aws eks update-kubeconfig --region us-east-1 --name {cluster_name}
   ```

## Module Structure

```
.
├── versions.tf         # Terraform and provider versions
├── providers.tf        # Provider configurations
├── variables.tf        # Input variables
├── terraform.tfvars    # Variable values
├── locals.tf          # Local values
├── vpc.tf             # VPC configuration
├── eks.tf             # EKS cluster
├── node_groups.tf     # Managed node groups
├── iam.tf             # IAM roles (IRSA)
├── addons.tf          # Kubernetes add-ons
├── karpenter.tf       # Karpenter autoscaler
├── security_groups.tf # Security groups
└── outputs.tf         # Outputs
```

## Customization

Edit `terraform.tfvars` to customize:
- Cluster name and version
- VPC CIDR and availability zones
- Node group configurations
- Add-on enablement

## Cleanup

```bash
terraform destroy
```

## Security Considerations

- All endpoints are private by default
- IMDSv2 enforced on all nodes
- EBS volumes encrypted with KMS
- VPC Flow Logs enabled
- Secrets encrypted with envelope encryption
'''
    
    def _generate_makefile(self) -> str:
        """Generate Makefile"""
        
        return '''# Terraform Makefile

.PHONY: init plan apply destroy fmt validate docs

# Initialize Terraform
init:
	terraform init -upgrade

# Format code
fmt:
	terraform fmt -recursive

# Validate configuration
validate:
	terraform validate

# Plan changes
plan:
	terraform plan -out=tfplan

# Apply changes
apply:
	terraform apply tfplan

# Apply with auto-approve (use with caution)
apply-auto:
	terraform apply -auto-approve

# Destroy infrastructure
destroy:
	terraform destroy

# Show outputs
output:
	terraform output

# Configure kubectl
kubeconfig:
	@eval "$$(terraform output -raw configure_kubectl)"

# Generate documentation
docs:
	terraform-docs markdown table . > TERRAFORM.md

# Clean up
clean:
	rm -rf .terraform tfplan .terraform.lock.hcl

# Full workflow
all: fmt validate plan apply
'''


# ============================================================================
# CLOUDFORMATION GENERATOR
# ============================================================================

class CloudFormationGenerator:
    """
    Generates CloudFormation templates for EKS clusters.
    """
    
    def generate_cloudformation(self, cluster_config: Dict) -> Dict[str, str]:
        """Generate CloudFormation templates"""
        
        files = {}
        
        # Main EKS template
        files["eks-cluster.yaml"] = self._generate_eks_template(cluster_config)
        
        # VPC template
        files["vpc.yaml"] = self._generate_vpc_template(cluster_config)
        
        # Node groups template
        files["node-groups.yaml"] = self._generate_nodegroups_template(cluster_config)
        
        # Master template (nested stacks)
        files["master.yaml"] = self._generate_master_template(cluster_config)
        
        return files
    
    def _generate_eks_template(self, config: Dict) -> str:
        """Generate EKS cluster CloudFormation template"""
        
        template = {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Description": "EKS Cluster Stack",
            "Parameters": {
                "ClusterName": {
                    "Type": "String",
                    "Default": config.get("cluster_name", "eks-cluster")
                },
                "KubernetesVersion": {
                    "Type": "String",
                    "Default": config.get("kubernetes_version", "1.29")
                },
                "VpcId": {
                    "Type": "AWS::EC2::VPC::Id"
                },
                "SubnetIds": {
                    "Type": "List<AWS::EC2::Subnet::Id>"
                }
            },
            "Resources": {
                "EKSClusterRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [{
                                "Effect": "Allow",
                                "Principal": {"Service": "eks.amazonaws.com"},
                                "Action": "sts:AssumeRole"
                            }]
                        },
                        "ManagedPolicyArns": [
                            "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
                        ]
                    }
                },
                "EKSCluster": {
                    "Type": "AWS::EKS::Cluster",
                    "Properties": {
                        "Name": {"Ref": "ClusterName"},
                        "Version": {"Ref": "KubernetesVersion"},
                        "RoleArn": {"Fn::GetAtt": ["EKSClusterRole", "Arn"]},
                        "ResourcesVpcConfig": {
                            "SubnetIds": {"Ref": "SubnetIds"},
                            "EndpointPublicAccess": False,
                            "EndpointPrivateAccess": True
                        },
                        "Logging": {
                            "ClusterLogging": {
                                "EnabledTypes": [
                                    {"Type": "api"},
                                    {"Type": "audit"},
                                    {"Type": "authenticator"},
                                    {"Type": "controllerManager"},
                                    {"Type": "scheduler"}
                                ]
                            }
                        }
                    }
                }
            },
            "Outputs": {
                "ClusterName": {
                    "Value": {"Ref": "EKSCluster"},
                    "Export": {"Name": {"Fn::Sub": "${AWS::StackName}-ClusterName"}}
                },
                "ClusterEndpoint": {
                    "Value": {"Fn::GetAtt": ["EKSCluster", "Endpoint"]},
                    "Export": {"Name": {"Fn::Sub": "${AWS::StackName}-ClusterEndpoint"}}
                },
                "ClusterArn": {
                    "Value": {"Fn::GetAtt": ["EKSCluster", "Arn"]},
                    "Export": {"Name": {"Fn::Sub": "${AWS::StackName}-ClusterArn"}}
                }
            }
        }
        
        return yaml.dump(template, default_flow_style=False, sort_keys=False)
    
    def _generate_vpc_template(self, config: Dict) -> str:
        """Generate VPC CloudFormation template"""
        
        vpc_cidr = config.get("network", {}).get("vpc_cidr", "10.0.0.0/16")
        
        template = {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Description": "VPC Stack for EKS",
            "Parameters": {
                "VpcCidr": {
                    "Type": "String",
                    "Default": vpc_cidr
                },
                "ClusterName": {
                    "Type": "String"
                }
            },
            "Resources": {
                "VPC": {
                    "Type": "AWS::EC2::VPC",
                    "Properties": {
                        "CidrBlock": {"Ref": "VpcCidr"},
                        "EnableDnsHostnames": True,
                        "EnableDnsSupport": True,
                        "Tags": [
                            {"Key": "Name", "Value": {"Fn::Sub": "${ClusterName}-vpc"}}
                        ]
                    }
                },
                "InternetGateway": {
                    "Type": "AWS::EC2::InternetGateway",
                    "Properties": {
                        "Tags": [
                            {"Key": "Name", "Value": {"Fn::Sub": "${ClusterName}-igw"}}
                        ]
                    }
                },
                "InternetGatewayAttachment": {
                    "Type": "AWS::EC2::VPCGatewayAttachment",
                    "Properties": {
                        "VpcId": {"Ref": "VPC"},
                        "InternetGatewayId": {"Ref": "InternetGateway"}
                    }
                }
            },
            "Outputs": {
                "VpcId": {
                    "Value": {"Ref": "VPC"},
                    "Export": {"Name": {"Fn::Sub": "${AWS::StackName}-VpcId"}}
                }
            }
        }
        
        return yaml.dump(template, default_flow_style=False, sort_keys=False)
    
    def _generate_nodegroups_template(self, config: Dict) -> str:
        """Generate Node Groups CloudFormation template"""
        
        template = {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Description": "EKS Node Groups Stack",
            "Parameters": {
                "ClusterName": {
                    "Type": "String"
                },
                "NodeGroupName": {
                    "Type": "String",
                    "Default": "default"
                },
                "InstanceTypes": {
                    "Type": "CommaDelimitedList",
                    "Default": "m6i.xlarge"
                },
                "DesiredSize": {
                    "Type": "Number",
                    "Default": 2
                },
                "MinSize": {
                    "Type": "Number",
                    "Default": 1
                },
                "MaxSize": {
                    "Type": "Number",
                    "Default": 10
                },
                "SubnetIds": {
                    "Type": "List<AWS::EC2::Subnet::Id>"
                }
            },
            "Resources": {
                "NodeInstanceRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [{
                                "Effect": "Allow",
                                "Principal": {"Service": "ec2.amazonaws.com"},
                                "Action": "sts:AssumeRole"
                            }]
                        },
                        "ManagedPolicyArns": [
                            "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
                            "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
                            "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
                            "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
                        ]
                    }
                },
                "NodeGroup": {
                    "Type": "AWS::EKS::Nodegroup",
                    "Properties": {
                        "ClusterName": {"Ref": "ClusterName"},
                        "NodegroupName": {"Ref": "NodeGroupName"},
                        "NodeRole": {"Fn::GetAtt": ["NodeInstanceRole", "Arn"]},
                        "Subnets": {"Ref": "SubnetIds"},
                        "InstanceTypes": {"Ref": "InstanceTypes"},
                        "ScalingConfig": {
                            "DesiredSize": {"Ref": "DesiredSize"},
                            "MinSize": {"Ref": "MinSize"},
                            "MaxSize": {"Ref": "MaxSize"}
                        },
                        "DiskSize": 100
                    }
                }
            },
            "Outputs": {
                "NodeGroupArn": {
                    "Value": {"Fn::GetAtt": ["NodeGroup", "Arn"]}
                }
            }
        }
        
        return yaml.dump(template, default_flow_style=False, sort_keys=False)
    
    def _generate_master_template(self, config: Dict) -> str:
        """Generate master CloudFormation template with nested stacks"""
        
        template = {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Description": "Master Stack for EKS Deployment",
            "Parameters": {
                "ClusterName": {
                    "Type": "String",
                    "Default": config.get("cluster_name", "eks-cluster")
                },
                "S3BucketName": {
                    "Type": "String",
                    "Description": "S3 bucket containing nested templates"
                }
            },
            "Resources": {
                "VPCStack": {
                    "Type": "AWS::CloudFormation::Stack",
                    "Properties": {
                        "TemplateURL": {"Fn::Sub": "https://${S3BucketName}.s3.amazonaws.com/vpc.yaml"},
                        "Parameters": {
                            "ClusterName": {"Ref": "ClusterName"}
                        }
                    }
                },
                "EKSStack": {
                    "Type": "AWS::CloudFormation::Stack",
                    "DependsOn": "VPCStack",
                    "Properties": {
                        "TemplateURL": {"Fn::Sub": "https://${S3BucketName}.s3.amazonaws.com/eks-cluster.yaml"},
                        "Parameters": {
                            "ClusterName": {"Ref": "ClusterName"},
                            "VpcId": {"Fn::GetAtt": ["VPCStack", "Outputs.VpcId"]}
                        }
                    }
                }
            },
            "Outputs": {
                "ClusterName": {
                    "Value": {"Fn::GetAtt": ["EKSStack", "Outputs.ClusterName"]}
                },
                "ClusterEndpoint": {
                    "Value": {"Fn::GetAtt": ["EKSStack", "Outputs.ClusterEndpoint"]}
                }
            }
        }
        
        return yaml.dump(template, default_flow_style=False, sort_keys=False)
