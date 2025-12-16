"""
EKS GitOps Configuration Generator
Part of the AI-Enhanced EKS Architecture Design Wizard

Features:
- ArgoCD / Flux Configuration Generator
- Repository Structure Templates
- Progressive Delivery Setup (Argo Rollouts / Flagger)
- Policy as Code (Kyverno / OPA Gatekeeper)
- Multi-cluster GitOps Patterns

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
import base64

# ============================================================================
# GITOPS ENUMS AND CONSTANTS
# ============================================================================

class GitOpsToolType(Enum):
    """GitOps Tool Selection"""
    ARGOCD = "argocd"
    FLUX = "flux"

class RepositoryProvider(Enum):
    """Git Repository Providers"""
    GITHUB = "github"
    GITLAB = "gitlab"
    CODECOMMIT = "codecommit"
    BITBUCKET = "bitbucket"

class BranchStrategy(Enum):
    """Branching Strategies"""
    GITFLOW = "gitflow"
    TRUNK_BASED = "trunk_based"
    GITHUB_FLOW = "github_flow"
    ENVIRONMENT_BRANCHES = "environment_branches"

class ProgressiveDeliveryTool(Enum):
    """Progressive Delivery Tools"""
    ARGO_ROLLOUTS = "argo_rollouts"
    FLAGGER = "flagger"
    NONE = "none"

class PolicyEngine(Enum):
    """Policy Engines"""
    KYVERNO = "kyverno"
    OPA_GATEKEEPER = "opa_gatekeeper"
    NONE = "none"


# ============================================================================
# GITOPS DATA CLASSES
# ============================================================================

@dataclass
class GitOpsConfiguration:
    """GitOps Configuration Specification"""
    tool: GitOpsToolType = GitOpsToolType.ARGOCD
    repository_provider: RepositoryProvider = RepositoryProvider.GITHUB
    repository_url: str = ""
    branch_strategy: BranchStrategy = BranchStrategy.GITFLOW
    
    environments: List[str] = field(default_factory=lambda: ["dev", "staging", "prod"])
    enable_progressive_delivery: bool = True
    progressive_delivery_tool: ProgressiveDeliveryTool = ProgressiveDeliveryTool.ARGO_ROLLOUTS
    
    enable_image_automation: bool = True
    image_update_strategy: str = "semver"  # semver, numeric, alphabetical
    
    enable_policy_as_code: bool = True
    policy_engine: PolicyEngine = PolicyEngine.KYVERNO
    
    enable_notifications: bool = True
    notification_channels: List[str] = field(default_factory=lambda: ["slack"])
    
    multi_cluster: bool = False
    clusters: List[str] = field(default_factory=list)
    
    sync_policy: str = "automated"  # automated, manual
    auto_prune: bool = True
    self_heal: bool = True


# ============================================================================
# REPOSITORY STRUCTURE TEMPLATES
# ============================================================================

REPOSITORY_STRUCTURES = {
    "monorepo": {
        "name": "Monorepo Pattern",
        "description": "Single repository for all applications and infrastructure",
        "structure": """
├── apps/
│   ├── app1/
│   │   ├── base/
│   │   │   ├── deployment.yaml
│   │   │   ├── service.yaml
│   │   │   ├── configmap.yaml
│   │   │   └── kustomization.yaml
│   │   └── overlays/
│   │       ├── dev/
│   │       │   ├── kustomization.yaml
│   │       │   └── patches/
│   │       ├── staging/
│   │       │   ├── kustomization.yaml
│   │       │   └── patches/
│   │       └── prod/
│   │           ├── kustomization.yaml
│   │           └── patches/
│   └── app2/
│       └── ... (same structure)
├── infrastructure/
│   ├── base/
│   │   ├── namespaces.yaml
│   │   ├── network-policies.yaml
│   │   └── kustomization.yaml
│   └── overlays/
│       ├── dev/
│       ├── staging/
│       └── prod/
├── platform/
│   ├── argocd/
│   ├── prometheus/
│   ├── cert-manager/
│   └── external-secrets/
├── policies/
│   ├── kyverno/
│   │   ├── require-labels.yaml
│   │   ├── require-probes.yaml
│   │   └── restrict-registries.yaml
│   └── opa/
└── clusters/
    ├── dev/
    │   └── kustomization.yaml
    ├── staging/
    │   └── kustomization.yaml
    └── prod/
        └── kustomization.yaml
""",
        "pros": ["Single source of truth", "Easier to manage", "Atomic changes"],
        "cons": ["Can become large", "Requires careful access control"],
        "best_for": ["Small to medium teams", "Tightly coupled services"]
    },
    "polyrepo": {
        "name": "Polyrepo Pattern",
        "description": "Separate repositories for applications and infrastructure",
        "structure": """
# App Repository (per service)
├── src/
├── tests/
├── Dockerfile
├── helm/
│   ├── Chart.yaml
│   ├── values.yaml
│   └── templates/
└── .github/workflows/

# GitOps Repository
├── apps/
│   ├── app1/
│   │   ├── dev/
│   │   │   └── values.yaml
│   │   ├── staging/
│   │   │   └── values.yaml
│   │   └── prod/
│   │       └── values.yaml
│   └── app2/
├── infrastructure/
├── platform/
└── clusters/
""",
        "pros": ["Team autonomy", "Independent release cycles", "Clear ownership"],
        "cons": ["Coordination overhead", "Version management complexity"],
        "best_for": ["Large organizations", "Independent teams"]
    },
    "app_of_apps": {
        "name": "App of Apps Pattern",
        "description": "Hierarchical application management with ArgoCD",
        "structure": """
├── argocd-apps/
│   ├── root-app.yaml           # Points to all environment apps
│   ├── dev-apps.yaml           # App of apps for dev
│   ├── staging-apps.yaml       # App of apps for staging
│   └── prod-apps.yaml          # App of apps for prod
├── applicationsets/
│   ├── cluster-generator.yaml  # Multi-cluster deployment
│   └── git-generator.yaml      # Dynamic app discovery
├── projects/
│   ├── platform.yaml
│   ├── applications.yaml
│   └── security.yaml
├── apps/
│   ├── platform/
│   │   ├── argocd/
│   │   ├── prometheus/
│   │   └── cert-manager/
│   └── workloads/
│       ├── app1/
│       └── app2/
└── clusters/
    ├── dev-cluster/
    ├── staging-cluster/
    └── prod-cluster/
""",
        "pros": ["Scalable", "Declarative hierarchy", "Easy multi-cluster"],
        "cons": ["ArgoCD specific", "Learning curve"],
        "best_for": ["ArgoCD users", "Multi-cluster setups"]
    }
}


# ============================================================================
# GITOPS GENERATOR
# ============================================================================

class GitOpsConfigurationGenerator:
    """
    Generates comprehensive GitOps configurations for EKS clusters.
    Supports ArgoCD, Flux, progressive delivery, and policy-as-code.
    """
    
    def __init__(self, config: GitOpsConfiguration):
        self.config = config
    
    def generate_all(self) -> Dict[str, Any]:
        """Generate all GitOps configurations"""
        
        result = {
            "repository_structure": self._generate_repo_structure(),
            "gitops_tool_config": self._generate_tool_config(),
            "applications": self._generate_application_configs(),
            "progressive_delivery": self._generate_progressive_delivery_config(),
            "policies": self._generate_policies(),
            "notifications": self._generate_notifications(),
            "scripts": self._generate_helper_scripts()
        }
        
        if self.config.multi_cluster:
            result["multi_cluster"] = self._generate_multi_cluster_config()
        
        return result
    
    def _generate_repo_structure(self) -> Dict[str, Any]:
        """Generate recommended repository structure"""
        
        # Base structure files
        files = {}
        
        # Root README
        files["README.md"] = self._generate_readme()
        
        # Base kustomization
        files["apps/base/kustomization.yaml"] = yaml.dump({
            "apiVersion": "kustomize.config.k8s.io/v1beta1",
            "kind": "Kustomization",
            "resources": []
        })
        
        # Environment overlays
        for env in self.config.environments:
            files[f"apps/overlays/{env}/kustomization.yaml"] = yaml.dump({
                "apiVersion": "kustomize.config.k8s.io/v1beta1",
                "kind": "Kustomization",
                "namespace": f"app-{env}",
                "resources": ["../../base"],
                "patches": [],
                "images": []
            })
        
        # Namespace definitions
        namespaces = []
        for env in self.config.environments:
            namespaces.append({
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": {
                    "name": f"app-{env}",
                    "labels": {
                        "environment": env,
                        "managed-by": "gitops"
                    }
                }
            })
        
        files["infrastructure/namespaces.yaml"] = yaml.dump_all(namespaces)
        
        return {
            "files": files,
            "recommended_pattern": "monorepo" if not self.config.multi_cluster else "app_of_apps",
            "structure_diagram": REPOSITORY_STRUCTURES["monorepo"]["structure"]
        }
    
    def _generate_tool_config(self) -> Dict[str, Any]:
        """Generate GitOps tool configuration"""
        
        if self.config.tool == GitOpsToolType.ARGOCD:
            return self._generate_argocd_config()
        else:
            return self._generate_flux_config()
    
    def _generate_argocd_config(self) -> Dict[str, Any]:
        """Generate ArgoCD configurations"""
        
        configs = {}
        
        # ArgoCD installation values
        configs["argocd-values.yaml"] = yaml.dump({
            "global": {
                "image": {
                    "tag": "v2.10.0"
                }
            },
            "configs": {
                "cm": {
                    "url": "https://argocd.example.com",
                    "admin.enabled": False,
                    "dex.config": """
connectors:
  - type: github
    id: github
    name: GitHub
    config:
      clientID: $GITHUB_CLIENT_ID
      clientSecret: $GITHUB_CLIENT_SECRET
      orgs:
        - name: your-org
"""
                },
                "params": {
                    "server.insecure": False,
                    "controller.status.processors": 20,
                    "controller.operation.processors": 10,
                    "applicationsetcontroller.enable.progressive.syncs": True
                },
                "rbac": {
                    "policy.default": "role:readonly",
                    "policy.csv": """
p, role:org-admin, applications, *, */*, allow
p, role:org-admin, clusters, get, *, allow
p, role:org-admin, projects, get, *, allow
g, your-org:platform-team, role:org-admin
"""
                }
            },
            "controller": {
                "replicas": 1,
                "resources": {
                    "limits": {"cpu": "1000m", "memory": "1024Mi"},
                    "requests": {"cpu": "250m", "memory": "512Mi"}
                },
                "metrics": {"enabled": True}
            },
            "server": {
                "replicas": 2,
                "autoscaling": {"enabled": True, "minReplicas": 2, "maxReplicas": 5},
                "ingress": {
                    "enabled": True,
                    "ingressClassName": "alb",
                    "annotations": {
                        "alb.ingress.kubernetes.io/scheme": "internet-facing",
                        "alb.ingress.kubernetes.io/target-type": "ip",
                        "alb.ingress.kubernetes.io/certificate-arn": "${ACM_CERT_ARN}"
                    },
                    "hosts": ["argocd.example.com"]
                }
            },
            "repoServer": {
                "replicas": 2,
                "autoscaling": {"enabled": True}
            },
            "applicationSet": {
                "enabled": True,
                "replicas": 2
            }
        })
        
        # ArgoCD Project
        configs["argocd-project.yaml"] = yaml.dump({
            "apiVersion": "argoproj.io/v1alpha1",
            "kind": "AppProject",
            "metadata": {
                "name": "applications",
                "namespace": "argocd"
            },
            "spec": {
                "description": "Application workloads",
                "sourceRepos": [self.config.repository_url or "https://github.com/your-org/*"],
                "destinations": [
                    {"namespace": "*", "server": "https://kubernetes.default.svc"}
                ],
                "clusterResourceWhitelist": [
                    {"group": "*", "kind": "*"}
                ],
                "namespaceResourceWhitelist": [
                    {"group": "*", "kind": "*"}
                ],
                "syncWindows": [
                    {
                        "kind": "deny",
                        "schedule": "0 22 * * 5",
                        "duration": "48h",
                        "applications": ["*"],
                        "namespaces": ["prod-*"],
                        "clusters": ["*"]
                    }
                ]
            }
        })
        
        # Application template
        configs["application-template.yaml"] = yaml.dump({
            "apiVersion": "argoproj.io/v1alpha1",
            "kind": "Application",
            "metadata": {
                "name": "${APP_NAME}-${ENV}",
                "namespace": "argocd",
                "finalizers": ["resources-finalizer.argocd.argoproj.io"]
            },
            "spec": {
                "project": "applications",
                "source": {
                    "repoURL": self.config.repository_url or "https://github.com/your-org/gitops-repo",
                    "targetRevision": "${ENV}",
                    "path": "apps/${APP_NAME}/overlays/${ENV}"
                },
                "destination": {
                    "server": "https://kubernetes.default.svc",
                    "namespace": "${APP_NAME}-${ENV}"
                },
                "syncPolicy": {
                    "automated": {
                        "prune": self.config.auto_prune,
                        "selfHeal": self.config.self_heal,
                        "allowEmpty": False
                    },
                    "syncOptions": [
                        "CreateNamespace=true",
                        "PrunePropagationPolicy=foreground",
                        "PruneLast=true"
                    ],
                    "retry": {
                        "limit": 5,
                        "backoff": {
                            "duration": "5s",
                            "factor": 2,
                            "maxDuration": "3m"
                        }
                    }
                }
            }
        })
        
        # ApplicationSet for multi-environment deployment
        configs["applicationset.yaml"] = yaml.dump({
            "apiVersion": "argoproj.io/v1alpha1",
            "kind": "ApplicationSet",
            "metadata": {
                "name": "applications",
                "namespace": "argocd"
            },
            "spec": {
                "generators": [
                    {
                        "matrix": {
                            "generators": [
                                {
                                    "git": {
                                        "repoURL": self.config.repository_url or "https://github.com/your-org/gitops-repo",
                                        "revision": "HEAD",
                                        "directories": [
                                            {"path": "apps/*"}
                                        ]
                                    }
                                },
                                {
                                    "list": {
                                        "elements": [
                                            {"env": env, "cluster": "https://kubernetes.default.svc"}
                                            for env in self.config.environments
                                        ]
                                    }
                                }
                            ]
                        }
                    }
                ],
                "template": {
                    "metadata": {
                        "name": "{{path.basename}}-{{env}}"
                    },
                    "spec": {
                        "project": "applications",
                        "source": {
                            "repoURL": self.config.repository_url or "https://github.com/your-org/gitops-repo",
                            "targetRevision": "HEAD",
                            "path": "{{path}}/overlays/{{env}}"
                        },
                        "destination": {
                            "server": "{{cluster}}",
                            "namespace": "{{path.basename}}-{{env}}"
                        },
                        "syncPolicy": {
                            "automated": {
                                "prune": True,
                                "selfHeal": True
                            }
                        }
                    }
                }
            }
        })
        
        return {
            "tool": "ArgoCD",
            "version": "2.10.0",
            "configs": configs,
            "installation_command": "helm upgrade --install argocd argo/argo-cd -n argocd --create-namespace -f argocd-values.yaml"
        }
    
    def _generate_flux_config(self) -> Dict[str, Any]:
        """Generate Flux configurations"""
        
        configs = {}
        
        # Flux installation
        configs["flux-install.sh"] = """#!/bin/bash
# Install Flux CLI
curl -s https://fluxcd.io/install.sh | sudo bash

# Bootstrap Flux
flux bootstrap github \\
  --owner=your-org \\
  --repository=gitops-repo \\
  --branch=main \\
  --path=clusters/production \\
  --personal
"""
        
        # GitRepository
        configs["git-repository.yaml"] = yaml.dump({
            "apiVersion": "source.toolkit.fluxcd.io/v1",
            "kind": "GitRepository",
            "metadata": {
                "name": "gitops-repo",
                "namespace": "flux-system"
            },
            "spec": {
                "interval": "1m",
                "url": self.config.repository_url or "https://github.com/your-org/gitops-repo",
                "ref": {
                    "branch": "main"
                },
                "secretRef": {
                    "name": "github-token"
                }
            }
        })
        
        # Kustomization
        for env in self.config.environments:
            configs[f"kustomization-{env}.yaml"] = yaml.dump({
                "apiVersion": "kustomize.toolkit.fluxcd.io/v1",
                "kind": "Kustomization",
                "metadata": {
                    "name": f"apps-{env}",
                    "namespace": "flux-system"
                },
                "spec": {
                    "interval": "5m",
                    "path": f"./apps/overlays/{env}",
                    "prune": True,
                    "sourceRef": {
                        "kind": "GitRepository",
                        "name": "gitops-repo"
                    },
                    "healthChecks": [
                        {
                            "apiVersion": "apps/v1",
                            "kind": "Deployment",
                            "namespace": f"app-{env}"
                        }
                    ],
                    "timeout": "2m"
                }
            })
        
        # Image automation
        if self.config.enable_image_automation:
            configs["image-repository.yaml"] = yaml.dump({
                "apiVersion": "image.toolkit.fluxcd.io/v1beta2",
                "kind": "ImageRepository",
                "metadata": {
                    "name": "app-image",
                    "namespace": "flux-system"
                },
                "spec": {
                    "image": "your-ecr-repo.dkr.ecr.region.amazonaws.com/app",
                    "interval": "1m",
                    "provider": "aws"
                }
            })
            
            configs["image-policy.yaml"] = yaml.dump({
                "apiVersion": "image.toolkit.fluxcd.io/v1beta2",
                "kind": "ImagePolicy",
                "metadata": {
                    "name": "app-image-policy",
                    "namespace": "flux-system"
                },
                "spec": {
                    "imageRepositoryRef": {
                        "name": "app-image"
                    },
                    "policy": {
                        "semver": {
                            "range": ">=1.0.0"
                        }
                    }
                }
            })
        
        return {
            "tool": "Flux",
            "version": "2.2.0",
            "configs": configs,
            "installation_command": "flux bootstrap github --owner=your-org --repository=gitops-repo --branch=main --path=clusters/production"
        }
    
    def _generate_application_configs(self) -> Dict[str, Any]:
        """Generate sample application configurations"""
        
        configs = {}
        
        # Sample deployment
        configs["deployment.yaml"] = yaml.dump({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": "sample-app",
                "labels": {
                    "app": "sample-app",
                    "version": "v1"
                }
            },
            "spec": {
                "replicas": 3,
                "selector": {
                    "matchLabels": {
                        "app": "sample-app"
                    }
                },
                "template": {
                    "metadata": {
                        "labels": {
                            "app": "sample-app",
                            "version": "v1"
                        },
                        "annotations": {
                            "prometheus.io/scrape": "true",
                            "prometheus.io/port": "8080"
                        }
                    },
                    "spec": {
                        "serviceAccountName": "sample-app",
                        "securityContext": {
                            "runAsNonRoot": True,
                            "runAsUser": 1000,
                            "fsGroup": 1000
                        },
                        "containers": [
                            {
                                "name": "app",
                                "image": "sample-app:v1.0.0",
                                "ports": [{"containerPort": 8080}],
                                "resources": {
                                    "requests": {"cpu": "100m", "memory": "128Mi"},
                                    "limits": {"cpu": "500m", "memory": "512Mi"}
                                },
                                "securityContext": {
                                    "allowPrivilegeEscalation": False,
                                    "readOnlyRootFilesystem": True,
                                    "capabilities": {"drop": ["ALL"]}
                                },
                                "livenessProbe": {
                                    "httpGet": {"path": "/health", "port": 8080},
                                    "initialDelaySeconds": 10,
                                    "periodSeconds": 10
                                },
                                "readinessProbe": {
                                    "httpGet": {"path": "/ready", "port": 8080},
                                    "initialDelaySeconds": 5,
                                    "periodSeconds": 5
                                }
                            }
                        ]
                    }
                }
            }
        })
        
        # Service
        configs["service.yaml"] = yaml.dump({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {
                "name": "sample-app"
            },
            "spec": {
                "selector": {
                    "app": "sample-app"
                },
                "ports": [
                    {"port": 80, "targetPort": 8080}
                ]
            }
        })
        
        # HorizontalPodAutoscaler
        configs["hpa.yaml"] = yaml.dump({
            "apiVersion": "autoscaling/v2",
            "kind": "HorizontalPodAutoscaler",
            "metadata": {
                "name": "sample-app"
            },
            "spec": {
                "scaleTargetRef": {
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "name": "sample-app"
                },
                "minReplicas": 3,
                "maxReplicas": 10,
                "metrics": [
                    {
                        "type": "Resource",
                        "resource": {
                            "name": "cpu",
                            "target": {"type": "Utilization", "averageUtilization": 70}
                        }
                    },
                    {
                        "type": "Resource",
                        "resource": {
                            "name": "memory",
                            "target": {"type": "Utilization", "averageUtilization": 80}
                        }
                    }
                ]
            }
        })
        
        # PodDisruptionBudget
        configs["pdb.yaml"] = yaml.dump({
            "apiVersion": "policy/v1",
            "kind": "PodDisruptionBudget",
            "metadata": {
                "name": "sample-app"
            },
            "spec": {
                "minAvailable": "50%",
                "selector": {
                    "matchLabels": {
                        "app": "sample-app"
                    }
                }
            }
        })
        
        return {
            "base": configs,
            "overlays": self._generate_environment_overlays()
        }
    
    def _generate_environment_overlays(self) -> Dict[str, Dict]:
        """Generate environment-specific overlays"""
        
        overlays = {}
        
        env_configs = {
            "dev": {"replicas": 1, "resources": {"cpu": "100m", "memory": "128Mi"}},
            "staging": {"replicas": 2, "resources": {"cpu": "250m", "memory": "256Mi"}},
            "prod": {"replicas": 3, "resources": {"cpu": "500m", "memory": "512Mi"}}
        }
        
        for env in self.config.environments:
            config = env_configs.get(env, env_configs["dev"])
            
            overlays[env] = {
                "kustomization.yaml": yaml.dump({
                    "apiVersion": "kustomize.config.k8s.io/v1beta1",
                    "kind": "Kustomization",
                    "namespace": f"app-{env}",
                    "resources": ["../../base"],
                    "patches": [
                        {
                            "target": {
                                "kind": "Deployment",
                                "name": "sample-app"
                            },
                            "patch": yaml.dump([
                                {
                                    "op": "replace",
                                    "path": "/spec/replicas",
                                    "value": config["replicas"]
                                }
                            ])
                        }
                    ],
                    "images": [
                        {
                            "name": "sample-app",
                            "newTag": f"v1.0.0-{env}"
                        }
                    ]
                })
            }
        
        return overlays
    
    def _generate_progressive_delivery_config(self) -> Dict[str, Any]:
        """Generate progressive delivery configurations"""
        
        if self.config.progressive_delivery_tool == ProgressiveDeliveryTool.NONE:
            return {"enabled": False}
        
        configs = {}
        
        if self.config.progressive_delivery_tool == ProgressiveDeliveryTool.ARGO_ROLLOUTS:
            # Argo Rollouts configuration
            configs["rollout.yaml"] = yaml.dump({
                "apiVersion": "argoproj.io/v1alpha1",
                "kind": "Rollout",
                "metadata": {
                    "name": "sample-app"
                },
                "spec": {
                    "replicas": 5,
                    "strategy": {
                        "canary": {
                            "canaryService": "sample-app-canary",
                            "stableService": "sample-app-stable",
                            "trafficRouting": {
                                "alb": {
                                    "ingress": "sample-app-ingress",
                                    "servicePort": 80
                                }
                            },
                            "steps": [
                                {"setWeight": 10},
                                {"pause": {"duration": "5m"}},
                                {
                                    "analysis": {
                                        "templates": [
                                            {"templateName": "success-rate"}
                                        ]
                                    }
                                },
                                {"setWeight": 25},
                                {"pause": {"duration": "5m"}},
                                {"setWeight": 50},
                                {"pause": {"duration": "5m"}},
                                {"setWeight": 75},
                                {"pause": {"duration": "5m"}}
                            ]
                        }
                    },
                    "revisionHistoryLimit": 3,
                    "selector": {
                        "matchLabels": {
                            "app": "sample-app"
                        }
                    },
                    "template": {
                        "metadata": {
                            "labels": {
                                "app": "sample-app"
                            }
                        },
                        "spec": {
                            "containers": [
                                {
                                    "name": "app",
                                    "image": "sample-app:v1.0.0",
                                    "ports": [{"containerPort": 8080}]
                                }
                            ]
                        }
                    }
                }
            })
            
            # Analysis template
            configs["analysis-template.yaml"] = yaml.dump({
                "apiVersion": "argoproj.io/v1alpha1",
                "kind": "AnalysisTemplate",
                "metadata": {
                    "name": "success-rate"
                },
                "spec": {
                    "metrics": [
                        {
                            "name": "success-rate",
                            "interval": "1m",
                            "successCondition": "result[0] >= 0.95",
                            "failureLimit": 3,
                            "provider": {
                                "prometheus": {
                                    "address": "http://prometheus-server.monitoring:80",
                                    "query": """
sum(rate(http_requests_total{status=~"2.*",app="{{args.app-name}}"}[5m])) /
sum(rate(http_requests_total{app="{{args.app-name}}"}[5m]))
"""
                                }
                            }
                        },
                        {
                            "name": "error-rate",
                            "interval": "1m",
                            "successCondition": "result[0] <= 0.05",
                            "failureLimit": 3,
                            "provider": {
                                "prometheus": {
                                    "address": "http://prometheus-server.monitoring:80",
                                    "query": """
sum(rate(http_requests_total{status=~"5.*",app="{{args.app-name}}"}[5m])) /
sum(rate(http_requests_total{app="{{args.app-name}}"}[5m]))
"""
                                }
                            }
                        }
                    ],
                    "args": [
                        {"name": "app-name"}
                    ]
                }
            })
        
        elif self.config.progressive_delivery_tool == ProgressiveDeliveryTool.FLAGGER:
            # Flagger canary configuration
            configs["canary.yaml"] = yaml.dump({
                "apiVersion": "flagger.app/v1beta1",
                "kind": "Canary",
                "metadata": {
                    "name": "sample-app"
                },
                "spec": {
                    "targetRef": {
                        "apiVersion": "apps/v1",
                        "kind": "Deployment",
                        "name": "sample-app"
                    },
                    "progressDeadlineSeconds": 60,
                    "service": {
                        "port": 80,
                        "targetPort": 8080,
                        "gateways": ["public-gateway"],
                        "hosts": ["sample-app.example.com"]
                    },
                    "analysis": {
                        "interval": "1m",
                        "threshold": 5,
                        "maxWeight": 50,
                        "stepWeight": 10,
                        "metrics": [
                            {
                                "name": "request-success-rate",
                                "thresholdRange": {"min": 99},
                                "interval": "1m"
                            },
                            {
                                "name": "request-duration",
                                "thresholdRange": {"max": 500},
                                "interval": "1m"
                            }
                        ],
                        "webhooks": [
                            {
                                "name": "load-test",
                                "url": "http://flagger-loadtester.test/",
                                "timeout": "5s",
                                "metadata": {
                                    "cmd": "hey -z 1m -q 10 -c 2 http://sample-app-canary.app:80/"
                                }
                            }
                        ]
                    }
                }
            })
        
        return {
            "enabled": True,
            "tool": self.config.progressive_delivery_tool.value,
            "configs": configs
        }
    
    def _generate_policies(self) -> Dict[str, Any]:
        """Generate policy-as-code configurations"""
        
        if self.config.policy_engine == PolicyEngine.NONE:
            return {"enabled": False}
        
        configs = {}
        
        if self.config.policy_engine == PolicyEngine.KYVERNO:
            # Kyverno policies
            configs["require-labels.yaml"] = yaml.dump({
                "apiVersion": "kyverno.io/v1",
                "kind": "ClusterPolicy",
                "metadata": {
                    "name": "require-labels"
                },
                "spec": {
                    "validationFailureAction": "Enforce",
                    "background": True,
                    "rules": [
                        {
                            "name": "require-team-label",
                            "match": {
                                "any": [
                                    {
                                        "resources": {
                                            "kinds": ["Deployment", "StatefulSet", "DaemonSet"]
                                        }
                                    }
                                ]
                            },
                            "validate": {
                                "message": "The label 'team' is required",
                                "pattern": {
                                    "metadata": {
                                        "labels": {
                                            "team": "?*"
                                        }
                                    }
                                }
                            }
                        }
                    ]
                }
            })
            
            configs["require-probes.yaml"] = yaml.dump({
                "apiVersion": "kyverno.io/v1",
                "kind": "ClusterPolicy",
                "metadata": {
                    "name": "require-probes"
                },
                "spec": {
                    "validationFailureAction": "Audit",
                    "background": True,
                    "rules": [
                        {
                            "name": "require-liveness-probe",
                            "match": {
                                "any": [
                                    {
                                        "resources": {
                                            "kinds": ["Deployment", "StatefulSet"]
                                        }
                                    }
                                ]
                            },
                            "validate": {
                                "message": "Liveness probe is required",
                                "pattern": {
                                    "spec": {
                                        "template": {
                                            "spec": {
                                                "containers": [
                                                    {
                                                        "livenessProbe": {
                                                            "httpGet": {
                                                                "path": "?*",
                                                                "port": "?*"
                                                            }
                                                        }
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    ]
                }
            })
            
            configs["restrict-registries.yaml"] = yaml.dump({
                "apiVersion": "kyverno.io/v1",
                "kind": "ClusterPolicy",
                "metadata": {
                    "name": "restrict-registries"
                },
                "spec": {
                    "validationFailureAction": "Enforce",
                    "background": True,
                    "rules": [
                        {
                            "name": "validate-registries",
                            "match": {
                                "any": [
                                    {
                                        "resources": {
                                            "kinds": ["Pod"]
                                        }
                                    }
                                ]
                            },
                            "validate": {
                                "message": "Images must be from approved registries",
                                "pattern": {
                                    "spec": {
                                        "containers": [
                                            {
                                                "image": "*.dkr.ecr.*.amazonaws.com/*"
                                            }
                                        ]
                                    }
                                }
                            }
                        }
                    ]
                }
            })
            
            configs["require-security-context.yaml"] = yaml.dump({
                "apiVersion": "kyverno.io/v1",
                "kind": "ClusterPolicy",
                "metadata": {
                    "name": "require-security-context"
                },
                "spec": {
                    "validationFailureAction": "Enforce",
                    "background": True,
                    "rules": [
                        {
                            "name": "run-as-non-root",
                            "match": {
                                "any": [
                                    {
                                        "resources": {
                                            "kinds": ["Pod"]
                                        }
                                    }
                                ]
                            },
                            "exclude": {
                                "any": [
                                    {
                                        "resources": {
                                            "namespaces": ["kube-system", "kube-node-lease"]
                                        }
                                    }
                                ]
                            },
                            "validate": {
                                "message": "Containers must run as non-root",
                                "pattern": {
                                    "spec": {
                                        "securityContext": {
                                            "runAsNonRoot": True
                                        }
                                    }
                                }
                            }
                        }
                    ]
                }
            })
        
        elif self.config.policy_engine == PolicyEngine.OPA_GATEKEEPER:
            # OPA Gatekeeper constraints
            configs["constraint-template-labels.yaml"] = yaml.dump({
                "apiVersion": "templates.gatekeeper.sh/v1",
                "kind": "ConstraintTemplate",
                "metadata": {
                    "name": "k8srequiredlabels"
                },
                "spec": {
                    "crd": {
                        "spec": {
                            "names": {
                                "kind": "K8sRequiredLabels"
                            },
                            "validation": {
                                "openAPIV3Schema": {
                                    "type": "object",
                                    "properties": {
                                        "labels": {
                                            "type": "array",
                                            "items": {"type": "string"}
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "targets": [
                        {
                            "target": "admission.k8s.gatekeeper.sh",
                            "rego": """
package k8srequiredlabels

violation[{"msg": msg, "details": {"missing_labels": missing}}] {
  provided := {label | input.review.object.metadata.labels[label]}
  required := {label | label := input.parameters.labels[_]}
  missing := required - provided
  count(missing) > 0
  msg := sprintf("Required labels are missing: %v", [missing])
}
"""
                        }
                    ]
                }
            })
            
            configs["constraint-require-labels.yaml"] = yaml.dump({
                "apiVersion": "constraints.gatekeeper.sh/v1beta1",
                "kind": "K8sRequiredLabels",
                "metadata": {
                    "name": "require-team-label"
                },
                "spec": {
                    "match": {
                        "kinds": [
                            {"apiGroups": ["apps"], "kinds": ["Deployment"]}
                        ]
                    },
                    "parameters": {
                        "labels": ["team", "environment"]
                    }
                }
            })
        
        return {
            "enabled": True,
            "engine": self.config.policy_engine.value,
            "configs": configs
        }
    
    def _generate_notifications(self) -> Dict[str, Any]:
        """Generate notification configurations"""
        
        if not self.config.enable_notifications:
            return {"enabled": False}
        
        configs = {}
        
        if self.config.tool == GitOpsToolType.ARGOCD:
            # ArgoCD notifications
            configs["notifications-cm.yaml"] = yaml.dump({
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": {
                    "name": "argocd-notifications-cm",
                    "namespace": "argocd"
                },
                "data": {
                    "service.slack": """
token: $slack-token
""",
                    "template.app-deployed": """
message: |
  Application {{.app.metadata.name}} has been deployed!
  Status: {{.app.status.operationState.phase}}
  Revision: {{.app.status.sync.revision}}
slack:
  attachments: |
    [{
      "title": "{{.app.metadata.name}}",
      "color": "{{if eq .app.status.sync.status \"Synced\"}}good{{else}}warning{{end}}"
    }]
""",
                    "template.app-health-degraded": """
message: |
  Application {{.app.metadata.name}} health is degraded!
slack:
  attachments: |
    [{
      "title": "{{.app.metadata.name}}",
      "color": "danger",
      "text": "Health: {{.app.status.health.status}}"
    }]
""",
                    "trigger.on-deployed": """
- when: app.status.operationState.phase in ['Succeeded']
  send: [app-deployed]
""",
                    "trigger.on-health-degraded": """
- when: app.status.health.status == 'Degraded'
  send: [app-health-degraded]
"""
                }
            })
        
        return {
            "enabled": True,
            "channels": self.config.notification_channels,
            "configs": configs
        }
    
    def _generate_multi_cluster_config(self) -> Dict[str, Any]:
        """Generate multi-cluster GitOps configurations"""
        
        configs = {}
        
        if self.config.tool == GitOpsToolType.ARGOCD:
            # Multi-cluster ApplicationSet
            configs["cluster-applicationset.yaml"] = yaml.dump({
                "apiVersion": "argoproj.io/v1alpha1",
                "kind": "ApplicationSet",
                "metadata": {
                    "name": "multi-cluster-apps",
                    "namespace": "argocd"
                },
                "spec": {
                    "generators": [
                        {
                            "clusters": {
                                "selector": {
                                    "matchLabels": {
                                        "argocd.argoproj.io/secret-type": "cluster"
                                    }
                                }
                            }
                        }
                    ],
                    "template": {
                        "metadata": {
                            "name": "{{name}}-platform"
                        },
                        "spec": {
                            "project": "default",
                            "source": {
                                "repoURL": self.config.repository_url or "https://github.com/your-org/gitops-repo",
                                "targetRevision": "HEAD",
                                "path": "clusters/{{name}}"
                            },
                            "destination": {
                                "server": "{{server}}",
                                "namespace": "platform"
                            },
                            "syncPolicy": {
                                "automated": {
                                    "prune": True,
                                    "selfHeal": True
                                }
                            }
                        }
                    }
                }
            })
            
            # Cluster secret template
            for cluster in self.config.clusters:
                configs[f"cluster-{cluster}.yaml"] = yaml.dump({
                    "apiVersion": "v1",
                    "kind": "Secret",
                    "metadata": {
                        "name": cluster,
                        "namespace": "argocd",
                        "labels": {
                            "argocd.argoproj.io/secret-type": "cluster"
                        }
                    },
                    "type": "Opaque",
                    "stringData": {
                        "name": cluster,
                        "server": f"https://{cluster}.eks.amazonaws.com",
                        "config": """
{
  "awsAuthConfig": {
    "clusterName": "${CLUSTER_NAME}",
    "roleARN": "arn:aws:iam::${AWS_ACCOUNT}:role/argocd-${CLUSTER_NAME}"
  }
}
"""
                    }
                })
        
        return {
            "enabled": True,
            "clusters": self.config.clusters,
            "configs": configs
        }
    
    def _generate_readme(self) -> str:
        """Generate README documentation"""
        
        return f"""# GitOps Repository

This repository contains Kubernetes manifests managed by {self.config.tool.value}.

## Repository Structure

```
{REPOSITORY_STRUCTURES['monorepo']['structure']}
```

## Environments

{chr(10).join([f'- **{env}**: {env.title()} environment' for env in self.config.environments])}

## Quick Start

### Prerequisites
- kubectl configured for your cluster
- {'ArgoCD CLI' if self.config.tool == GitOpsToolType.ARGOCD else 'Flux CLI'} installed
- Access to container registry

### Deploy {self.config.tool.value.title()}

```bash
# Install {self.config.tool.value.title()}
{'helm upgrade --install argocd argo/argo-cd -n argocd --create-namespace -f platform/argocd/values.yaml' if self.config.tool == GitOpsToolType.ARGOCD else 'flux bootstrap github --owner=your-org --repository=gitops-repo'}
```

### Add an Application

1. Create application directory under `apps/`
2. Add base manifests
3. Create environment overlays
4. {'Create ArgoCD Application' if self.config.tool == GitOpsToolType.ARGOCD else 'Create Flux Kustomization'}

## Progressive Delivery

{'Enabled with ' + self.config.progressive_delivery_tool.value if self.config.enable_progressive_delivery else 'Not configured'}

## Policies

{'Enabled with ' + self.config.policy_engine.value if self.config.enable_policy_as_code else 'Not configured'}

## Contributing

1. Create feature branch
2. Make changes
3. Submit PR
4. Wait for review and CI checks
5. Merge to trigger deployment
"""
    
    def _generate_helper_scripts(self) -> Dict[str, str]:
        """Generate helper scripts"""
        
        scripts = {}
        
        scripts["setup.sh"] = """#!/bin/bash
set -e

# Setup GitOps repository
echo "Setting up GitOps repository..."

# Create directory structure
mkdir -p apps/base apps/overlays/{dev,staging,prod}
mkdir -p infrastructure/base infrastructure/overlays/{dev,staging,prod}
mkdir -p platform/{argocd,prometheus,cert-manager}
mkdir -p policies/{kyverno,opa}
mkdir -p clusters/{dev,staging,prod}

echo "Directory structure created!"

# Initialize git
git init
git add .
git commit -m "Initial GitOps repository structure"

echo "Repository initialized!"
"""
        
        scripts["create-app.sh"] = """#!/bin/bash
set -e

APP_NAME=$1

if [ -z "$APP_NAME" ]; then
  echo "Usage: ./create-app.sh <app-name>"
  exit 1
fi

# Create app directory structure
mkdir -p apps/$APP_NAME/base
mkdir -p apps/$APP_NAME/overlays/{dev,staging,prod}

# Create base kustomization
cat > apps/$APP_NAME/base/kustomization.yaml << EOF
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - deployment.yaml
  - service.yaml
EOF

# Create base deployment
cat > apps/$APP_NAME/base/deployment.yaml << EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: $APP_NAME
spec:
  replicas: 1
  selector:
    matchLabels:
      app: $APP_NAME
  template:
    metadata:
      labels:
        app: $APP_NAME
    spec:
      containers:
        - name: app
          image: $APP_NAME:latest
          ports:
            - containerPort: 8080
EOF

# Create base service
cat > apps/$APP_NAME/base/service.yaml << EOF
apiVersion: v1
kind: Service
metadata:
  name: $APP_NAME
spec:
  selector:
    app: $APP_NAME
  ports:
    - port: 80
      targetPort: 8080
EOF

# Create overlay kustomizations
for env in dev staging prod; do
  cat > apps/$APP_NAME/overlays/$env/kustomization.yaml << EOF
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
namespace: $APP_NAME-$env
resources:
  - ../../base
EOF
done

echo "Created app: $APP_NAME"
"""
        
        scripts["sync-app.sh"] = """#!/bin/bash
set -e

APP_NAME=$1
ENV=$2

if [ -z "$APP_NAME" ] || [ -z "$ENV" ]; then
  echo "Usage: ./sync-app.sh <app-name> <environment>"
  exit 1
fi

argocd app sync $APP_NAME-$ENV --prune
argocd app wait $APP_NAME-$ENV --health

echo "Synced $APP_NAME to $ENV environment"
"""
        
        return scripts
