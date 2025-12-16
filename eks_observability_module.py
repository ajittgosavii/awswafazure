"""
EKS Observability Stack Module
Part of the AI-Enhanced EKS Architecture Design Wizard

Features:
- Prometheus/Thanos Configuration
- Grafana Dashboards Generator
- Logging Stack (Fluent Bit / Fluentd)
- Distributed Tracing (X-Ray / Jaeger / Tempo)
- Alerting Rules Generator
- SLO/SLI Definition

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

# ============================================================================
# OBSERVABILITY ENUMS
# ============================================================================

class MetricsBackend(Enum):
    """Metrics collection backend"""
    PROMETHEUS = "prometheus"
    PROMETHEUS_THANOS = "prometheus_thanos"
    CLOUDWATCH = "cloudwatch"
    DATADOG = "datadog"

class LoggingBackend(Enum):
    """Logging collection backend"""
    FLUENT_BIT = "fluent_bit"
    FLUENTD = "fluentd"
    CLOUDWATCH_AGENT = "cloudwatch_agent"

class LogDestination(Enum):
    """Log storage destination"""
    CLOUDWATCH = "cloudwatch"
    OPENSEARCH = "opensearch"
    S3 = "s3"
    LOKI = "loki"

class TracingBackend(Enum):
    """Distributed tracing backend"""
    XRAY = "xray"
    JAEGER = "jaeger"
    TEMPO = "tempo"
    ZIPKIN = "zipkin"

class AlertSeverity(Enum):
    """Alert severity levels"""
    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"


# ============================================================================
# OBSERVABILITY DATA CLASSES
# ============================================================================

@dataclass
class SLODefinition:
    """Service Level Objective definition"""
    name: str
    service: str
    sli_type: str  # availability, latency, error_rate, throughput
    target: float
    window: str  # 7d, 30d
    description: str
    alerting_rules: List[Dict] = field(default_factory=list)

@dataclass 
class AlertRule:
    """Prometheus alert rule"""
    name: str
    severity: AlertSeverity
    expr: str
    duration: str
    summary: str
    description: str
    runbook_url: Optional[str] = None
    labels: Dict[str, str] = field(default_factory=dict)

@dataclass
class GrafanaDashboard:
    """Grafana dashboard specification"""
    name: str
    uid: str
    description: str
    tags: List[str]
    panels: List[Dict]
    variables: List[Dict] = field(default_factory=list)


# ============================================================================
# PROMETHEUS CONFIGURATION GENERATOR
# ============================================================================

class PrometheusConfigGenerator:
    """
    Generates Prometheus and Thanos configurations for EKS clusters.
    """
    
    def generate_prometheus_stack(self, config: Dict) -> Dict[str, str]:
        """Generate complete Prometheus stack configuration"""
        
        configs = {}
        
        # Prometheus Operator values
        configs["prometheus-values.yaml"] = self._generate_prometheus_values(config)
        
        # ServiceMonitor for applications
        configs["servicemonitor-template.yaml"] = self._generate_servicemonitor_template()
        
        # PodMonitor template
        configs["podmonitor-template.yaml"] = self._generate_podmonitor_template()
        
        # Alerting rules
        configs["alerting-rules.yaml"] = self._generate_alerting_rules(config)
        
        # Recording rules for performance
        configs["recording-rules.yaml"] = self._generate_recording_rules()
        
        # Thanos configuration if multi-cluster
        if config.get("multi_cluster", False):
            configs["thanos-values.yaml"] = self._generate_thanos_config(config)
        
        return configs
    
    def _generate_prometheus_values(self, config: Dict) -> str:
        """Generate kube-prometheus-stack Helm values"""
        
        retention_days = config.get("observability", {}).get("prometheus_retention_days", 15)
        
        values = {
            "prometheus": {
                "prometheusSpec": {
                    "replicas": 2,
                    "retention": f"{retention_days}d",
                    "retentionSize": "50GB",
                    "resources": {
                        "requests": {"cpu": "500m", "memory": "2Gi"},
                        "limits": {"cpu": "2000m", "memory": "8Gi"}
                    },
                    "storageSpec": {
                        "volumeClaimTemplate": {
                            "spec": {
                                "storageClassName": "gp3",
                                "accessModes": ["ReadWriteOnce"],
                                "resources": {
                                    "requests": {"storage": "100Gi"}
                                }
                            }
                        }
                    },
                    "podMonitorSelectorNilUsesHelmValues": False,
                    "serviceMonitorSelectorNilUsesHelmValues": False,
                    "ruleSelectorNilUsesHelmValues": False,
                    "additionalScrapeConfigs": [
                        {
                            "job_name": "kubernetes-pods",
                            "kubernetes_sd_configs": [
                                {"role": "pod"}
                            ],
                            "relabel_configs": [
                                {
                                    "source_labels": ["__meta_kubernetes_pod_annotation_prometheus_io_scrape"],
                                    "action": "keep",
                                    "regex": "true"
                                },
                                {
                                    "source_labels": ["__meta_kubernetes_pod_annotation_prometheus_io_path"],
                                    "action": "replace",
                                    "target_label": "__metrics_path__",
                                    "regex": "(.+)"
                                },
                                {
                                    "source_labels": ["__address__", "__meta_kubernetes_pod_annotation_prometheus_io_port"],
                                    "action": "replace",
                                    "regex": "([^:]+)(?::\\d+)?;(\\d+)",
                                    "replacement": "$1:$2",
                                    "target_label": "__address__"
                                }
                            ]
                        }
                    ]
                },
                "ingress": {
                    "enabled": True,
                    "ingressClassName": "alb",
                    "annotations": {
                        "alb.ingress.kubernetes.io/scheme": "internal",
                        "alb.ingress.kubernetes.io/target-type": "ip"
                    },
                    "hosts": ["prometheus.internal.example.com"]
                }
            },
            "alertmanager": {
                "alertmanagerSpec": {
                    "replicas": 2,
                    "storage": {
                        "volumeClaimTemplate": {
                            "spec": {
                                "storageClassName": "gp3",
                                "accessModes": ["ReadWriteOnce"],
                                "resources": {
                                    "requests": {"storage": "10Gi"}
                                }
                            }
                        }
                    }
                },
                "config": {
                    "global": {
                        "resolve_timeout": "5m",
                        "slack_api_url": "${SLACK_WEBHOOK_URL}"
                    },
                    "route": {
                        "group_by": ["alertname", "namespace", "severity"],
                        "group_wait": "30s",
                        "group_interval": "5m",
                        "repeat_interval": "4h",
                        "receiver": "default-receiver",
                        "routes": [
                            {
                                "match": {"severity": "critical"},
                                "receiver": "critical-receiver",
                                "continue": True
                            },
                            {
                                "match": {"severity": "warning"},
                                "receiver": "warning-receiver"
                            }
                        ]
                    },
                    "receivers": [
                        {
                            "name": "default-receiver",
                            "slack_configs": [
                                {
                                    "channel": "#alerts",
                                    "send_resolved": True,
                                    "title": "{{ .Status | toUpper }}{{ if eq .Status \"firing\" }}:{{ .Alerts.Firing | len }}{{ end }} - {{ .CommonLabels.alertname }}",
                                    "text": "{{ range .Alerts }}*Alert:* {{ .Labels.alertname }}\n*Severity:* {{ .Labels.severity }}\n*Description:* {{ .Annotations.description }}\n{{ end }}"
                                }
                            ]
                        },
                        {
                            "name": "critical-receiver",
                            "pagerduty_configs": [
                                {
                                    "service_key": "${PAGERDUTY_SERVICE_KEY}",
                                    "send_resolved": True
                                }
                            ],
                            "slack_configs": [
                                {
                                    "channel": "#critical-alerts",
                                    "send_resolved": True
                                }
                            ]
                        },
                        {
                            "name": "warning-receiver",
                            "slack_configs": [
                                {
                                    "channel": "#warnings",
                                    "send_resolved": True
                                }
                            ]
                        }
                    ]
                }
            },
            "grafana": {
                "enabled": True,
                "replicas": 2,
                "persistence": {
                    "enabled": True,
                    "storageClassName": "gp3",
                    "size": "10Gi"
                },
                "adminPassword": "${GRAFANA_ADMIN_PASSWORD}",
                "ingress": {
                    "enabled": True,
                    "ingressClassName": "alb",
                    "annotations": {
                        "alb.ingress.kubernetes.io/scheme": "internet-facing",
                        "alb.ingress.kubernetes.io/target-type": "ip",
                        "alb.ingress.kubernetes.io/certificate-arn": "${ACM_CERT_ARN}"
                    },
                    "hosts": ["grafana.example.com"]
                },
                "datasources": {
                    "datasources.yaml": {
                        "apiVersion": 1,
                        "datasources": [
                            {
                                "name": "Prometheus",
                                "type": "prometheus",
                                "url": "http://prometheus-operated:9090",
                                "isDefault": True
                            },
                            {
                                "name": "CloudWatch",
                                "type": "cloudwatch",
                                "jsonData": {
                                    "authType": "default",
                                    "defaultRegion": config.get("region", "us-east-1")
                                }
                            },
                            {
                                "name": "Loki",
                                "type": "loki",
                                "url": "http://loki:3100"
                            }
                        ]
                    }
                },
                "dashboardProviders": {
                    "dashboardproviders.yaml": {
                        "apiVersion": 1,
                        "providers": [
                            {
                                "name": "default",
                                "orgId": 1,
                                "folder": "",
                                "type": "file",
                                "disableDeletion": False,
                                "editable": True,
                                "options": {
                                    "path": "/var/lib/grafana/dashboards/default"
                                }
                            }
                        ]
                    }
                },
                "sidecar": {
                    "dashboards": {
                        "enabled": True,
                        "searchNamespace": "ALL"
                    }
                }
            },
            "kubeStateMetrics": {
                "enabled": True
            },
            "nodeExporter": {
                "enabled": True
            },
            "prometheusOperator": {
                "enabled": True
            }
        }
        
        return yaml.dump(values, default_flow_style=False)
    
    def _generate_servicemonitor_template(self) -> str:
        """Generate ServiceMonitor template"""
        
        template = {
            "apiVersion": "monitoring.coreos.com/v1",
            "kind": "ServiceMonitor",
            "metadata": {
                "name": "${SERVICE_NAME}",
                "namespace": "${NAMESPACE}",
                "labels": {
                    "app": "${SERVICE_NAME}",
                    "release": "prometheus"
                }
            },
            "spec": {
                "selector": {
                    "matchLabels": {
                        "app": "${SERVICE_NAME}"
                    }
                },
                "namespaceSelector": {
                    "matchNames": ["${NAMESPACE}"]
                },
                "endpoints": [
                    {
                        "port": "metrics",
                        "interval": "30s",
                        "path": "/metrics",
                        "scrapeTimeout": "10s"
                    }
                ]
            }
        }
        
        return yaml.dump(template)
    
    def _generate_podmonitor_template(self) -> str:
        """Generate PodMonitor template"""
        
        template = {
            "apiVersion": "monitoring.coreos.com/v1",
            "kind": "PodMonitor",
            "metadata": {
                "name": "${POD_NAME}",
                "namespace": "${NAMESPACE}",
                "labels": {
                    "release": "prometheus"
                }
            },
            "spec": {
                "selector": {
                    "matchLabels": {
                        "app": "${POD_NAME}"
                    }
                },
                "namespaceSelector": {
                    "matchNames": ["${NAMESPACE}"]
                },
                "podMetricsEndpoints": [
                    {
                        "port": "metrics",
                        "interval": "30s",
                        "path": "/metrics"
                    }
                ]
            }
        }
        
        return yaml.dump(template)
    
    def _generate_alerting_rules(self, config: Dict) -> str:
        """Generate comprehensive alerting rules"""
        
        rules = {
            "apiVersion": "monitoring.coreos.com/v1",
            "kind": "PrometheusRule",
            "metadata": {
                "name": "eks-alerting-rules",
                "namespace": "monitoring",
                "labels": {
                    "release": "prometheus"
                }
            },
            "spec": {
                "groups": [
                    {
                        "name": "kubernetes-system",
                        "rules": [
                            {
                                "alert": "KubernetesNodeNotReady",
                                "expr": 'kube_node_status_condition{condition="Ready",status="true"} == 0',
                                "for": "5m",
                                "labels": {"severity": "critical"},
                                "annotations": {
                                    "summary": "Kubernetes Node not ready (instance {{ $labels.node }})",
                                    "description": "Node {{ $labels.node }} has been unready for more than 5 minutes.",
                                    "runbook_url": "https://runbooks.example.com/kubernetes-node-not-ready"
                                }
                            },
                            {
                                "alert": "KubernetesNodeMemoryPressure",
                                "expr": 'kube_node_status_condition{condition="MemoryPressure",status="true"} == 1',
                                "for": "5m",
                                "labels": {"severity": "warning"},
                                "annotations": {
                                    "summary": "Kubernetes Node has memory pressure (instance {{ $labels.node }})",
                                    "description": "Node {{ $labels.node }} is under memory pressure."
                                }
                            },
                            {
                                "alert": "KubernetesNodeDiskPressure",
                                "expr": 'kube_node_status_condition{condition="DiskPressure",status="true"} == 1',
                                "for": "5m",
                                "labels": {"severity": "warning"},
                                "annotations": {
                                    "summary": "Kubernetes Node has disk pressure (instance {{ $labels.node }})",
                                    "description": "Node {{ $labels.node }} is under disk pressure."
                                }
                            }
                        ]
                    },
                    {
                        "name": "kubernetes-pods",
                        "rules": [
                            {
                                "alert": "KubernetesPodCrashLooping",
                                "expr": 'increase(kube_pod_container_status_restarts_total[1h]) > 5',
                                "for": "5m",
                                "labels": {"severity": "warning"},
                                "annotations": {
                                    "summary": "Kubernetes pod crash looping (instance {{ $labels.pod }})",
                                    "description": "Pod {{ $labels.namespace }}/{{ $labels.pod }} is crash looping."
                                }
                            },
                            {
                                "alert": "KubernetesPodNotHealthy",
                                "expr": 'sum by (namespace, pod) (kube_pod_status_phase{phase=~"Pending|Unknown|Failed"}) > 0',
                                "for": "15m",
                                "labels": {"severity": "warning"},
                                "annotations": {
                                    "summary": "Kubernetes Pod not healthy (instance {{ $labels.pod }})",
                                    "description": "Pod {{ $labels.namespace }}/{{ $labels.pod }} has been in a non-ready state for longer than 15 minutes."
                                }
                            },
                            {
                                "alert": "ContainerHighCPU",
                                "expr": 'sum(rate(container_cpu_usage_seconds_total{container!=""}[5m])) by (pod, namespace) / sum(kube_pod_container_resource_limits{resource="cpu"}) by (pod, namespace) > 0.9',
                                "for": "5m",
                                "labels": {"severity": "warning"},
                                "annotations": {
                                    "summary": "Container High CPU usage (instance {{ $labels.pod }})",
                                    "description": "Container CPU usage is above 90% of limit."
                                }
                            },
                            {
                                "alert": "ContainerHighMemory",
                                "expr": 'sum(container_memory_working_set_bytes{container!=""}) by (pod, namespace) / sum(kube_pod_container_resource_limits{resource="memory"}) by (pod, namespace) > 0.9',
                                "for": "5m",
                                "labels": {"severity": "warning"},
                                "annotations": {
                                    "summary": "Container High Memory usage (instance {{ $labels.pod }})",
                                    "description": "Container memory usage is above 90% of limit."
                                }
                            }
                        ]
                    },
                    {
                        "name": "kubernetes-deployments",
                        "rules": [
                            {
                                "alert": "KubernetesDeploymentReplicasMismatch",
                                "expr": 'kube_deployment_spec_replicas != kube_deployment_status_replicas_available',
                                "for": "10m",
                                "labels": {"severity": "warning"},
                                "annotations": {
                                    "summary": "Kubernetes Deployment replicas mismatch (instance {{ $labels.deployment }})",
                                    "description": "Deployment {{ $labels.namespace }}/{{ $labels.deployment }} has not matched the expected number of replicas for longer than 10 minutes."
                                }
                            },
                            {
                                "alert": "KubernetesStatefulSetReplicasMismatch",
                                "expr": 'kube_statefulset_status_replicas_ready != kube_statefulset_status_replicas',
                                "for": "10m",
                                "labels": {"severity": "warning"},
                                "annotations": {
                                    "summary": "Kubernetes StatefulSet replicas mismatch (instance {{ $labels.statefulset }})",
                                    "description": "StatefulSet {{ $labels.namespace }}/{{ $labels.statefulset }} has not matched the expected number of replicas."
                                }
                            }
                        ]
                    },
                    {
                        "name": "application-slos",
                        "rules": [
                            {
                                "alert": "HighErrorRate",
                                "expr": 'sum(rate(http_requests_total{status=~"5.."}[5m])) by (service) / sum(rate(http_requests_total[5m])) by (service) > 0.05',
                                "for": "5m",
                                "labels": {"severity": "critical"},
                                "annotations": {
                                    "summary": "High error rate detected (service {{ $labels.service }})",
                                    "description": "Error rate is above 5% for service {{ $labels.service }}."
                                }
                            },
                            {
                                "alert": "HighLatency",
                                "expr": 'histogram_quantile(0.99, sum(rate(http_request_duration_seconds_bucket[5m])) by (le, service)) > 1',
                                "for": "5m",
                                "labels": {"severity": "warning"},
                                "annotations": {
                                    "summary": "High latency detected (service {{ $labels.service }})",
                                    "description": "P99 latency is above 1 second for service {{ $labels.service }}."
                                }
                            },
                            {
                                "alert": "SLOBurnRateHigh",
                                "expr": 'sum(rate(http_requests_total{status=~"5.."}[1h])) by (service) / sum(rate(http_requests_total[1h])) by (service) > (1 - 0.999) * 14.4',
                                "for": "2m",
                                "labels": {"severity": "critical"},
                                "annotations": {
                                    "summary": "SLO burn rate is too high (service {{ $labels.service }})",
                                    "description": "Service {{ $labels.service }} is burning through error budget too fast."
                                }
                            }
                        ]
                    },
                    {
                        "name": "eks-specific",
                        "rules": [
                            {
                                "alert": "EKSNodeGroupScalingFailed",
                                "expr": 'karpenter_nodes_created_total - karpenter_nodes_terminated_total < karpenter_pending_pods_total',
                                "for": "10m",
                                "labels": {"severity": "warning"},
                                "annotations": {
                                    "summary": "EKS node scaling may be failing",
                                    "description": "There are pending pods that haven't been scheduled for 10 minutes."
                                }
                            },
                            {
                                "alert": "SpotInstanceInterruption",
                                "expr": 'increase(karpenter_interruption_received_total[5m]) > 0',
                                "for": "0m",
                                "labels": {"severity": "info"},
                                "annotations": {
                                    "summary": "Spot instance interruption received",
                                    "description": "A Spot instance interruption notice has been received."
                                }
                            }
                        ]
                    }
                ]
            }
        }
        
        return yaml.dump(rules, default_flow_style=False)
    
    def _generate_recording_rules(self) -> str:
        """Generate recording rules for performance optimization"""
        
        rules = {
            "apiVersion": "monitoring.coreos.com/v1",
            "kind": "PrometheusRule",
            "metadata": {
                "name": "recording-rules",
                "namespace": "monitoring",
                "labels": {
                    "release": "prometheus"
                }
            },
            "spec": {
                "groups": [
                    {
                        "name": "kubernetes-recording-rules",
                        "rules": [
                            {
                                "record": "namespace:container_cpu_usage_seconds_total:sum_rate",
                                "expr": 'sum(rate(container_cpu_usage_seconds_total{container!="", container!="POD"}[5m])) by (namespace)'
                            },
                            {
                                "record": "namespace:container_memory_usage_bytes:sum",
                                "expr": 'sum(container_memory_working_set_bytes{container!="", container!="POD"}) by (namespace)'
                            },
                            {
                                "record": "node:node_cpu_utilisation:avg1m",
                                "expr": 'avg by (node) (1 - rate(node_cpu_seconds_total{mode="idle"}[1m]))'
                            },
                            {
                                "record": "node:node_memory_utilisation:ratio",
                                "expr": '1 - sum by (node) (node_memory_MemAvailable_bytes) / sum by (node) (node_memory_MemTotal_bytes)'
                            },
                            {
                                "record": "cluster:namespace:pod_cpu:active:kube_pod_container_resource_requests",
                                "expr": 'sum by (namespace) (kube_pod_container_resource_requests{resource="cpu"})'
                            },
                            {
                                "record": "cluster:namespace:pod_memory:active:kube_pod_container_resource_requests",
                                "expr": 'sum by (namespace) (kube_pod_container_resource_requests{resource="memory"})'
                            }
                        ]
                    },
                    {
                        "name": "slo-recording-rules",
                        "rules": [
                            {
                                "record": "service:http_requests_total:rate5m",
                                "expr": 'sum(rate(http_requests_total[5m])) by (service)'
                            },
                            {
                                "record": "service:http_errors_total:rate5m",
                                "expr": 'sum(rate(http_requests_total{status=~"5.."}[5m])) by (service)'
                            },
                            {
                                "record": "service:http_request_duration_seconds:p99",
                                "expr": 'histogram_quantile(0.99, sum(rate(http_request_duration_seconds_bucket[5m])) by (le, service))'
                            },
                            {
                                "record": "service:http_request_duration_seconds:p95",
                                "expr": 'histogram_quantile(0.95, sum(rate(http_request_duration_seconds_bucket[5m])) by (le, service))'
                            },
                            {
                                "record": "service:http_request_duration_seconds:p50",
                                "expr": 'histogram_quantile(0.50, sum(rate(http_request_duration_seconds_bucket[5m])) by (le, service))'
                            }
                        ]
                    }
                ]
            }
        }
        
        return yaml.dump(rules, default_flow_style=False)
    
    def _generate_thanos_config(self, config: Dict) -> str:
        """Generate Thanos configuration for multi-cluster setup"""
        
        values = {
            "query": {
                "enabled": True,
                "replicas": 2,
                "stores": [
                    "dnssrv+_grpc._tcp.prometheus-operated.monitoring.svc.cluster.local"
                ],
                "ingress": {
                    "enabled": True,
                    "hostname": "thanos-query.example.com"
                }
            },
            "queryFrontend": {
                "enabled": True,
                "replicas": 2
            },
            "compactor": {
                "enabled": True,
                "persistence": {
                    "enabled": True,
                    "size": "100Gi"
                },
                "retentionResolutionRaw": "30d",
                "retentionResolution5m": "60d",
                "retentionResolution1h": "1y"
            },
            "storegateway": {
                "enabled": True,
                "replicas": 2,
                "persistence": {
                    "enabled": True,
                    "size": "50Gi"
                }
            },
            "ruler": {
                "enabled": True,
                "replicas": 2,
                "alertmanagers": [
                    "http://alertmanager-operated.monitoring.svc.cluster.local:9093"
                ]
            },
            "objstoreConfig": {
                "type": "S3",
                "config": {
                    "bucket": "${THANOS_S3_BUCKET}",
                    "region": config.get("region", "us-east-1"),
                    "endpoint": "s3.${AWS_REGION}.amazonaws.com"
                }
            }
        }
        
        return yaml.dump(values, default_flow_style=False)


# ============================================================================
# LOGGING CONFIGURATION GENERATOR
# ============================================================================

class LoggingConfigGenerator:
    """
    Generates logging stack configurations for EKS clusters.
    """
    
    def generate_logging_stack(self, config: Dict) -> Dict[str, str]:
        """Generate complete logging stack configuration"""
        
        configs = {}
        
        logging_config = config.get("observability", {})
        logging_solution = logging_config.get("logging_solution", "fluent-bit")
        log_destination = logging_config.get("log_destination", "cloudwatch")
        
        if logging_solution == "fluent-bit":
            configs["fluent-bit-values.yaml"] = self._generate_fluent_bit_config(config)
        else:
            configs["fluentd-values.yaml"] = self._generate_fluentd_config(config)
        
        if log_destination == "opensearch":
            configs["opensearch-values.yaml"] = self._generate_opensearch_config(config)
        elif log_destination == "loki":
            configs["loki-values.yaml"] = self._generate_loki_config(config)
        
        return configs
    
    def _generate_fluent_bit_config(self, config: Dict) -> str:
        """Generate Fluent Bit configuration"""
        
        log_destination = config.get("observability", {}).get("log_destination", "cloudwatch")
        region = config.get("region", "us-east-1")
        cluster_name = config.get("cluster_name", "eks-cluster")
        
        values = {
            "serviceAccount": {
                "create": True,
                "annotations": {
                    "eks.amazonaws.com/role-arn": "arn:aws:iam::${AWS_ACCOUNT_ID}:role/FluentBitRole"
                }
            },
            "config": {
                "service": """
[SERVICE]
    Flush         5
    Log_Level     info
    Daemon        off
    Parsers_File  parsers.conf
    HTTP_Server   On
    HTTP_Listen   0.0.0.0
    HTTP_Port     2020
""",
                "inputs": """
[INPUT]
    Name              tail
    Tag               kube.*
    Path              /var/log/containers/*.log
    Parser            docker
    DB                /var/log/flb_kube.db
    Mem_Buf_Limit     50MB
    Skip_Long_Lines   On
    Refresh_Interval  10

[INPUT]
    Name              tail
    Tag               host.*
    Path              /var/log/messages,/var/log/secure
    Parser            syslog
    DB                /var/log/flb_host.db
    Mem_Buf_Limit     5MB
""",
                "filters": """
[FILTER]
    Name                kubernetes
    Match               kube.*
    Kube_URL            https://kubernetes.default.svc:443
    Kube_CA_File        /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
    Kube_Token_File     /var/run/secrets/kubernetes.io/serviceaccount/token
    Kube_Tag_Prefix     kube.var.log.containers.
    Merge_Log           On
    Merge_Log_Key       log_processed
    K8S-Logging.Parser  On
    K8S-Logging.Exclude Off
    Labels              On
    Annotations         Off

[FILTER]
    Name          modify
    Match         kube.*
    Add           cluster_name """ + cluster_name + """
    Add           region """ + region + """

[FILTER]
    Name          nest
    Match         kube.*
    Operation     lift
    Nested_under  kubernetes
    Add_prefix    kubernetes_
""",
                "outputs": self._get_fluent_bit_output(log_destination, region, cluster_name),
                "customParsers": """
[PARSER]
    Name        docker
    Format      json
    Time_Key    time
    Time_Format %Y-%m-%dT%H:%M:%S.%L
    Time_Keep   On

[PARSER]
    Name        syslog
    Format      regex
    Regex       ^(?<time>[^ ]* {1,2}[^ ]* [^ ]*) (?<host>[^ ]*) (?<ident>[a-zA-Z0-9_\/\.\-]*)(?:\[(?<pid>[0-9]+)\])?(?:[^\:]*\:)? *(?<message>.*)$
    Time_Key    time
    Time_Format %b %d %H:%M:%S
"""
            },
            "tolerations": [
                {"key": "node-role.kubernetes.io/master", "operator": "Exists", "effect": "NoSchedule"},
                {"key": "node-role.kubernetes.io/control-plane", "operator": "Exists", "effect": "NoSchedule"}
            ],
            "resources": {
                "requests": {"cpu": "100m", "memory": "128Mi"},
                "limits": {"cpu": "500m", "memory": "512Mi"}
            }
        }
        
        return yaml.dump(values, default_flow_style=False)
    
    def _get_fluent_bit_output(self, destination: str, region: str, cluster_name: str) -> str:
        """Get Fluent Bit output configuration based on destination"""
        
        if destination == "cloudwatch":
            return f"""
[OUTPUT]
    Name                cloudwatch_logs
    Match               kube.*
    region              {region}
    log_group_name      /aws/eks/{cluster_name}/containers
    log_stream_prefix   ${{HOSTNAME}}-
    auto_create_group   true
    log_retention_days  30

[OUTPUT]
    Name                cloudwatch_logs
    Match               host.*
    region              {region}
    log_group_name      /aws/eks/{cluster_name}/host
    log_stream_prefix   ${{HOSTNAME}}-
    auto_create_group   true
    log_retention_days  30
"""
        elif destination == "opensearch":
            return """
[OUTPUT]
    Name            opensearch
    Match           kube.*
    Host            ${OPENSEARCH_HOST}
    Port            443
    Index           kubernetes
    Type            _doc
    AWS_Auth        On
    AWS_Region      ${AWS_REGION}
    tls             On
    Suppress_Type_Name On

[OUTPUT]
    Name            opensearch
    Match           host.*
    Host            ${OPENSEARCH_HOST}
    Port            443
    Index           host-logs
    Type            _doc
    AWS_Auth        On
    AWS_Region      ${AWS_REGION}
    tls             On
    Suppress_Type_Name On
"""
        elif destination == "loki":
            return """
[OUTPUT]
    Name            loki
    Match           kube.*
    Host            loki.monitoring.svc.cluster.local
    Port            3100
    Labels          job=fluent-bit, cluster=${CLUSTER_NAME}
    Label_keys      $kubernetes_namespace_name,$kubernetes_pod_name,$kubernetes_container_name
    Remove_keys     kubernetes_pod_id,kubernetes_host,kubernetes_container_hash

[OUTPUT]
    Name            loki
    Match           host.*
    Host            loki.monitoring.svc.cluster.local
    Port            3100
    Labels          job=fluent-bit-host
"""
        else:
            return """
[OUTPUT]
    Name            stdout
    Match           *
"""
    
    def _generate_fluentd_config(self, config: Dict) -> str:
        """Generate Fluentd configuration"""
        
        values = {
            "image": {
                "repository": "fluent/fluentd-kubernetes-daemonset",
                "tag": "v1.16-debian-cloudwatch-1"
            },
            "serviceAccount": {
                "create": True,
                "annotations": {
                    "eks.amazonaws.com/role-arn": "arn:aws:iam::${AWS_ACCOUNT_ID}:role/FluentdRole"
                }
            },
            "configMaps": {
                "useDefaults": {
                    "containersInputConf": True,
                    "containersKeepTimeKey": True,
                    "systemInputConf": True,
                    "outputConf": False
                }
            },
            "fileConfigs": {
                "output.conf": """
<match **>
  @type cloudwatch_logs
  log_group_name /aws/eks/${CLUSTER_NAME}/fluentd
  log_stream_name_key kubernetes.pod_name
  auto_create_stream true
  region ${AWS_REGION}
  <buffer>
    @type file
    path /var/log/fluentd-buffers/cloudwatch
    flush_interval 5s
    chunk_limit_size 2m
    queued_chunks_limit_size 32
    retry_forever true
  </buffer>
</match>
"""
            },
            "tolerations": [
                {"key": "node-role.kubernetes.io/master", "operator": "Exists", "effect": "NoSchedule"}
            ],
            "resources": {
                "requests": {"cpu": "200m", "memory": "256Mi"},
                "limits": {"cpu": "1000m", "memory": "1Gi"}
            }
        }
        
        return yaml.dump(values, default_flow_style=False)
    
    def _generate_opensearch_config(self, config: Dict) -> str:
        """Generate OpenSearch configuration"""
        
        values = {
            "clusterName": "opensearch-cluster",
            "nodeGroup": "master",
            "masterService": "opensearch-cluster-master",
            "replicas": 3,
            "minimumMasterNodes": 2,
            "opensearchJavaOpts": "-Xmx4g -Xms4g",
            "resources": {
                "requests": {"cpu": "1000m", "memory": "8Gi"},
                "limits": {"cpu": "2000m", "memory": "8Gi"}
            },
            "persistence": {
                "enabled": True,
                "storageClass": "gp3",
                "size": "100Gi"
            },
            "securityConfig": {
                "enabled": True
            },
            "dashboards": {
                "enabled": True,
                "replicas": 1
            }
        }
        
        return yaml.dump(values, default_flow_style=False)
    
    def _generate_loki_config(self, config: Dict) -> str:
        """Generate Grafana Loki configuration"""
        
        values = {
            "loki": {
                "auth_enabled": False,
                "storage": {
                    "type": "s3",
                    "bucketNames": {
                        "chunks": "${LOKI_S3_BUCKET}",
                        "ruler": "${LOKI_S3_BUCKET}",
                        "admin": "${LOKI_S3_BUCKET}"
                    },
                    "s3": {
                        "region": config.get("region", "us-east-1"),
                        "insecure": False,
                        "s3ForcePathStyle": False
                    }
                },
                "schemaConfig": {
                    "configs": [
                        {
                            "from": "2024-01-01",
                            "store": "tsdb",
                            "object_store": "s3",
                            "schema": "v13",
                            "index": {
                                "prefix": "loki_index_",
                                "period": "24h"
                            }
                        }
                    ]
                }
            },
            "deploymentMode": "SimpleScalable",
            "backend": {
                "replicas": 2
            },
            "read": {
                "replicas": 2
            },
            "write": {
                "replicas": 3,
                "persistence": {
                    "size": "50Gi",
                    "storageClass": "gp3"
                }
            },
            "serviceAccount": {
                "create": True,
                "annotations": {
                    "eks.amazonaws.com/role-arn": "arn:aws:iam::${AWS_ACCOUNT_ID}:role/LokiRole"
                }
            }
        }
        
        return yaml.dump(values, default_flow_style=False)


# ============================================================================
# TRACING CONFIGURATION GENERATOR
# ============================================================================

class TracingConfigGenerator:
    """
    Generates distributed tracing configurations for EKS clusters.
    """
    
    def generate_tracing_stack(self, config: Dict) -> Dict[str, str]:
        """Generate tracing stack configuration"""
        
        configs = {}
        
        tracing_config = config.get("observability", {})
        tracing_solution = tracing_config.get("tracing_solution", "xray")
        
        if tracing_solution == "xray":
            configs["xray-daemon.yaml"] = self._generate_xray_config(config)
            configs["otel-collector-xray.yaml"] = self._generate_otel_collector_xray(config)
        elif tracing_solution == "jaeger":
            configs["jaeger-values.yaml"] = self._generate_jaeger_config(config)
        elif tracing_solution == "tempo":
            configs["tempo-values.yaml"] = self._generate_tempo_config(config)
        
        # OpenTelemetry Collector for all solutions
        configs["otel-collector-values.yaml"] = self._generate_otel_collector(config)
        
        return configs
    
    def _generate_xray_config(self, config: Dict) -> str:
        """Generate AWS X-Ray daemon configuration"""
        
        xray = {
            "apiVersion": "apps/v1",
            "kind": "DaemonSet",
            "metadata": {
                "name": "xray-daemon",
                "namespace": "monitoring"
            },
            "spec": {
                "selector": {
                    "matchLabels": {
                        "app": "xray-daemon"
                    }
                },
                "template": {
                    "metadata": {
                        "labels": {
                            "app": "xray-daemon"
                        }
                    },
                    "spec": {
                        "serviceAccountName": "xray-daemon",
                        "containers": [
                            {
                                "name": "xray-daemon",
                                "image": "amazon/aws-xray-daemon:latest",
                                "ports": [
                                    {"containerPort": 2000, "protocol": "UDP", "name": "xray-ingest"},
                                    {"containerPort": 2000, "protocol": "TCP", "name": "xray-tcp"}
                                ],
                                "resources": {
                                    "requests": {"cpu": "50m", "memory": "64Mi"},
                                    "limits": {"cpu": "100m", "memory": "128Mi"}
                                },
                                "env": [
                                    {"name": "AWS_REGION", "value": config.get("region", "us-east-1")}
                                ]
                            }
                        ]
                    }
                }
            }
        }
        
        return yaml.dump(xray, default_flow_style=False)
    
    def _generate_otel_collector_xray(self, config: Dict) -> str:
        """Generate OpenTelemetry Collector config for X-Ray"""
        
        otel_config = {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": "otel-collector-config",
                "namespace": "monitoring"
            },
            "data": {
                "config.yaml": """
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
      http:
        endpoint: 0.0.0.0:4318
  
processors:
  batch:
    timeout: 1s
    send_batch_size: 50
  memory_limiter:
    check_interval: 1s
    limit_mib: 512
    spike_limit_mib: 128

exporters:
  awsxray:
    region: """ + config.get("region", "us-east-1") + """
    index_all_attributes: true
  logging:
    verbosity: detailed

service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [memory_limiter, batch]
      exporters: [awsxray, logging]
"""
            }
        }
        
        return yaml.dump(otel_config, default_flow_style=False)
    
    def _generate_jaeger_config(self, config: Dict) -> str:
        """Generate Jaeger configuration"""
        
        values = {
            "provisionDataStore": {
                "cassandra": False,
                "elasticsearch": True
            },
            "storage": {
                "type": "elasticsearch",
                "elasticsearch": {
                    "host": "elasticsearch-master",
                    "port": 9200,
                    "scheme": "http"
                }
            },
            "agent": {
                "enabled": True
            },
            "collector": {
                "enabled": True,
                "replicas": 2,
                "service": {
                    "type": "ClusterIP"
                },
                "resources": {
                    "requests": {"cpu": "100m", "memory": "128Mi"},
                    "limits": {"cpu": "500m", "memory": "512Mi"}
                }
            },
            "query": {
                "enabled": True,
                "replicas": 2,
                "ingress": {
                    "enabled": True,
                    "hosts": ["jaeger.internal.example.com"]
                }
            },
            "elasticsearch": {
                "replicas": 3,
                "minimumMasterNodes": 2,
                "resources": {
                    "requests": {"cpu": "1000m", "memory": "2Gi"},
                    "limits": {"cpu": "2000m", "memory": "4Gi"}
                },
                "persistence": {
                    "enabled": True,
                    "size": "50Gi"
                }
            }
        }
        
        return yaml.dump(values, default_flow_style=False)
    
    def _generate_tempo_config(self, config: Dict) -> str:
        """Generate Grafana Tempo configuration"""
        
        values = {
            "tempo": {
                "storage": {
                    "trace": {
                        "backend": "s3",
                        "s3": {
                            "bucket": "${TEMPO_S3_BUCKET}",
                            "endpoint": f"s3.{config.get('region', 'us-east-1')}.amazonaws.com",
                            "region": config.get("region", "us-east-1")
                        }
                    }
                },
                "receivers": {
                    "jaeger": {
                        "protocols": {
                            "thrift_http": {"endpoint": "0.0.0.0:14268"},
                            "grpc": {"endpoint": "0.0.0.0:14250"}
                        }
                    },
                    "otlp": {
                        "protocols": {
                            "http": {"endpoint": "0.0.0.0:4318"},
                            "grpc": {"endpoint": "0.0.0.0:4317"}
                        }
                    }
                },
                "metricsGenerator": {
                    "enabled": True,
                    "remoteWriteUrl": "http://prometheus-operated:9090/api/v1/write"
                }
            },
            "serviceAccount": {
                "create": True,
                "annotations": {
                    "eks.amazonaws.com/role-arn": "arn:aws:iam::${AWS_ACCOUNT_ID}:role/TempoRole"
                }
            },
            "persistence": {
                "enabled": True,
                "size": "50Gi"
            }
        }
        
        return yaml.dump(values, default_flow_style=False)
    
    def _generate_otel_collector(self, config: Dict) -> str:
        """Generate OpenTelemetry Collector Helm values"""
        
        values = {
            "mode": "deployment",
            "replicaCount": 2,
            "config": {
                "receivers": {
                    "otlp": {
                        "protocols": {
                            "grpc": {"endpoint": "0.0.0.0:4317"},
                            "http": {"endpoint": "0.0.0.0:4318"}
                        }
                    },
                    "prometheus": {
                        "config": {
                            "scrape_configs": [
                                {
                                    "job_name": "otel-collector",
                                    "scrape_interval": "10s",
                                    "static_configs": [
                                        {"targets": ["0.0.0.0:8888"]}
                                    ]
                                }
                            ]
                        }
                    }
                },
                "processors": {
                    "batch": {
                        "timeout": "1s",
                        "send_batch_size": 1024
                    },
                    "memory_limiter": {
                        "check_interval": "1s",
                        "limit_mib": 1000,
                        "spike_limit_mib": 200
                    },
                    "resource": {
                        "attributes": [
                            {"key": "cluster", "value": config.get("cluster_name", "eks-cluster"), "action": "insert"}
                        ]
                    }
                },
                "exporters": {
                    "otlp": {
                        "endpoint": "tempo.monitoring.svc.cluster.local:4317",
                        "tls": {"insecure": True}
                    },
                    "prometheus": {
                        "endpoint": "0.0.0.0:8889"
                    }
                },
                "service": {
                    "pipelines": {
                        "traces": {
                            "receivers": ["otlp"],
                            "processors": ["memory_limiter", "resource", "batch"],
                            "exporters": ["otlp"]
                        },
                        "metrics": {
                            "receivers": ["otlp", "prometheus"],
                            "processors": ["memory_limiter", "batch"],
                            "exporters": ["prometheus"]
                        }
                    }
                }
            },
            "resources": {
                "requests": {"cpu": "200m", "memory": "256Mi"},
                "limits": {"cpu": "1000m", "memory": "1Gi"}
            },
            "serviceAccount": {
                "create": True,
                "annotations": {
                    "eks.amazonaws.com/role-arn": "arn:aws:iam::${AWS_ACCOUNT_ID}:role/OtelCollectorRole"
                }
            }
        }
        
        return yaml.dump(values, default_flow_style=False)


# ============================================================================
# GRAFANA DASHBOARD GENERATOR
# ============================================================================

class GrafanaDashboardGenerator:
    """
    Generates Grafana dashboards for EKS observability.
    """
    
    def generate_dashboards(self, config: Dict) -> Dict[str, str]:
        """Generate all Grafana dashboards"""
        
        dashboards = {}
        
        # Cluster overview dashboard
        dashboards["cluster-overview.json"] = json.dumps(
            self._generate_cluster_overview_dashboard(config), indent=2
        )
        
        # Namespace dashboard
        dashboards["namespace-overview.json"] = json.dumps(
            self._generate_namespace_dashboard(), indent=2
        )
        
        # Pod dashboard
        dashboards["pod-details.json"] = json.dumps(
            self._generate_pod_dashboard(), indent=2
        )
        
        # SLO dashboard
        dashboards["slo-dashboard.json"] = json.dumps(
            self._generate_slo_dashboard(), indent=2
        )
        
        # Cost dashboard
        dashboards["cost-dashboard.json"] = json.dumps(
            self._generate_cost_dashboard(), indent=2
        )
        
        # ConfigMap for dashboard provisioning
        dashboards["dashboard-configmap.yaml"] = self._generate_dashboard_configmap(dashboards)
        
        return dashboards
    
    def _generate_cluster_overview_dashboard(self, config: Dict) -> Dict:
        """Generate cluster overview dashboard"""
        
        return {
            "annotations": {"list": []},
            "editable": True,
            "fiscalYearStartMonth": 0,
            "graphTooltip": 0,
            "id": None,
            "links": [],
            "liveNow": False,
            "panels": [
                {
                    "datasource": {"type": "prometheus", "uid": "prometheus"},
                    "fieldConfig": {
                        "defaults": {"color": {"mode": "palette-classic"}, "unit": "short"},
                        "overrides": []
                    },
                    "gridPos": {"h": 4, "w": 6, "x": 0, "y": 0},
                    "id": 1,
                    "options": {"colorMode": "value", "graphMode": "area", "justifyMode": "auto"},
                    "targets": [
                        {"expr": "count(kube_node_info)", "legendFormat": "Nodes"}
                    ],
                    "title": "Total Nodes",
                    "type": "stat"
                },
                {
                    "datasource": {"type": "prometheus", "uid": "prometheus"},
                    "fieldConfig": {
                        "defaults": {"color": {"mode": "palette-classic"}, "unit": "short"},
                        "overrides": []
                    },
                    "gridPos": {"h": 4, "w": 6, "x": 6, "y": 0},
                    "id": 2,
                    "options": {"colorMode": "value", "graphMode": "area", "justifyMode": "auto"},
                    "targets": [
                        {"expr": "count(kube_pod_info)", "legendFormat": "Pods"}
                    ],
                    "title": "Total Pods",
                    "type": "stat"
                },
                {
                    "datasource": {"type": "prometheus", "uid": "prometheus"},
                    "fieldConfig": {
                        "defaults": {"color": {"mode": "palette-classic"}, "unit": "percentunit"},
                        "overrides": []
                    },
                    "gridPos": {"h": 4, "w": 6, "x": 12, "y": 0},
                    "id": 3,
                    "options": {"colorMode": "value", "graphMode": "area", "justifyMode": "auto"},
                    "targets": [
                        {
                            "expr": "1 - avg(rate(node_cpu_seconds_total{mode=\"idle\"}[5m]))",
                            "legendFormat": "CPU"
                        }
                    ],
                    "title": "Cluster CPU Usage",
                    "type": "stat"
                },
                {
                    "datasource": {"type": "prometheus", "uid": "prometheus"},
                    "fieldConfig": {
                        "defaults": {"color": {"mode": "palette-classic"}, "unit": "percentunit"},
                        "overrides": []
                    },
                    "gridPos": {"h": 4, "w": 6, "x": 18, "y": 0},
                    "id": 4,
                    "options": {"colorMode": "value", "graphMode": "area", "justifyMode": "auto"},
                    "targets": [
                        {
                            "expr": "1 - sum(node_memory_MemAvailable_bytes) / sum(node_memory_MemTotal_bytes)",
                            "legendFormat": "Memory"
                        }
                    ],
                    "title": "Cluster Memory Usage",
                    "type": "stat"
                },
                {
                    "datasource": {"type": "prometheus", "uid": "prometheus"},
                    "fieldConfig": {"defaults": {"color": {"mode": "palette-classic"}}},
                    "gridPos": {"h": 8, "w": 12, "x": 0, "y": 4},
                    "id": 5,
                    "options": {"legend": {"displayMode": "list", "placement": "bottom"}},
                    "targets": [
                        {
                            "expr": "sum(rate(node_cpu_seconds_total{mode!=\"idle\"}[5m])) by (node)",
                            "legendFormat": "{{node}}"
                        }
                    ],
                    "title": "CPU Usage by Node",
                    "type": "timeseries"
                },
                {
                    "datasource": {"type": "prometheus", "uid": "prometheus"},
                    "fieldConfig": {"defaults": {"color": {"mode": "palette-classic"}, "unit": "bytes"}},
                    "gridPos": {"h": 8, "w": 12, "x": 12, "y": 4},
                    "id": 6,
                    "options": {"legend": {"displayMode": "list", "placement": "bottom"}},
                    "targets": [
                        {
                            "expr": "sum(container_memory_working_set_bytes{container!=\"\"}) by (node)",
                            "legendFormat": "{{node}}"
                        }
                    ],
                    "title": "Memory Usage by Node",
                    "type": "timeseries"
                }
            ],
            "schemaVersion": 38,
            "style": "dark",
            "tags": ["kubernetes", "eks", "overview"],
            "templating": {"list": []},
            "time": {"from": "now-1h", "to": "now"},
            "timepicker": {},
            "timezone": "",
            "title": "EKS Cluster Overview",
            "uid": "eks-cluster-overview",
            "version": 1
        }
    
    def _generate_namespace_dashboard(self) -> Dict:
        """Generate namespace overview dashboard"""
        
        return {
            "annotations": {"list": []},
            "editable": True,
            "panels": [
                {
                    "datasource": {"type": "prometheus", "uid": "prometheus"},
                    "gridPos": {"h": 8, "w": 12, "x": 0, "y": 0},
                    "id": 1,
                    "targets": [
                        {
                            "expr": "sum(rate(container_cpu_usage_seconds_total{namespace=\"$namespace\"}[5m])) by (pod)",
                            "legendFormat": "{{pod}}"
                        }
                    ],
                    "title": "CPU Usage by Pod",
                    "type": "timeseries"
                },
                {
                    "datasource": {"type": "prometheus", "uid": "prometheus"},
                    "gridPos": {"h": 8, "w": 12, "x": 12, "y": 0},
                    "id": 2,
                    "targets": [
                        {
                            "expr": "sum(container_memory_working_set_bytes{namespace=\"$namespace\"}) by (pod)",
                            "legendFormat": "{{pod}}"
                        }
                    ],
                    "title": "Memory Usage by Pod",
                    "type": "timeseries"
                }
            ],
            "schemaVersion": 38,
            "tags": ["kubernetes", "namespace"],
            "templating": {
                "list": [
                    {
                        "name": "namespace",
                        "query": "label_values(kube_namespace_created, namespace)",
                        "type": "query"
                    }
                ]
            },
            "title": "Namespace Overview",
            "uid": "namespace-overview"
        }
    
    def _generate_pod_dashboard(self) -> Dict:
        """Generate pod details dashboard"""
        
        return {
            "annotations": {"list": []},
            "editable": True,
            "panels": [
                {
                    "datasource": {"type": "prometheus", "uid": "prometheus"},
                    "gridPos": {"h": 6, "w": 8, "x": 0, "y": 0},
                    "id": 1,
                    "targets": [
                        {
                            "expr": "sum(rate(container_cpu_usage_seconds_total{namespace=\"$namespace\",pod=\"$pod\"}[5m])) by (container)",
                            "legendFormat": "{{container}}"
                        }
                    ],
                    "title": "CPU Usage",
                    "type": "timeseries"
                },
                {
                    "datasource": {"type": "prometheus", "uid": "prometheus"},
                    "gridPos": {"h": 6, "w": 8, "x": 8, "y": 0},
                    "id": 2,
                    "targets": [
                        {
                            "expr": "sum(container_memory_working_set_bytes{namespace=\"$namespace\",pod=\"$pod\"}) by (container)",
                            "legendFormat": "{{container}}"
                        }
                    ],
                    "title": "Memory Usage",
                    "type": "timeseries"
                },
                {
                    "datasource": {"type": "prometheus", "uid": "prometheus"},
                    "gridPos": {"h": 6, "w": 8, "x": 16, "y": 0},
                    "id": 3,
                    "targets": [
                        {
                            "expr": "kube_pod_container_status_restarts_total{namespace=\"$namespace\",pod=\"$pod\"}",
                            "legendFormat": "{{container}}"
                        }
                    ],
                    "title": "Container Restarts",
                    "type": "timeseries"
                }
            ],
            "schemaVersion": 38,
            "tags": ["kubernetes", "pod"],
            "templating": {
                "list": [
                    {
                        "name": "namespace",
                        "query": "label_values(kube_pod_info, namespace)",
                        "type": "query"
                    },
                    {
                        "name": "pod",
                        "query": "label_values(kube_pod_info{namespace=\"$namespace\"}, pod)",
                        "type": "query"
                    }
                ]
            },
            "title": "Pod Details",
            "uid": "pod-details"
        }
    
    def _generate_slo_dashboard(self) -> Dict:
        """Generate SLO tracking dashboard"""
        
        return {
            "annotations": {"list": []},
            "editable": True,
            "panels": [
                {
                    "datasource": {"type": "prometheus", "uid": "prometheus"},
                    "fieldConfig": {
                        "defaults": {
                            "color": {"mode": "thresholds"},
                            "thresholds": {
                                "mode": "absolute",
                                "steps": [
                                    {"color": "red", "value": None},
                                    {"color": "yellow", "value": 99},
                                    {"color": "green", "value": 99.9}
                                ]
                            },
                            "unit": "percentunit"
                        }
                    },
                    "gridPos": {"h": 6, "w": 8, "x": 0, "y": 0},
                    "id": 1,
                    "targets": [
                        {
                            "expr": "1 - (sum(rate(http_requests_total{status=~\"5..\"}[30d])) / sum(rate(http_requests_total[30d])))",
                            "legendFormat": "Availability"
                        }
                    ],
                    "title": "30-Day Availability SLO",
                    "type": "gauge"
                },
                {
                    "datasource": {"type": "prometheus", "uid": "prometheus"},
                    "fieldConfig": {
                        "defaults": {
                            "color": {"mode": "thresholds"},
                            "thresholds": {
                                "mode": "absolute",
                                "steps": [
                                    {"color": "green", "value": None},
                                    {"color": "yellow", "value": 0.5},
                                    {"color": "red", "value": 1}
                                ]
                            },
                            "unit": "s"
                        }
                    },
                    "gridPos": {"h": 6, "w": 8, "x": 8, "y": 0},
                    "id": 2,
                    "targets": [
                        {
                            "expr": "histogram_quantile(0.99, sum(rate(http_request_duration_seconds_bucket[5m])) by (le))",
                            "legendFormat": "P99 Latency"
                        }
                    ],
                    "title": "P99 Latency",
                    "type": "gauge"
                },
                {
                    "datasource": {"type": "prometheus", "uid": "prometheus"},
                    "gridPos": {"h": 6, "w": 8, "x": 16, "y": 0},
                    "id": 3,
                    "targets": [
                        {
                            "expr": "(1 - (sum(rate(http_requests_total{status=~\"5..\"}[1h])) / sum(rate(http_requests_total[1h])))) / (1 - 0.999)",
                            "legendFormat": "Error Budget Remaining"
                        }
                    ],
                    "title": "Error Budget Burn Rate",
                    "type": "timeseries"
                }
            ],
            "schemaVersion": 38,
            "tags": ["slo", "sre"],
            "title": "SLO Dashboard",
            "uid": "slo-dashboard"
        }
    
    def _generate_cost_dashboard(self) -> Dict:
        """Generate cost monitoring dashboard"""
        
        return {
            "annotations": {"list": []},
            "editable": True,
            "panels": [
                {
                    "datasource": {"type": "prometheus", "uid": "prometheus"},
                    "fieldConfig": {"defaults": {"unit": "currencyUSD"}},
                    "gridPos": {"h": 6, "w": 8, "x": 0, "y": 0},
                    "id": 1,
                    "targets": [
                        {
                            "expr": "sum(container_cpu_usage_seconds_total) * 0.05",
                            "legendFormat": "Estimated CPU Cost"
                        }
                    ],
                    "title": "Estimated Daily CPU Cost",
                    "type": "stat"
                },
                {
                    "datasource": {"type": "prometheus", "uid": "prometheus"},
                    "gridPos": {"h": 8, "w": 12, "x": 0, "y": 6},
                    "id": 2,
                    "targets": [
                        {
                            "expr": "sum(kube_pod_container_resource_requests{resource=\"cpu\"}) by (namespace)",
                            "legendFormat": "{{namespace}}"
                        }
                    ],
                    "title": "CPU Requests by Namespace",
                    "type": "piechart"
                },
                {
                    "datasource": {"type": "prometheus", "uid": "prometheus"},
                    "gridPos": {"h": 8, "w": 12, "x": 12, "y": 6},
                    "id": 3,
                    "targets": [
                        {
                            "expr": "sum(kube_pod_container_resource_requests{resource=\"memory\"}) by (namespace)",
                            "legendFormat": "{{namespace}}"
                        }
                    ],
                    "title": "Memory Requests by Namespace",
                    "type": "piechart"
                }
            ],
            "schemaVersion": 38,
            "tags": ["cost", "finops"],
            "title": "Cost Dashboard",
            "uid": "cost-dashboard"
        }
    
    def _generate_dashboard_configmap(self, dashboards: Dict) -> str:
        """Generate ConfigMap for dashboard provisioning"""
        
        configmap = {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": "grafana-dashboards",
                "namespace": "monitoring",
                "labels": {
                    "grafana_dashboard": "1"
                }
            },
            "data": {}
        }
        
        for name, content in dashboards.items():
            if name.endswith(".json"):
                configmap["data"][name] = content
        
        return yaml.dump(configmap, default_flow_style=False)
