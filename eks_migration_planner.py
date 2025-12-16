"""
EKS Migration Planner Module
Part of the AI-Enhanced EKS Architecture Design Wizard

Features:
- Workload Assessment and Scoring
- Containerization Readiness Analysis
- Migration Wave Planning
- Risk Assessment
- Rollback Strategy Generation
- Timeline and Resource Estimation

Author: Infosys Cloud Architecture Team
Version: 2.0.0
"""

import streamlit as st
import json
import yaml
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
import os

# ============================================================================
# MIGRATION ENUMS AND CONSTANTS
# ============================================================================

class MigrationStrategy(Enum):
    """Migration Strategy Types (6 Rs)"""
    REHOST = "rehost"           # Lift and shift
    REPLATFORM = "replatform"   # Lift, tinker, and shift
    REFACTOR = "refactor"       # Re-architect
    REPURCHASE = "repurchase"   # Replace with SaaS
    RETIRE = "retire"           # Decommission
    RETAIN = "retain"           # Keep as-is

class WorkloadComplexity(Enum):
    """Workload Complexity Levels"""
    SIMPLE = "simple"           # Stateless, single container
    MODERATE = "moderate"       # Some state, multiple containers
    COMPLEX = "complex"         # Stateful, distributed
    VERY_COMPLEX = "very_complex"  # Legacy, tightly coupled

class MigrationRisk(Enum):
    """Migration Risk Levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ContainerizationReadiness(Enum):
    """Containerization Readiness Levels"""
    READY = "ready"                 # Already containerized or easily containerizable
    MINOR_CHANGES = "minor_changes" # Small modifications needed
    MODERATE_EFFORT = "moderate_effort"  # Significant changes required
    MAJOR_REFACTOR = "major_refactor"    # Substantial re-architecture needed
    NOT_SUITABLE = "not_suitable"        # Cannot be containerized


# ============================================================================
# MIGRATION DATA CLASSES
# ============================================================================

@dataclass
class WorkloadAssessment:
    """Individual workload assessment"""
    name: str
    description: str
    current_platform: str  # VM, bare-metal, other cloud
    technology_stack: List[str]
    dependencies: List[str]
    
    # Assessment scores (1-10)
    containerization_score: int = 5
    cloud_native_score: int = 5
    complexity_score: int = 5
    business_criticality: int = 5
    
    # Characteristics
    is_stateless: bool = True
    has_persistent_storage: bool = False
    requires_gpu: bool = False
    requires_specific_os: bool = False
    has_licensing_constraints: bool = False
    
    # Network requirements
    requires_static_ip: bool = False
    requires_specific_ports: bool = False
    has_external_integrations: List[str] = field(default_factory=list)
    
    # Data characteristics
    data_volume_gb: float = 0
    data_sensitivity: str = "low"  # low, medium, high, critical
    
    # Performance requirements
    cpu_cores: int = 2
    memory_gb: int = 4
    iops_required: int = 0
    latency_sensitive: bool = False
    
    # Calculated fields
    migration_strategy: MigrationStrategy = MigrationStrategy.REPLATFORM
    containerization_readiness: ContainerizationReadiness = ContainerizationReadiness.MINOR_CHANGES
    complexity: WorkloadComplexity = WorkloadComplexity.MODERATE
    risk_level: MigrationRisk = MigrationRisk.MEDIUM
    estimated_effort_days: int = 5
    migration_wave: int = 1

@dataclass
class MigrationWave:
    """Migration wave definition"""
    wave_number: int
    name: str
    description: str
    start_date: str
    end_date: str
    workloads: List[str]
    dependencies: List[int]  # Previous waves that must complete
    risk_level: MigrationRisk
    resources_required: Dict[str, int]  # role: count
    success_criteria: List[str]
    rollback_trigger: List[str]

@dataclass
class MigrationPlan:
    """Complete migration plan"""
    project_name: str
    total_workloads: int
    total_waves: int
    start_date: str
    target_end_date: str
    
    workload_assessments: List[WorkloadAssessment] = field(default_factory=list)
    waves: List[MigrationWave] = field(default_factory=list)
    
    # Summary metrics
    total_effort_days: int = 0
    total_resources_required: Dict[str, int] = field(default_factory=dict)
    overall_risk: MigrationRisk = MigrationRisk.MEDIUM
    
    # Strategy breakdown
    strategy_breakdown: Dict[str, int] = field(default_factory=dict)
    
    # Prerequisites
    prerequisites: List[Dict] = field(default_factory=list)
    
    # Risks and mitigations
    risks: List[Dict] = field(default_factory=list)
    
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())


# ============================================================================
# MIGRATION ASSESSMENT ENGINE
# ============================================================================

class MigrationAssessmentEngine:
    """
    AI-powered migration assessment and planning engine.
    Analyzes workloads and generates comprehensive migration plans.
    """
    
    def __init__(self):
        self.anthropic_client = None
        self._init_ai_client()
    
    def _init_ai_client(self):
        """Initialize Anthropic client for AI-powered analysis"""
        try:
            import anthropic
            api_key = os.getenv("ANTHROPIC_API_KEY") or st.secrets.get("ANTHROPIC_API_KEY", "")
            if api_key:
                self.anthropic_client = anthropic.Anthropic(api_key=api_key)
        except Exception:
            pass
    
    def assess_workload(self, workload_info: Dict) -> WorkloadAssessment:
        """
        Assess a single workload for migration readiness.
        
        Args:
            workload_info: Dictionary containing workload information
            
        Returns:
            WorkloadAssessment with scores and recommendations
        """
        assessment = WorkloadAssessment(
            name=workload_info.get("name", "Unknown"),
            description=workload_info.get("description", ""),
            current_platform=workload_info.get("current_platform", "VM"),
            technology_stack=workload_info.get("technology_stack", []),
            dependencies=workload_info.get("dependencies", [])
        )
        
        # Update characteristics from input
        assessment.is_stateless = workload_info.get("is_stateless", True)
        assessment.has_persistent_storage = workload_info.get("has_persistent_storage", False)
        assessment.requires_gpu = workload_info.get("requires_gpu", False)
        assessment.requires_specific_os = workload_info.get("requires_specific_os", False)
        assessment.has_licensing_constraints = workload_info.get("has_licensing_constraints", False)
        assessment.data_volume_gb = workload_info.get("data_volume_gb", 0)
        assessment.data_sensitivity = workload_info.get("data_sensitivity", "low")
        assessment.cpu_cores = workload_info.get("cpu_cores", 2)
        assessment.memory_gb = workload_info.get("memory_gb", 4)
        assessment.latency_sensitive = workload_info.get("latency_sensitive", False)
        assessment.business_criticality = workload_info.get("business_criticality", 5)
        
        # Calculate scores
        assessment.containerization_score = self._calculate_containerization_score(assessment)
        assessment.cloud_native_score = self._calculate_cloud_native_score(assessment)
        assessment.complexity_score = self._calculate_complexity_score(assessment)
        
        # Determine migration strategy
        assessment.migration_strategy = self._determine_migration_strategy(assessment)
        
        # Determine containerization readiness
        assessment.containerization_readiness = self._determine_containerization_readiness(assessment)
        
        # Determine complexity level
        assessment.complexity = self._determine_complexity(assessment)
        
        # Calculate risk level
        assessment.risk_level = self._calculate_risk_level(assessment)
        
        # Estimate effort
        assessment.estimated_effort_days = self._estimate_effort(assessment)
        
        return assessment
    
    def _calculate_containerization_score(self, assessment: WorkloadAssessment) -> int:
        """Calculate containerization readiness score (1-10)"""
        score = 10
        
        # Deductions
        if not assessment.is_stateless:
            score -= 2
        if assessment.has_persistent_storage:
            score -= 1
        if assessment.requires_gpu:
            score -= 1
        if assessment.requires_specific_os:
            score -= 2
        if assessment.has_licensing_constraints:
            score -= 2
        if assessment.requires_static_ip:
            score -= 1
        if assessment.data_volume_gb > 100:
            score -= 1
        
        # Technology stack bonuses
        stack = [s.lower() for s in assessment.technology_stack]
        if any(t in stack for t in ["docker", "kubernetes", "container"]):
            score += 2
        if any(t in stack for t in ["java", "python", "node", "go", "rust"]):
            score += 1
        if any(t in stack for t in ["cobol", "fortran", "legacy"]):
            score -= 3
        
        return max(1, min(10, score))
    
    def _calculate_cloud_native_score(self, assessment: WorkloadAssessment) -> int:
        """Calculate cloud-native readiness score (1-10)"""
        score = 5
        
        # Bonuses
        if assessment.is_stateless:
            score += 2
        if not assessment.requires_specific_os:
            score += 1
        if not assessment.has_licensing_constraints:
            score += 1
        
        # Technology bonuses
        stack = [s.lower() for s in assessment.technology_stack]
        if any(t in stack for t in ["microservices", "api", "rest", "grpc"]):
            score += 2
        if any(t in stack for t in ["12factor", "cloud-native"]):
            score += 2
        
        # Deductions
        if assessment.latency_sensitive:
            score -= 1
        if len(assessment.dependencies) > 5:
            score -= 2
        
        return max(1, min(10, score))
    
    def _calculate_complexity_score(self, assessment: WorkloadAssessment) -> int:
        """Calculate complexity score (1-10, higher = more complex)"""
        score = 3
        
        # Increase for complexity factors
        if not assessment.is_stateless:
            score += 2
        if assessment.has_persistent_storage:
            score += 1
        if assessment.requires_gpu:
            score += 2
        if assessment.data_volume_gb > 100:
            score += 1
        if assessment.data_volume_gb > 500:
            score += 1
        if len(assessment.dependencies) > 3:
            score += 1
        if len(assessment.dependencies) > 7:
            score += 2
        if assessment.business_criticality > 7:
            score += 1
        if len(assessment.has_external_integrations) > 2:
            score += 1
        
        return max(1, min(10, score))
    
    def _determine_migration_strategy(self, assessment: WorkloadAssessment) -> MigrationStrategy:
        """Determine recommended migration strategy"""
        
        # Already containerized - Rehost
        if assessment.containerization_score >= 9:
            return MigrationStrategy.REHOST
        
        # Good candidate with minor changes - Replatform
        if assessment.containerization_score >= 6 and assessment.cloud_native_score >= 5:
            return MigrationStrategy.REPLATFORM
        
        # Needs significant work but valuable - Refactor
        if assessment.business_criticality >= 7 and assessment.containerization_score >= 4:
            return MigrationStrategy.REFACTOR
        
        # Legacy with low business value - Retire
        if assessment.business_criticality <= 3 and assessment.containerization_score <= 4:
            return MigrationStrategy.RETIRE
        
        # Too complex or constrained - Retain
        if assessment.containerization_score <= 3 or assessment.has_licensing_constraints:
            return MigrationStrategy.RETAIN
        
        # Default - Replatform
        return MigrationStrategy.REPLATFORM
    
    def _determine_containerization_readiness(self, assessment: WorkloadAssessment) -> ContainerizationReadiness:
        """Determine containerization readiness level"""
        
        score = assessment.containerization_score
        
        if score >= 9:
            return ContainerizationReadiness.READY
        elif score >= 7:
            return ContainerizationReadiness.MINOR_CHANGES
        elif score >= 5:
            return ContainerizationReadiness.MODERATE_EFFORT
        elif score >= 3:
            return ContainerizationReadiness.MAJOR_REFACTOR
        else:
            return ContainerizationReadiness.NOT_SUITABLE
    
    def _determine_complexity(self, assessment: WorkloadAssessment) -> WorkloadComplexity:
        """Determine workload complexity level"""
        
        score = assessment.complexity_score
        
        if score <= 3:
            return WorkloadComplexity.SIMPLE
        elif score <= 5:
            return WorkloadComplexity.MODERATE
        elif score <= 7:
            return WorkloadComplexity.COMPLEX
        else:
            return WorkloadComplexity.VERY_COMPLEX
    
    def _calculate_risk_level(self, assessment: WorkloadAssessment) -> MigrationRisk:
        """Calculate migration risk level"""
        
        risk_score = 0
        
        # Business criticality impact
        if assessment.business_criticality >= 8:
            risk_score += 3
        elif assessment.business_criticality >= 6:
            risk_score += 2
        
        # Complexity impact
        if assessment.complexity == WorkloadComplexity.VERY_COMPLEX:
            risk_score += 3
        elif assessment.complexity == WorkloadComplexity.COMPLEX:
            risk_score += 2
        
        # Data sensitivity impact
        if assessment.data_sensitivity == "critical":
            risk_score += 3
        elif assessment.data_sensitivity == "high":
            risk_score += 2
        
        # Dependencies impact
        if len(assessment.dependencies) > 5:
            risk_score += 2
        elif len(assessment.dependencies) > 2:
            risk_score += 1
        
        # Strategy impact
        if assessment.migration_strategy == MigrationStrategy.REFACTOR:
            risk_score += 2
        
        # Determine risk level
        if risk_score >= 8:
            return MigrationRisk.CRITICAL
        elif risk_score >= 5:
            return MigrationRisk.HIGH
        elif risk_score >= 3:
            return MigrationRisk.MEDIUM
        else:
            return MigrationRisk.LOW
    
    def _estimate_effort(self, assessment: WorkloadAssessment) -> int:
        """Estimate migration effort in person-days"""
        
        base_effort = {
            MigrationStrategy.REHOST: 3,
            MigrationStrategy.REPLATFORM: 10,
            MigrationStrategy.REFACTOR: 30,
            MigrationStrategy.REPURCHASE: 5,
            MigrationStrategy.RETIRE: 2,
            MigrationStrategy.RETAIN: 1
        }
        
        effort = base_effort.get(assessment.migration_strategy, 10)
        
        # Complexity multiplier
        complexity_multiplier = {
            WorkloadComplexity.SIMPLE: 0.5,
            WorkloadComplexity.MODERATE: 1.0,
            WorkloadComplexity.COMPLEX: 2.0,
            WorkloadComplexity.VERY_COMPLEX: 3.0
        }
        
        effort *= complexity_multiplier.get(assessment.complexity, 1.0)
        
        # Additional factors
        if assessment.has_persistent_storage:
            effort += 3
        if assessment.requires_gpu:
            effort += 5
        if len(assessment.dependencies) > 5:
            effort += len(assessment.dependencies) - 5
        if assessment.data_volume_gb > 100:
            effort += 2
        if assessment.data_volume_gb > 500:
            effort += 5
        
        return int(effort)


# ============================================================================
# MIGRATION PLANNER
# ============================================================================

class MigrationPlanner:
    """
    Generates comprehensive migration plans with waves, timelines, and resources.
    """
    
    def __init__(self):
        self.assessment_engine = MigrationAssessmentEngine()
    
    def create_migration_plan(self, workloads: List[Dict], 
                              project_name: str = "EKS Migration",
                              start_date: str = None) -> MigrationPlan:
        """
        Create a comprehensive migration plan.
        
        Args:
            workloads: List of workload information dictionaries
            project_name: Name of the migration project
            start_date: Project start date (ISO format)
            
        Returns:
            MigrationPlan with all details
        """
        if start_date is None:
            start_date = datetime.now().isoformat()[:10]
        
        # Assess all workloads
        assessments = []
        for workload in workloads:
            assessment = self.assessment_engine.assess_workload(workload)
            assessments.append(assessment)
        
        # Assign migration waves
        self._assign_waves(assessments)
        
        # Create wave definitions
        waves = self._create_waves(assessments, start_date)
        
        # Calculate totals
        total_effort = sum(a.estimated_effort_days for a in assessments)
        
        # Strategy breakdown
        strategy_breakdown = {}
        for a in assessments:
            strategy = a.migration_strategy.value
            strategy_breakdown[strategy] = strategy_breakdown.get(strategy, 0) + 1
        
        # Calculate overall risk
        risk_scores = {
            MigrationRisk.LOW: 1,
            MigrationRisk.MEDIUM: 2,
            MigrationRisk.HIGH: 3,
            MigrationRisk.CRITICAL: 4
        }
        avg_risk = sum(risk_scores[a.risk_level] for a in assessments) / len(assessments)
        if avg_risk >= 3.5:
            overall_risk = MigrationRisk.CRITICAL
        elif avg_risk >= 2.5:
            overall_risk = MigrationRisk.HIGH
        elif avg_risk >= 1.5:
            overall_risk = MigrationRisk.MEDIUM
        else:
            overall_risk = MigrationRisk.LOW
        
        # Calculate end date
        target_end_date = waves[-1].end_date if waves else start_date
        
        # Generate prerequisites
        prerequisites = self._generate_prerequisites(assessments)
        
        # Generate risks
        risks = self._generate_risks(assessments)
        
        # Calculate resources
        total_resources = self._calculate_resources(assessments)
        
        plan = MigrationPlan(
            project_name=project_name,
            total_workloads=len(assessments),
            total_waves=len(waves),
            start_date=start_date,
            target_end_date=target_end_date,
            workload_assessments=assessments,
            waves=waves,
            total_effort_days=total_effort,
            total_resources_required=total_resources,
            overall_risk=overall_risk,
            strategy_breakdown=strategy_breakdown,
            prerequisites=prerequisites,
            risks=risks
        )
        
        return plan
    
    def _assign_waves(self, assessments: List[WorkloadAssessment]):
        """Assign workloads to migration waves"""
        
        # Sort by complexity and dependencies
        # Wave 1: Simple, low-risk workloads (pilot)
        # Wave 2: Medium complexity, some dependencies
        # Wave 3: Complex workloads
        # Wave 4: Critical and highly complex
        
        for assessment in assessments:
            if assessment.migration_strategy in [MigrationStrategy.RETIRE, MigrationStrategy.RETAIN]:
                assessment.migration_wave = 0  # Not migrating
            elif assessment.complexity == WorkloadComplexity.SIMPLE and assessment.risk_level == MigrationRisk.LOW:
                assessment.migration_wave = 1
            elif assessment.complexity in [WorkloadComplexity.SIMPLE, WorkloadComplexity.MODERATE]:
                if assessment.risk_level in [MigrationRisk.LOW, MigrationRisk.MEDIUM]:
                    assessment.migration_wave = 2
                else:
                    assessment.migration_wave = 3
            elif assessment.complexity == WorkloadComplexity.COMPLEX:
                assessment.migration_wave = 3
            else:
                assessment.migration_wave = 4
    
    def _create_waves(self, assessments: List[WorkloadAssessment], 
                      start_date: str) -> List[MigrationWave]:
        """Create migration wave definitions"""
        
        waves = []
        current_date = datetime.fromisoformat(start_date)
        
        wave_configs = [
            {
                "number": 1,
                "name": "Pilot Wave",
                "description": "Initial pilot migration with simple, low-risk workloads to validate process and tooling",
                "duration_weeks": 2
            },
            {
                "number": 2,
                "name": "Foundation Wave",
                "description": "Core infrastructure and medium-complexity workloads",
                "duration_weeks": 4
            },
            {
                "number": 3,
                "name": "Main Migration Wave",
                "description": "Bulk of application migrations including complex workloads",
                "duration_weeks": 6
            },
            {
                "number": 4,
                "name": "Critical Systems Wave",
                "description": "Business-critical and highly complex systems with extensive testing",
                "duration_weeks": 4
            }
        ]
        
        for wave_config in wave_configs:
            wave_num = wave_config["number"]
            wave_workloads = [a.name for a in assessments if a.migration_wave == wave_num]
            
            if not wave_workloads:
                continue
            
            wave_assessments = [a for a in assessments if a.migration_wave == wave_num]
            
            # Calculate wave risk
            risk_scores = {"low": 1, "medium": 2, "high": 3, "critical": 4}
            avg_risk = sum(risk_scores[a.risk_level.value] for a in wave_assessments) / len(wave_assessments)
            if avg_risk >= 3:
                wave_risk = MigrationRisk.HIGH
            elif avg_risk >= 2:
                wave_risk = MigrationRisk.MEDIUM
            else:
                wave_risk = MigrationRisk.LOW
            
            # Calculate resources
            total_effort = sum(a.estimated_effort_days for a in wave_assessments)
            duration_days = wave_config["duration_weeks"] * 5  # Working days
            team_size = max(2, int(total_effort / duration_days) + 1)
            
            resources = {
                "cloud_architect": 1,
                "devops_engineer": team_size,
                "developer": max(1, team_size - 1),
                "qa_engineer": max(1, team_size // 2),
                "project_manager": 1
            }
            
            end_date = current_date + timedelta(weeks=wave_config["duration_weeks"])
            
            wave = MigrationWave(
                wave_number=wave_num,
                name=wave_config["name"],
                description=wave_config["description"],
                start_date=current_date.isoformat()[:10],
                end_date=end_date.isoformat()[:10],
                workloads=wave_workloads,
                dependencies=[w for w in range(1, wave_num)],
                risk_level=wave_risk,
                resources_required=resources,
                success_criteria=[
                    "All workloads successfully deployed to EKS",
                    "Health checks passing for all services",
                    "Performance metrics within acceptable thresholds",
                    "No critical incidents within 48 hours post-migration",
                    "Rollback procedures tested and documented"
                ],
                rollback_trigger=[
                    "Error rate exceeds 5% for more than 15 minutes",
                    "P99 latency exceeds SLA by 50%",
                    "Data integrity issues detected",
                    "Security vulnerability identified"
                ]
            )
            
            waves.append(wave)
            current_date = end_date + timedelta(days=2)  # Buffer between waves
        
        return waves
    
    def _generate_prerequisites(self, assessments: List[WorkloadAssessment]) -> List[Dict]:
        """Generate migration prerequisites"""
        
        prerequisites = [
            {
                "category": "Infrastructure",
                "items": [
                    "EKS cluster provisioned and validated",
                    "VPC and networking configured",
                    "IAM roles and policies created",
                    "Container registry (ECR) set up",
                    "Secrets management configured",
                    "Monitoring and logging stack deployed"
                ],
                "owner": "Platform Team",
                "estimated_days": 10
            },
            {
                "category": "Security",
                "items": [
                    "Security review completed",
                    "Network policies defined",
                    "Pod security standards configured",
                    "Image scanning enabled",
                    "Compliance requirements documented"
                ],
                "owner": "Security Team",
                "estimated_days": 5
            },
            {
                "category": "CI/CD",
                "items": [
                    "CI/CD pipelines configured",
                    "GitOps repository structure created",
                    "Deployment automation tested",
                    "Rollback procedures documented"
                ],
                "owner": "DevOps Team",
                "estimated_days": 7
            },
            {
                "category": "Team Readiness",
                "items": [
                    "Team training on Kubernetes completed",
                    "Runbooks and documentation prepared",
                    "On-call procedures established",
                    "Communication plan finalized"
                ],
                "owner": "Project Manager",
                "estimated_days": 5
            }
        ]
        
        # Add data-specific prerequisites if needed
        has_large_data = any(a.data_volume_gb > 100 for a in assessments)
        if has_large_data:
            prerequisites.append({
                "category": "Data Migration",
                "items": [
                    "Data migration strategy defined",
                    "Data synchronization tools configured",
                    "Backup and recovery procedures tested",
                    "Data validation scripts prepared"
                ],
                "owner": "Data Team",
                "estimated_days": 10
            })
        
        # Add GPU prerequisites if needed
        has_gpu = any(a.requires_gpu for a in assessments)
        if has_gpu:
            prerequisites.append({
                "category": "GPU Workloads",
                "items": [
                    "GPU node groups configured",
                    "NVIDIA device plugin installed",
                    "GPU scheduling tested",
                    "Cost monitoring for GPU instances"
                ],
                "owner": "Platform Team",
                "estimated_days": 5
            })
        
        return prerequisites
    
    def _generate_risks(self, assessments: List[WorkloadAssessment]) -> List[Dict]:
        """Generate risk assessment with mitigations"""
        
        risks = [
            {
                "risk": "Service disruption during migration",
                "probability": "Medium",
                "impact": "High",
                "mitigation": [
                    "Blue-green deployment strategy",
                    "Comprehensive rollback procedures",
                    "Migration during low-traffic windows",
                    "Real-time monitoring during cutover"
                ],
                "owner": "Migration Lead"
            },
            {
                "risk": "Performance degradation post-migration",
                "probability": "Medium",
                "impact": "Medium",
                "mitigation": [
                    "Performance testing before cutover",
                    "Proper resource sizing",
                    "Horizontal pod autoscaling configured",
                    "Performance baselines established"
                ],
                "owner": "Platform Team"
            },
            {
                "risk": "Data loss or corruption",
                "probability": "Low",
                "impact": "Critical",
                "mitigation": [
                    "Comprehensive backup before migration",
                    "Data validation checkpoints",
                    "Point-in-time recovery capability",
                    "Data integrity verification scripts"
                ],
                "owner": "Data Team"
            },
            {
                "risk": "Security vulnerabilities introduced",
                "probability": "Medium",
                "impact": "High",
                "mitigation": [
                    "Security scanning in CI/CD pipeline",
                    "Network policies enforcement",
                    "Regular security audits",
                    "Least privilege IAM policies"
                ],
                "owner": "Security Team"
            },
            {
                "risk": "Team skill gaps",
                "probability": "Medium",
                "impact": "Medium",
                "mitigation": [
                    "Kubernetes training program",
                    "Documentation and runbooks",
                    "Pair programming during migration",
                    "External consultant support if needed"
                ],
                "owner": "Engineering Manager"
            },
            {
                "risk": "Timeline slippage",
                "probability": "High",
                "impact": "Medium",
                "mitigation": [
                    "Buffer time in schedule",
                    "Prioritized migration order",
                    "Regular progress reviews",
                    "Early escalation process"
                ],
                "owner": "Project Manager"
            }
        ]
        
        # Add workload-specific risks
        critical_workloads = [a for a in assessments if a.business_criticality >= 8]
        if critical_workloads:
            risks.append({
                "risk": f"Critical system migration ({len(critical_workloads)} workloads)",
                "probability": "Medium",
                "impact": "Critical",
                "mitigation": [
                    "Extended testing period",
                    "Executive stakeholder communication",
                    "Dedicated support team during cutover",
                    "Phased traffic migration"
                ],
                "owner": "Migration Lead"
            })
        
        complex_workloads = [a for a in assessments if a.complexity == WorkloadComplexity.VERY_COMPLEX]
        if complex_workloads:
            risks.append({
                "risk": f"Complex legacy system migration ({len(complex_workloads)} workloads)",
                "probability": "High",
                "impact": "High",
                "mitigation": [
                    "Detailed discovery and documentation",
                    "Incremental migration approach",
                    "Extended parallel running period",
                    "Legacy system experts involved"
                ],
                "owner": "Technical Lead"
            })
        
        return risks
    
    def _calculate_resources(self, assessments: List[WorkloadAssessment]) -> Dict[str, int]:
        """Calculate total resources required"""
        
        total_effort = sum(a.estimated_effort_days for a in assessments)
        
        # Assume 3-month migration timeline
        working_days = 60
        
        # Calculate team size
        base_team_size = max(3, int(total_effort / working_days) + 1)
        
        resources = {
            "cloud_architect": max(1, base_team_size // 4),
            "devops_engineer": max(2, base_team_size // 2),
            "software_developer": max(2, base_team_size // 2),
            "qa_engineer": max(1, base_team_size // 3),
            "security_engineer": 1,
            "project_manager": 1,
            "technical_writer": 1
        }
        
        return resources
    
    def generate_rollback_plan(self, wave: MigrationWave) -> Dict[str, Any]:
        """Generate detailed rollback plan for a migration wave"""
        
        rollback_plan = {
            "wave": wave.name,
            "trigger_conditions": wave.rollback_trigger,
            "decision_authority": "Migration Lead with approval from Engineering Director",
            "communication_plan": {
                "immediate": ["On-call team", "Stakeholders"],
                "within_15_min": ["Engineering leadership", "Support team"],
                "within_1_hour": ["Business stakeholders", "Customers (if applicable)"]
            },
            "rollback_steps": [
                {
                    "step": 1,
                    "action": "Initiate rollback decision",
                    "owner": "Migration Lead",
                    "duration": "5 minutes",
                    "details": [
                        "Confirm rollback trigger condition",
                        "Get approval from decision authority",
                        "Announce rollback initiation"
                    ]
                },
                {
                    "step": 2,
                    "action": "Switch traffic back to original system",
                    "owner": "Platform Engineer",
                    "duration": "10 minutes",
                    "details": [
                        "Update DNS/load balancer to point to original",
                        "Scale down new deployment",
                        "Verify traffic routing"
                    ]
                },
                {
                    "step": 3,
                    "action": "Verify original system health",
                    "owner": "QA Engineer",
                    "duration": "15 minutes",
                    "details": [
                        "Run health checks on original system",
                        "Verify data integrity",
                        "Confirm service availability"
                    ]
                },
                {
                    "step": 4,
                    "action": "Data reconciliation (if needed)",
                    "owner": "Data Engineer",
                    "duration": "30 minutes - 2 hours",
                    "details": [
                        "Identify data written during migration window",
                        "Sync data back to original system if needed",
                        "Verify data consistency"
                    ]
                },
                {
                    "step": 5,
                    "action": "Post-rollback verification",
                    "owner": "QA Engineer",
                    "duration": "30 minutes",
                    "details": [
                        "Complete end-to-end testing",
                        "Verify all integrations",
                        "Confirm monitoring is working"
                    ]
                },
                {
                    "step": 6,
                    "action": "Communication and documentation",
                    "owner": "Project Manager",
                    "duration": "1 hour",
                    "details": [
                        "Send all-clear communication",
                        "Document rollback reason and timeline",
                        "Schedule post-mortem"
                    ]
                }
            ],
            "post_rollback_actions": [
                "Conduct post-mortem within 48 hours",
                "Document root cause and lessons learned",
                "Update migration plan based on findings",
                "Reschedule migration with fixes applied"
            ],
            "estimated_total_rollback_time": "1-3 hours depending on data sync requirements"
        }
        
        return rollback_plan
    
    def export_plan_to_yaml(self, plan: MigrationPlan) -> str:
        """Export migration plan to YAML format"""
        
        plan_dict = {
            "migration_plan": {
                "project_name": plan.project_name,
                "created_at": plan.created_at,
                "timeline": {
                    "start_date": plan.start_date,
                    "target_end_date": plan.target_end_date,
                    "total_waves": plan.total_waves
                },
                "summary": {
                    "total_workloads": plan.total_workloads,
                    "total_effort_days": plan.total_effort_days,
                    "overall_risk": plan.overall_risk.value,
                    "strategy_breakdown": plan.strategy_breakdown
                },
                "resources_required": plan.total_resources_required,
                "waves": [
                    {
                        "wave_number": w.wave_number,
                        "name": w.name,
                        "description": w.description,
                        "start_date": w.start_date,
                        "end_date": w.end_date,
                        "workloads": w.workloads,
                        "risk_level": w.risk_level.value,
                        "resources": w.resources_required,
                        "success_criteria": w.success_criteria,
                        "rollback_triggers": w.rollback_trigger
                    }
                    for w in plan.waves
                ],
                "workload_assessments": [
                    {
                        "name": a.name,
                        "strategy": a.migration_strategy.value,
                        "complexity": a.complexity.value,
                        "risk_level": a.risk_level.value,
                        "estimated_effort_days": a.estimated_effort_days,
                        "migration_wave": a.migration_wave,
                        "containerization_readiness": a.containerization_readiness.value
                    }
                    for a in plan.workload_assessments
                ],
                "prerequisites": plan.prerequisites,
                "risks": plan.risks
            }
        }
        
        return yaml.dump(plan_dict, default_flow_style=False, sort_keys=False)
