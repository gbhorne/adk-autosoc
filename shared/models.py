# shared/models.py
# Pydantic schemas for all data objects passed between AutoSOC agents

from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime, timezone
from enum import Enum


# --- Enums ---

class AlertType(str, Enum):
    PUBLIC_BUCKET = "PUBLIC_BUCKET"
    IAM_ANOMALY = "IAM_ANOMALY"
    DATA_ACCESS = "DATA_ACCESS"
    NETWORK_ANOMALY = "NETWORK_ANOMALY"
    MALWARE = "MALWARE"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    UNKNOWN = "UNKNOWN"


class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class InvestigationStatus(str, Enum):
    NEW = "NEW"
    TRIAGING = "TRIAGING"
    INVESTIGATING = "INVESTIGATING"
    REMEDIATING = "REMEDIATING"
    RESOLVED = "RESOLVED"
    ESCALATED = "ESCALATED"


class RemediationAction(str, Enum):
    AUTO_EXECUTE = "AUTO_EXECUTE"
    HUMAN_APPROVAL_REQUIRED = "HUMAN_APPROVAL_REQUIRED"
    NO_ACTION = "NO_ACTION"


# --- Core Models ---

class SCCFinding(BaseModel):
    """Raw finding from Security Command Center"""
    finding_id: str
    category: str
    resource_name: str
    project_id: str
    severity: str
    state: str
    event_time: datetime
    description: Optional[str] = None
    source_properties: Optional[dict] = None


class Alert(BaseModel):
    """Structured alert created by Detection Agent from SCC finding"""
    investigation_id: str
    alert_type: AlertType
    severity: SeverityLevel
    resource: str
    principal: Optional[str] = None
    project_id: str
    scc_finding_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    raw_finding: Optional[dict] = None


class TriageResult(BaseModel):
    """Enrichment and scoring produced by Triage Agent"""
    investigation_id: str
    severity_score: int = Field(ge=1, le=10)
    severity_reasoning: str
    principal_roles: Optional[List[str]] = None
    principal_has_bq_access: bool = False
    principal_has_storage_access: bool = False
    resource_has_sensitive_tags: bool = False
    normal_behavior_deviation: bool = False
    recommended_next_agent: str


class ThreatIntelResult(BaseModel):
    """External threat context produced by Threat Intel Agent"""
    investigation_id: str
    mitre_technique_id: Optional[str] = None
    mitre_technique_name: Optional[str] = None
    virustotal_hits: int = 0
    known_malicious_ip: bool = False
    threat_confidence: int = Field(default=0, ge=0, le=100)
    threat_summary: str


class ForensicsResult(BaseModel):
    """Timeline and blast radius produced by Forensics Agent"""
    investigation_id: str
    timeline_events: List[dict] = []
    blast_radius: List[str] = []
    related_resources: List[str] = []
    earliest_event: Optional[datetime] = None
    latest_event: Optional[datetime] = None
    forensics_summary: str


class RemediationResult(BaseModel):
    """Action taken or requested by Remediation Agent"""
    investigation_id: str
    action_type: RemediationAction
    action_taken: str
    action_successful: Optional[bool] = None
    human_approval_requested: bool = False
    approver_notified: Optional[str] = None
    remediation_notes: str


class Investigation(BaseModel):
    """Full investigation state stored in Firestore by Orchestrator"""
    investigation_id: str
    status: InvestigationStatus = InvestigationStatus.NEW
    alert: Optional[Alert] = None
    triage: Optional[TriageResult] = None
    threat_intel: Optional[ThreatIntelResult] = None
    forensics: Optional[ForensicsResult] = None
    remediation: Optional[RemediationResult] = None
    current_agent: str = "detection"
    agents_completed: List[str] = []
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_updated: datetime = Field(default_factory=datetime.utcnow)
    project_id: str = ""


class Finding(BaseModel):
    """Final record written to BigQuery by Reporting Agent"""
    investigation_id: str
    alert_type: str
    severity_score: int
    resource_affected: str
    principal: str
    resolution: str
    time_to_resolve: int  # seconds
    nl_summary: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
