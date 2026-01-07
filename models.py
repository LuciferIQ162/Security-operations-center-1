"""Data models for AI SOC Agent."""
from datetime import datetime
from enum import Enum
from typing import Optional, Dict, List, Any
from pydantic import BaseModel, Field


class AlertType(str, Enum):
    """Types of security alerts."""
    EDR = "edr"
    PHISHING = "phishing"
    CLOUD_SECURITY = "cloud_security"
    NETWORK = "network"
    IDENTITY = "identity"
    MALWARE = "malware"
    UNKNOWN = "unknown"


class ThreatSeverity(str, Enum):
    """Threat severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    FALSE_POSITIVE = "false_positive"


class InvestigationStatus(str, Enum):
    """Investigation status."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    ESCALATED = "escalated"


class Alert(BaseModel):
    """Security alert model."""
    id: Optional[str] = None
    alert_type: AlertType
    source: str
    timestamp: datetime = Field(default_factory=datetime.now)
    raw_data: Dict[str, Any]
    severity: Optional[ThreatSeverity] = None
    title: str
    description: Optional[str] = None
    user_id: Optional[str] = None
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    enriched_data: Optional[Dict[str, Any]] = None


class InvestigationResult(BaseModel):
    """Investigation result model."""
    alert_id: str
    status: InvestigationStatus
    findings: List[Dict[str, Any]] = []
    correlated_alerts: List[str] = []
    threat_indicators: List[str] = []
    risk_score: float = Field(default=0.0, ge=0.0, le=10.0)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    reasoning: str = ""
    business_impact: Optional[str] = None
    investigation_timeline: List[Dict[str, Any]] = []
    started_at: datetime = Field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None


class ActionableConclusion(BaseModel):
    """Actionable conclusion from investigation."""
    alert_id: str
    risk_assessment: str
    threat_severity: ThreatSeverity
    recommended_actions: List[str]
    containment_steps: Optional[List[str]] = None
    blast_radius: Optional[str] = None
    evidence_summary: str
    next_steps: List[str]
    requires_human_review: bool
    ticket_id: Optional[str] = None


class AgentDecision(BaseModel):
    """Agent decision model."""
    alert_id: str
    decision: str
    reasoning: str
    confidence: float
    organizational_context: Dict[str, Any]
    policy_compliance: bool
    timestamp: datetime = Field(default_factory=datetime.now)
