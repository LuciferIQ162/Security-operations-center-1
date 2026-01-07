"""Contextual decision-making system."""
from datetime import datetime
from typing import Dict, Any, Optional
from models import Alert, InvestigationResult, AgentDecision, ThreatSeverity
from config import settings


class DecisionMaker:
    """Makes contextual decisions based on investigation results."""
    
    def __init__(self):
        self.organizational_policies = self._load_policies()
    
    def make_decision(self, alert: Alert, investigation: InvestigationResult) -> AgentDecision:
        """Make a decision about how to handle the alert."""
        
        # Assess threat severity
        threat_severity = self._assess_threat_severity(investigation)
        
        # Check policy compliance
        policy_compliance = self._check_policy_compliance(alert, investigation)
        
        # Determine action
        decision = self._determine_action(alert, investigation, threat_severity)
        
        # Generate reasoning
        reasoning = self._generate_reasoning(alert, investigation, decision, policy_compliance)
        
        # Calculate confidence
        confidence = self._calculate_confidence(investigation, policy_compliance)
        
        # Get organizational context
        org_context = self._get_organizational_context(alert, investigation)
        
        return AgentDecision(
            alert_id=alert.id,
            decision=decision,
            reasoning=reasoning,
            confidence=confidence,
            organizational_context=org_context,
            policy_compliance=policy_compliance,
            timestamp=datetime.now(),
        )
    
    def _assess_threat_severity(self, investigation: InvestigationResult) -> ThreatSeverity:
        """Assess threat severity based on investigation."""
        risk_score = investigation.risk_score
        
        if risk_score >= 8.5:
            return ThreatSeverity.CRITICAL
        elif risk_score >= 6.5:
            return ThreatSeverity.HIGH
        elif risk_score >= 4.5:
            return ThreatSeverity.MEDIUM
        elif risk_score >= 2.5:
            return ThreatSeverity.LOW
        else:
            return ThreatSeverity.FALSE_POSITIVE
    
    def _check_policy_compliance(self, alert: Alert, investigation: InvestigationResult) -> bool:
        """Check if alert handling complies with organizational policies."""
        # Check various policy aspects
        compliance_checks = []
        
        # Check if investigation was thorough enough
        if len(investigation.findings) >= 2:
            compliance_checks.append(True)
        else:
            compliance_checks.append(False)
        
        # Check if risk assessment was performed
        if investigation.risk_score is not None:
            compliance_checks.append(True)
        else:
            compliance_checks.append(False)
        
        # Check if reasoning was provided
        if investigation.reasoning:
            compliance_checks.append(True)
        else:
            compliance_checks.append(False)
        
        return all(compliance_checks)
    
    def _determine_action(self, alert: Alert, investigation: InvestigationResult, threat_severity: ThreatSeverity) -> str:
        """Determine what action to take."""
        risk_score = investigation.risk_score
        
        if threat_severity == ThreatSeverity.CRITICAL:
            return "immediate_containment"
        elif threat_severity == ThreatSeverity.HIGH:
            return "escalate_to_analyst"
        elif threat_severity == ThreatSeverity.MEDIUM:
            return "monitor_and_log"
        elif threat_severity == ThreatSeverity.LOW:
            return "close_with_note"
        else:  # FALSE_POSITIVE
            return "close_false_positive"
    
    def _generate_reasoning(self, alert: Alert, investigation: InvestigationResult, decision: str, policy_compliance: bool) -> str:
        """Generate human-readable reasoning for the decision."""
        reasoning_parts = []
        
        reasoning_parts.append(f"Investigation found {len(investigation.findings)} findings")
        reasoning_parts.append(f"Risk score: {investigation.risk_score:.2f}/10")
        reasoning_parts.append(f"Confidence: {investigation.confidence:.2%}")
        
        if investigation.correlated_alerts:
            reasoning_parts.append(f"Correlated with {len(investigation.correlated_alerts)} other alerts")
        
        if investigation.business_impact:
            reasoning_parts.append(f"Business impact: {investigation.business_impact}")
        
        if policy_compliance:
            reasoning_parts.append("Decision complies with organizational policies")
        else:
            reasoning_parts.append("Warning: Some policy compliance checks failed")
        
        reasoning_parts.append(f"Recommended action: {decision}")
        
        return " | ".join(reasoning_parts)
    
    def _calculate_confidence(self, investigation: InvestigationResult, policy_compliance: bool) -> float:
        """Calculate confidence in the decision."""
        # Base confidence from investigation
        confidence = investigation.confidence
        
        # Adjust based on policy compliance
        if policy_compliance:
            confidence = min(1.0, confidence + 0.1)
        else:
            confidence = max(0.0, confidence - 0.2)
        
        # Adjust based on number of findings
        if len(investigation.findings) >= 3:
            confidence = min(1.0, confidence + 0.1)
        elif len(investigation.findings) == 0:
            confidence = max(0.0, confidence - 0.2)
        
        return confidence
    
    def _get_organizational_context(self, alert: Alert, investigation: InvestigationResult) -> Dict[str, Any]:
        """Get organizational context for the decision."""
        return {
            "autonomy_level": settings.agent_autonomy_level,
            "policies_applied": list(self.organizational_policies.keys()),
            "business_impact": investigation.business_impact,
            "requires_escalation": investigation.risk_score >= 7.0,
        }
    
    def _load_policies(self) -> Dict[str, Any]:
        """Load organizational security policies."""
        # In production, this would load from a policy management system
        return {
            "minimum_investigation_depth": 2,
            "auto_contain_threshold": 8.5,
            "escalation_threshold": 6.5,
            "false_positive_threshold": 2.5,
            "data_retention_days": 90,
        }
