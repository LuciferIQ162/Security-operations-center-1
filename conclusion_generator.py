"""Actionable conclusions generator."""
from datetime import datetime
from typing import List, Dict, Any
from models import Alert, InvestigationResult, AgentDecision, ActionableConclusion, ThreatSeverity


class ConclusionGenerator:
    """Generates actionable conclusions from investigations."""
    
    def generate_conclusion(
        self,
        alert: Alert,
        investigation: InvestigationResult,
        decision: AgentDecision
    ) -> ActionableConclusion:
        """Generate actionable conclusion."""
        
        # Generate risk assessment
        risk_assessment = self._generate_risk_assessment(investigation)
        
        # Determine threat severity
        threat_severity = self._determine_threat_severity(investigation)
        
        # Generate recommended actions
        recommended_actions = self._generate_recommended_actions(alert, investigation, decision)
        
        # Generate containment steps if needed
        containment_steps = None
        if decision.decision in ["immediate_containment", "escalate_to_analyst"]:
            containment_steps = self._generate_containment_steps(alert, investigation)
        
        # Calculate blast radius
        blast_radius = self._calculate_blast_radius(alert, investigation)
        
        # Generate evidence summary
        evidence_summary = self._generate_evidence_summary(investigation)
        
        # Generate next steps
        next_steps = self._generate_next_steps(decision, investigation)
        
        # Determine if human review is required
        requires_human_review = self._requires_human_review(decision, investigation)
        
        return ActionableConclusion(
            alert_id=alert.id,
            risk_assessment=risk_assessment,
            threat_severity=threat_severity,
            recommended_actions=recommended_actions,
            containment_steps=containment_steps,
            blast_radius=blast_radius,
            evidence_summary=evidence_summary,
            next_steps=next_steps,
            requires_human_review=requires_human_review,
        )
    
    def _generate_risk_assessment(self, investigation: InvestigationResult) -> str:
        """Generate risk assessment text."""
        risk_score = investigation.risk_score
        
        if risk_score >= 8.5:
            assessment = f"CRITICAL RISK ({risk_score:.1f}/10): Immediate threat detected requiring urgent containment. "
        elif risk_score >= 6.5:
            assessment = f"HIGH RISK ({risk_score:.1f}/10): Significant security threat identified. "
        elif risk_score >= 4.5:
            assessment = f"MEDIUM RISK ({risk_score:.1f}/10): Moderate security concern requiring monitoring. "
        elif risk_score >= 2.5:
            assessment = f"LOW RISK ({risk_score:.1f}/10): Minor security event with limited impact. "
        else:
            assessment = f"MINIMAL RISK ({risk_score:.1f}/10): Likely false positive or benign activity. "
        
        assessment += f"Investigation confidence: {investigation.confidence:.1%}. "
        assessment += investigation.reasoning
        
        return assessment
    
    def _determine_threat_severity(self, investigation: InvestigationResult) -> ThreatSeverity:
        """Determine threat severity from investigation."""
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
    
    def _generate_recommended_actions(
        self,
        alert: Alert,
        investigation: InvestigationResult,
        decision: AgentDecision
    ) -> List[str]:
        """Generate recommended actions."""
        actions = []
        
        if decision.decision == "immediate_containment":
            actions.append("Isolate affected systems from network")
            actions.append("Disable compromised user accounts")
            actions.append("Preserve evidence for forensic analysis")
            actions.append("Notify incident response team immediately")
        elif decision.decision == "escalate_to_analyst":
            actions.append("Escalate to senior security analyst for review")
            actions.append("Gather additional context from affected systems")
            actions.append("Monitor for related activity")
        elif decision.decision == "monitor_and_log":
            actions.append("Continue monitoring for similar activity")
            actions.append("Log for trend analysis")
            actions.append("Review in next security assessment")
        elif decision.decision == "close_false_positive":
            actions.append("Close alert as false positive")
            actions.append("Update detection rules to reduce false positives")
        
        # Add investigation-specific actions
        if investigation.correlated_alerts:
            actions.append(f"Review {len(investigation.correlated_alerts)} correlated alerts")
        
        if investigation.threat_indicators:
            actions.append(f"Block {len(investigation.threat_indicators)} identified threat indicators")
        
        return actions
    
    def _generate_containment_steps(
        self,
        alert: Alert,
        investigation: InvestigationResult
    ) -> List[str]:
        """Generate containment steps."""
        steps = []
        
        if alert.hostname:
            steps.append(f"Isolate host {alert.hostname} from network")
        
        if alert.user_id:
            steps.append(f"Disable user account: {alert.user_id}")
        
        if alert.ip_address:
            steps.append(f"Block IP address: {alert.ip_address}")
        
        # Add threat indicator blocking
        for indicator in investigation.threat_indicators[:5]:  # Limit to top 5
            steps.append(f"Block indicator: {indicator}")
        
        steps.append("Preserve system logs and artifacts")
        steps.append("Initiate incident response procedures")
        
        return steps
    
    def _calculate_blast_radius(
        self,
        alert: Alert,
        investigation: InvestigationResult
    ) -> str:
        """Calculate and describe blast radius."""
        affected_entities = []
        
        if alert.hostname:
            affected_entities.append(f"Host: {alert.hostname}")
        if alert.user_id:
            affected_entities.append(f"User: {alert.user_id}")
        if alert.ip_address:
            affected_entities.append(f"IP: {alert.ip_address}")
        
        if investigation.correlated_alerts:
            affected_entities.append(f"{len(investigation.correlated_alerts)} related alerts")
        
        if affected_entities:
            return f"Affected entities: {', '.join(affected_entities)}"
        else:
            return "Blast radius: Limited - single alert with no correlations"
    
    def _generate_evidence_summary(self, investigation: InvestigationResult) -> str:
        """Generate evidence summary."""
        summary_parts = []
        
        summary_parts.append(f"Investigation completed in {len(investigation.investigation_timeline)} steps")
        summary_parts.append(f"Found {len(investigation.findings)} findings from data sources")
        
        if investigation.threat_indicators:
            summary_parts.append(f"Identified {len(investigation.threat_indicators)} threat indicators")
        
        if investigation.correlated_alerts:
            summary_parts.append(f"Correlated with {len(investigation.correlated_alerts)} other alerts")
        
        summary_parts.append(f"Risk assessment: {investigation.risk_score:.1f}/10")
        summary_parts.append(f"Confidence: {investigation.confidence:.1%}")
        
        return " | ".join(summary_parts)
    
    def _generate_next_steps(
        self,
        decision: AgentDecision,
        investigation: InvestigationResult
    ) -> List[str]:
        """Generate next steps."""
        steps = []
        
        if decision.decision == "immediate_containment":
            steps.append("Execute containment procedures")
            steps.append("Begin forensic analysis")
            steps.append("Update threat intelligence feeds")
        elif decision.decision == "escalate_to_analyst":
            steps.append("Wait for analyst review")
            steps.append("Prepare detailed investigation report")
        elif decision.decision == "monitor_and_log":
            steps.append("Continue automated monitoring")
            steps.append("Schedule periodic review")
        else:
            steps.append("Close alert")
            steps.append("Update learning system with outcome")
        
        # Add learning step
        if investigation.risk_score < 3.0:
            steps.append("Mark as false positive for learning system")
        
        return steps
    
    def _requires_human_review(
        self,
        decision: AgentDecision,
        investigation: InvestigationResult
    ) -> bool:
        """Determine if human review is required."""
        # Require human review for high-risk decisions
        if investigation.risk_score >= 7.0:
            return True
        
        # Require human review if confidence is low
        if investigation.confidence < 0.6:
            return True
        
        # Require human review for escalation decisions
        if decision.decision == "escalate_to_analyst":
            return True
        
        return False
