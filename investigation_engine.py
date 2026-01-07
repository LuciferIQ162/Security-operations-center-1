"""Autonomous investigation engine."""
import uuid
import asyncio
from datetime import datetime
from typing import List, Dict, Any, Optional
from models import Alert, InvestigationResult, InvestigationStatus, ThreatSeverity, AlertType
from database import InvestigationModel, async_session_maker
from sqlalchemy import select
import httpx
from config import settings


class InvestigationEngine:
    """Autonomous investigation engine that reasons through security alerts."""
    
    def __init__(self):
        self.data_sources = {
            "edr": settings.edr_endpoint,
            "siem": settings.siem_endpoint,
            "threat_intel": settings.threat_intel_endpoint,
        }
        self.http_client = httpx.AsyncClient(timeout=30.0)
    
    async def investigate_alert(self, alert: Alert) -> InvestigationResult:
        """Autonomously investigate an alert."""
        investigation_id = str(uuid.uuid4())
        
        # Create investigation result
        investigation = InvestigationResult(
            alert_id=alert.id,
            status=InvestigationStatus.IN_PROGRESS,
            started_at=datetime.now(),
        )
        
        # Add initial timeline entry
        investigation.investigation_timeline.append({
            "timestamp": datetime.now().isoformat(),
            "action": "investigation_started",
            "details": f"Starting investigation for {alert.alert_type.value} alert",
        })
        
        # Query multiple data sources in parallel
        findings = await self._query_data_sources(alert, investigation)
        investigation.findings = findings
        
        # Correlate with other alerts
        correlated_alerts = await self._correlate_alerts(alert)
        investigation.correlated_alerts = correlated_alerts
        
        # Extract threat indicators
        threat_indicators = await self._extract_threat_indicators(alert, findings)
        investigation.threat_indicators = threat_indicators
        
        # Apply organizational context
        context = await self._apply_organizational_context(alert, findings)
        
        # Reason through attack scenarios
        reasoning_result = await self._reason_through_scenarios(alert, findings, context)
        investigation.reasoning = reasoning_result["reasoning"]
        investigation.risk_score = reasoning_result["risk_score"]
        investigation.confidence = reasoning_result["confidence"]
        investigation.business_impact = reasoning_result.get("business_impact")
        
        # Update timeline
        investigation.investigation_timeline.append({
            "timestamp": datetime.now().isoformat(),
            "action": "investigation_completed",
            "details": f"Investigation completed with risk score: {investigation.risk_score}",
        })
        
        # Mark as completed
        investigation.status = InvestigationStatus.COMPLETED
        investigation.completed_at = datetime.now()
        
        # Store investigation
        await self._store_investigation(investigation)
        
        return investigation
    
    async def _query_data_sources(self, alert: Alert, investigation: InvestigationResult) -> List[Dict[str, Any]]:
        """Query multiple data sources in parallel."""
        tasks = []
        
        # Query EDR
        if alert.alert_type == AlertType.EDR or alert.hostname:
            tasks.append(self._query_edr(alert))
        
        # Query SIEM
        tasks.append(self._query_siem(alert))
        
        # Query Threat Intelligence
        if alert.ip_address or alert.hostname:
            tasks.append(self._query_threat_intel(alert))
        
        # Execute queries in parallel
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        findings = []
        for result in results:
            if isinstance(result, Exception):
                investigation.investigation_timeline.append({
                    "timestamp": datetime.now().isoformat(),
                    "action": "data_source_error",
                    "details": str(result),
                })
            else:
                findings.extend(result)
        
        return findings
    
    async def _query_edr(self, alert: Alert) -> List[Dict[str, Any]]:
        """Query EDR system."""
        try:
            # Placeholder for actual EDR integration
            # In production, this would make real API calls
            response = await self.http_client.get(
                f"{self.data_sources['edr']}/query",
                params={
                    "hostname": alert.hostname,
                    "user_id": alert.user_id,
                    "timeframe": "24h",
                }
            )
            if response.status_code == 200:
                return response.json().get("results", [])
        except Exception as e:
            # Fallback to mock data for demonstration
            pass
        
        # Mock data for demonstration
        return [
            {
                "source": "edr",
                "type": "process_activity",
                "details": f"Recent process activity on {alert.hostname or 'unknown host'}",
                "timestamp": datetime.now().isoformat(),
            }
        ]
    
    async def _query_siem(self, alert: Alert) -> List[Dict[str, Any]]:
        """Query SIEM system."""
        try:
            response = await self.http_client.get(
                f"{self.data_sources['siem']}/query",
                params={
                    "alert_id": alert.id,
                    "timeframe": "7d",
                }
            )
            if response.status_code == 200:
                return response.json().get("results", [])
        except Exception:
            pass
        
        # Mock data
        return [
            {
                "source": "siem",
                "type": "log_correlation",
                "details": "Correlated log entries found",
                "timestamp": datetime.now().isoformat(),
            }
        ]
    
    async def _query_threat_intel(self, alert: Alert) -> List[Dict[str, Any]]:
        """Query threat intelligence feeds."""
        try:
            response = await self.http_client.get(
                f"{self.data_sources['threat_intel']}/lookup",
                params={
                    "ip": alert.ip_address,
                    "hostname": alert.hostname,
                }
            )
            if response.status_code == 200:
                return response.json().get("results", [])
        except Exception:
            pass
        
        # Mock data
        return [
            {
                "source": "threat_intel",
                "type": "reputation_check",
                "details": "No known threats found",
                "timestamp": datetime.now().isoformat(),
            }
        ]
    
    async def _correlate_alerts(self, alert: Alert) -> List[str]:
        """Correlate alert with other similar alerts."""
        # In production, this would query the database for similar alerts
        # based on user_id, hostname, IP, time window, etc.
        correlated = []
        
        # Placeholder logic
        if alert.user_id:
            # Find other alerts for same user in last 24 hours
            pass
        
        return correlated
    
    async def _extract_threat_indicators(self, alert: Alert, findings: List[Dict[str, Any]]) -> List[str]:
        """Extract threat indicators from alert and findings."""
        indicators = []
        
        # Extract from alert
        if alert.ip_address:
            indicators.append(f"IP: {alert.ip_address}")
        if alert.hostname:
            indicators.append(f"Hostname: {alert.hostname}")
        if alert.user_id:
            indicators.append(f"User: {alert.user_id}")
        
        # Extract from findings
        for finding in findings:
            if "ioc" in finding:
                indicators.append(finding["ioc"])
            if "hash" in finding:
                indicators.append(f"Hash: {finding['hash']}")
        
        return indicators
    
    async def _apply_organizational_context(self, alert: Alert, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Apply organizational context to investigation."""
        context = {
            "user_role": "standard",  # Would come from identity system
            "host_criticality": "medium",  # Would come from asset management
            "business_unit": "unknown",
            "compliance_requirements": [],
        }
        
        # Enhance context based on alert and findings
        if alert.enriched_data:
            if "user_context" in alert.enriched_data:
                context.update(alert.enriched_data["user_context"])
            if "host_context" in alert.enriched_data:
                context.update(alert.enriched_data["host_context"])
        
        return context
    
    async def _reason_through_scenarios(self, alert: Alert, findings: List[Dict[str, Any]], context: Dict[str, Any]) -> Dict[str, Any]:
        """Reason through potential attack scenarios."""
        # This would use an LLM in production for sophisticated reasoning
        # For now, using rule-based logic with some intelligence
        
        risk_score = 5.0  # Default medium risk
        confidence = 0.7
        reasoning_parts = []
        
        # Analyze alert severity
        if alert.severity == ThreatSeverity.CRITICAL:
            risk_score += 3.0
            reasoning_parts.append("Alert has critical severity rating")
        elif alert.severity == ThreatSeverity.HIGH:
            risk_score += 2.0
            reasoning_parts.append("Alert has high severity rating")
        
        # Analyze findings
        if len(findings) > 3:
            risk_score += 1.0
            reasoning_parts.append(f"Multiple data sources returned {len(findings)} findings")
        
        # Analyze context
        if context.get("host_criticality") == "high":
            risk_score += 1.5
            reasoning_parts.append("Alert involves high-criticality host")
        
        # Analyze threat indicators
        threat_indicators = await self._extract_threat_indicators(alert, findings)
        if len(threat_indicators) > 2:
            risk_score += 1.0
            reasoning_parts.append(f"Multiple threat indicators identified: {len(threat_indicators)}")
        
        # Normalize risk score
        risk_score = min(10.0, max(0.0, risk_score))
        
        # Determine business impact
        business_impact = "Low"
        if risk_score >= 8.0:
            business_impact = "Critical - Immediate action required"
        elif risk_score >= 6.0:
            business_impact = "High - Significant potential impact"
        elif risk_score >= 4.0:
            business_impact = "Medium - Moderate potential impact"
        
        reasoning = " | ".join(reasoning_parts) if reasoning_parts else "Standard investigation completed"
        
        return {
            "risk_score": risk_score,
            "confidence": confidence,
            "reasoning": reasoning,
            "business_impact": business_impact,
        }
    
    async def _store_investigation(self, investigation: InvestigationResult):
        """Store investigation in database."""
        async with async_session_maker() as session:
            investigation_model = InvestigationModel(
                id=str(uuid.uuid4()),
                alert_id=investigation.alert_id,
                status=investigation.status.value,
                findings=investigation.findings,
                correlated_alerts=investigation.correlated_alerts,
                threat_indicators=investigation.threat_indicators,
                risk_score=investigation.risk_score,
                confidence=investigation.confidence,
                reasoning=investigation.reasoning,
                business_impact=investigation.business_impact,
                investigation_timeline=investigation.investigation_timeline,
                started_at=investigation.started_at,
                completed_at=investigation.completed_at,
            )
            session.add(investigation_model)
            await session.commit()
    
    async def get_investigation(self, alert_id: str) -> Optional[InvestigationResult]:
        """Retrieve investigation from database."""
        async with async_session_maker() as session:
            result = await session.execute(
                select(InvestigationModel).where(InvestigationModel.alert_id == alert_id)
            )
            inv_model = result.scalar_one_or_none()
            
            if inv_model:
                return InvestigationResult(
                    alert_id=inv_model.alert_id,
                    status=InvestigationStatus(inv_model.status),
                    findings=inv_model.findings or [],
                    correlated_alerts=inv_model.correlated_alerts or [],
                    threat_indicators=inv_model.threat_indicators or [],
                    risk_score=inv_model.risk_score,
                    confidence=inv_model.confidence,
                    reasoning=inv_model.reasoning,
                    business_impact=inv_model.business_impact,
                    investigation_timeline=inv_model.investigation_timeline or [],
                    started_at=inv_model.started_at,
                    completed_at=inv_model.completed_at,
                )
            return None
