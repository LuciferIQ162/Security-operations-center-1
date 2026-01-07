"""Alert ingestion and classification system."""
import uuid
from datetime import datetime
from typing import Dict, Any, Optional
from models import Alert, AlertType, ThreatSeverity
from database import AlertModel, async_session_maker
from sqlalchemy import select


class AlertProcessor:
    """Processes and classifies incoming security alerts."""
    
    def __init__(self):
        self.alert_patterns = {
            AlertType.EDR: ["endpoint", "edr", "malware", "process", "file"],
            AlertType.PHISHING: ["phishing", "email", "suspicious", "url", "attachment"],
            AlertType.CLOUD_SECURITY: ["cloud", "aws", "azure", "gcp", "s3", "bucket"],
            AlertType.NETWORK: ["network", "firewall", "connection", "traffic", "packet"],
            AlertType.IDENTITY: ["identity", "authentication", "login", "access", "user"],
            AlertType.MALWARE: ["malware", "virus", "trojan", "ransomware", "infection"],
        }
    
    async def ingest_alert(self, raw_alert: Dict[str, Any]) -> Alert:
        """Ingest and process a raw alert."""
        # Generate alert ID
        alert_id = str(uuid.uuid4())
        
        # Classify alert type
        alert_type = self._classify_alert(raw_alert)
        
        # Extract basic information
        title = raw_alert.get("title", raw_alert.get("name", "Untitled Alert"))
        description = raw_alert.get("description", raw_alert.get("message", ""))
        source = raw_alert.get("source", raw_alert.get("system", "unknown"))
        
        # Extract severity if present
        severity = None
        if "severity" in raw_alert:
            try:
                severity = ThreatSeverity(raw_alert["severity"].lower())
            except ValueError:
                pass
        
        # Create alert object
        alert = Alert(
            id=alert_id,
            alert_type=alert_type,
            source=source,
            timestamp=datetime.fromisoformat(raw_alert.get("timestamp", datetime.now().isoformat())),
            raw_data=raw_alert,
            severity=severity,
            title=title,
            description=description,
            user_id=raw_alert.get("user_id"),
            hostname=raw_alert.get("hostname"),
            ip_address=raw_alert.get("ip_address"),
        )
        
        # Enrich alert with additional context
        alert = await self._enrich_alert(alert)
        
        # Store in database
        await self._store_alert(alert)
        
        return alert
    
    def _classify_alert(self, raw_alert: Dict[str, Any]) -> AlertType:
        """Classify alert type based on content."""
        # Combine all text fields for analysis
        text_content = " ".join([
            str(raw_alert.get("title", "")),
            str(raw_alert.get("description", "")),
            str(raw_alert.get("message", "")),
            str(raw_alert.get("type", "")),
            str(raw_alert.get("category", "")),
        ]).lower()
        
        # Check against patterns
        scores = {}
        for alert_type, patterns in self.alert_patterns.items():
            score = sum(1 for pattern in patterns if pattern in text_content)
            scores[alert_type] = score
        
        # Return type with highest score, or UNKNOWN if no match
        if scores:
            max_type = max(scores.items(), key=lambda x: x[1])
            if max_type[1] > 0:
                return max_type[0]
        
        return AlertType.UNKNOWN
    
    async def _enrich_alert(self, alert: Alert) -> Alert:
        """Enrich alert with additional context."""
        enriched_data = {
            "classification_confidence": 0.85,
            "requires_investigation": True,
            "priority": self._calculate_priority(alert),
        }
        
        # Add contextual information
        if alert.user_id:
            enriched_data["user_context"] = await self._get_user_context(alert.user_id)
        
        if alert.hostname:
            enriched_data["host_context"] = await self._get_host_context(alert.hostname)
        
        if alert.ip_address:
            enriched_data["ip_context"] = await self._get_ip_context(alert.ip_address)
        
        alert.enriched_data = enriched_data
        return alert
    
    def _calculate_priority(self, alert: Alert) -> str:
        """Calculate alert priority."""
        if alert.severity == ThreatSeverity.CRITICAL:
            return "immediate"
        elif alert.severity == ThreatSeverity.HIGH:
            return "high"
        elif alert.severity == ThreatSeverity.MEDIUM:
            return "medium"
        else:
            return "low"
    
    async def _get_user_context(self, user_id: str) -> Dict[str, Any]:
        """Get user context (placeholder for integration)."""
        return {
            "role": "unknown",
            "department": "unknown",
            "access_level": "unknown",
        }
    
    async def _get_host_context(self, hostname: str) -> Dict[str, Any]:
        """Get host context (placeholder for integration)."""
        return {
            "os": "unknown",
            "criticality": "unknown",
            "location": "unknown",
        }
    
    async def _get_ip_context(self, ip_address: str) -> Dict[str, Any]:
        """Get IP context (placeholder for integration)."""
        return {
            "geolocation": "unknown",
            "reputation": "unknown",
            "is_internal": False,
        }
    
    async def _store_alert(self, alert: Alert):
        """Store alert in database."""
        async with async_session_maker() as session:
            alert_model = AlertModel(
                id=alert.id,
                alert_type=alert.alert_type.value,
                source=alert.source,
                timestamp=alert.timestamp,
                raw_data=alert.raw_data,
                severity=alert.severity.value if alert.severity else None,
                title=alert.title,
                description=alert.description,
                user_id=alert.user_id,
                hostname=alert.hostname,
                ip_address=alert.ip_address,
                enriched_data=alert.enriched_data,
                processed=False,
            )
            session.add(alert_model)
            await session.commit()
    
    async def get_alert(self, alert_id: str) -> Optional[Alert]:
        """Retrieve alert from database."""
        async with async_session_maker() as session:
            result = await session.execute(
                select(AlertModel).where(AlertModel.id == alert_id)
            )
            alert_model = result.scalar_one_or_none()
            
            if alert_model:
                return Alert(
                    id=alert_model.id,
                    alert_type=AlertType(alert_model.alert_type),
                    source=alert_model.source,
                    timestamp=alert_model.timestamp,
                    raw_data=alert_model.raw_data,
                    severity=ThreatSeverity(alert_model.severity) if alert_model.severity else None,
                    title=alert_model.title,
                    description=alert_model.description,
                    user_id=alert_model.user_id,
                    hostname=alert_model.hostname,
                    ip_address=alert_model.ip_address,
                    enriched_data=alert_model.enriched_data,
                )
            return None
