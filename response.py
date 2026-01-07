import uuid
import hashlib
from datetime import datetime
from typing import Dict, Any, List
from sqlalchemy import select
from enum import Enum
from database import async_session_maker, ResponseActionModel, IncidentModel, AuditTrailModel, AlertModel
from config import settings

def _hash_record(data: Dict[str, Any], prev_hash: str = "") -> str:
    s = prev_hash + str(sorted(data.items()))
    return hashlib.sha256(s.encode()).hexdigest()

class ResponseManager:
    async def execute(self, alert: Dict[str, Any], investigation: Dict[str, Any], decision: Dict[str, Any]) -> Dict[str, Any]:
        severity_value = investigation.get("risk_score", 0.0)
        actions: List[Dict[str, Any]] = []
        if severity_value < settings.severity_threshold:
            actions.extend([
                {"type": "isolate_component", "target": alert.get("hostname") or alert.get("ip_address"), "details": "isolated component"},
                {"type": "automated_remediation", "target": alert.get("hostname") or alert.get("ip_address"), "details": "remediation started"},
            ])
        else:
            actions.extend([
                {"type": "terminate_sessions", "target": alert.get("user_id"), "details": "sessions terminated"},
                {"type": "logout_user", "target": alert.get("user_id"), "details": "user logged out"},
                {"type": "quarantine_asset", "target": alert.get("hostname") or alert.get("ip_address"), "details": "asset quarantined"},
                {"type": "trigger_protocol", "target": settings.protocol_id, "details": "emergency protocol triggered"},
            ])
        report = await self._persist(alert, investigation, decision, actions)
        return {"actions": actions, "incident_id": report["incident_id"]}

    async def _persist(self, alert: Dict[str, Any], investigation: Dict[str, Any], decision: Dict[str, Any], actions: List[Dict[str, Any]]) -> Dict[str, Any]:
        timestamp = datetime.now().strftime(settings.timestamp_format)
        forensic = {
            "timestamp": timestamp,
            "ip_address": alert.get("ip_address"),
            "username": alert.get("user_id"),
            "threat_type": alert.get("alert_type"),
        }
        incident_id = str(uuid.uuid4())
        def _sanitize(obj):
            if isinstance(obj, datetime):
                return obj.isoformat()
            if isinstance(obj, Enum):
                return obj.value
            if isinstance(obj, dict):
                return {k: _sanitize(v) for k, v in obj.items()}
            if isinstance(obj, list):
                return [_sanitize(v) for v in obj]
            return obj
        async with async_session_maker() as session:
            incident = IncidentModel(
                id=incident_id,
                alert_id=alert.get("id"),
                severity=investigation.get("risk_score"),
                report_format=settings.report_format,
                report_content={
                    "alert": _sanitize(alert),
                    "investigation": _sanitize(investigation),
                    "decision": _sanitize(decision),
                    "actions": _sanitize(actions),
                    "forensic": forensic,
                    "security_standard": settings.security_standard,
                },
                forensic_data=forensic,
            )
            session.add(incident)
            prev = ""
            for a in actions:
                ra = ResponseActionModel(
                    id=str(uuid.uuid4()),
                    alert_id=alert.get("id"),
                    action_type=a["type"],
                    target=a["target"],
                    status="executed",
                    timestamp=datetime.now(),
                    details=a["details"],
                )
                session.add(ra)
                h = _hash_record({
                    "incident_id": incident_id,
                    "action_id": ra.id,
                    "type": a["type"],
                    "target": a["target"],
                    "timestamp": timestamp,
                }, prev)
                at = AuditTrailModel(
                    id=str(uuid.uuid4()),
                    entity_type="response_action",
                    entity_id=ra.id,
                    hash=h,
                    prev_hash=prev,
                    created_at=datetime.now(),
                )
                session.add(at)
                prev = h
            await session.commit()
        return {"incident_id": incident_id}
