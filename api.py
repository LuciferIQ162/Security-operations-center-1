"""FastAPI application for AI SOC Agent."""
from fastapi import FastAPI, HTTPException, BackgroundTasks, Request, Response, Depends
from fastapi.middleware.cors import CORSMiddleware
from typing import Dict, Any, Optional
from pydantic import BaseModel
from agent import AISOCAgent
from database import init_db, async_session_maker, AlertModel, InvestigationModel, UserModel, AccessLogModel, ResponseActionModel, IncidentModel
from config import settings
import asyncio
from sqlalchemy import select, desc
from auth import (
    hash_password,
    verify_password,
    create_session_token,
    decode_session_token,
    generate_csrf_token,
    validate_csrf,
    rate_limit_login,
)
import uuid
from response import ResponseManager
from decision_maker import DecisionMaker
from models import Alert, InvestigationResult

app = FastAPI(
    title="AI SOC Agent API",
    description="Autonomous AI Security Operations Center Agent",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize agent
agent = AISOCAgent()


@app.on_event("startup")
async def startup_event():
    """Initialize database on startup."""
    await init_db()
    # Bootstrap admin user if none exists and env provided
    async with async_session_maker() as session:
        res = await session.execute(select(UserModel).limit(1))
        exists = res.scalar_one_or_none()
        if not exists and settings.bootstrap_admin_username and settings.bootstrap_admin_password:
            admin = UserModel(
                id=str(uuid.uuid4()),
                username=settings.bootstrap_admin_username,
                email=settings.bootstrap_admin_email or "",
                role="admin",
                hashed_password=hash_password(settings.bootstrap_admin_password),
            )
            session.add(admin)
            await session.commit()

def set_secure_cookie(response: Response, name: str, value: str, max_age: int = 1800):
    response.set_cookie(
        key=name,
        value=value,
        max_age=max_age,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="strict",
        path="/",
    )

def set_csrf_cookie(response: Response, token: str):
    response.set_cookie(
        key="csrf_token",
        value=token,
        max_age=settings.session_exp_minutes * 60,
        httponly=False,
        secure=settings.cookie_secure,
        samesite="strict",
        path="/",
    )

async def get_current_admin(request: Request) -> Dict[str, Any]:
    cookie = request.cookies.get("session")
    if not cookie:
        raise HTTPException(status_code=401, detail="Not authenticated")
    payload = decode_session_token(cookie)
    if payload.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin required")
    return payload

# Request/Response Models
class AlertRequest(BaseModel):
    """Alert ingestion request."""
    title: Optional[str] = None
    description: Optional[str] = None
    source: str
    alert_type: Optional[str] = None
    severity: Optional[str] = None
    user_id: Optional[str] = None
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    timestamp: Optional[str] = None
    raw_data: Optional[Dict[str, Any]] = None


class FeedbackRequest(BaseModel):
    """Feedback request for learning."""
    outcome: str  # "true_positive", "false_positive", etc.
    feedback: Optional[str] = None

class LoginRequest(BaseModel):
    username: str
    password: str
    
class MonitorAlertRequest(BaseModel):
    server_name: Optional[str] = None
    device_id: Optional[str] = None
    network_segment: Optional[str] = None
    website_url: Optional[str] = None
    user_id: Optional[str] = None
    ip_address: Optional[str] = None
    alert_type: Optional[str] = None
    severity: Optional[str] = None
    threat_type: Optional[str] = None


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "message": "AI SOC Agent API",
        "version": "1.0.0",
        "status": "operational"
    }


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy"}

@app.get("/auth/csrf")
async def get_csrf():
    token = generate_csrf_token()
    response = Response(content="OK")
    set_csrf_cookie(response, token)
    return response

@app.post("/auth/login")
async def login(request: Request, creds: LoginRequest):
    ip = request.client.host if request.client else "unknown"
    rate_limit_login(ip)
    async with async_session_maker() as session:
        user_res = await session.execute(select(UserModel).where(UserModel.username == creds.username))
        user = user_res.scalar_one_or_none()
        success = False
        reason = ""
        if settings.bootstrap_admin_username and settings.bootstrap_admin_password:
            if creds.username == settings.bootstrap_admin_username and creds.password == settings.bootstrap_admin_password:
                success = True
                if not user:
                    user = UserModel(
                        id=str(uuid.uuid4()),
                        username=creds.username,
                        email=settings.bootstrap_admin_email or "",
                        role="admin",
                        hashed_password=hash_password(creds.password),
                    )
                    session.add(user)
            else:
                reason = "invalid_credentials_or_role"
        elif user:
            if user.locked_until and user.locked_until > datetime.now():
                reason = "account_locked"
            elif verify_password(creds.password, user.hashed_password) and user.role == "admin":
                success = True
            else:
                reason = "invalid_credentials_or_role"
        else:
            reason = "user_not_found"
        # log access
        log = AccessLogModel(
            id=str(uuid.uuid4()),
            user_id=(user.id if user else "unknown"),
            username=creds.username,
            ip_address=ip,
            success=success,
            reason=reason,
        )
        session.add(log)
        # update failed attempts
        if user and not success:
            user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
            user.last_failed_login_at = datetime.now()
            if user.failed_login_attempts >= 5:
                from datetime import timedelta
                user.locked_until = datetime.now() + timedelta(minutes=15)
        elif user and success:
            user.failed_login_attempts = 0
            user.locked_until = None
        await session.commit()
        if not success:
            raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_session_token(user.id, user.role)
    csrf = generate_csrf_token()
    response = Response(content="OK")
    set_secure_cookie(response, "session", token, max_age=settings.session_exp_minutes * 60)
    set_csrf_cookie(response, csrf)
    return response

@app.post("/auth/logout")
async def logout(request: Request):
    validate_csrf(request)
    response = Response(content="OK")
    response.delete_cookie("session", path="/")
    response.delete_cookie("csrf_token", path="/")
    return response

@app.get("/auth/me")
async def me(payload: Dict[str, Any] = Depends(get_current_admin)):
    return {"user_id": payload["sub"], "role": payload["role"]}

@app.post("/alerts", response_model=Dict[str, Any])
async def ingest_alert(alert_request: AlertRequest, background: BackgroundTasks = None):
    """
    Ingest and process a security alert.
    
    The agent will:
    1. Classify the alert
    2. Investigate autonomously
    3. Make contextual decisions
    4. Generate actionable conclusions
    """
    try:
        # Convert request to dict
        raw_alert = alert_request.dict(exclude_none=True)
        
        # Process alert
        result = await agent.process_alert(raw_alert)
        
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/alerts/async", response_model=Dict[str, str])
async def ingest_alert_async(alert_request: AlertRequest):
    """
    Ingest alert asynchronously.
    
    Returns immediately with alert ID. Use /alerts/{alert_id} to check status.
    """
    try:
        raw_alert = alert_request.dict(exclude_none=True)
        alert_id = await agent.process_alert_async(raw_alert)
        return {"alert_id": alert_id, "status": "processing"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/alerts/{alert_id}", response_model=Dict[str, Any])
async def get_alert_result(alert_id: str):
    """Get the result of a processed alert."""
    result = await agent.get_alert_result(alert_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return result


@app.get("/alerts")
async def list_alerts():
    async with async_session_maker() as session:
        result = await session.execute(
            select(AlertModel).order_by(desc(AlertModel.timestamp)).limit(20)
        )
        alerts = []
        for a in result.scalars().all():
            status = "pending"
            inv = await session.execute(
                select(InvestigationModel).where(InvestigationModel.alert_id == a.id)
            )
            inv_model = inv.scalar_one_or_none()
            if inv_model:
                status = "resolved" if inv_model.status == "completed" else "investigating"
            alerts.append({
                "id": a.id,
                "title": a.title or "Alert",
                "type": a.alert_type,
                "severity": (a.severity or "low"),
                "status": status,
                "timestamp": a.timestamp.isoformat(),
                "hostname": a.hostname,
            })
        return {"items": alerts}


@app.get("/investigations")
async def list_investigations():
    async with async_session_maker() as session:
        result = await session.execute(
            select(InvestigationModel).order_by(desc(InvestigationModel.started_at)).limit(20)
        )
        items = []
        for inv in result.scalars().all():
            alert_res = await session.execute(
                select(AlertModel).where(AlertModel.id == inv.alert_id)
            )
            alert = alert_res.scalar_one_or_none()
            duration = None
            if inv.started_at and inv.completed_at:
                delta = inv.completed_at - inv.started_at
                mins = int(delta.total_seconds() // 60)
                secs = int(delta.total_seconds() % 60)
                duration = f"{mins}m {secs}s"
            items.append({
                "alertId": inv.alert_id,
                "title": (alert.title if alert and alert.title else "Investigation"),
                "currentStage": ("decision" if inv.status == "completed" else "investigation"),
                "riskScore": inv.risk_score or 0,
                "duration": duration or "",
                "findings": len(inv.findings or []),
            })
        return {"items": items}


@app.get("/activity")
async def recent_activity():
    async with async_session_maker() as session:
        inv_res = await session.execute(
            select(InvestigationModel).order_by(desc(InvestigationModel.started_at)).limit(10)
        )
        activities = []
        for inv in inv_res.scalars().all():
            for i, step in enumerate(inv.investigation_timeline or []):
                t = step.get("action")
                msg = step.get("details") or t
                map_type = {
                    "investigation_started": "investigation_started",
                    "investigation_completed": "conclusion_generated",
                    "data_source_error": "finding_discovered",
                }.get(t, "finding_discovered")
                activities.append({
                    "id": f"{inv.alert_id}-{i}",
                    "type": map_type,
                    "message": msg,
                    "timestamp": step.get("timestamp"),
                })
        alert_res = await session.execute(
            select(AlertModel).order_by(desc(AlertModel.timestamp)).limit(5)
        )
        for a in alert_res.scalars().all():
            activities.append({
                "id": f"ingest-{a.id}",
                "type": "alert_ingested",
                "message": f"Ingested alert: {a.title or a.id}",
                "timestamp": a.timestamp.isoformat(),
            })
        activities.sort(key=lambda x: x["timestamp"], reverse=True)
        return {"items": activities[:20]}

@app.get("/incidents")
async def list_incidents(payload: Dict[str, Any] = Depends(get_current_admin)):
    async with async_session_maker() as session:
        res = await session.execute(select(InvestigationModel))
        inv_by_alert = {i.alert_id: i for i in res.scalars().all()}
        res2 = await session.execute(select(AlertModel))
        alerts_by_id = {a.id: a for a in res2.scalars().all()}
        res3 = await session.execute(select(AccessLogModel).order_by(desc(AccessLogModel.timestamp)).limit(50))
        access_logs = [
            {
                "username": l.username,
                "ip_address": l.ip_address,
                "timestamp": l.timestamp.isoformat(),
                "success": l.success,
                "reason": l.reason,
            } for l in res3.scalars().all()
        ]
        from sqlalchemy import select as s
        res4 = await session.execute(s(ResponseActionModel))
        actions = [
            {
                "action_type": a.action_type,
                "target": a.target,
                "status": a.status,
                "timestamp": a.timestamp.isoformat(),
                "details": a.details,
                "alert_id": a.alert_id,
            } for a in res4.scalars().all()
        ]
        from sqlalchemy import select as s2
        res5 = await session.execute(s2(IncidentModel).order_by(desc(IncidentModel.created_at)).limit(50))
        incidents = []
        for inc in res5.scalars().all():
            al = alerts_by_id.get(inc.alert_id)
            inv = inv_by_alert.get(inc.alert_id)
            incidents.append({
                "id": inc.id,
                "alert_id": inc.alert_id,
                "title": al.title if al else "",
                "severity": inc.severity,
                "created_at": inc.created_at.isoformat(),
                "findings": len(inv.findings if inv else []),
            })
        return {"incidents": incidents, "actions": actions, "access_logs": access_logs}

@app.post("/respond/{alert_id}/replay")
async def replay_response(alert_id: str, payload: Dict[str, Any] = Depends(get_current_admin)):
    async with async_session_maker() as session:
        res = await session.execute(select(AlertModel).where(AlertModel.id == alert_id))
        alert = res.scalar_one_or_none()
        res2 = await session.execute(select(InvestigationModel).where(InvestigationModel.alert_id == alert_id))
        inv = res2.scalar_one_or_none()
        if not alert or not inv:
            raise HTTPException(status_code=404, detail="Alert or investigation not found")
        alert_dict = {
            "id": alert.id,
            "alert_type": alert.alert_type,
            "source": alert.source,
            "timestamp": alert.timestamp.isoformat() if alert.timestamp else None,
            "raw_data": alert.raw_data or {},
            "severity": alert.severity,
            "title": alert.title or "",
            "description": alert.description or "",
            "user_id": alert.user_id,
            "hostname": alert.hostname,
            "ip_address": alert.ip_address,
            "enriched_data": alert.enriched_data or {},
        }
        inv_dict = {
            "alert_id": inv.alert_id,
            "status": inv.status,
            "findings": inv.findings or [],
            "correlated_alerts": inv.correlated_alerts or [],
            "threat_indicators": inv.threat_indicators or [],
            "risk_score": inv.risk_score or 0.0,
            "confidence": inv.confidence or 0.0,
            "reasoning": inv.reasoning or "",
            "business_impact": inv.business_impact,
            "investigation_timeline": inv.investigation_timeline or [],
            "started_at": inv.started_at.isoformat() if inv.started_at else None,
            "completed_at": inv.completed_at.isoformat() if inv.completed_at else None,
        }
        dm = DecisionMaker()
        dec = dm.make_decision(Alert(**alert_dict), InvestigationResult(**inv_dict))
        rm = ResponseManager()
        out = await rm.execute(alert_dict, inv_dict, dec.dict())
        return out

@app.post("/monitor/alert")
async def monitor_alert(req: MonitorAlertRequest):
    raw = {
        "title": f"Threat detected on {req.server_name or req.device_id or req.network_segment or req.website_url}",
        "description": f"Detected threat type {req.threat_type or 'unknown'}",
        "source": "monitor",
        "alert_type": req.alert_type or "network",
        "severity": req.severity or "high",
        "user_id": req.user_id,
        "hostname": req.server_name or req.device_id,
        "ip_address": req.ip_address,
        "raw_data": {
            "server_name": req.server_name,
            "device_id": req.device_id,
            "network_segment": req.network_segment,
            "website_url": req.website_url,
            "threat_type": req.threat_type,
        }
    }
    result = await agent.process_alert(raw)
    return result
@app.post("/alerts/{alert_id}/feedback", response_model=Dict[str, Any])
async def submit_feedback(alert_id: str, feedback_request: FeedbackRequest):
    """
    Submit feedback on an alert investigation.
    
    This helps the learning system improve over time.
    """
    try:
        result = await agent.record_feedback(
            alert_id,
            feedback_request.outcome,
            feedback_request.feedback
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/stats", response_model=Dict[str, Any])
async def get_agent_stats():
    """Get agent statistics and performance metrics."""
    stats = await agent.get_agent_stats()
    return stats


@app.get("/capabilities")
async def get_capabilities():
    """Get agent capabilities."""
    return {
        "capabilities": [
            "Alert Triage & Investigation",
            "Threat Intelligence Integration",
            "Incident Response Support",
            "Continuous Learning",
            "Autonomous Decision Making",
            "Contextual Risk Assessment",
        ],
        "features": [
            "Automatic alert classification",
            "Parallel data source queries",
            "Cross-platform correlation",
            "False positive reduction",
            "Adaptive risk scoring",
            "Actionable recommendations",
        ],
        "autonomy_level": settings.agent_autonomy_level,
        "learning_enabled": settings.learning_enabled,
    }


# Example alert endpoint for testing
@app.post("/alerts/example")
async def create_example_alert():
    """Create an example alert for testing."""
    example_alert = {
        "title": "Suspicious Process Execution Detected",
        "description": "Unusual process activity detected on endpoint",
        "source": "edr",
        "alert_type": "edr",
        "severity": "high",
        "user_id": "user123",
        "hostname": "workstation-01",
        "ip_address": "192.168.1.100",
        "raw_data": {
            "process_name": "suspicious.exe",
            "command_line": "suspicious.exe --stealth",
            "parent_process": "explorer.exe",
        }
    }
    
    result = await agent.process_alert(example_alert)
    return result


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=settings.host, port=settings.port)
