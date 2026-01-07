"""Database models and session management."""
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import declarative_base
from sqlalchemy import Column, String, DateTime, Float, Integer, JSON, Boolean, Text
from datetime import datetime
from config import settings

Base = declarative_base()


class AlertModel(Base):
    """Alert database model."""
    __tablename__ = "alerts"
    
    id = Column(String, primary_key=True)
    alert_type = Column(String, nullable=False)
    source = Column(String, nullable=False)
    timestamp = Column(DateTime, default=datetime.now)
    raw_data = Column(JSON)
    severity = Column(String)
    title = Column(String)
    description = Column(Text)
    user_id = Column(String)
    hostname = Column(String)
    ip_address = Column(String)
    enriched_data = Column(JSON)
    processed = Column(Boolean, default=False)


class InvestigationModel(Base):
    """Investigation database model."""
    __tablename__ = "investigations"
    
    id = Column(String, primary_key=True)
    alert_id = Column(String, nullable=False)
    status = Column(String, nullable=False)
    findings = Column(JSON)
    correlated_alerts = Column(JSON)
    threat_indicators = Column(JSON)
    risk_score = Column(Float)
    confidence = Column(Float)
    reasoning = Column(Text)
    business_impact = Column(Text)
    investigation_timeline = Column(JSON)
    started_at = Column(DateTime, default=datetime.now)
    completed_at = Column(DateTime)


class LearningModel(Base):
    """Learning outcomes database model."""
    __tablename__ = "learning_outcomes"
    
    id = Column(String, primary_key=True)
    alert_id = Column(String)
    investigation_id = Column(String)
    outcome = Column(String)  # true_positive, false_positive, etc.
    feedback = Column(Text)
    patterns_learned = Column(JSON)
    timestamp = Column(DateTime, default=datetime.now)

class UserModel(Base):
    """Admin user model."""
    __tablename__ = "users"
    id = Column(String, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    email = Column(String, unique=True)
    role = Column(String, default="user")
    hashed_password = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.now)
    failed_login_attempts = Column(Integer, default=0)
    last_failed_login_at = Column(DateTime)
    locked_until = Column(DateTime)

class AccessLogModel(Base):
    """Access logs for admin auditing."""
    __tablename__ = "access_logs"
    id = Column(String, primary_key=True)
    user_id = Column(String, nullable=False)
    username = Column(String, nullable=False)
    ip_address = Column(String)
    success = Column(Boolean, default=False)
    timestamp = Column(DateTime, default=datetime.now)
    reason = Column(Text)

class ResponseActionModel(Base):
    __tablename__ = "response_actions"
    id = Column(String, primary_key=True)
    alert_id = Column(String, nullable=False)
    action_type = Column(String, nullable=False)
    target = Column(String)
    status = Column(String, default="executed")
    timestamp = Column(DateTime, default=datetime.now)
    details = Column(Text)

class IncidentModel(Base):
    __tablename__ = "incidents"
    id = Column(String, primary_key=True)
    alert_id = Column(String, nullable=False)
    severity = Column(Float, default=0.0)
    report_format = Column(String, default="json")
    report_content = Column(JSON)
    forensic_data = Column(JSON)
    created_at = Column(DateTime, default=datetime.now)

class AuditTrailModel(Base):
    __tablename__ = "audit_trail"
    id = Column(String, primary_key=True)
    entity_type = Column(String, nullable=False)
    entity_id = Column(String, nullable=False)
    hash = Column(String, nullable=False)
    prev_hash = Column(String)
    created_at = Column(DateTime, default=datetime.now)

# Database engine and session
engine = create_async_engine(settings.database_url, echo=False)
async_session_maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def init_db():
    """Initialize database tables."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_db() -> AsyncSession:
    """Get database session."""
    async with async_session_maker() as session:
        try:
            yield session
        finally:
            await session.close()
