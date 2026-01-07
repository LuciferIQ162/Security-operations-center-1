"""Configuration management for AI SOC Agent."""
import os
from typing import Optional
from dotenv import load_dotenv

load_dotenv()


class Settings:
    """Application settings."""
    
    def __init__(self):
        # API Keys
        self.openai_api_key: str = os.getenv("OPENAI_API_KEY", "")
        self.secret_key: str = os.getenv("SECRET_KEY", "change_me")
        self.session_exp_minutes: int = int(os.getenv("SESSION_EXP_MINUTES", "30"))
        self.cookie_secure: bool = os.getenv("COOKIE_SECURE", "false").lower() == "true"
        self.bootstrap_admin_username: Optional[str] = os.getenv("ADMIN_USERNAME")
        self.bootstrap_admin_password: Optional[str] = os.getenv("ADMIN_PASSWORD")
        self.bootstrap_admin_email: Optional[str] = os.getenv("ADMIN_EMAIL")
        
        # Database
        self.database_url: str = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./soc_agent.db")
        
        # Agent Configuration
        self.agent_autonomy_level: str = os.getenv("AGENT_AUTONOMY_LEVEL", "high")
        learning_enabled_str = os.getenv("LEARNING_ENABLED", "true")
        self.learning_enabled: bool = learning_enabled_str.lower() == "true"
        self.max_parallel_investigations: int = int(os.getenv("MAX_PARALLEL_INVESTIGATIONS", "10"))
        
        # Integration Endpoints
        self.edr_endpoint: str = os.getenv("EDR_ENDPOINT", "http://localhost:8001")
        self.siem_endpoint: str = os.getenv("SIEM_ENDPOINT", "http://localhost:8002")
        self.threat_intel_endpoint: str = os.getenv("THREAT_INTEL_ENDPOINT", "http://localhost:8003")
        
        # Server Configuration
        self.host: str = os.getenv("HOST", "0.0.0.0")
        self.port: int = int(os.getenv("PORT", "8000"))
        
        # Threat Response Settings
        self.severity_threshold: float = float(os.getenv("SEVERITY_THRESHOLD", "7.0"))
        self.report_format: str = os.getenv("REPORT_FORMAT", "json")
        self.protocol_id: str = os.getenv("PROTOCOL_ID", "EMERGENCY-001")
        self.timestamp_format: str = os.getenv("TIMESTAMP_FORMAT", "%Y-%m-%dT%H:%M:%S")
        self.security_standard: str = os.getenv("SECURITY_STANDARD", "ISO27001")


settings = Settings()
