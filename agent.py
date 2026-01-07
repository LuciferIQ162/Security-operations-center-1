"""Main AI SOC Agent orchestrator."""
import asyncio
from typing import Dict, Any, Optional
from models import Alert, InvestigationResult, AgentDecision, ActionableConclusion
from alert_processor import AlertProcessor
from investigation_engine import InvestigationEngine
from decision_maker import DecisionMaker
from conclusion_generator import ConclusionGenerator
from learning_system import LearningSystem
from config import settings
from response import ResponseManager


class AISOCAgent:
    """Main AI SOC Agent that orchestrates the entire workflow."""
    
    def __init__(self):
        self.alert_processor = AlertProcessor()
        self.investigation_engine = InvestigationEngine()
        self.decision_maker = DecisionMaker()
        self.conclusion_generator = ConclusionGenerator()
        self.learning_system = LearningSystem()
        self.response_manager = ResponseManager()
        self.active_investigations = {}
    
    async def process_alert(self, raw_alert: Dict[str, Any]) -> Dict[str, Any]:
        """Process an alert through the complete workflow."""
        try:
            # Step 1: Alert Ingestion & Classification
            alert = await self.alert_processor.ingest_alert(raw_alert)
            
            # Step 2: Autonomous Investigation
            investigation = await self.investigation_engine.investigate_alert(alert)
            
            # Apply learning adjustments if enabled
            if settings.learning_enabled:
                adjusted_risk = await self.learning_system.adjust_risk_score(
                    investigation,
                    investigation.risk_score
                )
                investigation.risk_score = adjusted_risk
            
            # Step 3: Contextual Decision Making
            decision = self.decision_maker.make_decision(alert, investigation)
            
            # Step 4: Generate Actionable Conclusions
            conclusion = self.conclusion_generator.generate_conclusion(
                alert,
                investigation,
                decision
            )
            
            response_result = await self.response_manager.execute(alert.dict(), investigation.dict(), decision.dict())
            
            # Check if should auto-close (learning-based)
            if settings.learning_enabled:
                should_auto_close = await self.learning_system.should_auto_close(investigation)
                if should_auto_close and conclusion.threat_severity.value == "false_positive":
                    conclusion.requires_human_review = False
            
            return {
                "alert": alert.dict(),
                "investigation": investigation.dict(),
                "decision": decision.dict(),
                "conclusion": conclusion.dict(),
                "status": "completed",
                "response": response_result,
            }
        
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
            }
    
    async def process_alert_async(self, raw_alert: Dict[str, Any]) -> str:
        """Process alert asynchronously and return alert ID."""
        alert = await self.alert_processor.ingest_alert(raw_alert)
        
        # Start investigation in background
        asyncio.create_task(self._process_alert_background(alert))
        
        return alert.id
    
    async def _process_alert_background(self, alert: Alert):
        """Process alert in background."""
        try:
            investigation = await self.investigation_engine.investigate_alert(alert)
            decision = self.decision_maker.make_decision(alert, investigation)
            conclusion = self.conclusion_generator.generate_conclusion(
                alert,
                investigation,
                decision
            )
            await self.response_manager.execute(alert.dict(), investigation.dict(), decision.dict())
            
            # Store result
            self.active_investigations[alert.id] = {
                "alert": alert,
                "investigation": investigation,
                "decision": decision,
                "conclusion": conclusion,
            }
        except Exception as e:
            self.active_investigations[alert.id] = {
                "error": str(e),
            }
    
    async def get_alert_result(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """Get result for a processed alert."""
        if alert_id in self.active_investigations:
            result = self.active_investigations[alert_id]
            if "error" in result:
                return {"status": "error", "error": result["error"]}
            
            return {
                "alert": result["alert"].dict(),
                "investigation": result["investigation"].dict(),
                "decision": result["decision"].dict(),
                "conclusion": result["conclusion"].dict(),
                "status": "completed",
            }
        
        # Try to get from database
        alert = await self.alert_processor.get_alert(alert_id)
        if alert:
            investigation = await self.investigation_engine.get_investigation(alert_id)
            if investigation:
                decision = self.decision_maker.make_decision(alert, investigation)
                conclusion = self.conclusion_generator.generate_conclusion(
                    alert,
                    investigation,
                    decision
                )
                return {
                    "alert": alert.dict(),
                    "investigation": investigation.dict(),
                    "decision": decision.dict(),
                    "conclusion": conclusion.dict(),
                    "status": "completed",
                }
        
        return None
    
    async def record_feedback(
        self,
        alert_id: str,
        outcome: str,
        feedback: Optional[str] = None
    ) -> Dict[str, Any]:
        """Record feedback for learning."""
        if settings.learning_enabled:
            # Get investigation ID
            investigation = await self.investigation_engine.get_investigation(alert_id)
            if investigation:
                investigation_id = investigation.alert_id  # Use alert_id as proxy
                await self.learning_system.record_outcome(
                    alert_id,
                    investigation_id,
                    outcome,
                    feedback
                )
                return {"status": "recorded", "message": "Feedback recorded for learning"}
        
        return {"status": "error", "message": "Learning system disabled or investigation not found"}
    
    async def get_agent_stats(self) -> Dict[str, Any]:
        """Get agent statistics and performance metrics."""
        stats = {
            "active_investigations": len(self.active_investigations),
            "autonomy_level": settings.agent_autonomy_level,
            "learning_enabled": settings.learning_enabled,
        }
        
        if settings.learning_enabled:
            stats["learning_metrics"] = self.learning_system.get_performance_metrics()
            stats["learned_patterns"] = await self.learning_system.get_learned_patterns()
        
        return stats
