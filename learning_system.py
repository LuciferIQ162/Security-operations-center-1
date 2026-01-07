"""Continuous learning and adaptation system."""
import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from models import InvestigationResult, ActionableConclusion
from database import LearningModel, InvestigationModel, async_session_maker
from sqlalchemy import select, func
import json


class LearningSystem:
    """Continuous learning system that adapts based on outcomes."""
    
    def __init__(self):
        self.patterns = {}
        self.false_positive_patterns = []
        self.true_positive_patterns = []
        self.performance_metrics = {
            "total_investigations": 0,
            "false_positives": 0,
            "true_positives": 0,
            "accuracy": 0.0,
        }
    
    async def record_outcome(
        self,
        alert_id: str,
        investigation_id: str,
        outcome: str,
        feedback: Optional[str] = None
    ):
        """Record the outcome of an investigation for learning."""
        learning_id = str(uuid.uuid4())
        
        # Extract patterns from the outcome
        patterns = await self._extract_patterns(alert_id, investigation_id, outcome)
        
        # Store learning outcome
        async with async_session_maker() as session:
            learning_model = LearningModel(
                id=learning_id,
                alert_id=alert_id,
                investigation_id=investigation_id,
                outcome=outcome,
                feedback=feedback,
                patterns_learned=patterns,
                timestamp=datetime.now(),
            )
            session.add(learning_model)
            await session.commit()
        
        # Update internal patterns
        await self._update_patterns(patterns, outcome)
        
        # Update performance metrics
        self._update_metrics(outcome)
    
    async def _extract_patterns(
        self,
        alert_id: str,
        investigation_id: str,
        outcome: str
    ) -> Dict[str, Any]:
        """Extract patterns from investigation for learning."""
        async with async_session_maker() as session:
            result = await session.execute(
                select(InvestigationModel).where(InvestigationModel.id == investigation_id)
            )
            inv_model = result.scalar_one_or_none()
            
            if not inv_model:
                return {}
            
            patterns = {
                "risk_score_range": self._categorize_risk_score(inv_model.risk_score),
                "finding_count": len(inv_model.findings or []),
                "indicator_count": len(inv_model.threat_indicators or []),
                "correlation_count": len(inv_model.correlated_alerts or []),
                "confidence_level": self._categorize_confidence(inv_model.confidence),
            }
            
            # Extract specific patterns from findings
            if inv_model.findings:
                patterns["data_sources"] = [
                    f.get("source") for f in inv_model.findings if f.get("source")
                ]
            
            return patterns
    
    def _categorize_risk_score(self, risk_score: float) -> str:
        """Categorize risk score."""
        if risk_score >= 8.5:
            return "critical"
        elif risk_score >= 6.5:
            return "high"
        elif risk_score >= 4.5:
            return "medium"
        elif risk_score >= 2.5:
            return "low"
        else:
            return "minimal"
    
    def _categorize_confidence(self, confidence: float) -> str:
        """Categorize confidence level."""
        if confidence >= 0.8:
            return "high"
        elif confidence >= 0.6:
            return "medium"
        else:
            return "low"
    
    async def _update_patterns(self, patterns: Dict[str, Any], outcome: str):
        """Update learned patterns based on outcome."""
        if outcome == "false_positive":
            self.false_positive_patterns.append(patterns)
            # Keep only recent patterns (last 100)
            if len(self.false_positive_patterns) > 100:
                self.false_positive_patterns.pop(0)
        elif outcome == "true_positive":
            self.true_positive_patterns.append(patterns)
            if len(self.true_positive_patterns) > 100:
                self.true_positive_patterns.pop(0)
    
    def _update_metrics(self, outcome: str):
        """Update performance metrics."""
        self.performance_metrics["total_investigations"] += 1
        
        if outcome == "false_positive":
            self.performance_metrics["false_positives"] += 1
        elif outcome == "true_positive":
            self.performance_metrics["true_positives"] += 1
        
        # Calculate accuracy
        total_classified = (
            self.performance_metrics["false_positives"] +
            self.performance_metrics["true_positives"]
        )
        if total_classified > 0:
            self.performance_metrics["accuracy"] = (
                self.performance_metrics["true_positives"] / total_classified
            )
    
    async def should_auto_close(self, investigation: InvestigationResult) -> bool:
        """Determine if alert should be auto-closed based on learned patterns."""
        # Check against false positive patterns
        investigation_patterns = {
            "risk_score_range": self._categorize_risk_score(investigation.risk_score),
            "finding_count": len(investigation.findings),
            "indicator_count": len(investigation.threat_indicators),
            "correlation_count": len(investigation.correlated_alerts),
            "confidence_level": self._categorize_confidence(investigation.confidence),
        }
        
        # Check similarity to known false positives
        for fp_pattern in self.false_positive_patterns[-20:]:  # Check last 20
            similarity = self._calculate_pattern_similarity(investigation_patterns, fp_pattern)
            if similarity > 0.8:  # 80% similarity threshold
                return True
        
        return False
    
    def _calculate_pattern_similarity(
        self,
        pattern1: Dict[str, Any],
        pattern2: Dict[str, Any]
    ) -> float:
        """Calculate similarity between two patterns."""
        matches = 0
        total = 0
        
        for key in pattern1:
            if key in pattern2:
                total += 1
                if pattern1[key] == pattern2[key]:
                    matches += 1
        
        return matches / total if total > 0 else 0.0
    
    async def adjust_risk_score(
        self,
        investigation: InvestigationResult,
        base_risk_score: float
    ) -> float:
        """Adjust risk score based on learned patterns."""
        adjusted_score = base_risk_score
        
        investigation_patterns = {
            "risk_score_range": self._categorize_risk_score(investigation.risk_score),
            "finding_count": len(investigation.findings),
            "indicator_count": len(investigation.threat_indicators),
        }
        
        # Check against false positive patterns (reduce score)
        for fp_pattern in self.false_positive_patterns[-10:]:
            similarity = self._calculate_pattern_similarity(investigation_patterns, fp_pattern)
            if similarity > 0.7:
                adjusted_score -= 1.0  # Reduce risk score
        
        # Check against true positive patterns (increase score)
        for tp_pattern in self.true_positive_patterns[-10:]:
            similarity = self._calculate_pattern_similarity(investigation_patterns, tp_pattern)
            if similarity > 0.7:
                adjusted_score += 0.5  # Increase risk score
        
        # Normalize
        adjusted_score = max(0.0, min(10.0, adjusted_score))
        
        return adjusted_score
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get current performance metrics."""
        return self.performance_metrics.copy()
    
    async def get_learned_patterns(self) -> Dict[str, Any]:
        """Get summary of learned patterns."""
        return {
            "false_positive_patterns_count": len(self.false_positive_patterns),
            "true_positive_patterns_count": len(self.true_positive_patterns),
            "performance_metrics": self.performance_metrics,
        }
