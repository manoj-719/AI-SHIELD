"""
AI Shield - Machine Learning Anomaly Detection Adapter Interface.
Defines the contract for ML anomaly scoring and risk evaluation.

NOTE: This file contains a clearly-labeled MockMLAnomalyAdapter for Phase 2 integration
testing. When teammates complete the ML module (in `ml/`), it can be plugged in
via `set_ml_adapter(custom_adapter)`.
"""

from typing import Dict, Any, Optional

class MLAnomalyResult:
    """Standardized output returned by ML anomaly detection."""
    def __init__(
        self,
        anomaly: bool = False,
        risk_score: float = 0.0,
        risk_level: str = "low",
        confidence: float = 0.85,
        factors: Optional[list] = None
    ):
        self.anomaly = bool(anomaly)
        self.risk_score = round(float(risk_score), 2)
        self.risk_level = risk_level.lower()
        self.confidence = float(confidence)
        self.factors = factors or []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "anomaly": self.anomaly,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "confidence": self.confidence,
            "factors": self.factors
        }


class MockMLAnomalyAdapter:
    """
    Temporary reference adapter for testing ML integration.
    Scores events based on statistical baseline heuristics until the teammate ML model is loaded.
    """
    def score(self, event: Dict[str, Any]) -> MLAnomalyResult:
        # 1. If incoming event already has explicit ML detection scores from upstream, respect them
        in_anomaly = event.get("anomaly")
        in_risk_score = event.get("risk_score")
        if in_risk_score is not None:
            score = float(in_risk_score)
            is_anomaly = bool(in_anomaly) if in_anomaly is not None else (score >= 60.0)
            level = "critical" if score >= 80.0 else ("high" if score >= 60.0 else ("medium" if score >= 30.0 else "low"))
            return MLAnomalyResult(
                anomaly=is_anomaly,
                risk_score=score,
                risk_level=level,
                confidence=0.90,
                factors=["Upstream ML score preserved"]
            )

        # 2. Heuristic baseline scoring for development/testing
        destination = str(event.get("destination", "")).lower()
        is_sensitive = bool(event.get("is_sensitive", False))
        action = str(event.get("action", "")).lower()
        actor_type = str(event.get("actor_type", "")).lower()

        is_internal = not destination or any(kw in destination for kw in ("internal", "local", "intranet", "workstation", "laptop", "corp", "none"))
        is_external = bool(destination) and not is_internal

        if is_sensitive and is_external:
            return MLAnomalyResult(
                anomaly=True,
                risk_score=85.0,
                risk_level="critical",
                confidence=0.94,
                factors=["Sensitive data destination is external", "High exfiltration probability"]
            )
        elif actor_type == "agent" and is_sensitive:
            return MLAnomalyResult(
                anomaly=True,
                risk_score=75.0,
                risk_level="high",
                confidence=0.88,
                factors=["Agent access to sensitive asset outside nominal baseline"]
            )
        elif is_sensitive:
            return MLAnomalyResult(
                anomaly=False,
                risk_score=35.0,
                risk_level="medium",
                confidence=0.80,
                factors=["Internal access to sensitive document"]
            )
        else:
            return MLAnomalyResult(
                anomaly=False,
                risk_score=10.0,
                risk_level="low",
                confidence=0.95,
                factors=["Standard routine activity within baseline"]
            )


# Global adapter registry
_active_ml_adapter = MockMLAnomalyAdapter()

def get_ml_adapter():
    """Return the currently registered ML adapter."""
    global _active_ml_adapter
    return _active_ml_adapter

def set_ml_adapter(adapter):
    """
    Register a custom ML adapter (e.g., when teammates provide `ml/anomaly_detector.py`).
    Adapter must implement `.score(event: dict) -> MLAnomalyResult`.
    """
    global _active_ml_adapter
    _active_ml_adapter = adapter

def reset_ml_adapter():
    """Reset to default reference adapter."""
    global _active_ml_adapter
    _active_ml_adapter = MockMLAnomalyAdapter()
