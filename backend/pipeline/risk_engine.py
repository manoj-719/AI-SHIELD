"""
AI Shield - Central Risk Processing Engine.
Combines security rule outputs and ML anomaly signals to compute composite risk scores and levels.

KEY PRINCIPLE (api_contract.md Rule 4):
"ML provides an anomaly signal; it must never override a hard security denial."
If a hard denial is issued by security rules, the risk level remains CRITICAL/HIGH
regardless of a low ML score.
"""

from typing import Dict, Any, Tuple
from backend.pipeline.security_adapter import SecurityRuleResult
from backend.pipeline.ml_adapter import MLAnomalyResult

# Configurable Risk Level Thresholds
THRESHOLD_LOW = 30.0
THRESHOLD_MEDIUM = 60.0
THRESHOLD_HIGH = 80.0
HARD_DENIAL_MIN_SCORE = 85.0

def score_to_risk_level(score: float) -> str:
    """Map numeric risk score (0.0 - 100.0) to risk level string."""
    if score >= THRESHOLD_HIGH:
        return "critical"
    elif score >= THRESHOLD_MEDIUM:
        return "high"
    elif score >= THRESHOLD_LOW:
        return "medium"
    else:
        return "low"

def calculate_composite_risk(
    security_result: SecurityRuleResult,
    ml_result: MLAnomalyResult,
    raw_event: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Calculate the unified risk score, risk level, and final recommended action.
    
    Guarantees:
    1. Hard security denials CANNOT be overridden or reduced by a low ML score.
    2. High ML anomalies elevate risk if security rules did not catch them.
    3. Output maps strictly to docs/api_contract.md fields.
    """
    rule_result = security_result.rule_result
    hard_denial = security_result.hard_denial
    recommended_action = security_result.recommended_action
    
    ml_anomaly = ml_result.anomaly
    ml_score = ml_result.risk_score

    # Check if incoming event already had explicit recommended_action or rule_result
    if raw_event.get("recommended_action") and recommended_action == "none":
        recommended_action = raw_event["recommended_action"]
    if raw_event.get("rule_result") and rule_result == "allowed":
        rule_result = raw_event["rule_result"]

    # CASE 1: HARD SECURITY DENIAL
    if hard_denial:
        # Enforce Rule 4: Hard denial forces high/critical risk regardless of ML score
        composite_score = max(ml_score, HARD_DENIAL_MIN_SCORE)
        composite_level = "critical"
        final_anomaly = True if ml_anomaly else True  # Hard violation is intrinsically anomalous
        
        return {
            "rule_result": rule_result,
            "anomaly": final_anomaly,
            "risk_score": round(composite_score, 2),
            "risk_level": composite_level,
            "recommended_action": recommended_action,
            "hard_denial_preserved": True
        }

    # CASE 2: ML ANOMALY DETECTED (WITHOUT HARD DENIAL)
    if ml_anomaly:
        # Security rules permitted it, but ML flagged unusual statistical variance
        composite_score = max(ml_score, 65.0)
        composite_level = score_to_risk_level(composite_score)
        if recommended_action == "none":
            recommended_action = "flag_for_analyst_review"

        return {
            "rule_result": rule_result if rule_result != "allowed" else "flagged_by_ml_anomaly",
            "anomaly": True,
            "risk_score": round(composite_score, 2),
            "risk_level": composite_level,
            "recommended_action": recommended_action,
            "hard_denial_preserved": False
        }

    # CASE 3: NOMINAL / STANDARD ACCESS
    composite_score = ml_score
    composite_level = score_to_risk_level(composite_score)

    return {
        "rule_result": rule_result,
        "anomaly": False,
        "risk_score": round(composite_score, 2),
        "risk_level": composite_level,
        "recommended_action": recommended_action,
        "hard_denial_preserved": False
    }
