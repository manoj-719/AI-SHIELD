"""
AI Shield - Event Processing Pipeline Package.
"""

from backend.pipeline.event_processor import process_security_event
from backend.pipeline.security_adapter import (
    SecurityRuleResult,
    MockSecurityRuleAdapter,
    get_security_adapter,
    set_security_adapter,
    reset_security_adapter
)
from backend.pipeline.ml_adapter import (
    MLAnomalyResult,
    MockMLAnomalyAdapter,
    get_ml_adapter,
    set_ml_adapter,
    reset_ml_adapter
)
from backend.pipeline.risk_engine import (
    calculate_composite_risk,
    score_to_risk_level
)
from backend.pipeline.incident_generator import (
    evaluate_and_generate_alerts,
    generate_alert_type
)

__all__ = [
    "process_security_event",
    "SecurityRuleResult",
    "MockSecurityRuleAdapter",
    "get_security_adapter",
    "set_security_adapter",
    "reset_security_adapter",
    "MLAnomalyResult",
    "MockMLAnomalyAdapter",
    "get_ml_adapter",
    "set_ml_adapter",
    "reset_ml_adapter",
    "calculate_composite_risk",
    "score_to_risk_level",
    "evaluate_and_generate_alerts",
    "generate_alert_type"
]
