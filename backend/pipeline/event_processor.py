"""
AI Shield - Central Event Processing Pipeline Orchestrator.
Orchestrates the entire event lifecycle:
Receive Event → Validate Event → Evaluate Security Rules → Obtain ML Result →
Calculate Risk → Store Results in Supabase → Generate Incident/Alert

Architecture:
- Modular, decoupled, extensible.
- Strictly adheres to docs/api_contract.md.
- Reuses existing validation and Supabase singleton.
- Enforces hard denial preservation.
"""

import uuid
from typing import Dict, Any, Tuple
from backend.database import get_supabase_client
from backend.utils.validation import validate_event_payload, get_current_iso_timestamp
from backend.pipeline.security_adapter import get_security_adapter
from backend.pipeline.ml_adapter import get_ml_adapter
from backend.pipeline.risk_engine import calculate_composite_risk
from backend.pipeline.incident_generator import evaluate_and_generate_alerts

def process_security_event(raw_payload: Dict[str, Any], client=None) -> Tuple[bool, Any, int]:
    """
    Execute the central event processing pipeline for an incoming event.
    
    Returns:
        (success: bool, result_or_error: dict | str, status_code: int)
    """
    # STEP 1: VALIDATE EVENT
    is_valid, err_msg, cleaned = validate_event_payload(raw_payload)
    if not is_valid:
        return False, err_msg, 400

    try:
        supabase = client or get_supabase_client()

        # STEP 2: DUPLICATE CHECK (Event ID)
        check_res = supabase.table("security_events").select("event_id").eq("event_id", cleaned["event_id"]).execute()
        if check_res.data:
            return False, f"Event with event_id '{cleaned['event_id']}' already exists", 409

        # STEP 3: EVALUATE SECURITY RULES
        sec_adapter = get_security_adapter()
        sec_result = sec_adapter.evaluate(cleaned)

        # STEP 4: OBTAIN ML RESULT (OR RESPECT INCOMING ML SCORES)
        ml_adapter = get_ml_adapter()
        ml_result = ml_adapter.score(cleaned)

        # STEP 5: CALCULATE COMPOSITE RISK (PRESERVING HARD DENIALS)
        risk_assessment = calculate_composite_risk(sec_result, ml_result, cleaned)

        # Merge calculated detection attributes into the cleaned event
        cleaned["rule_result"] = risk_assessment["rule_result"]
        cleaned["anomaly"] = risk_assessment["anomaly"]
        cleaned["risk_score"] = risk_assessment["risk_score"]
        cleaned["risk_level"] = risk_assessment["risk_level"]
        cleaned["recommended_action"] = risk_assessment["recommended_action"]

        # STEP 6: STORE ENRICHED EVENT IN SUPABASE
        insert_res = supabase.table("security_events").insert(cleaned).execute()
        saved_event = insert_res.data[0] if insert_res.data else cleaned

        # STEP 7: AUTOMATIC INCIDENTS AND ALERTS (DEDUPLICATED)
        alert_record, incident_record = evaluate_and_generate_alerts(
            saved_event, risk_assessment, supabase
        )

        # STEP 8: RECORD ACTIVITY LOG
        try:
            log_id = f"LOG-{uuid.uuid4().hex[:8].upper()}"
            supabase.table("activity_logs").insert({
                "log_id": log_id,
                "action": "ingest_security_event",
                "performed_by": cleaned.get("actor_id", "system"),
                "details": f"Processed {cleaned['event_id']} ({cleaned['event_type']}) - Risk: {cleaned['risk_level'].upper()}",
                "ip_address": "127.0.0.1",
                "timestamp": get_current_iso_timestamp()
            }).execute()
        except Exception as log_err:
            print(f"[Pipeline] Notice: Activity log write bypassed: {log_err}")

        pipeline_output = {
            "event": saved_event,
            "risk_assessment": risk_assessment,
            "alert": alert_record,
            "incident": incident_record
        }

        return True, pipeline_output, 201

    except RuntimeError as re:
        return False, f"Database configuration error: {str(re)}", 503
    except Exception as e:
        err_str = str(e)
        if "23505" in err_str or "duplicate key" in err_str:
            return False, f"Duplicate event_id conflict: {err_str}", 409
        return False, f"Pipeline processing failed: {err_str}", 500
