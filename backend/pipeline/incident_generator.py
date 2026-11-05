"""
AI Shield - Automated Incident and Alert Generator.
Evaluates processed security events and generates corresponding alerts and incidents in Supabase.

CRITICAL REQUIREMENTS:
1. High and critical risk events trigger alerts.
2. Hard denials and critical violations trigger incidents.
3. Deduplication: Avoids duplicate alerts or incidents for the same event_id.
4. Transparency: Clearly states simulated/recommended actions without false enforcement claims.
"""

import uuid
from typing import Dict, Any, Optional, Tuple
from datetime import datetime, timezone

def generate_alert_type(event_type: str, rule_result: str) -> str:
    """Map rule result and event type to a standard alert type category."""
    if "dlp" in rule_result or "share" in rule_result:
        return "DLP_VIOLATION"
    elif "agent" in rule_result:
        return "UNAUTHORIZED_AGENT_ACCESS"
    elif "auth" in rule_result or "login" in rule_result or "brute" in rule_result:
        return "ANOMALOUS_AUTHENTICATION"
    elif "export" in rule_result:
        return "REMOVABLE_MEDIA_EXFILTRATION"
    elif "anomaly" in rule_result:
        return "STATISTICAL_ANOMALY"
    else:
        return f"HIGH_RISK_{event_type.upper()}"

def evaluate_and_generate_alerts(
    event_record: Dict[str, Any],
    risk_assessment: Dict[str, Any],
    supabase_client
) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """
    Generate alerts and incidents for high/critical security events.
    Returns: (alert_record, incident_record)
    """
    if not supabase_client:
        return None, None

    event_id = event_record.get("event_id")
    actor_id = event_record.get("actor_id", "unknown_actor")
    resource = event_record.get("resource", "unspecified_resource")
    action = event_record.get("action", "unknown_action")
    event_type = event_record.get("event_type", "security_event")

    risk_level = risk_assessment.get("risk_level", "low").lower()
    rule_result = risk_assessment.get("rule_result", "allowed")
    recommended_action = risk_assessment.get("recommended_action", "none")
    hard_denial = risk_assessment.get("hard_denial_preserved", False)

    now_iso = datetime.now(timezone.utc).isoformat()
    created_alert = None
    created_incident = None

    # Check eligibility: Alerts are triggered for high or critical risk
    should_alert = risk_level in ("high", "critical") or hard_denial
    # Incidents are created for critical violations or confirmed hard denials
    should_create_incident = risk_level == "critical" or hard_denial

    if not should_alert and not should_create_incident:
        return None, None

    incident_id = None

    # 1. GENERATE INCIDENT (if critical or hard denial)
    if should_create_incident:
        try:
            # Check deduplication: does an incident already exist for this event_id?
            existing_inc = supabase_client.table("security_incidents").select("*").eq("event_id", event_id).execute()
            if existing_inc.data:
                created_incident = existing_inc.data[0]
                incident_id = created_incident.get("incident_id")
            else:
                incident_id = f"INC-{uuid.uuid4().hex[:8].upper()}"
                title = f"Simulated Security Violation: {rule_result} ({event_id})"
                description = (
                    f"Simulated security event flagged. Actor '{actor_id}' performed '{action}' on '{resource}'. "
                    f"Risk Level: {risk_level.upper()}. Recommended Action: {recommended_action}."
                )
                inc_record = {
                    "incident_id": incident_id,
                    "title": title,
                    "description": description,
                    "severity": risk_level,
                    "status": "open",
                    "actor_id": actor_id,
                    "event_id": event_id,
                    "assigned_to": None,
                    "resolved_at": None,
                    "created_at": now_iso,
                    "updated_at": now_iso
                }
                res = supabase_client.table("security_incidents").insert(inc_record).execute()
                created_incident = res.data[0] if res.data else inc_record
        except Exception as e:
            print(f"[Pipeline] Warning: Failed to create incident for event {event_id}: {e}")

    # 2. GENERATE ALERT (for high or critical risk)
    if should_alert:
        try:
            # Check deduplication: does an alert already exist for this event_id?
            existing_alt = supabase_client.table("alerts").select("*").eq("event_id", event_id).execute()
            if existing_alt.data:
                created_alert = existing_alt.data[0]
            else:
                alert_id = f"ALT-{uuid.uuid4().hex[:8].upper()}"
                alert_type = generate_alert_type(event_type, rule_result)
                message = (
                    f"Simulated event on '{resource}' by '{actor_id}' flagged as {risk_level.upper()} risk. "
                    f"Recommended Action: {recommended_action}."
                )
                alt_record = {
                    "alert_id": alert_id,
                    "event_id": event_id,
                    "incident_id": incident_id,
                    "alert_type": alert_type,
                    "severity": risk_level,
                    "message": message,
                    "is_read": False,
                    "created_at": now_iso
                }
                res = supabase_client.table("alerts").insert(alt_record).execute()
                created_alert = res.data[0] if res.data else alt_record
        except Exception as e:
            print(f"[Pipeline] Warning: Failed to create alert for event {event_id}: {e}")

    return created_alert, created_incident
