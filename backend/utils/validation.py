import re
import uuid
from datetime import datetime, timezone

EMAIL_REGEX = re.compile(r"^[\w\.-]+@[\w\.-]+\.\w+$")

VALID_ACTOR_TYPES = {"employee", "agent", "external"}
VALID_EMPLOYEE_STATUSES = {"active", "suspended", "under_investigation", "terminated"}
VALID_RISK_LEVELS = {"low", "medium", "high", "critical"}

def get_current_iso_timestamp():
    """Return current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()

def validate_employee_payload(data):
    """
    Validate input payload for creating an employee.
    Returns: (is_valid: bool, error: str | None, cleaned: dict | None)
    """
    if not isinstance(data, dict):
        return False, "Payload must be a JSON object", None

    # Required fields
    required = ["name", "email", "department", "role"]
    for field in required:
        val = data.get(field)
        if not val or not isinstance(val, str) or not val.strip():
            return False, f"Missing or invalid required field: '{field}'", None

    name = data["name"].strip()
    email = data["email"].strip().lower()
    department = data["department"].strip()
    role = data["role"].strip()

    if not EMAIL_REGEX.match(email):
        return False, "Invalid email address format", None

    # Optional employee_id
    employee_id = data.get("employee_id")
    if employee_id:
        if not isinstance(employee_id, str) or not employee_id.strip():
            return False, "Invalid 'employee_id' format", None
        employee_id = employee_id.strip()
    else:
        employee_id = f"EMP-{uuid.uuid4().hex[:8].upper()}"

    # Status
    status = data.get("status", "active")
    if status not in VALID_EMPLOYEE_STATUSES:
        return False, f"Invalid status '{status}'. Must be one of: {sorted(list(VALID_EMPLOYEE_STATUSES))}", None

    # Risk score
    risk_score = data.get("risk_score", 0.0)
    try:
        risk_score = float(risk_score)
        if risk_score < 0.0 or risk_score > 100.0:
            return False, "risk_score must be between 0.0 and 100.0", None
    except (ValueError, TypeError):
        return False, "risk_score must be a numeric value", None

    cleaned = {
        "employee_id": employee_id,
        "name": name,
        "email": email,
        "department": department,
        "role": role,
        "risk_score": risk_score,
        "status": status,
        "created_at": get_current_iso_timestamp(),
        "updated_at": get_current_iso_timestamp()
    }
    return True, None, cleaned

def validate_event_payload(data):
    """
    Validate security event against docs/api_contract.md specification.
    Returns: (is_valid: bool, error: str | None, cleaned: dict | None)
    """
    if not isinstance(data, dict):
        return False, "Payload must be a JSON object", None

    required_fields = [
        "event_type",
        "actor_type",
        "actor_id",
        "resource",
        "is_sensitive",
        "action",
        "source"
    ]

    for field in required_fields:
        if field not in data:
            return False, f"Missing required field: '{field}'", None

    event_type = str(data["event_type"]).strip()
    actor_type = str(data["actor_type"]).strip().lower()
    actor_id = str(data["actor_id"]).strip()
    resource = str(data["resource"]).strip()
    action = str(data["action"]).strip()
    source = str(data["source"]).strip()

    if not event_type:
        return False, "event_type cannot be empty", None
    if not actor_id:
        return False, "actor_id cannot be empty", None
    if not resource:
        return False, "resource cannot be empty", None
    if not action:
        return False, "action cannot be empty", None
    if not source:
        return False, "source cannot be empty", None

    if actor_type not in VALID_ACTOR_TYPES:
        return False, f"Invalid actor_type '{actor_type}'. Must be one of: {sorted(list(VALID_ACTOR_TYPES))}", None

    is_sensitive = data.get("is_sensitive")
    if not isinstance(is_sensitive, bool) and is_sensitive not in (0, 1):
        return False, "is_sensitive must be a boolean (true or false)", None
    is_sensitive_val = bool(is_sensitive)

    event_id = data.get("event_id")
    if event_id:
        event_id = str(event_id).strip()
    else:
        event_id = f"EVT-{uuid.uuid4().hex[:8].upper()}"

    timestamp = data.get("timestamp")
    if timestamp:
        timestamp = str(timestamp).strip()
    else:
        timestamp = get_current_iso_timestamp()

    destination = data.get("destination")
    if destination is not None:
        destination = str(destination).strip()

    description = data.get("description")
    if description is not None:
        description = str(description).strip()

    # Optional backend detection outputs
    rule_result = data.get("rule_result")
    anomaly = data.get("anomaly")
    anomaly_val = None
    if anomaly is not None:
        if not isinstance(anomaly, bool) and anomaly not in (0, 1):
            return False, "anomaly must be a boolean", None
        anomaly_val = bool(anomaly)

    risk_score = data.get("risk_score")
    if risk_score is not None:
        try:
            risk_score = float(risk_score)
        except (ValueError, TypeError):
            return False, "risk_score must be a numeric value", None

    risk_level = data.get("risk_level")
    if risk_level is not None:
        risk_level = str(risk_level).lower().strip()
        if risk_level not in VALID_RISK_LEVELS:
            return False, f"Invalid risk_level '{risk_level}'. Must be one of: {sorted(list(VALID_RISK_LEVELS))}", None

    recommended_action = data.get("recommended_action")
    if recommended_action is not None:
        recommended_action = str(recommended_action).strip()

    cleaned = {
        "event_id": event_id,
        "event_type": event_type,
        "actor_type": actor_type,
        "actor_id": actor_id,
        "resource": resource,
        "is_sensitive": is_sensitive_val,
        "action": action,
        "destination": destination,
        "timestamp": timestamp,
        "source": source,
        "description": description,
        "rule_result": rule_result,
        "anomaly": anomaly_val,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "recommended_action": recommended_action,
        "created_at": get_current_iso_timestamp()
    }
    return True, None, cleaned
