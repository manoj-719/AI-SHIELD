import uuid
from flask import Blueprint, request
from backend.database import get_supabase_client
from backend.utils.response import api_response, error_response
from backend.utils.validation import get_current_iso_timestamp

alerts_bp = Blueprint("alerts", __name__)

VALID_SEVERITIES = {"low", "medium", "high", "critical"}

@alerts_bp.route("/api/alerts", methods=["GET"])
def get_alerts():
    """
    Retrieve security alerts from Supabase PostgreSQL.
    Supports optional filters: severity, is_read, limit, offset.
    """
    severity = request.args.get("severity")
    is_read_param = request.args.get("is_read")

    try:
        limit = min(int(request.args.get("limit", 50)), 200)
        offset = max(int(request.args.get("offset", 0)), 0)
    except ValueError:
        return error_response("Query parameters 'limit' and 'offset' must be valid integers", 400)

    try:
        supabase = get_supabase_client()
        query = supabase.table("alerts").select("*", count="exact")

        if severity:
            query = query.eq("severity", severity.lower())
        if is_read_param is not None:
            is_read_val = is_read_param.lower() in ("true", "1")
            query = query.eq("is_read", is_read_val)

        query = query.order("created_at", desc=True).range(offset, offset + limit - 1)
        res = query.execute()

        alerts = res.data or []
        total_count = res.count if res.count is not None else len(alerts)

        meta = {
            "total": total_count,
            "limit": limit,
            "offset": offset,
            "returned": len(alerts)
        }
        return api_response(data=alerts, message="Alerts retrieved successfully", meta=meta, status_code=200)

    except RuntimeError as re:
        return error_response("Database configuration error", 503, details=str(re))
    except Exception as e:
        return error_response("Failed to retrieve alerts from Supabase", 500, details=str(e))

@alerts_bp.route("/api/alerts", methods=["POST"])
def create_alert():
    """
    Create a new alert in Supabase PostgreSQL.
    """
    if not request.is_json:
        return error_response("Request body must be JSON with Content-Type: application/json", 400)

    data = request.get_json()
    if not isinstance(data, dict):
        return error_response("Payload must be a JSON object", 400)

    required = ["alert_type", "severity", "message"]
    for field in required:
        if not data.get(field):
            return error_response(f"Missing required field: '{field}'", 400)

    severity = str(data["severity"]).strip().lower()
    if severity not in VALID_SEVERITIES:
        return error_response(f"Invalid severity '{severity}'. Must be one of: {sorted(list(VALID_SEVERITIES))}", 400)

    alert_id = data.get("alert_id") or f"ALT-{uuid.uuid4().hex[:8].upper()}"
    event_id = data.get("event_id")
    incident_id = data.get("incident_id")
    alert_type = str(data["alert_type"]).strip()
    message = str(data["message"]).strip()
    now_iso = get_current_iso_timestamp()

    alert_record = {
        "alert_id": alert_id,
        "event_id": event_id,
        "incident_id": incident_id,
        "alert_type": alert_type,
        "severity": severity,
        "message": message,
        "is_read": False,
        "created_at": now_iso
    }

    try:
        supabase = get_supabase_client()
        insert_res = supabase.table("alerts").insert(alert_record).execute()
        saved = insert_res.data[0] if insert_res.data else alert_record
        return api_response(data=saved, message="Alert created successfully", status_code=201)

    except RuntimeError as re:
        return error_response("Database configuration error", 503, details=str(re))
    except Exception as e:
        err_str = str(e)
        if "23505" in err_str or "duplicate key" in err_str:
            return error_response("Duplicate alert ID conflict", 409, details=err_str)
        return error_response("Failed to create alert", 500, details=err_str)

@alerts_bp.route("/api/alerts/<alert_id>", methods=["PATCH"])
def update_alert(alert_id):
    """
    Update an existing alert's read status (is_read) in Supabase PostgreSQL.
    """
    if not request.is_json:
        return error_response("Request body must be JSON with Content-Type: application/json", 400)

    data = request.get_json()
    if not isinstance(data, dict):
        return error_response("Payload must be a JSON object", 400)

    if "is_read" not in data:
        return error_response("Missing required field: 'is_read'", 400)

    is_read = data.get("is_read")
    if not isinstance(is_read, bool):
        return error_response("Field 'is_read' must be a boolean (true or false)", 400)

    try:
        supabase = get_supabase_client()
        update_res = supabase.table("alerts").update({"is_read": is_read}).eq("alert_id", alert_id).execute()
        if not update_res.data:
            return error_response(f"Alert with ID '{alert_id}' not found", 404)

        updated_alert = update_res.data[0]
        return api_response(data=updated_alert, message="Alert updated successfully", status_code=200)

    except RuntimeError as re:
        return error_response("Database configuration error", 503, details=str(re))
    except Exception as e:
        return error_response("Failed to update alert", 500, details=str(e))
