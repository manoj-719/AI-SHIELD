import uuid
from flask import Blueprint, request
from backend.database import get_supabase_client
from backend.utils.response import api_response, error_response
from backend.utils.validation import validate_event_payload

from backend.pipeline.event_processor import process_security_event

events_bp = Blueprint("events", __name__)

@events_bp.route("/api/events", methods=["GET"])
def get_events():
    """
    Retrieve security events from Supabase PostgreSQL.
    Supports optional filters: event_type, actor_type, actor_id, is_sensitive, risk_level, limit, offset.
    """
    event_type = request.args.get("event_type")
    actor_type = request.args.get("actor_type")
    actor_id = request.args.get("actor_id")
    is_sensitive_param = request.args.get("is_sensitive")
    risk_level = request.args.get("risk_level")

    try:
        limit = min(int(request.args.get("limit", 50)), 200)
        offset = max(int(request.args.get("offset", 0)), 0)
    except ValueError:
        return error_response("Query parameters 'limit' and 'offset' must be valid integers", 400)

    try:
        supabase = get_supabase_client()
        query = supabase.table("security_events").select("*", count="exact")

        if event_type:
            query = query.eq("event_type", event_type)
        if actor_type:
            query = query.eq("actor_type", actor_type)
        if actor_id:
            query = query.eq("actor_id", actor_id)
        if is_sensitive_param is not None:
            is_sensitive_val = is_sensitive_param.lower() in ("true", "1")
            query = query.eq("is_sensitive", is_sensitive_val)
        if risk_level:
            query = query.eq("risk_level", risk_level.lower())

        query = query.order("timestamp", desc=True).range(offset, offset + limit - 1)
        res = query.execute()

        events = res.data or []
        total_count = res.count if res.count is not None else len(events)

        meta = {
            "total": total_count,
            "limit": limit,
            "offset": offset,
            "returned": len(events)
        }
        return api_response(data=events, message="Events retrieved successfully", meta=meta, status_code=200)

    except RuntimeError as re:
        return error_response("Database configuration error", 503, details=str(re))
    except Exception as e:
        return error_response("Failed to retrieve security events from Supabase", 500, details=str(e))

@events_bp.route("/api/events/<event_id>", methods=["GET"])
def get_event(event_id):
    """
    Retrieve a single security event by its event_id.
    """
    try:
        supabase = get_supabase_client()
        res = supabase.table("security_events").select("*").eq("event_id", event_id).limit(1).execute()
        if not res.data:
            return error_response(f"Security event with ID '{event_id}' not found", 404)
        return api_response(data=res.data[0], message="Event retrieved successfully", status_code=200)

    except RuntimeError as re:
        return error_response("Database configuration error", 503, details=str(re))
    except Exception as e:
        return error_response("Failed to fetch security event", 500, details=str(e))

@events_bp.route("/api/events", methods=["POST"])
def create_event():
    """
    Ingest a new security event conforming strictly to docs/api_contract.md.
    Executes the central event-processing pipeline:
    Validate -> Evaluate Rules -> Score ML -> Calculate Risk -> Generate Incidents/Alerts -> Store
    """
    if not request.is_json:
        return error_response("Request body must be JSON with Content-Type: application/json", 400)

    payload = request.get_json()
    success, result, status_code = process_security_event(payload)
    if not success:
        return error_response(result, status_code)

    saved_event = result["event"]
    meta = {}
    if result.get("alert"):
        meta["alert_id"] = result["alert"].get("alert_id")
    if result.get("incident"):
        meta["incident_id"] = result["incident"].get("incident_id")
    if result.get("risk_assessment"):
        meta["risk_level"] = result["risk_assessment"].get("risk_level")
        meta["risk_score"] = result["risk_assessment"].get("risk_score")

    return api_response(
        data=saved_event,
        message="Security event registered successfully",
        meta=meta if meta else None,
        status_code=201
    )
