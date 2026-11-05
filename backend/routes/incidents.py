import uuid
from flask import Blueprint, request
from backend.database import get_supabase_client
from backend.utils.response import api_response, error_response
from backend.utils.validation import get_current_iso_timestamp

incidents_bp = Blueprint("incidents", __name__)

VALID_SEVERITIES = {"low", "medium", "high", "critical"}
VALID_INCIDENT_STATUSES = {"open", "investigating", "resolved", "closed"}

@incidents_bp.route("/api/incidents", methods=["GET"])
def get_incidents():
    """
    Retrieve security incidents from Supabase PostgreSQL.
    Supports optional filters: severity, status, actor_id, limit, offset.
    """
    severity = request.args.get("severity")
    status = request.args.get("status")
    actor_id = request.args.get("actor_id")

    try:
        limit = min(int(request.args.get("limit", 50)), 200)
        offset = max(int(request.args.get("offset", 0)), 0)
    except ValueError:
        return error_response("Query parameters 'limit' and 'offset' must be valid integers", 400)

    try:
        supabase = get_supabase_client()
        query = supabase.table("security_incidents").select("*", count="exact")

        if severity:
            query = query.eq("severity", severity.lower())
        if status:
            query = query.eq("status", status.lower())
        if actor_id:
            query = query.eq("actor_id", actor_id)

        query = query.order("created_at", desc=True).range(offset, offset + limit - 1)
        res = query.execute()

        incidents = res.data or []
        total_count = res.count if res.count is not None else len(incidents)

        meta = {
            "total": total_count,
            "limit": limit,
            "offset": offset,
            "returned": len(incidents)
        }
        return api_response(data=incidents, message="Incidents retrieved successfully", meta=meta, status_code=200)

    except RuntimeError as re:
        return error_response("Database configuration error", 503, details=str(re))
    except Exception as e:
        return error_response("Failed to retrieve incidents from Supabase", 500, details=str(e))

@incidents_bp.route("/api/incidents/<incident_id>", methods=["GET"])
def get_incident(incident_id):
    """
    Retrieve a single incident by its incident_id.
    """
    try:
        supabase = get_supabase_client()
        res = supabase.table("security_incidents").select("*").eq("incident_id", incident_id).limit(1).execute()
        if not res.data:
            return error_response(f"Incident with ID '{incident_id}' not found", 404)
        return api_response(data=res.data[0], message="Incident retrieved successfully", status_code=200)

    except RuntimeError as re:
        return error_response("Database configuration error", 503, details=str(re))
    except Exception as e:
        return error_response("Failed to fetch incident", 500, details=str(e))

@incidents_bp.route("/api/incidents", methods=["POST"])
def create_incident():
    """
    Create a new security incident in Supabase PostgreSQL.
    """
    if not request.is_json:
        return error_response("Request body must be JSON with Content-Type: application/json", 400)

    data = request.get_json()
    if not isinstance(data, dict):
        return error_response("Payload must be a JSON object", 400)

    required_fields = ["title", "description", "severity"]
    for field in required_fields:
        val = data.get(field)
        if not val or not str(val).strip():
            return error_response(f"Missing or empty required field: '{field}'", 400)

    title = str(data["title"]).strip()
    description = str(data["description"]).strip()
    severity = str(data["severity"]).strip().lower()

    if severity not in VALID_SEVERITIES:
        return error_response(f"Invalid severity '{severity}'. Must be one of: {sorted(list(VALID_SEVERITIES))}", 400)

    status = str(data.get("status", "open")).strip().lower()
    if status not in VALID_INCIDENT_STATUSES:
        return error_response(f"Invalid status '{status}'. Must be one of: {sorted(list(VALID_INCIDENT_STATUSES))}", 400)

    incident_id = data.get("incident_id")
    if incident_id:
        incident_id = str(incident_id).strip()
    else:
        incident_id = f"INC-{uuid.uuid4().hex[:8].upper()}"

    actor_id = data.get("actor_id")
    event_id = data.get("event_id")
    assigned_to = data.get("assigned_to")
    now_iso = get_current_iso_timestamp()

    incident_record = {
        "incident_id": incident_id,
        "title": title,
        "description": description,
        "severity": severity,
        "status": status,
        "actor_id": actor_id,
        "event_id": event_id,
        "assigned_to": assigned_to,
        "resolved_at": None,
        "created_at": now_iso,
        "updated_at": now_iso
    }

    try:
        supabase = get_supabase_client()

        # Enforce unique incident_id
        check_res = supabase.table("security_incidents").select("incident_id").eq("incident_id", incident_id).execute()
        if check_res.data:
            return error_response(f"Incident with ID '{incident_id}' already exists", 409)

        insert_res = supabase.table("security_incidents").insert(incident_record).execute()
        saved = insert_res.data[0] if insert_res.data else incident_record

        return api_response(data=saved, message="Incident created successfully", status_code=201)

    except RuntimeError as re:
        return error_response("Database configuration error", 503, details=str(re))
    except Exception as e:
        err_str = str(e)
        if "23505" in err_str or "duplicate key" in err_str:
            return error_response("Duplicate incident ID conflict", 409, details=err_str)
        return error_response("Failed to create incident", 500, details=err_str)

@incidents_bp.route("/api/incidents/<incident_id>", methods=["PATCH"])
def update_incident(incident_id):
    """
    Update an existing security incident's status or assigned_to in Supabase PostgreSQL.
    Supported statuses: open, investigating, resolved, closed.
    """
    if not request.is_json:
        return error_response("Request body must be JSON with Content-Type: application/json", 400)

    data = request.get_json()
    if not isinstance(data, dict):
        return error_response("Payload must be a JSON object", 400)

    if not data:
        return error_response("Request body cannot be empty", 400)

    update_payload = {}

    # Validate status if provided
    if "status" in data:
        status_val = data.get("status")
        if not isinstance(status_val, str) or not status_val.strip():
            return error_response("Field 'status' must be a non-empty string", 400)
        status = status_val.strip().lower()
        if status not in VALID_INCIDENT_STATUSES:
            return error_response(
                f"Invalid status '{status}'. Must be one of: {sorted(list(VALID_INCIDENT_STATUSES))}",
                400
            )
        update_payload["status"] = status
        now_iso = get_current_iso_timestamp()
        update_payload["updated_at"] = now_iso
        if status in ("resolved", "closed"):
            update_payload["resolved_at"] = now_iso
        elif status in ("open", "investigating"):
            update_payload["resolved_at"] = None

    # Validate assigned_to if provided
    if "assigned_to" in data:
        assigned_val = data.get("assigned_to")
        update_payload["assigned_to"] = str(assigned_val).strip() if assigned_val else None
        if "updated_at" not in update_payload:
            update_payload["updated_at"] = get_current_iso_timestamp()

    if not update_payload:
        return error_response(
            "No updatable fields provided. Supported fields: 'status', 'assigned_to'",
            400
        )

    try:
        supabase = get_supabase_client()
        update_res = supabase.table("security_incidents").update(update_payload).eq("incident_id", incident_id).execute()
        if not update_res.data:
            return error_response(f"Incident with ID '{incident_id}' not found", 404)

        updated_incident = update_res.data[0]
        return api_response(data=updated_incident, message="Incident updated successfully", status_code=200)

    except RuntimeError as re:
        return error_response("Database configuration error", 503, details=str(re))
    except Exception as e:
        return error_response("Failed to update incident", 500, details=str(e))
