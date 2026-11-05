import uuid
from flask import Blueprint, request
from backend.database import get_supabase_client
from backend.utils.response import api_response, error_response
from backend.utils.validation import validate_employee_payload, get_current_iso_timestamp

employees_bp = Blueprint("employees", __name__)

@employees_bp.route("/api/employees", methods=["GET"])
def get_employees():
    """
    Retrieve employees from Supabase PostgreSQL database.
    Supports optional query filters: department, status, limit, offset.
    """
    department = request.args.get("department")
    status = request.args.get("status")

    try:
        limit = min(int(request.args.get("limit", 50)), 200)
        offset = max(int(request.args.get("offset", 0)), 0)
    except ValueError:
        return error_response("Query parameters 'limit' and 'offset' must be valid integers", 400)

    try:
        supabase = get_supabase_client()
        query = supabase.table("employees").select("*", count="exact")

        if department:
            query = query.eq("department", department)
        if status:
            query = query.eq("status", status)

        query = query.order("created_at", desc=True).range(offset, offset + limit - 1)
        res = query.execute()

        employees = res.data or []
        total_count = res.count if res.count is not None else len(employees)

        meta = {
            "total": total_count,
            "limit": limit,
            "offset": offset,
            "returned": len(employees)
        }
        return api_response(data=employees, message="Employees retrieved successfully", meta=meta, status_code=200)

    except RuntimeError as re:
        return error_response("Database configuration error", 503, details=str(re))
    except Exception as e:
        return error_response("Failed to retrieve employees from Supabase", 500, details=str(e))

@employees_bp.route("/api/employees/<employee_id>", methods=["GET"])
def get_employee(employee_id):
    """
    Retrieve a single employee by their employee_id.
    """
    try:
        supabase = get_supabase_client()
        res = supabase.table("employees").select("*").eq("employee_id", employee_id).limit(1).execute()
        if not res.data:
            return error_response(f"Employee with ID '{employee_id}' not found", 404)
        return api_response(data=res.data[0], message="Employee retrieved successfully", status_code=200)

    except RuntimeError as re:
        return error_response("Database configuration error", 503, details=str(re))
    except Exception as e:
        return error_response("Failed to fetch employee", 500, details=str(e))

@employees_bp.route("/api/employees", methods=["POST"])
def create_employee():
    """
    Register a new employee.
    Validates payload, enforces uniqueness on employee_id and email via Supabase,
    and inserts the record into PostgreSQL.
    """
    if not request.is_json:
        return error_response("Request body must be JSON with Content-Type: application/json", 400)

    payload = request.get_json()
    is_valid, err_msg, cleaned = validate_employee_payload(payload)
    if not is_valid:
        return error_response(err_msg, 400)

    try:
        supabase = get_supabase_client()

        # Check for existing email or employee_id
        check_res = supabase.table("employees").select("employee_id, email").or_(
            f"employee_id.eq.{cleaned['employee_id']},email.eq.{cleaned['email']}"
        ).execute()

        if check_res.data:
            for existing in check_res.data:
                if existing.get("employee_id") == cleaned["employee_id"]:
                    return error_response(f"Employee with ID '{cleaned['employee_id']}' already exists", 409)
                if existing.get("email") == cleaned["email"]:
                    return error_response(f"Employee with email '{cleaned['email']}' already exists", 409)

        insert_res = supabase.table("employees").insert(cleaned).execute()
        new_employee = insert_res.data[0] if insert_res.data else cleaned

        # Record action in activity_logs
        try:
            log_id = f"LOG-{uuid.uuid4().hex[:8].upper()}"
            supabase.table("activity_logs").insert({
                "log_id": log_id,
                "action": "create_employee",
                "performed_by": "system",
                "details": f"Registered employee {cleaned['employee_id']} ({cleaned['name']})",
                "ip_address": request.remote_addr,
                "timestamp": get_current_iso_timestamp()
            }).execute()
        except Exception as log_err:
            print(f"[Warning] Failed to log activity: {log_err}")

        return api_response(data=new_employee, message="Employee created successfully", status_code=201)

    except RuntimeError as re:
        return error_response("Database configuration error", 503, details=str(re))
    except Exception as e:
        err_str = str(e)
        if "23505" in err_str or "duplicate key" in err_str:
            return error_response("Duplicate employee record conflict", 409, details=err_str)
        return error_response("Failed to create employee", 500, details=err_str)
