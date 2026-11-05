import sys
from datetime import datetime, timezone
from flask import Blueprint
from backend.database import check_supabase_connection
from backend.utils.response import api_response, error_response

health_bp = Blueprint("health", __name__)

@health_bp.route("/api/health", methods=["GET"])
def health_check():
    """
    Health check endpoint.
    Verifies that the backend server is running and tests actual connectivity
    to Supabase PostgreSQL database.
    """
    is_connected, message = check_supabase_connection()

    payload = {
        "status": "healthy" if is_connected else "degraded",
        "database": "connected" if is_connected else "disconnected",
        "database_type": "supabase_postgresql",
        "service": "AI Shield Backend API",
        "version": "1.0.0",
        "python_version": sys.version.split()[0],
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

    if is_connected:
        return api_response(data=payload, message="System and Supabase database are operational", status_code=200)
    else:
        payload["message"] = message
        return error_response(
            message="Database connection unavailable",
            status_code=503,
            details=payload
        )
