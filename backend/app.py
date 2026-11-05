import os
import sys
from pathlib import Path
from flask import Flask, request, jsonify

# Ensure project root is in sys.path for direct script execution
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.config import Config
from backend.routes.health import health_bp
from backend.routes.employees import employees_bp
from backend.routes.events import events_bp
from backend.routes.incidents import incidents_bp
from backend.routes.alerts import alerts_bp
from backend.utils.response import error_response

def create_app(test_config=None):
    """
    Application factory for AI Shield backend powered by Supabase PostgreSQL.
    """
    app = Flask(__name__)

    # Default configuration
    app.config.from_object(Config)

    # Override configuration if provided (useful for tests)
    if test_config:
        app.config.update(test_config)

    # Log Supabase configuration state on startup
    if Config.is_supabase_configured():
        print(f"[App] Supabase configured with URL: {Config.SUPABASE_URL}")
    else:
        print("[App] Notice: Supabase credentials not set or placeholder in .env. Configure SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY to connect.")

    # Register blueprints
    app.register_blueprint(health_bp)
    app.register_blueprint(employees_bp)
    app.register_blueprint(events_bp)
    app.register_blueprint(incidents_bp)
    app.register_blueprint(alerts_bp)

    # Root route for quick discovery
    @app.route("/", methods=["GET"])
    def root():
        return jsonify({
            "service": "AI Shield Security Platform API",
            "database_backend": "Supabase PostgreSQL",
            "status": "online",
            "endpoints": [
                "/api/health",
                "/api/employees",
                "/api/events",
                "/api/incidents",
                "/api/alerts"
            ],
            "documentation": "/docs/api_contract.md"
        }), 200

    # Universal CORS support
    @app.after_request
    def apply_cors_headers(response):
        allowed_origin = app.config.get("CORS_ORIGIN", "*")
        response.headers["Access-Control-Allow-Origin"] = allowed_origin
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS, PATCH"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Requested-With"
        return response

    # Global error handlers returning JSON
    @app.errorhandler(400)
    def bad_request(e):
        return error_response(str(e.description) if hasattr(e, "description") else "Bad Request", 400)

    @app.errorhandler(404)
    def not_found(e):
        return error_response("Endpoint or resource not found", 404)

    @app.errorhandler(405)
    def method_not_allowed(e):
        return error_response("HTTP method not allowed for this endpoint", 405)

    @app.errorhandler(500)
    def internal_error(e):
        return error_response("Internal server error", 500)

    return app

if __name__ == "__main__":
    app = create_app()
    host = app.config.get("HOST", "127.0.0.1")
    port = app.config.get("PORT", 5000)
    debug = app.config.get("DEBUG", True)
    print(f"[AI Shield] Starting Supabase backend server on http://{host}:{port} (debug={debug})")
    app.run(host=host, port=port, debug=debug)
