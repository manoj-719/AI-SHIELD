from security.agent_guard import process_agent_request
from security.data_classifier import scan_file
from security.dlp_engine import evaluate_file_transfer
import uuid
from datetime import datetime, timezone
from security.incident_analyzer import analyze_incident


def inspect_file(file_path):
    """Scan a file for sensitive information."""
    return scan_file(file_path)


def check_agent_access(agent_name, file_name, action="read",
                       destination="internal"):
    """Check whether an AI agent can access a file."""
    return process_agent_request(
        agent_name,
        file_name,
        action,
        destination
    )


def check_file_transfer(file_path, destination):
    """Apply DLP policy before a file transfer."""
    return evaluate_file_transfer(file_path, destination)
def create_transfer_event(file_path, destination, result):
    """Create a backend-compatible event for a file transfer attempt."""

    scan_result = result.get("scan_result", {})
    blocked = not result.get("allowed", False)

    return {
        "event_id": f"EVT-{uuid.uuid4().hex[:10]}",
        "event_type": "dlp_blocked_transfer" if blocked else "file_transfer",
        "actor_type": "employee",
        "actor_id": "system_user",
        "resource": str(file_path),
        "is_sensitive": scan_result.get("is_sensitive", False),
        "action": "transfer",
        "destination": destination,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": "security_engine",
        "description": result.get("reason", "File transfer evaluated")
    }
def investigate_security_event(event):
    """Analyze a security event and return an explanation."""
    return analyze_incident(event)