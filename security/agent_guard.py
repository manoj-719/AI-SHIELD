from pathlib import Path
from datetime import datetime, timezone
import uuid

from security.data_classifier import scan_file
from security.violation_tracker import record_violation
from security.agent_persistence import (
    get_persistent_agent_state,
    get_persistent_agent,
    save_agent_status,
    sync_agent_registry_from_db
)

# Registered AI agents and their permitted resources
AGENT_REGISTRY = {
    "invoice_agent": {
        "active": True,
        "allowed_files": [
            "invoices.csv",
            "customer_orders.csv",
            "customer_records.csv"
        ],
        "allowed_actions": ["read"],
        "allowed_destinations": ["internal"]
    },
    "hr_agent": {
        "active": True,
        "allowed_files": [
            "employee_salary.csv",
            "employee_records.csv"
        ],
        "allowed_actions": ["read"],
        "allowed_destinations": ["internal"]
    }
}

# Keep the existing variable for backward compatibility
AGENT_PERMISSIONS = {
    name: details["allowed_files"]
    for name, details in AGENT_REGISTRY.items()
}

# Sync in-memory registry with persistent database state on module load
try:
    sync_agent_registry_from_db(AGENT_REGISTRY)
except Exception:
    pass


def is_sensitive_file(file_name):
    if any(keyword in file_name.lower() for keyword in [
        "salary", "customer", "employee", "personal",
        "payment", "bank", "aadhaar"
    ]):
        return True

    file_path = Path(file_name)

    if file_path.is_file():
        try:
            return scan_file(file_path)["is_sensitive"]
        except (ValueError, OSError):
            return True

    return False


def check_permission(
    agent_name,
    file_name,
    action="read",
    destination="internal"
):
    requested_file = Path(file_name)

    if requested_file.name != file_name:
        return {
            "allowed": False,
            "reason": "Invalid file path"
        }

    agent = AGENT_REGISTRY.get(agent_name)

    if agent is None:
        return {
            "allowed": False,
            "reason": "Unknown agent"
        }

    # Verify active status against persistent store (fail closed on unverifiable)
    try:
        state, persisted = get_persistent_agent_state(agent_name)
        if state == "suspended":
            AGENT_REGISTRY[agent_name]["active"] = False
            agent["active"] = False
            return {
                "allowed": False,
                "reason": "Agent is inactive"
            }
        elif state == "unverifiable":
            AGENT_REGISTRY[agent_name]["active"] = False
            agent["active"] = False
            return {
                "allowed": False,
                "reason": "Agent persistence state unverifiable (fail-closed security policy)"
            }
        elif state == "active":
            AGENT_REGISTRY[agent_name]["active"] = True
            agent["active"] = True
    except Exception as e:
        print(f"[AgentGuard] Notice: Database state check notice: {e}")
        AGENT_REGISTRY[agent_name]["active"] = False
        agent["active"] = False
        return {
            "allowed": False,
            "reason": "Agent persistence state unverifiable (fail-closed security policy)"
        }

    if not agent["active"]:
        return {
            "allowed": False,
            "reason": "Agent is inactive"
        }

    elif file_name not in agent["allowed_files"]:
        reason = "Agent is not authorized to access this file"

    elif action not in agent["allowed_actions"]:
        reason = "Unauthorized action"

    elif destination not in agent["allowed_destinations"]:
        if is_sensitive_file(file_name):
            reason = "DLP blocked external sharing of sensitive data"
        else:
            reason = "Destination is not allowed"

    else:
        return {
            "allowed": True,
            "reason": "Agent has permission"
        }

    return {
        "allowed": False,
        "reason": reason
    }


def create_security_event(
    agent_name,
    file_name,
    action,
    destination,
    result
):
    if result["allowed"]:
        return None

    return {
        "event_id": f"EVT-{uuid.uuid4().hex[:8]}",
        "event_type": "unauthorized_agent_access",
        "actor_type": "agent",
        "actor_id": agent_name,
        "resource": file_name,
        "is_sensitive": is_sensitive_file(file_name),
        "action": action,
        "destination": destination,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": "agent_guard",
        "description": result["reason"]
    }


def process_agent_request(
    agent_name,
    file_name,
    action="read",
    destination="internal"
):
    result = check_permission(
        agent_name,
        file_name,
        action,
        destination
    )

    event = create_security_event(
        agent_name,
        file_name,
        action,
        destination,
        result
    )

    violation = None

    if not result["allowed"]:
        violation = record_violation(agent_name)

    if violation and violation["suspicious"] and agent_name in AGENT_REGISTRY:
        set_agent_status(
            agent_name,
            False,
            reason="Agent automatically suspended after repeated violations"
        )
        violation["message"] = (
            "Agent automatically suspended after repeated violations"
        )
        violation["agent_suspended"] = True

    return {
        "allowed": result["allowed"],
        "reason": result["reason"],
        "event": event,
        "violation": violation
    }


def set_agent_status(agent_name, active, reason=None):
    if agent_name not in AGENT_REGISTRY:
        raise ValueError("Unknown agent")

    AGENT_REGISTRY[agent_name]["active"] = bool(active)

    try:
        save_agent_status(agent_name, bool(active), reason=reason)
    except Exception as e:
        print(f"[AgentGuard] Notice: Failed to persist agent status: {e}")

    return {
        "agent": agent_name,
        "active": AGENT_REGISTRY[agent_name]["active"]
    }
