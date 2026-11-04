from security.agent_guard import (
    check_permission,
    create_security_event,
    process_agent_request,
    set_agent_status,
)


tests = [
    ("invoice_agent", "invoices.csv", "read", "internal"),
    ("invoice_agent", "invoices.csv", "read", "personal_email"),
    ("invoice_agent", "invoices.csv", "write", "internal"),
    ("invoice_agent", "employee_salary.csv", "read", "internal"),
    ("unknown_agent", "invoices.csv", "read", "internal")
]

for agent, file, action, destination in tests:
    result = check_permission(agent, file, action, destination)

    event = create_security_event(
        agent, file, action, destination, result
    )

    decision = "ALLOW" if result["allowed"] else "DENY"

    print(f"{agent} | {action} | {destination} | {decision}")

    if event:
        print("  Security event:", event)
print("\n--- AI SHIELD EVENT CONTRACT CHECK ---")

required_fields = [
    "event_id",
    "event_type",
    "actor_type",
    "actor_id",
    "resource",
    "is_sensitive",
    "action",
    "destination",
    "timestamp",
    "source",
    "description"
]

if event:
    missing_fields = [
        field for field in required_fields
        if field not in event
    ]

    if not missing_fields:
        print("SUCCESS: All 11 contract fields are present.")
    else:
        print("Missing fields:", missing_fields)
print("\n--- INTEGRATION TEST ---")

response = process_agent_request(
    "invoice_agent",
    "employee_salary.csv",
    "read",
    "internal"
)

print("Allowed:", response["allowed"])
print("Reason:", response["reason"])
print("Security event:", response["event"])
print("\n--- DLP TEST ---")

dlp_response = process_agent_request(
    "invoice_agent",
    "customer_records.csv",
    "read",
    "personal_email"
)

print("Allowed:", dlp_response["allowed"])
print("Reason:", dlp_response["reason"])
print("Sensitive:", dlp_response["event"]["is_sensitive"])
print("Destination:", dlp_response["event"]["destination"])
import pytest

from security.agent_guard import (
    check_permission,
    process_agent_request,
    set_agent_status,
)


def test_invoice_agent_can_read_invoice():
    result = check_permission(
        "invoice_agent",
        "invoices.csv"
    )

    assert result["allowed"] is True


def test_invoice_agent_cannot_access_salary_file():
    result = check_permission(
        "invoice_agent",
        "employee_salary.csv"
    )

    assert result["allowed"] is False


def test_unknown_agent_is_rejected():
    result = check_permission(
        "unknown_agent",
        "invoices.csv"
    )

    assert result["allowed"] is False
    assert result["reason"] == "Unknown agent"


def test_agent_cannot_access_path_traversal():
    result = check_permission(
        "invoice_agent",
        "../employee_salary.csv"
    )

    assert result["allowed"] is False


def test_agent_can_be_deactivated_and_reactivated():
    set_agent_status("invoice_agent", False)

    result = check_permission(
        "invoice_agent",
        "invoices.csv"
    )

    assert result["allowed"] is False

    set_agent_status("invoice_agent", True)

    result = check_permission(
        "invoice_agent",
        "invoices.csv"
    )

    assert result["allowed"] is True
def test_agent_suspended_after_three_violations():
    results = [
        process_agent_request("hr_agent", "restricted.csv")
        for _ in range(3)
    ]

    assert results[0]["violation"]["violation_count"] == 1
    assert results[1]["violation"]["violation_count"] == 2
    assert results[2]["violation"]["agent_suspended"] is True

    result = process_agent_request("hr_agent", "employee_salary.csv")

    assert result["allowed"] is False
    assert result["reason"] == "Agent is inactive"