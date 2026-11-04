def analyze_incident(event):
    event_type = event.get("event_type", "")
    is_sensitive = event.get("is_sensitive", False)
    action = event.get("action", "")
    destination = event.get("destination", "")
    actor = event.get("actor_id", "Unknown")

    if event_type == "dlp_blocked_transfer":
        severity = "high"
        explanation = (
            f"User {actor} attempted to transfer a sensitive file "
            f"to {destination}. The DLP policy blocked the transfer."
        )
        recommendation = (
            "Keep the file restricted. Verify the user's identity "
            "and review whether the transfer was legitimate."
        )

    elif event_type == "unauthorized_agent_access":
        severity = "high"
        explanation = (
            f"AI agent {actor} attempted an unauthorized "
            f"{action} operation on a resource."
        )
        recommendation = (
            "Keep the access denied. Review the agent's permissions "
            "and investigate repeated attempts."
        )

    elif is_sensitive and destination != "internal":
        severity = "medium"
        explanation = (
            f"A sensitive resource was involved in an operation "
            f"with an external destination: {destination}."
        )
        recommendation = (
            "Review the destination and enforce the applicable "
            "data-sharing policy."
        )

    else:
        severity = "low"
        explanation = "A security event was recorded for review."
        recommendation = (
            "Review the event details and monitor for unusual activity."
        )

    return {
        "recommended_actions": (
    [
        "Keep the file quarantined",
        "Review employee access history",
        "Verify the external destination",
        "Record the incident for audit"
    ]
    if severity == "high"
    else [
        "Review the event",
        "Monitor for repeated activity"
    ]
),
        "event_id": event.get("event_id", "unknown"),
        "severity": severity,
        "explanation": explanation,
        "recommendation": recommendation,
        "requires_review": severity in ["high", "medium"]
    }