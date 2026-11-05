from security.incident_analyzer import analyze_incident


def test_high_risk_incident_analysis():

    event = {
        "event_id": "EVT-TEST001",
        "event_type": "dlp_blocked_transfer",
        "actor_type": "employee",
        "actor_id": "EMP001",
        "resource": "customer_data.csv",
        "is_sensitive": True,
        "action": "transfer",
        "destination": "personal_email",
        "timestamp": "2026-11-04T10:00:00+00:00",
        "source": "security_engine",
        "description": "Sensitive data transfer blocked"
    }

    result = analyze_incident(event)

    assert result["severity"] == "high"
    assert result["requires_review"] is True
    assert result["explanation"]
    assert result["recommendation"]
    assert len(result["recommended_actions"]) > 0


def test_low_risk_incident_analysis():

    event = {
        "event_id": "EVT-TEST002",
        "event_type": "file_access",
        "actor_type": "employee",
        "actor_id": "EMP002",
        "resource": "public_policy.pdf",
        "is_sensitive": False,
        "action": "read",
        "destination": "internal",
        "timestamp": "2026-11-04T10:05:00+00:00",
        "source": "security_engine",
        "description": "Normal file access"
    }

    result = analyze_incident(event)

    assert result["severity"] == "low"
    assert result["requires_review"] is False
    assert result["explanation"]
    assert result["recommendation"]