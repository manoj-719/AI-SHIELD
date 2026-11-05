"""
Database Seed Script for AI Shield Platform (Supabase PostgreSQL).
Seeds development-only sample data for employees, security events, incidents, alerts, and activity logs.
Uses upsert on unique keys to prevent duplicate records when executed repeatedly.

Run via: python backend/seed.py
"""

import sys
from pathlib import Path
from datetime import datetime, timezone

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.config import Config
from backend.database import get_supabase_client, check_supabase_connection

SAMPLE_EMPLOYEES = [
    {
        "employee_id": "EMP001",
        "name": "Alice Chen",
        "email": "alice.chen@aishield.local",
        "department": "Security Operations",
        "role": "Senior Security Analyst",
        "risk_score": 12.50,
        "status": "active"
    },
    {
        "employee_id": "EMP002",
        "name": "Bob Smith",
        "email": "bob.smith@aishield.local",
        "department": "Finance",
        "role": "Financial Analyst",
        "risk_score": 68.00,
        "status": "under_investigation"
    },
    {
        "employee_id": "EMP003",
        "name": "Carol Danvers",
        "email": "carol.danvers@aishield.local",
        "department": "Engineering",
        "role": "Lead Systems Architect",
        "risk_score": 8.00,
        "status": "active"
    },
    {
        "employee_id": "EMP004",
        "name": "David Miller",
        "email": "david.miller@aishield.local",
        "department": "Marketing",
        "role": "Growth Specialist",
        "risk_score": 35.00,
        "status": "active"
    },
    {
        "employee_id": "EMP005",
        "name": "Elena Rostova",
        "email": "elena.rostova@aishield.local",
        "department": "Infrastructure",
        "role": "Cloud DevOps Engineer",
        "risk_score": 15.00,
        "status": "active"
    }
]

SAMPLE_EVENTS = [
    {
        "event_id": "EVT001",
        "event_type": "file_share",
        "actor_type": "employee",
        "actor_id": "EMP002",
        "resource": "customer_records.csv",
        "is_sensitive": True,
        "action": "share",
        "destination": "personal_email",
        "timestamp": "2026-11-04T10:30:00Z",
        "source": "employee_simulator",
        "description": "Attempted external file sharing of sensitive customer list",
        "rule_result": "flagged_dlp_violation",
        "anomaly": True,
        "risk_score": 82.50,
        "risk_level": "high",
        "recommended_action": "quarantine_attachment_and_notify_manager"
    },
    {
        "event_id": "EVT002",
        "event_type": "authentication",
        "actor_type": "employee",
        "actor_id": "EMP004",
        "resource": "/admin/dashboard",
        "is_sensitive": True,
        "action": "login",
        "destination": "internal",
        "timestamp": "2026-11-04T11:15:22Z",
        "source": "auth_service",
        "description": "Multiple consecutive failed logins followed by success from foreign IP",
        "rule_result": "flagged_brute_force",
        "anomaly": True,
        "risk_score": 64.00,
        "risk_level": "medium",
        "recommended_action": "force_mfa_challenge"
    },
    {
        "event_id": "EVT003",
        "event_type": "api_request",
        "actor_type": "agent",
        "actor_id": "agent_indexer_01",
        "resource": "/api/v1/catalog",
        "is_sensitive": False,
        "action": "read",
        "destination": "internal",
        "timestamp": "2026-11-04T11:45:00Z",
        "source": "api_gateway",
        "description": "Routine scheduled indexing of catalog assets",
        "rule_result": "allowed",
        "anomaly": False,
        "risk_score": 5.00,
        "risk_level": "low",
        "recommended_action": "none"
    },
    {
        "event_id": "EVT004",
        "event_type": "data_export",
        "actor_type": "employee",
        "actor_id": "EMP002",
        "resource": "q3_payroll_sensitive.xlsx",
        "is_sensitive": True,
        "action": "read",
        "destination": "removable_media",
        "timestamp": "2026-11-04T12:05:10Z",
        "source": "endpoint_agent",
        "description": "Large payroll spreadsheet copied to removable storage device",
        "rule_result": "flagged_removable_media",
        "anomaly": True,
        "risk_score": 91.00,
        "risk_level": "critical",
        "recommended_action": "block_removable_media_and_escalate"
    }
]

SAMPLE_INCIDENTS = [
    {
        "incident_id": "INC001",
        "title": "Suspected Data Exfiltration by Finance Employee",
        "description": "Multiple indicators of sensitive file exfiltration (customer records & payroll) involving EMP002.",
        "severity": "critical",
        "status": "investigating",
        "actor_id": "EMP002",
        "event_id": "EVT004",
        "assigned_to": "EMP001"
    },
    {
        "incident_id": "INC002",
        "title": "Anomalous Administrative Portal Login",
        "description": "Off-hours login to /admin/dashboard with geographic velocity anomaly.",
        "severity": "medium",
        "status": "open",
        "actor_id": "EMP004",
        "event_id": "EVT002",
        "assigned_to": "EMP001"
    }
]

SAMPLE_ALERTS = [
    {
        "alert_id": "ALT001",
        "event_id": "EVT001",
        "incident_id": "INC001",
        "alert_type": "DLP_VIOLATION",
        "severity": "high",
        "message": "Sensitive customer_records.csv shared to external address."
    },
    {
        "alert_id": "ALT002",
        "event_id": "EVT004",
        "incident_id": "INC001",
        "alert_type": "REMOVABLE_MEDIA_EXFILTRATION",
        "severity": "critical",
        "message": "Payroll document copied to USB drive by EMP002."
    },
    {
        "alert_id": "ALT003",
        "event_id": "EVT002",
        "incident_id": "INC002",
        "alert_type": "ANOMALOUS_AUTHENTICATION",
        "severity": "medium",
        "message": "Unusual IP login detected for EMP004."
    }
]

def seed_database():
    """Seed Supabase PostgreSQL with sample development data using upserts."""
    if not Config.is_supabase_configured():
        print("[Seed Error] Cannot seed: SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are not configured.")
        print("[Seed Error] Please add them to your backend/.env file.")
        return False

    is_conn, msg = check_supabase_connection()
    if not is_conn:
        print(f"[Seed Error] Cannot seed: {msg}")
        return False

    supabase = get_supabase_client()
    now_iso = datetime.now(timezone.utc).isoformat()

    print("[Seed] Seeding sample employees (upsert on employee_id)...")
    for emp in SAMPLE_EMPLOYEES:
        payload = dict(emp)
        payload["created_at"] = now_iso
        payload["updated_at"] = now_iso
        supabase.table("employees").upsert(payload, on_conflict="employee_id").execute()

    print("[Seed] Seeding sample security events (upsert on event_id)...")
    for evt in SAMPLE_EVENTS:
        payload = dict(evt)
        payload["created_at"] = now_iso
        supabase.table("security_events").upsert(payload, on_conflict="event_id").execute()

    print("[Seed] Seeding sample security incidents (upsert on incident_id)...")
    for inc in SAMPLE_INCIDENTS:
        payload = dict(inc)
        payload["created_at"] = now_iso
        payload["updated_at"] = now_iso
        supabase.table("security_incidents").upsert(payload, on_conflict="incident_id").execute()

    print("[Seed] Seeding sample alerts (upsert on alert_id)...")
    for alt in SAMPLE_ALERTS:
        payload = dict(alt)
        payload["is_read"] = False
        payload["created_at"] = now_iso
        supabase.table("alerts").upsert(payload, on_conflict="alert_id").execute()

    print("[Seed] Seeding initial activity log...")
    supabase.table("activity_logs").upsert({
        "log_id": "LOG-INIT-001",
        "action": "system_seed",
        "performed_by": "seed_script",
        "details": "Development seed dataset populated via Supabase client",
        "ip_address": "127.0.0.1",
        "timestamp": now_iso
    }, on_conflict="log_id").execute()

    print("[Seed] Supabase development seed completed successfully without duplicates!")
    return True

if __name__ == "__main__":
    success = seed_database()
    sys.exit(0 if success else 1)
