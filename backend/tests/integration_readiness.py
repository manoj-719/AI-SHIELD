"""
AI Shield - Backend Integration Readiness Test.
Executes an end-to-end audit across 8 realistic security scenarios through the actual Flask API.
Verifies persistence, risk calculation, Rule 4 preservation, alert/incident triggers, and cleanup.

Run via: python backend/tests/integration_readiness.py
"""

import sys
import json
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app import create_app
from backend.database import get_supabase_client

TEST_EVENT_PREFIX = "READY_TEST_"

def run_integration_readiness_test():
    print("=" * 80)
    print("AI Shield — Backend Integration Readiness Test (Realistic End-to-End Audit)")
    print("=" * 80)

    app = create_app()
    client = app.test_client()
    db = get_supabase_client()

    created_events = []
    created_alerts = []
    created_incidents = []

    # Check baseline seed data
    baseline_events = db.table("security_events").select("count", count="exact").execute().count or 0
    baseline_incidents = db.table("security_incidents").select("count", count="exact").execute().count or 0
    baseline_alerts = db.table("alerts").select("count", count="exact").execute().count or 0
    print(f"\n[Baseline Supabase State] Events: {baseline_events} | Incidents: {baseline_incidents} | Alerts: {baseline_alerts}")

    scenarios = [
        {
            "name": "1. Normal employee file access",
            "payload": {
                "event_id": f"{TEST_EVENT_PREFIX}01_NORM_READ",
                "event_type": "file_access",
                "actor_type": "employee",
                "actor_id": "EMP001",
                "resource": "project_roadmap.pdf",
                "is_sensitive": False,
                "action": "read",
                "destination": "internal",
                "source": "employee_simulator",
                "description": "Routine employee reading non-sensitive team roadmap"
            },
            "expected_status": 201,
            "expected_risk": "low",
            "expected_rule": "allowed",
            "expect_alert": False,
            "expect_incident": False
        },
        {
            "name": "2. Sensitive employee record access",
            "payload": {
                "event_id": f"{TEST_EVENT_PREFIX}02_SENS_EMP_ACCESS",
                "event_type": "file_access",
                "actor_type": "employee",
                "actor_id": "EMP002",
                "resource": "employee_performance_q3.csv",
                "is_sensitive": True,
                "action": "read",
                "destination": "internal",
                "source": "employee_simulator",
                "description": "Internal authorized read of sensitive employee evaluations"
            },
            "expected_status": 201,
            "expected_risk": "medium",
            "expected_rule": "allowed_with_audit",
            "expect_alert": False,
            "expect_incident": False
        },
        {
            "name": "3. Sensitive file downloaded",
            "payload": {
                "event_id": f"{TEST_EVENT_PREFIX}03_SENS_DOWNLOAD",
                "event_type": "file_download",
                "actor_type": "employee",
                "actor_id": "EMP003",
                "resource": "q4_payroll_master.xlsx",
                "is_sensitive": True,
                "action": "download",
                "destination": "internal_workstation",
                "source": "employee_simulator",
                "description": "Internal download of payroll document to authorized workstation"
            },
            "expected_status": 201,
            "expected_risk": "medium",
            "expected_rule": "allowed_with_audit",
            "expect_alert": False,
            "expect_incident": False
        },
        {
            "name": "4. Sensitive file shared with an external email",
            "payload": {
                "event_id": f"{TEST_EVENT_PREFIX}04_DLP_EXT_SHARE",
                "event_type": "file_share",
                "actor_type": "employee",
                "actor_id": "EMP002",
                "resource": "customer_pii_vault.csv",
                "is_sensitive": True,
                "action": "share",
                "destination": "personal_external_mail@gmail.com",
                "source": "employee_simulator",
                "description": "Attempted file transfer of sensitive customer list to external personal email"
            },
            "expected_status": 201,
            "expected_risk": "critical",
            "expected_rule": "flagged_dlp_external_share",
            "expect_alert": True,
            "expect_incident": True
        },
        {
            "name": "5. Unauthorized AI agent access",
            "payload": {
                "event_id": f"{TEST_EVENT_PREFIX}05_UNAUTH_AGENT",
                "event_type": "api_request",
                "actor_type": "agent",
                "actor_id": "external_crawler_bot",
                "resource": "/admin/keys/production_secrets.env",
                "is_sensitive": True,
                "action": "read",
                "destination": "internal",
                "source": "api_gateway",
                "description": "Autonomous AI agent attempted access to administrative secrets file"
            },
            "expected_status": 201,
            "expected_risk": "critical",
            "expected_rule": "flagged_unauthorized_agent_access",
            "expect_alert": True,
            "expect_incident": True
        },
        {
            "name": "6. Repeated suspicious API requests",
            "payload": {
                "event_id": f"{TEST_EVENT_PREFIX}06_SUSPICIOUS_API",
                "event_type": "api_request",
                "actor_type": "external",
                "actor_id": "external_client_99.123",
                "resource": "/api/v1/auth/login",
                "is_sensitive": True,
                "action": "login",
                "destination": "internal",
                "source": "auth_service",
                "description": "Burst of anomalous failed login attempts from unknown subnet",
                "anomaly": True,
                "risk_score": 75.0
            },
            "expected_status": 201,
            "expected_risk": "high",
            "expected_rule": "flagged_by_ml_anomaly",
            "expect_alert": True,
            "expect_incident": False
        },
        {
            "name": "7. High anomaly score",
            "payload": {
                "event_id": f"{TEST_EVENT_PREFIX}07_HIGH_ANOMALY",
                "event_type": "data_export",
                "actor_type": "employee",
                "actor_id": "EMP004",
                "resource": "anomalous_bulk_export.json",
                "is_sensitive": False,
                "action": "export",
                "destination": "unknown_staging_bucket",
                "source": "endpoint_agent",
                "description": "Extreme statistical anomaly detected during off-hours",
                "anomaly": True,
                "risk_score": 88.0
            },
            "expected_status": 201,
            "expected_risk": "critical",
            "expected_rule": "flagged_by_ml_anomaly",
            "expect_alert": True,
            "expect_incident": True
        },
        {
            "name": "8. Normal internal activity",
            "payload": {
                "event_id": f"{TEST_EVENT_PREFIX}08_NORM_AUTH",
                "event_type": "authentication",
                "actor_type": "employee",
                "actor_id": "EMP005",
                "resource": "/dashboard/overview",
                "is_sensitive": False,
                "action": "login",
                "destination": "internal",
                "source": "auth_service",
                "description": "Standard single sign-on user login during business hours"
            },
            "expected_status": 201,
            "expected_risk": "low",
            "expected_rule": "allowed",
            "expect_alert": False,
            "expect_incident": False
        }
    ]

    all_scenarios_passed = True
    audit_results = []

    try:
        print("\n--- EXECUTING SCENARIOS THROUGH ACTUAL FLASK API (POST /api/events) ---")
        for sc in scenarios:
            name = sc["name"]
            payload = sc["payload"]
            evt_id = payload["event_id"]

            res = client.post("/api/events", json=payload)
            status_code = res.status_code
            res_json = res.get_json() or {}
            data = res_json.get("data", {})
            meta = res_json.get("meta", {})

            if status_code == 201:
                created_events.append(evt_id)
                if meta.get("alert_id"):
                    created_alerts.append(meta["alert_id"])
                if meta.get("incident_id"):
                    created_incidents.append(meta["incident_id"])

            # Verify against database
            db_row = db.table("security_events").select("*").eq("event_id", evt_id).execute()
            persisted = len(db_row.data) == 1
            persisted_record = db_row.data[0] if persisted else {}

            rule_res = persisted_record.get("rule_result")
            risk_level = persisted_record.get("risk_level")
            risk_score = persisted_record.get("risk_score")
            rec_action = persisted_record.get("recommended_action")

            alert_exists = bool(meta.get("alert_id"))
            incident_exists = bool(meta.get("incident_id"))

            status_match = (status_code == sc["expected_status"])
            risk_match = (risk_level == sc["expected_risk"])
            alert_match = (alert_exists == sc["expect_alert"])
            incident_match = (incident_exists == sc["expect_incident"])

            passed = status_match and persisted and risk_match and alert_match and incident_match
            if not passed:
                all_scenarios_passed = False

            mark = "[PASS]" if passed else "[FAIL]"
            print(f"{mark} {name}")
            print(f"       HTTP {status_code} | Persisted: {persisted} | Rule: {rule_res} | Risk: {risk_level} ({risk_score})")
            print(f"       Alert Generated: {alert_exists} | Incident Generated: {incident_exists} | Action: {rec_action}")

            audit_results.append({
                "scenario": name,
                "passed": passed,
                "http_status": status_code,
                "persisted": persisted,
                "rule_result": rule_res,
                "risk_level": risk_level,
                "risk_score": risk_score,
                "alert": alert_exists,
                "incident": incident_exists,
                "action": rec_action
            })

        # --- SPECIAL VERIFICATION 1: RULE 4 HARD DENIAL PRESERVATION ---
        print("\n--- SPECIAL VERIFICATION: RULE 4 HARD DENIAL PRESERVATION ---")
        rule4_evt_id = f"{TEST_EVENT_PREFIX}09_RULE4_PRESERVATION"
        rule4_payload = {
            "event_id": rule4_evt_id,
            "event_type": "file_share",
            "actor_type": "employee",
            "actor_id": "EMP002",
            "resource": "ip_patents.zip",
            "is_sensitive": True,
            "action": "share",
            "destination": "external_malicious_server.ru",
            "source": "dlp_agent",
            "description": "Exfiltration attempt with deceptive low ML score injected",
            "anomaly": False,
            "risk_score": 5.0
        }
        r4_res = client.post("/api/events", json=rule4_payload)
        r4_data = (r4_res.get_json() or {}).get("data", {})
        r4_meta = (r4_res.get_json() or {}).get("meta", {})
        created_events.append(rule4_evt_id)
        if r4_meta.get("alert_id"):
            created_alerts.append(r4_meta["alert_id"])
        if r4_meta.get("incident_id"):
            created_incidents.append(r4_meta["incident_id"])

        r4_passed = (
            r4_res.status_code == 201 and
            r4_data.get("risk_level") == "critical" and
            r4_data.get("risk_score") >= 85.0 and
            r4_data.get("rule_result") == "flagged_dlp_external_share"
        )
        if not r4_passed:
            all_scenarios_passed = False
        r4_mark = "[PASS]" if r4_passed else "[FAIL]"
        print(f"{r4_mark} Rule 4 Hard Denial Preservation (Injected low ML score 5.0 overridden by hard denial)")
        print(f"       Resulting Risk Level: {r4_data.get('risk_level')} | Final Risk Score: {r4_data.get('risk_score')}")

        # --- SPECIAL VERIFICATION 2: DUPLICATE EVENT ID REJECTION ---
        print("\n--- SPECIAL VERIFICATION: DUPLICATE EVENT REJECTION ---")
        dup_res = client.post("/api/events", json=scenarios[0]["payload"])
        dup_passed = (dup_res.status_code == 409)
        if not dup_passed:
            all_scenarios_passed = False
        dup_mark = "[PASS]" if dup_passed else "[FAIL]"
        print(f"{dup_mark} Duplicate Event ID Rejection (Re-submitting event 01 returns HTTP 409 Conflict)")

    finally:
        print("\n--- CLEANING UP TEST RECORDS IN SUPABASE (PRESERVING SEED DATA) ---")
        deleted_alerts_count = 0
        deleted_incidents_count = 0
        deleted_events_count = 0

        # 1. Clean alerts created during this run
        for alt_id in created_alerts:
            try:
                db.table("alerts").delete().eq("alert_id", alt_id).execute()
                deleted_alerts_count += 1
            except Exception as e:
                print(f"Warning: Failed to clean alert {alt_id}: {e}")

        # 2. Clean incidents created during this run
        for inc_id in created_incidents:
            try:
                db.table("security_incidents").delete().eq("incident_id", inc_id).execute()
                deleted_incidents_count += 1
            except Exception as e:
                print(f"Warning: Failed to clean incident {inc_id}: {e}")

        # 3. Clean events created during this run
        for evt_id in created_events:
            try:
                db.table("security_events").delete().eq("event_id", evt_id).execute()
                deleted_events_count += 1
            except Exception as e:
                print(f"Warning: Failed to clean event {evt_id}: {e}")

        print(f"Cleaned test records: {deleted_events_count} events, {deleted_alerts_count} alerts, {deleted_incidents_count} incidents.")

        # Post-test baseline verification
        final_events = db.table("security_events").select("count", count="exact").execute().count or 0
        final_incidents = db.table("security_incidents").select("count", count="exact").execute().count or 0
        final_alerts = db.table("alerts").select("count", count="exact").execute().count or 0
        seed_preserved = (
            final_events == baseline_events and
            final_incidents == baseline_incidents and
            final_alerts == baseline_alerts
        )
        print(f"[Final Supabase State] Events: {final_events} | Incidents: {final_incidents} | Alerts: {final_alerts}")
        print(f"[Seed Preservation Status] Seed data intact and untouched: {seed_preserved}")

    print("\n" + "=" * 80)
    readiness = "READY FOR TEAMMATE MODULE INTEGRATION" if (all_scenarios_passed and seed_preserved) else "NOT READY"
    print(f"CONCLUSION: {readiness}")
    print("=" * 80)
    return all_scenarios_passed and seed_preserved

if __name__ == "__main__":
    success = run_integration_readiness_test()
    sys.exit(0 if success else 1)
