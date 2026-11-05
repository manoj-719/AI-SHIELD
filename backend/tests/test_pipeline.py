"""
AI Shield - Event Processing Pipeline Comprehensive Test Suite.
Tests all 10 core integration scenarios:
1. Normal low-risk event.
2. Sensitive file accessed internally.
3. Sensitive file shared externally (DLP).
4. Unauthorized agent access.
5. High ML anomaly score.
6. Hard security denial with a low ML score (Rule 4 preservation).
7. High-risk event generating an alert.
8. Duplicate event and incident handling.
9. Invalid event input.
10. Database failure handling.
"""

import os
import sys
import unittest
from unittest.mock import MagicMock, patch
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app import create_app
from backend.database import set_supabase_client, reset_supabase_client
from backend.pipeline import (
    process_security_event,
    SecurityRuleResult,
    MLAnomalyResult,
    calculate_composite_risk,
    set_security_adapter,
    reset_security_adapter,
    set_ml_adapter,
    reset_ml_adapter
)

class AIShieldPipelineTestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app({"TESTING": True})
        self.client = self.app.test_client()

        # In-memory mock store
        self.mock_store = {
            "employees": [],
            "security_events": [],
            "security_incidents": [],
            "alerts": [],
            "activity_logs": []
        }

        # Setup mock Supabase
        self.mock_client = self._create_mock_supabase()
        set_supabase_client(self.mock_client)

        # Reset pipeline adapters
        reset_security_adapter()
        reset_ml_adapter()

    def tearDown(self):
        reset_supabase_client()
        reset_security_adapter()
        reset_ml_adapter()

    def _create_mock_supabase(self):
        mock_client = MagicMock()

        def table_side_effect(table_name):
            store = self.mock_store.setdefault(table_name, [])

            class MockQueryBuilder:
                def __init__(self, store_ref):
                    self.store_ref = store_ref
                    self.items = list(store_ref)
                    self._count = len(self.items)
                    self._pending_insert = None

                def select(self, *args, **kwargs):
                    self.items = list(self.store_ref)
                    self._count = len(self.items)
                    return self

                def eq(self, field, value):
                    self.items = [x for x in self.items if str(x.get(field)) == str(value)]
                    self._count = len(self.items)
                    return self

                def or_(self, condition):
                    return self

                def order(self, field, desc=False):
                    return self

                def range(self, start, end):
                    self.items = self.items[start:end + 1]
                    return self

                def limit(self, count):
                    self.items = self.items[:count]
                    return self

                def insert(self, payload):
                    to_add = [dict(x) for x in payload] if isinstance(payload, list) else [dict(payload)]
                    for item in to_add:
                        if "id" not in item:
                            item["id"] = len(self.store_ref) + 1
                        self.store_ref.append(item)
                    self._pending_insert = to_add
                    return self

                def delete(self):
                    return self

                def execute(self):
                    res = MagicMock()
                    if self._pending_insert is not None:
                        res.data = self._pending_insert
                        res.count = len(self._pending_insert)
                    else:
                        res.data = self.items
                        res.count = len(self.items)
                    return res

            builder = MockQueryBuilder(store)
            table_mock = MagicMock()
            table_mock.select = builder.select
            table_mock.insert = builder.insert
            table_mock.delete = builder.delete
            return table_mock

        mock_client.table.side_effect = table_side_effect
        return mock_client

    # 1. Normal low-risk event
    def test_1_normal_low_risk_event(self):
        payload = {
            "event_id": "EVT_NORM_001",
            "event_type": "file_share",
            "actor_type": "employee",
            "actor_id": "EMP001",
            "resource": "team_meeting_notes.docx",
            "is_sensitive": False,
            "action": "read",
            "destination": "internal",
            "source": "employee_simulator",
            "description": "Routine read of team meeting notes"
        }
        success, result, code = process_security_event(payload, self.mock_client)
        self.assertTrue(success)
        self.assertEqual(code, 201)

        event = result["event"]
        self.assertEqual(event["risk_level"], "low")
        self.assertLess(event["risk_score"], 30.0)
        self.assertFalse(event["anomaly"])
        self.assertEqual(event["rule_result"], "allowed")
        self.assertIsNone(result["alert"])
        self.assertIsNone(result["incident"])

    # 2. Sensitive file accessed internally
    def test_2_sensitive_file_accessed_internally(self):
        payload = {
            "event_id": "EVT_SENS_INT_001",
            "event_type": "file_share",
            "actor_type": "employee",
            "actor_id": "EMP002",
            "resource": "q3_financial_audit.xlsx",
            "is_sensitive": True,
            "action": "read",
            "destination": "internal",
            "source": "employee_simulator",
            "description": "Authorized internal access to financial document"
        }
        success, result, code = process_security_event(payload, self.mock_client)
        self.assertTrue(success)
        self.assertEqual(code, 201)

        event = result["event"]
        self.assertEqual(event["rule_result"], "allowed_with_audit")
        self.assertEqual(event["risk_level"], "medium")
        self.assertEqual(event["recommended_action"], "log_sensitive_access")

    # 3. Sensitive file shared externally (DLP Violation)
    def test_3_sensitive_file_shared_externally(self):
        payload = {
            "event_id": "EVT_DLP_EXT_001",
            "event_type": "file_share",
            "actor_type": "employee",
            "actor_id": "EMP002",
            "resource": "customer_pii_records.csv",
            "is_sensitive": True,
            "action": "share",
            "destination": "personal_dropbox",
            "source": "employee_simulator",
            "description": "Attempted export of sensitive customer list to cloud storage"
        }
        success, result, code = process_security_event(payload, self.mock_client)
        self.assertTrue(success)
        self.assertEqual(code, 201)

        event = result["event"]
        self.assertEqual(event["rule_result"], "flagged_dlp_external_share")
        self.assertEqual(event["risk_level"], "critical")
        self.assertGreaterEqual(event["risk_score"], 85.0)
        self.assertEqual(event["recommended_action"], "quarantine_attachment_and_notify_manager")

        # Must trigger alert and incident
        self.assertIsNotNone(result["alert"])
        self.assertEqual(result["alert"]["severity"], "critical")
        self.assertIsNotNone(result["incident"])
        self.assertEqual(result["incident"]["severity"], "critical")

    # 4. Unauthorized agent access
    def test_4_unauthorized_agent_access(self):
        payload = {
            "event_id": "EVT_AGENT_UNAUTH_001",
            "event_type": "api_request",
            "actor_type": "agent",
            "actor_id": "crawler_bot_09",
            "resource": "/admin/payroll/master_keys.env",
            "is_sensitive": True,
            "action": "read",
            "destination": "internal",
            "source": "api_gateway",
            "description": "Autonomous bot attempted to access administrative credential file"
        }
        success, result, code = process_security_event(payload, self.mock_client)
        self.assertTrue(success)
        self.assertEqual(code, 201)

        event = result["event"]
        self.assertEqual(event["rule_result"], "flagged_unauthorized_agent_access")
        self.assertEqual(event["risk_level"], "critical")
        self.assertEqual(event["recommended_action"], "revoke_agent_token_and_isolate")

        # Alert and Incident must be created
        self.assertIsNotNone(result["alert"])
        self.assertEqual(result["alert"]["alert_type"], "UNAUTHORIZED_AGENT_ACCESS")
        self.assertIsNotNone(result["incident"])

    # 5. High ML anomaly score
    def test_5_high_ml_anomaly_score(self):
        class HighAnomalyMockMLAdapter:
            def score(self, event):
                return MLAnomalyResult(
                    anomaly=True,
                    risk_score=78.50,
                    risk_level="high",
                    factors=["Unusual temporal clustering", "Rapid burst queries"]
                )

        set_ml_adapter(HighAnomalyMockMLAdapter())

        payload = {
            "event_id": "EVT_ML_HIGH_001",
            "event_type": "api_request",
            "actor_type": "employee",
            "actor_id": "EMP004",
            "resource": "public_catalog_asset",
            "is_sensitive": False,
            "action": "read",
            "destination": "internal",
            "source": "gateway",
            "description": "High velocity read access"
        }
        success, result, code = process_security_event(payload, self.mock_client)
        self.assertTrue(success)

        event = result["event"]
        self.assertTrue(event["anomaly"])
        self.assertEqual(event["risk_level"], "high")
        self.assertGreaterEqual(event["risk_score"], 65.0)
        self.assertEqual(event["recommended_action"], "flag_for_analyst_review")

        # High risk generates an alert
        self.assertIsNotNone(result["alert"])
        self.assertEqual(result["alert"]["severity"], "high")

    # 6. Hard security denial with a low ML score (Rule 4 preservation)
    def test_6_hard_security_denial_with_low_ml_score(self):
        # Configure ML adapter to return a deceptive low risk score (5.0, no anomaly)
        class DeceptiveLowMLAdapter:
            def score(self, event):
                return MLAnomalyResult(
                    anomaly=False,
                    risk_score=5.00,
                    risk_level="low",
                    factors=["Model incorrectly predicts normal behavior"]
                )

        set_ml_adapter(DeceptiveLowMLAdapter())

        # Event triggers hard denial in security rules
        payload = {
            "event_id": "EVT_HARD_DENIAL_001",
            "event_type": "file_share",
            "actor_type": "employee",
            "actor_id": "EMP002",
            "resource": "secret_customer_records.csv",
            "is_sensitive": True,
            "action": "share",
            "destination": "external_attacker_site.com",
            "source": "dlp_agent",
            "description": "External exfiltration of sensitive document"
        }
        success, result, code = process_security_event(payload, self.mock_client)
        self.assertTrue(success)

        event = result["event"]
        # Rule 4: Hard security denial MUST NOT be overridden by low ML score
        self.assertEqual(event["risk_level"], "critical")
        self.assertGreaterEqual(event["risk_score"], 85.0)
        self.assertEqual(event["rule_result"], "flagged_dlp_external_share")
        self.assertTrue(result["risk_assessment"]["hard_denial_preserved"])

    # 7. High-risk event generating an alert
    def test_7_high_risk_event_generating_alert(self):
        payload = {
            "event_id": "EVT_ALERT_GEN_001",
            "event_type": "data_export",
            "actor_type": "employee",
            "actor_id": "EMP005",
            "resource": "sensitive_database_dump.sql",
            "is_sensitive": True,
            "action": "share",
            "destination": "external_ftp",
            "source": "backup_agent",
            "description": "Unauthorized database export to external server"
        }
        res = self.client.post("/api/events", json=payload)
        self.assertEqual(res.status_code, 201)
        data = res.get_json()
        self.assertTrue(data["success"])
        self.assertIn("alert_id", data["meta"])

        # Check alerts table in store
        alerts = self.mock_store["alerts"]
        matching = [a for a in alerts if a["event_id"] == "EVT_ALERT_GEN_001"]
        self.assertEqual(len(matching), 1)
        self.assertEqual(matching[0]["severity"], "critical")
        self.assertIn("Simulated event", matching[0]["message"])

    # 8. Duplicate event and incident handling
    def test_8_duplicate_event_and_incident_handling(self):
        payload = {
            "event_id": "EVT_DUP_TEST_001",
            "event_type": "file_share",
            "actor_type": "employee",
            "actor_id": "EMP001",
            "resource": "shared_doc.pdf",
            "is_sensitive": True,
            "action": "share",
            "destination": "external_web",
            "source": "test_simulator",
            "description": "Testing duplicate prevention"
        }
        # First insertion succeeds
        res1 = self.client.post("/api/events", json=payload)
        self.assertEqual(res1.status_code, 201)

        # Second insertion with same event_id must return 409 Conflict
        res2 = self.client.post("/api/events", json=payload)
        self.assertEqual(res2.status_code, 409)
        data2 = res2.get_json()
        self.assertIn("already exists", data2["error"])

    # 9. Invalid event input
    def test_9_invalid_event_input(self):
        # Missing required actor_type and action
        invalid_payload = {
            "event_id": "EVT_BAD_001",
            "resource": "doc.txt"
        }
        res = self.client.post("/api/events", json=invalid_payload)
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertFalse(data["success"])

        # Non-JSON payload
        res_raw = self.client.post("/api/events", data="not json", content_type="text/plain")
        self.assertEqual(res_raw.status_code, 400)

    # 10. Database failure handling where practical
    def test_10_database_failure_handling(self):
        faulty_client = MagicMock()
        faulty_client.table.side_effect = Exception("Supabase connection timeout / socket drop")

        payload = {
            "event_id": "EVT_FAIL_001",
            "event_type": "file_share",
            "actor_type": "employee",
            "actor_id": "EMP001",
            "resource": "notes.txt",
            "is_sensitive": False,
            "action": "read",
            "destination": "internal",
            "source": "test",
            "description": "Test error handling"
        }
        success, err_msg, code = process_security_event(payload, faulty_client)
        self.assertFalse(success)
        self.assertEqual(code, 500)
        self.assertIn("Pipeline processing failed", err_msg)

if __name__ == "__main__":
    unittest.main()
