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
from backend.config import Config
from backend.database import set_supabase_client, reset_supabase_client

class AIShieldSupabaseBackendTestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app({"TESTING": True})
        self.client = self.app.test_client()

        # In-memory mock database store for deterministic testing
        self.mock_store = {
            "employees": [
                {
                    "id": 1,
                    "employee_id": "EMP001",
                    "name": "Alice Chen",
                    "email": "alice.chen@aishield.local",
                    "department": "Security Operations",
                    "role": "Senior Security Analyst",
                    "risk_score": 12.50,
                    "status": "active",
                    "created_at": "2026-11-04T10:00:00Z"
                },
                {
                    "id": 2,
                    "employee_id": "EMP002",
                    "name": "Bob Smith",
                    "email": "bob.smith@aishield.local",
                    "department": "Finance",
                    "role": "Financial Analyst",
                    "risk_score": 68.00,
                    "status": "under_investigation",
                    "created_at": "2026-11-04T10:05:00Z"
                }
            ],
            "security_events": [
                {
                    "id": 1,
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
                    "description": "Attempted external file sharing",
                    "rule_result": "flagged_dlp_violation",
                    "anomaly": True,
                    "risk_score": 82.50,
                    "risk_level": "high",
                    "recommended_action": "quarantine"
                }
            ],
            "security_incidents": [
                {
                    "id": 1,
                    "incident_id": "INC001",
                    "title": "Suspected Data Exfiltration",
                    "description": "Sensitive customer file exfiltration",
                    "severity": "critical",
                    "status": "investigating",
                    "actor_id": "EMP002",
                    "event_id": "EVT001",
                    "created_at": "2026-11-04T11:00:00Z"
                }
            ],
            "alerts": [
                {
                    "id": 1,
                    "alert_id": "ALT001",
                    "event_id": "EVT001",
                    "alert_type": "DLP_VIOLATION",
                    "severity": "high",
                    "message": "Sensitive customer list shared",
                    "is_read": False,
                    "created_at": "2026-11-04T11:01:00Z"
                }
            ],
            "activity_logs": []
        }

        # Setup mock Supabase client
        self.mock_client = self._create_mock_supabase()
        set_supabase_client(self.mock_client)

    def tearDown(self):
        reset_supabase_client()

    def _create_mock_supabase(self):
        mock_client = MagicMock()

        def table_side_effect(table_name):
            store = self.mock_store.setdefault(table_name, [])

            # Mock Query Builder conforming to Supabase PostgREST chaining
            class MockQueryBuilder:
                def __init__(self, items, store_ref):
                    self.items = list(items)
                    self._count = len(self.items)
                    self.store_ref = store_ref
                    self._pending_insert = None
                    self._pending_update = None

                def select(self, *args, **kwargs):
                    return self

                def eq(self, field, value):
                    self.items = [item for item in self.items if str(item.get(field)) == str(value)]
                    self._count = len(self.items)
                    return self

                def or_(self, condition):
                    parts = condition.split(",")
                    matched = []
                    for item in self.items:
                        match = False
                        for p in parts:
                            if ".eq." in p:
                                k, v = p.split(".eq.", 1)
                                if str(item.get(k)) == str(v):
                                    match = True
                                    break
                        if match:
                            matched.append(item)
                    self.items = matched
                    self._count = len(self.items)
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

                def upsert(self, payload, on_conflict=None):
                    return self.insert(payload)

                def update(self, payload):
                    self._pending_update = dict(payload)
                    return self

                def execute(self):
                    res = MagicMock()
                    if self._pending_insert is not None:
                        res.data = self._pending_insert
                        res.count = len(self._pending_insert)
                    elif self._pending_update is not None:
                        updated = []
                        for item in self.items:
                            item.update(self._pending_update)
                            for stored in self.store_ref:
                                match = False
                                for key in ("id", "incident_id", "alert_id", "event_id", "employee_id"):
                                    if key in item and key in stored and item[key] == stored[key]:
                                        match = True
                                        break
                                if match:
                                    stored.update(self._pending_update)
                            updated.append(dict(item))
                        res.data = updated
                        res.count = len(updated)
                    else:
                        res.data = self.items
                        res.count = self._count
                    return res

            builder = MockQueryBuilder(store, store)
            table_mock = MagicMock()
            table_mock.select = builder.select
            table_mock.insert = builder.insert
            table_mock.upsert = builder.upsert
            table_mock.update = builder.update
            return table_mock

        mock_client.table.side_effect = table_side_effect
        return mock_client

    # 1. Health Check Tests
    def test_health_check_connected(self):
        with patch("backend.routes.health.check_supabase_connection", return_value=(True, "Connected")):
            response = self.client.get("/api/health")
            self.assertEqual(response.status_code, 200)
            data = response.get_json()
            self.assertTrue(data["success"])
            self.assertEqual(data["data"]["database"], "connected")
            self.assertEqual(data["data"]["database_type"], "supabase_postgresql")

    def test_health_check_disconnected(self):
        with patch("backend.routes.health.check_supabase_connection", return_value=(False, "Connection failed")):
            response = self.client.get("/api/health")
            self.assertEqual(response.status_code, 503)
            data = response.get_json()
            self.assertFalse(data["success"])
            self.assertEqual(data["details"]["database"], "disconnected")

    # 2. Employees API Tests
    def test_get_employees_list(self):
        response = self.client.get("/api/employees")
        self.assertEqual(response.status_code, 200)
        res = response.get_json()
        self.assertTrue(res["success"])
        self.assertEqual(len(res["data"]), 2)
        self.assertEqual(res["meta"]["total"], 2)

    def test_get_employees_filter_department(self):
        response = self.client.get("/api/employees?department=Finance")
        self.assertEqual(response.status_code, 200)
        res = response.get_json()
        self.assertEqual(len(res["data"]), 1)
        self.assertEqual(res["data"][0]["employee_id"], "EMP002")

    def test_create_employee_success(self):
        payload = {
            "employee_id": "EMP099",
            "name": "Sarah Connor",
            "email": "sarah.connor@aishield.local",
            "department": "Security Ops",
            "role": "Threat Hunter",
            "risk_score": 10.0,
            "status": "active"
        }
        response = self.client.post("/api/employees", json=payload)
        self.assertEqual(response.status_code, 201)
        res = response.get_json()
        self.assertTrue(res["success"])
        self.assertEqual(res["data"]["employee_id"], "EMP099")

    def test_create_employee_missing_fields(self):
        payload = {"name": "Incomplete Employee"}
        response = self.client.post("/api/employees", json=payload)
        self.assertEqual(response.status_code, 400)
        res = response.get_json()
        self.assertFalse(res["success"])

    def test_create_employee_invalid_email(self):
        payload = {
            "name": "Bad Email User",
            "email": "not-a-valid-email",
            "department": "IT",
            "role": "Admin"
        }
        response = self.client.post("/api/employees", json=payload)
        self.assertEqual(response.status_code, 400)
        res = response.get_json()
        self.assertIn("Invalid email address format", res["error"])

    def test_create_employee_duplicate_email(self):
        payload = {
            "employee_id": "EMP101",
            "name": "Duplicate Alice",
            "email": "alice.chen@aishield.local",
            "department": "SecOps",
            "role": "Analyst"
        }
        response = self.client.post("/api/employees", json=payload)
        self.assertEqual(response.status_code, 409)

    # 3. Security Events API Tests (docs/api_contract.md)
    def test_get_events_list(self):
        response = self.client.get("/api/events")
        self.assertEqual(response.status_code, 200)
        res = response.get_json()
        self.assertTrue(res["success"])
        self.assertEqual(len(res["data"]), 1)

    def test_get_events_filter_type(self):
        response = self.client.get("/api/events?event_type=file_share")
        self.assertEqual(response.status_code, 200)
        res = response.get_json()
        self.assertEqual(len(res["data"]), 1)
        self.assertEqual(res["data"][0]["event_id"], "EVT001")

    def test_create_event_contract_format(self):
        payload = {
            "event_id": "EVT100",
            "event_type": "file_share",
            "actor_type": "employee",
            "actor_id": "EMP003",
            "resource": "api_keys.env",
            "is_sensitive": True,
            "action": "share",
            "destination": "external_drive",
            "timestamp": "2026-11-04T12:00:00Z",
            "source": "dlp_agent",
            "description": "Attempted export of secret environment keys"
        }
        response = self.client.post("/api/events", json=payload)
        self.assertEqual(response.status_code, 201)
        res = response.get_json()
        self.assertTrue(res["success"])
        self.assertEqual(res["data"]["event_id"], "EVT100")
        self.assertTrue(res["data"]["is_sensitive"])

    def test_create_event_missing_required_field(self):
        payload = {"event_id": "EVT999", "event_type": "login"}
        response = self.client.post("/api/events", json=payload)
        self.assertEqual(response.status_code, 400)

    def test_create_event_duplicate_id(self):
        payload = {
            "event_id": "EVT001",
            "event_type": "file_share",
            "actor_type": "employee",
            "actor_id": "EMP001",
            "resource": "doc.pdf",
            "is_sensitive": False,
            "action": "read",
            "source": "manual_test"
        }
        response = self.client.post("/api/events", json=payload)
        self.assertEqual(response.status_code, 409)

    # 4. Security Incidents API Tests
    def test_get_incidents_list(self):
        response = self.client.get("/api/incidents")
        self.assertEqual(response.status_code, 200)
        res = response.get_json()
        self.assertTrue(res["success"])
        self.assertEqual(len(res["data"]), 1)

    def test_create_incident_success(self):
        payload = {
            "incident_id": "INC099",
            "title": "Suspected Credential Stuffing",
            "description": "500 failed login attempts across multiple user accounts",
            "severity": "high",
            "status": "open",
            "actor_id": "external_attacker_01"
        }
        response = self.client.post("/api/incidents", json=payload)
        self.assertEqual(response.status_code, 201)
        res = response.get_json()
        self.assertEqual(res["data"]["incident_id"], "INC099")

    def test_update_incident_status_success(self):
        # Update status to investigating
        response = self.client.patch("/api/incidents/INC001", json={"status": "investigating"})
        self.assertEqual(response.status_code, 200)
        res = response.get_json()
        self.assertTrue(res["success"])
        self.assertEqual(res["data"]["status"], "investigating")
        self.assertIn("updated_at", res["data"])

        # Update status to resolved
        response2 = self.client.patch("/api/incidents/INC001", json={"status": "resolved"})
        self.assertEqual(response2.status_code, 200)
        res2 = response2.get_json()
        self.assertEqual(res2["data"]["status"], "resolved")
        self.assertIsNotNone(res2["data"]["resolved_at"])

    def test_update_incident_status_invalid(self):
        response = self.client.patch("/api/incidents/INC001", json={"status": "invalid_status"})
        self.assertEqual(response.status_code, 400)
        res = response.get_json()
        self.assertFalse(res["success"])
        self.assertIn("Invalid status", res["error"])

    def test_update_incident_not_found(self):
        response = self.client.patch("/api/incidents/INC_NONEXISTENT", json={"status": "investigating"})
        self.assertEqual(response.status_code, 404)
        res = response.get_json()
        self.assertFalse(res["success"])
        self.assertIn("not found", res["error"])

    def test_update_incident_invalid_payload(self):
        response = self.client.patch("/api/incidents/INC001", json={})
        self.assertEqual(response.status_code, 400)
        res = response.get_json()
        self.assertFalse(res["success"])

    # 5. Alerts API Tests
    def test_get_alerts_list(self):
        response = self.client.get("/api/alerts")
        self.assertEqual(response.status_code, 200)
        res = response.get_json()
        self.assertTrue(res["success"])
        self.assertEqual(len(res["data"]), 1)

    def test_update_alert_mark_read(self):
        response = self.client.patch("/api/alerts/ALT001", json={"is_read": True})
        self.assertEqual(response.status_code, 200)
        res = response.get_json()
        self.assertTrue(res["success"])
        self.assertTrue(res["data"]["is_read"])

    def test_update_alert_mark_unread(self):
        # Set to True first
        self.client.patch("/api/alerts/ALT001", json={"is_read": True})
        # Mark unread
        response = self.client.patch("/api/alerts/ALT001", json={"is_read": False})
        self.assertEqual(response.status_code, 200)
        res = response.get_json()
        self.assertTrue(res["success"])
        self.assertFalse(res["data"]["is_read"])

    def test_update_alert_invalid_is_read(self):
        # String instead of boolean
        res1 = self.client.patch("/api/alerts/ALT001", json={"is_read": "true"})
        self.assertEqual(res1.status_code, 400)
        self.assertIn("must be a boolean", res1.get_json()["error"])

        # Integer instead of boolean
        res2 = self.client.patch("/api/alerts/ALT001", json={"is_read": 1})
        self.assertEqual(res2.status_code, 400)
        self.assertIn("must be a boolean", res2.get_json()["error"])

        # Missing field
        res3 = self.client.patch("/api/alerts/ALT001", json={})
        self.assertEqual(res3.status_code, 400)
        self.assertIn("Missing required field", res3.get_json()["error"])

    def test_update_alert_not_found(self):
        response = self.client.patch("/api/alerts/ALT_NONEXISTENT", json={"is_read": True})
        self.assertEqual(response.status_code, 404)
        res = response.get_json()
        self.assertFalse(res["success"])
        self.assertIn("not found", res["error"])

    # 6. Global 404 Error Handler
    def test_not_found_endpoint(self):
        response = self.client.get("/api/nonexistent_route")
        self.assertEqual(response.status_code, 404)
        res = response.get_json()
        self.assertFalse(res["success"])
        self.assertEqual(res["error"], "Endpoint or resource not found")

if __name__ == "__main__":
    unittest.main()
