"""
AI Shield - Security Module Integration Test Suite.
Verifies the integration of Manoj's Security Module (security/) with the
AI-SHIELD central event processing pipeline, Supabase persistence, and risk engine.

Scenarios tested:
1. Normal authorized employee file access passes security policy.
2. DLP Policy: Sensitive file shared externally triggers hard denial and quarantine action.
3. Registered AI Agent: Authorized resource access succeeds (e.g., invoice_agent -> invoices.csv).
4. AI Agent Access Control: Unauthorized access attempt triggers hard denial (e.g., invoice_agent -> employee_salary.csv).
5. Unknown AI Agent: Unregistered agent access is blocked with hard denial.
6. Auto-Suspension: Repeated agent violations (>=3) automatically suspend the rogue agent and persist to database.
7. Hard Denial Preservation (Rule 4): Security hard denial is never overridden by a low ML risk score.
8. Physical File Quarantine: Sensitive file in test_data transferred to blocked destination is quarantined.
9. End-to-End Pipeline Ingestion: Complete execution through validation, security evaluation, ML scoring, Supabase persistence, and incident/alert generation.
10. Restart Simulation: Agent suspension state persists across simulated application restarts.
11. Unknown Agent Denial: Unregistered agents are consistently denied across sessions.
12. Fail-Safe Persistence: Database unavailability does not silently reactivate a suspended agent.
13. Admin Reactivation: Explicit administrator reactivation clears suspension and resets violation count.
"""

import sys
import unittest
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app import create_app
from backend.database import set_supabase_client, reset_supabase_client
from backend.pipeline import (
    process_security_event,
    SecurityRuleResult,
    MLAnomalyResult,
    ManojSecurityEngineAdapter,
    calculate_composite_risk,
    get_security_adapter,
    set_security_adapter,
    reset_security_adapter,
    reset_ml_adapter
)
from security.agent_guard import AGENT_REGISTRY, set_agent_status, check_permission
from security.violation_tracker import agent_violations
from security.agent_persistence import (
    get_persistent_agent,
    get_persistent_agent_state,
    save_agent_status,
    sync_agent_registry_from_db,
    reset_agent_persistence,
    _load_local_cache,
    _save_local_cache,
    CACHE_FILE
)


class AIShieldSecurityIntegrationTestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app({"TESTING": True})
        self.client = self.app.test_client()

        # In-memory mock database store conforming to Supabase schema
        self.mock_store = {
            "employees": [],
            "security_events": [],
            "security_incidents": [],
            "alerts": [],
            "activity_logs": [],
            "ai_agents": []
        }

        self.mock_client = self._create_mock_supabase()
        set_supabase_client(self.mock_client)

        # Reset security and ML adapters to clean state
        reset_security_adapter()
        reset_ml_adapter()

    def tearDown(self):
        reset_security_adapter()
        reset_ml_adapter()
        reset_supabase_client()

    def _create_mock_supabase(self):
        mock_client = MagicMock()

        def table_side_effect(table_name):
            store = self.mock_store.setdefault(table_name, [])

            class MockQueryBuilder:
                def __init__(self, store_ref):
                    self.store_ref = store_ref
                    self.items = list(store_ref)
                    self._count = len(self.items)

                def select(self, *args, **kwargs):
                    self.items = list(self.store_ref)
                    self._count = len(self.items)
                    return self

                def eq(self, field, value):
                    self.items = [x for x in self.items if str(x.get(field)) == str(value)]
                    self._count = len(self.items)
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
                    self.items = to_add
                    return self

                def update(self, payload):
                    pending_update = dict(payload)
                    updated = []
                    for item in self.items:
                        item.update(pending_update)
                        for stored in self.store_ref:
                            match = False
                            for key in ("id", "agent_name", "incident_id", "alert_id", "event_id", "employee_id"):
                                if key in item and key in stored and item[key] == stored[key]:
                                    match = True
                                    break
                            if match:
                                stored.update(pending_update)
                        updated.append(dict(item))
                    self.items = updated
                    return self

                def upsert(self, payload, on_conflict=None):
                    to_upsert = [dict(x) for x in payload] if isinstance(payload, list) else [dict(payload)]
                    conflict_key = on_conflict or "id"
                    res_items = []
                    for item in to_upsert:
                        match_found = False
                        for stored in self.store_ref:
                            if conflict_key in item and conflict_key in stored and item[conflict_key] == stored[conflict_key]:
                                stored.update(item)
                                res_items.append(stored)
                                match_found = True
                                break
                        if not match_found:
                            if "id" not in item:
                                item["id"] = len(self.store_ref) + 1
                            self.store_ref.append(item)
                            res_items.append(item)
                    self.items = res_items
                    return self

                def execute(self):
                    res = MagicMock()
                    res.data = list(self.items)
                    res.count = len(self.items)
                    return res

            builder = MockQueryBuilder(store)
            table_mock = MagicMock()
            table_mock.select = builder.select
            table_mock.eq = builder.eq
            table_mock.insert = builder.insert
            table_mock.update = builder.update
            table_mock.upsert = builder.upsert
            table_mock.limit = builder.limit
            return table_mock

        mock_client.table.side_effect = table_side_effect
        return mock_client

    # 1. Normal authorized employee access
    def test_01_normal_authorized_access_allowed(self):
        adapter = get_security_adapter()
        event = {
            "event_id": "EVT-SEC-001",
            "actor_type": "employee",
            "actor_id": "EMP-101",
            "resource": "project_documentation.txt",
            "is_sensitive": False,
            "action": "read",
            "destination": "internal"
        }
        res = adapter.evaluate(event)
        self.assertEqual(res.rule_result, "allowed")
        self.assertFalse(res.hard_denial)
        self.assertEqual(res.recommended_action, "none")
        self.assertEqual(len(res.rule_violations), 0)

    # 2. Sensitive file shared externally triggers DLP violation & hard denial
    def test_02_dlp_external_share_blocked(self):
        adapter = get_security_adapter()
        event = {
            "event_id": "EVT-SEC-002",
            "actor_type": "employee",
            "actor_id": "EMP-102",
            "resource": "customer_financial_records.csv",
            "is_sensitive": True,
            "action": "share",
            "destination": "personal_email"
        }
        res = adapter.evaluate(event)
        self.assertEqual(res.rule_result, "flagged_dlp_external_share")
        self.assertTrue(res.hard_denial)
        self.assertEqual(res.recommended_action, "quarantine_attachment_and_notify_manager")
        self.assertTrue(len(res.rule_violations) > 0)
        self.assertIn("DLP", res.rule_violations[0])

    # 3. Registered AI agent accessing authorized resource
    def test_03_registered_agent_authorized_access(self):
        adapter = get_security_adapter()
        event = {
            "event_id": "EVT-SEC-003",
            "actor_type": "agent",
            "actor_id": "invoice_agent",
            "resource": "invoices.csv",
            "is_sensitive": False,
            "action": "read",
            "destination": "internal"
        }
        res = adapter.evaluate(event)
        self.assertEqual(res.rule_result, "allowed")
        self.assertFalse(res.hard_denial)
        self.assertEqual(res.recommended_action, "none")

    # 4. Registered AI agent accessing unauthorized resource
    def test_04_registered_agent_unauthorized_access_blocked(self):
        adapter = get_security_adapter()
        event = {
            "event_id": "EVT-SEC-004",
            "actor_type": "agent",
            "actor_id": "invoice_agent",
            "resource": "employee_salary.csv",
            "is_sensitive": True,
            "action": "read",
            "destination": "internal"
        }
        res = adapter.evaluate(event)
        self.assertEqual(res.rule_result, "flagged_unauthorized_agent_access")
        self.assertTrue(res.hard_denial)
        self.assertEqual(res.recommended_action, "revoke_agent_token_and_isolate")
        self.assertTrue(len(res.rule_violations) > 0)
        self.assertIn("ACL-002", res.rule_violations[0])

    # 5. Unknown AI agent is rejected
    def test_05_unknown_agent_rejected(self):
        adapter = get_security_adapter()
        event = {
            "event_id": "EVT-SEC-005",
            "actor_type": "agent",
            "actor_id": "rogue_ai_bot",
            "resource": "invoices.csv",
            "is_sensitive": False,
            "action": "read",
            "destination": "internal"
        }
        res = adapter.evaluate(event)
        self.assertEqual(res.rule_result, "flagged_unauthorized_agent_access")
        self.assertTrue(res.hard_denial)
        self.assertEqual(res.recommended_action, "revoke_agent_token_and_isolate")

    # 6. Repeated agent violations trigger auto-suspension and persist to Supabase
    def test_06_agent_auto_suspension_after_repeated_violations(self):
        adapter = get_security_adapter()
        agent_violations.clear()
        set_agent_status("hr_agent", True)

        # Trigger 3 violations
        for i in range(3):
            event = {
                "event_id": f"EVT-VIOL-{i}",
                "actor_type": "agent",
                "actor_id": "hr_agent",
                "resource": "unauthorized_restricted.csv",
                "is_sensitive": True,
                "action": "read",
                "destination": "internal"
            }
            res = adapter.evaluate(event)
            self.assertEqual(res.rule_result, "flagged_unauthorized_agent_access")
            self.assertTrue(res.hard_denial)

        # In-memory registry check
        self.assertFalse(AGENT_REGISTRY["hr_agent"]["active"])

        # Persistent database check
        persisted = get_persistent_agent("hr_agent", client=self.mock_client)
        self.assertIsNotNone(persisted)
        self.assertEqual(persisted["status"], "suspended")
        self.assertFalse(persisted["is_active"])
        self.assertEqual(persisted["violation_count"], 3)
        self.assertIsNotNone(persisted["suspended_at"])
        self.assertIn("repeated violations", persisted["suspension_reason"])

        # Even normally allowed access is now blocked because agent is suspended
        allowed_event = {
            "event_id": "EVT-VIOL-AFTER",
            "actor_type": "agent",
            "actor_id": "hr_agent",
            "resource": "employee_salary.csv",
            "is_sensitive": True,
            "action": "read",
            "destination": "internal"
        }
        res_after = adapter.evaluate(allowed_event)
        self.assertEqual(res_after.rule_result, "flagged_unauthorized_agent_access")
        self.assertTrue(res_after.hard_denial)

    # 7. Hard denial preservation (Rule 4): low ML score never overrides security denial
    def test_07_hard_denial_preserved_against_low_ml_score(self):
        sec_result = SecurityRuleResult(
            rule_result="flagged_dlp_external_share",
            hard_denial=True,
            recommended_action="quarantine_attachment_and_notify_manager",
            rule_violations=["DLP-001: Data exfiltration blocked"]
        )

        ml_result = MLAnomalyResult(
            anomaly=False,
            risk_score=2.5,
            risk_level="low",
            confidence=0.98,
            factors=["Isolation Forest: normal pattern"]
        )

        composite = calculate_composite_risk(sec_result, ml_result, {})
        self.assertEqual(composite["risk_level"], "critical")
        self.assertGreaterEqual(composite["risk_score"], 85.0)
        self.assertTrue(composite["hard_denial_preserved"])
        self.assertEqual(composite["recommended_action"], "quarantine_attachment_and_notify_manager")

    # 8. Physical file quarantine integration
    def test_08_physical_quarantine_integration(self):
        test_file = PROJECT_ROOT / "test_data" / "sec_test_sensitive.csv"
        test_file.write_text("id,name,salary,bank_account\n1,Alice,150000,9876543210\n", encoding="utf-8")

        adapter = get_security_adapter()
        event = {
            "event_id": "EVT-SEC-008",
            "actor_type": "employee",
            "actor_id": "EMP-007",
            "resource": str(test_file),
            "is_sensitive": True,
            "action": "transfer",
            "destination": "personal_email"
        }

        res = adapter.evaluate(event)
        self.assertEqual(res.rule_result, "flagged_dlp_external_share")
        self.assertTrue(res.hard_denial)

        # The file in test_data should have been moved to quarantine/
        self.assertFalse(test_file.exists())

        quarantine_dir = PROJECT_ROOT / "quarantine"
        quarantined_files = list(quarantine_dir.glob("*_sec_test_sensitive.csv"))
        for qf in quarantined_files:
            try:
                qf.unlink()
            except Exception:
                pass

    # 9. Full central event pipeline execution through persistence and incident generation
    def test_09_full_pipeline_ingestion_with_security_engine(self):
        unauthorized_agent_payload = {
            "event_id": "EVT-PIPE-SEC-01",
            "event_type": "file_access",
            "actor_type": "agent",
            "actor_id": "invoice_agent",
            "resource": "employee_salary.csv",
            "is_sensitive": True,
            "action": "read",
            "destination": "internal",
            "timestamp": "2026-11-05T12:00:00Z",
            "source": "api_gateway",
            "description": "Invoice agent attempted access to salary file"
        }

        success, result, status_code = process_security_event(
            unauthorized_agent_payload,
            client=self.mock_client
        )

        self.assertTrue(success)
        self.assertEqual(status_code, 201)

        saved = self.mock_store["security_events"]
        self.assertEqual(len(saved), 1)
        self.assertEqual(saved[0]["event_id"], "EVT-PIPE-SEC-01")
        self.assertEqual(saved[0]["rule_result"], "flagged_unauthorized_agent_access")
        self.assertEqual(saved[0]["risk_level"], "critical")
        self.assertTrue(saved[0]["anomaly"])

        incidents = self.mock_store["security_incidents"]
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["event_id"], "EVT-PIPE-SEC-01")
        self.assertEqual(incidents[0]["severity"], "critical")

        alerts = self.mock_store["alerts"]
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["event_id"], "EVT-PIPE-SEC-01")
        self.assertEqual(alerts[0]["alert_type"], "UNAUTHORIZED_AGENT_ACCESS")
        self.assertEqual(alerts[0]["severity"], "critical")

    # 10. Agent suspension survives reinitialization / simulated backend restart
    def test_10_agent_suspension_survives_restart_simulation(self):
        adapter = get_security_adapter()

        # Step 1: Suspend hr_agent
        set_agent_status("hr_agent", False, reason="Suspended by test policy")
        self.assertFalse(AGENT_REGISTRY["hr_agent"]["active"])

        # Step 2: Simulate backend restart by wiping volatile in-memory state
        AGENT_REGISTRY["hr_agent"]["active"] = True  # reset in-memory dict to startup default
        agent_violations.clear()                     # clear in-memory violation lists

        # Step 3: Attempt access as hr_agent
        # check_permission must query persistent store and keep hr_agent inactive
        check = check_permission("hr_agent", "employee_salary.csv")
        self.assertFalse(check["allowed"])
        self.assertEqual(check["reason"], "Agent is inactive")

        # In-memory registry was re-synchronized to False
        self.assertFalse(AGENT_REGISTRY["hr_agent"]["active"])

        # Step 4: Pipeline evaluation must issue hard denial
        event = {
            "event_id": "EVT-RESTART-01",
            "actor_type": "agent",
            "actor_id": "hr_agent",
            "resource": "employee_salary.csv",
            "is_sensitive": True,
            "action": "read",
            "destination": "internal"
        }
        res = adapter.evaluate(event)
        self.assertEqual(res.rule_result, "flagged_unauthorized_agent_access")
        self.assertTrue(res.hard_denial)
        self.assertEqual(res.recommended_action, "revoke_agent_token_and_isolate")

    # 11. Unknown agent denial is strictly preserved across sessions
    def test_11_unknown_agent_denied_across_sessions(self):
        adapter = get_security_adapter()

        # Unknown agent is not in registry
        check = check_permission("shadow_bot_99", "invoices.csv")
        self.assertFalse(check["allowed"])
        self.assertEqual(check["reason"], "Unknown agent")

        event = {
            "event_id": "EVT-UNKNOWN-AGENT-01",
            "actor_type": "agent",
            "actor_id": "shadow_bot_99",
            "resource": "invoices.csv",
            "is_sensitive": False,
            "action": "read",
            "destination": "internal"
        }
        res = adapter.evaluate(event)
        self.assertEqual(res.rule_result, "flagged_unauthorized_agent_access")
        self.assertTrue(res.hard_denial)

    # 12. Fail-safe behavior: Supabase connection failure does not silently reactivate
    def test_12_supabase_failure_fails_safely(self):
        # Suspend hr_agent
        set_agent_status("hr_agent", False, reason="Suspended prior to network failure")

        # Simulate Supabase client failure (broken connection)
        broken_client = MagicMock()
        broken_client.table.side_effect = RuntimeError("Supabase cluster unreachable (503 Service Unavailable)")
        set_supabase_client(broken_client)

        # Clear volatile in-memory registry to test fallback
        AGENT_REGISTRY["hr_agent"]["active"] = True

        # System must fall back to local persistent cache and FAIL SAFELY
        check = check_permission("hr_agent", "employee_salary.csv")
        self.assertFalse(check["allowed"])
        self.assertEqual(check["reason"], "Agent is inactive")
        self.assertFalse(AGENT_REGISTRY["hr_agent"]["active"])

    # 13. Admin reactivation clears suspension and resets violation count
    def test_13_admin_reactivation_clears_suspension(self):
        # Suspend hr_agent
        set_agent_status("hr_agent", False, reason="Policy suspension")
        self.assertFalse(AGENT_REGISTRY["hr_agent"]["active"])

        # Admin explicitly reactivates agent
        reactivate_res = set_agent_status("hr_agent", True)
        self.assertTrue(reactivate_res["active"])
        self.assertTrue(AGENT_REGISTRY["hr_agent"]["active"])

        # Check persistent database record
        persisted = get_persistent_agent("hr_agent", client=self.mock_client)
        self.assertIsNotNone(persisted)
        self.assertEqual(persisted["status"], "active")
        self.assertTrue(persisted["is_active"])
        self.assertEqual(persisted["violation_count"], 0)

        # Access is now permitted for authorized file
        check = check_permission("hr_agent", "employee_salary.csv")
        self.assertTrue(check["allowed"])
        self.assertEqual(check["reason"], "Agent has permission")

    # 14. Migration 002 policy rerun safety (static SQL inspection)
    def test_14_migration_002_policy_rerun_safety(self):
        migration_file = PROJECT_ROOT / "backend" / "migrations" / "002_agent_suspension.sql"
        self.assertTrue(migration_file.exists())
        sql_content = migration_file.read_text(encoding="utf-8")

        # Must use DROP POLICY IF EXISTS before CREATE POLICY for idempotency
        self.assertIn('DROP POLICY IF EXISTS "Service role full access on ai_agents" ON public.ai_agents;', sql_content)
        self.assertIn('CREATE POLICY "Service role full access on ai_agents" ON public.ai_agents', sql_content)
        self.assertIn('CREATE TABLE IF NOT EXISTS public.ai_agents', sql_content)
        self.assertIn('CREATE INDEX IF NOT EXISTS', sql_content)
        self.assertIn('ON CONFLICT (agent_name) DO NOTHING', sql_content)

    # 15. Atomic cache replacement writes atomically and cleans up temp files
    def test_15_atomic_cache_replacement(self):
        save_agent_status("invoice_agent", True, client=self.mock_client)
        self.assertTrue(CACHE_FILE.exists())

        # No leftover temp files should exist in quarantine directory
        tmp_files = list(CACHE_FILE.parent.glob("*.tmp*"))
        self.assertEqual(len(tmp_files), 0)

        # Cache file must be valid JSON
        data = _load_local_cache()
        self.assertIn("invoice_agent", data)
        self.assertTrue(data["invoice_agent"]["is_active"])

    # 16. Failed cache write preserves previous valid file
    def test_16_failed_cache_write_preserves_valid_file(self):
        # Establish valid baseline cache
        _save_local_cache({"test_agent": {"status": "active", "is_active": True}})
        self.assertTrue(CACHE_FILE.exists())

        # Mock json.dump to simulate an unhandled write/serialization failure
        with patch("json.dump", side_effect=TypeError("Simulated serialization exception")):
            result = _save_local_cache({"corrupted": "bad_state"})
            self.assertFalse(result)

        # Original cache file must be preserved intact
        current_data = _load_local_cache()
        self.assertIn("test_agent", current_data)
        self.assertTrue(current_data["test_agent"]["is_active"])

    # 17. Corrupted cache handling fails safely without crashing
    def test_17_corrupted_cache_handling(self):
        # Write corrupted JSON to CACHE_FILE
        CACHE_FILE.write_text("{ unclosed_corrupted_json_syntax: 123 ", encoding="utf-8")

        # Must catch JSONDecodeError and return empty dict safely
        loaded = _load_local_cache()
        self.assertEqual(loaded, {})

    # 18. Supabase upsert behavior handles inserts and updates atomically
    def test_18_supabase_upsert_behavior(self):
        # Clear ai_agents store to test from scratch
        self.mock_store["ai_agents"] = []

        # First upsert: insert new row
        save_agent_status("invoice_agent", True, client=self.mock_client)
        agents = [a for a in self.mock_store["ai_agents"] if a["agent_name"] == "invoice_agent"]
        self.assertEqual(len(agents), 1)
        self.assertEqual(agents[0]["agent_name"], "invoice_agent")
        self.assertTrue(agents[0]["is_active"])

        # Second upsert: update existing row in place (conflict on agent_name)
        save_agent_status("invoice_agent", False, reason="Suspension test", client=self.mock_client)
        agents = [a for a in self.mock_store["ai_agents"] if a["agent_name"] == "invoice_agent"]
        self.assertEqual(len(agents), 1)  # No duplicate rows created on conflict
        self.assertEqual(agents[0]["status"], "suspended")
        self.assertFalse(agents[0]["is_active"])

    # 19. Existing suspension preserved during registration sync
    def test_19_existing_suspension_preserved_during_registration(self):
        # Pre-seed persistent store with suspended agent
        self.mock_store["ai_agents"] = [{
            "agent_name": "hr_agent",
            "status": "suspended",
            "is_active": False,
            "violation_count": 3,
            "violation_history": ["2026-11-05T12:00:00Z"]
        }]

        # In-memory registry defaults to active (as on code import)
        AGENT_REGISTRY["hr_agent"]["active"] = True

        # Sync from database must preserve existing suspension
        sync_agent_registry_from_db(AGENT_REGISTRY, client=self.mock_client)
        self.assertFalse(AGENT_REGISTRY["hr_agent"]["active"])
        self.assertEqual(self.mock_store["ai_agents"][0]["status"], "suspended")

    # 20. Fail-closed edge case: Supabase unavailable + missing cache fails closed
    def test_20_supabase_unavailable_and_missing_cache_fails_closed(self):
        adapter = get_security_adapter()

        # Simulate broken Supabase connection
        broken_client = MagicMock()
        broken_client.table.side_effect = RuntimeError("Supabase cluster unreachable (503)")
        set_supabase_client(broken_client)

        # Remove local cache file to simulate missing/corrupted cache
        if CACHE_FILE.exists():
            CACHE_FILE.unlink()

        # In-memory registry has default active: True
        AGENT_REGISTRY["hr_agent"]["active"] = True

        # Attempt access: must FAIL CLOSED because persistent state is unverifiable
        check = check_permission("hr_agent", "employee_salary.csv")
        self.assertFalse(check["allowed"])
        self.assertIn("unverifiable", check["reason"].lower())
        self.assertFalse(AGENT_REGISTRY["hr_agent"]["active"])

        # Pipeline evaluation must issue hard denial
        event = {
            "event_id": "EVT-FAIL-CLOSED-01",
            "actor_type": "agent",
            "actor_id": "hr_agent",
            "resource": "employee_salary.csv",
            "is_sensitive": True,
            "action": "read",
            "destination": "internal"
        }
        res = adapter.evaluate(event)
        self.assertEqual(res.rule_result, "flagged_unauthorized_agent_access")
        self.assertTrue(res.hard_denial)


if __name__ == "__main__":
    unittest.main()
