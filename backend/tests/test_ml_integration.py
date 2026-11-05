"""
AI Shield - Machine Learning Integration Test Suite.
Tests the integration of Vishnu's Isolation Forest anomaly detection model into
the central event processing pipeline, Supabase persistence, and risk engine.

Scenarios tested:
1. Normal event classified by the ML model.
2. Anomalous event classified by the ML model.
3. Missing or invalid ML features handled safely.
4. Model artifact unavailable handled gracefully.
5. ML prediction failure does not silently treat events as safe.
6. Security hard denial remains effective even when ML predicts normal.
7. ML anomaly contributes to composite risk calculation.
8. Complete event processing through persistence and incident/alert generation.
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

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
    VishnuIsolationForestAdapter,
    calculate_composite_risk,
    get_ml_adapter,
    set_ml_adapter,
    reset_ml_adapter,
    reset_security_adapter
)

class AIShieldMLIntegrationTestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app({"TESTING": True})
        self.client = self.app.test_client()

        # In-memory mock database store
        self.mock_store = {
            "employees": [],
            "security_events": [],
            "security_incidents": [],
            "alerts": [],
            "activity_logs": []
        }

        self.mock_client = self._create_mock_supabase()
        set_supabase_client(self.mock_client)

        # Ensure Vishnu ML adapter is active
        reset_ml_adapter()
        reset_security_adapter()

    def tearDown(self):
        reset_supabase_client()
        reset_ml_adapter()
        reset_security_adapter()

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

                def insert(self, payload):
                    to_add = [dict(x) for x in payload] if isinstance(payload, list) else [dict(payload)]
                    for item in to_add:
                        if "id" not in item:
                            item["id"] = len(self.store_ref) + 1
                        self.store_ref.append(item)
                    self._pending_insert = to_add
                    return self

                def execute(self):
                    res = MagicMock()
                    if self._pending_insert is not None:
                        res.data = self._pending_insert
                        res.count = len(self._pending_insert)
                    else:
                        res.data = self.items
                        res.count = self._count
                    return res

            builder = MockQueryBuilder(store)
            table_mock = MagicMock()
            table_mock.select = builder.select
            table_mock.insert = builder.insert
            return table_mock

        mock_client.table.side_effect = table_side_effect
        return mock_client

    # 1. Normal event classified by the ML model
    def test_01_normal_event_classification(self):
        adapter = get_ml_adapter()
        self.assertTrue(adapter.is_loaded, "Vishnu Isolation Forest model should be loaded")

        normal_event = {
            "actor_id": "EMP001",
            "actor_type": "employee",
            "event_type": "file_access",
            "resource": "team_handbook.pdf",
            "is_sensitive": False,
            "action": "read",
            "destination": "internal_workstation",
            "timestamp": "2026-11-04T10:00:00Z",
            "source": "workstation_agent",
            "employee_activities_24h": 1,
            "downloads_24h": 0,
            "external_activities_24h": 0,
            "sensitive_accesses_24h": 0
        }

        result = adapter.score(normal_event)
        self.assertFalse(result.anomaly)
        self.assertIn(result.risk_level, ("low", "medium"))
        self.assertLessEqual(result.risk_score, 35.0)
        self.assertGreaterEqual(result.confidence, 0.85)

    # 2. Anomalous event classified by the ML model
    def test_02_anomalous_event_classification(self):
        adapter = get_ml_adapter()

        anomalous_event = {
            "actor_id": "EMP002",
            "actor_type": "employee",
            "event_type": "file_share",
            "resource": "executive_payroll_q3.xlsx",
            "is_sensitive": True,
            "action": "download",
            "destination": "external_cloud_drive",
            "timestamp": "2026-11-01T02:30:00Z",  # Sunday 2:30 AM (weekend + off-hours)
            "source": "endpoint_monitor",
            "employee_activities_24h": 25,
            "downloads_24h": 12,
            "external_activities_24h": 8,
            "sensitive_accesses_24h": 10
        }

        result = adapter.score(anomalous_event)
        self.assertTrue(result.anomaly, "Off-hours sensitive bulk exfiltration should be flagged anomalous")
        self.assertIn(result.risk_level, ("high", "critical"))
        self.assertGreaterEqual(result.risk_score, 70.0)
        self.assertTrue(len(result.factors) > 0)
        self.assertTrue(any("Isolation Forest" in f for f in result.factors))

    # 3. Missing or invalid ML features handled safely
    def test_03_missing_or_invalid_features(self):
        adapter = get_ml_adapter()

        # Bare minimum payload with missing timestamps, destinations, and actions
        sparse_event = {
            "actor_id": "EMP999",
            "resource": "unknown_file.bin"
        }

        result = adapter.score(sparse_event)
        self.assertIsInstance(result, MLAnomalyResult)
        self.assertIsInstance(result.anomaly, bool)
        self.assertIsInstance(result.risk_score, float)
        self.assertIn(result.risk_level, ("low", "medium", "high", "critical"))

    # 4. Model artifact unavailable handled gracefully
    def test_04_model_artifact_unavailable(self):
        bad_adapter = VishnuIsolationForestAdapter(
            model_path=Path("/nonexistent/path/model.pkl"),
            threshold_path=Path("/nonexistent/path/threshold.txt")
        )
        self.assertFalse(bad_adapter.is_loaded)

        test_event = {
            "actor_id": "EMP001",
            "resource": "doc.pdf",
            "is_sensitive": True
        }

        result = bad_adapter.score(test_event)
        self.assertIsInstance(result, MLAnomalyResult)
        # Never silently treats as safe: flags degraded fallback
        self.assertTrue(any("unavailable" in f.lower() for f in result.factors))

    # 5. ML prediction failure does not silently treat events as safe
    def test_05_prediction_failure_handled_safely(self):
        adapter = VishnuIsolationForestAdapter()
        # Mock score_samples to raise an exception
        mock_model = MagicMock()
        mock_model.score_samples.side_effect = RuntimeError("Feature vector dimensional error")
        adapter.model = mock_model
        adapter.is_loaded = True

        event = {"actor_id": "EMP001", "resource": "financials.csv"}
        result = adapter.score(event)

        # Must flag for analyst review rather than returning safe low risk
        self.assertTrue(result.anomaly)
        self.assertGreaterEqual(result.risk_score, 50.0)
        self.assertTrue(any("exception" in f.lower() or "error" in f.lower() for f in result.factors))

    # 6. Security hard denial remains effective even when ML predicts normal
    def test_06_hard_denial_preserved_against_normal_ml(self):
        # Security engine issues hard denial
        sec_result = SecurityRuleResult(
            rule_result="flagged_dlp_external_share",
            hard_denial=True,
            recommended_action="quarantine_attachment_and_notify_manager"
        )
        # ML predicts completely normal
        ml_result = MLAnomalyResult(
            anomaly=False,
            risk_score=5.0,
            risk_level="low",
            confidence=0.99,
            factors=["ML baseline says completely normal"]
        )

        composite = calculate_composite_risk(sec_result, ml_result, {})
        self.assertEqual(composite["risk_level"], "critical")
        self.assertGreaterEqual(composite["risk_score"], 85.0)
        self.assertTrue(composite["hard_denial_preserved"])
        self.assertEqual(composite["recommended_action"], "quarantine_attachment_and_notify_manager")

    # 7. ML anomaly contributes to composite risk calculation
    def test_07_ml_anomaly_contributes_to_risk(self):
        # Security engine permits access (nominal policy)
        sec_result = SecurityRuleResult(
            rule_result="allowed",
            hard_denial=False,
            recommended_action="none"
        )
        # ML flags behavioral anomaly
        ml_result = MLAnomalyResult(
            anomaly=True,
            risk_score=75.0,
            risk_level="high",
            confidence=0.88,
            factors=["Anomalous access pattern by Isolation Forest"]
        )

        composite = calculate_composite_risk(sec_result, ml_result, {})
        self.assertTrue(composite["anomaly"])
        self.assertEqual(composite["risk_level"], "high")
        self.assertGreaterEqual(composite["risk_score"], 65.0)
        self.assertEqual(composite["rule_result"], "flagged_by_ml_anomaly")
        self.assertEqual(composite["recommended_action"], "flag_for_analyst_review")

    # 8. Complete event processing through persistence and incident/alert generation
    def test_08_complete_event_processing_with_ml(self):
        anomalous_payload = {
            "event_id": "EVT-ML-001",
            "event_type": "file_share",
            "actor_type": "employee",
            "actor_id": "EMP002",
            "resource": "proprietary_algorithms.zip",
            "is_sensitive": True,
            "action": "share",
            "destination": "external_drive",
            "timestamp": "2026-11-04T03:15:00Z",
            "source": "dlp_endpoint",
            "description": "Suspicious overnight external archive transfer",
            "employee_activities_24h": 30,
            "downloads_24h": 15,
            "external_activities_24h": 10,
            "sensitive_accesses_24h": 12
        }

        success, result, status_code = process_security_event(anomalous_payload, client=self.mock_client)
        self.assertTrue(success)
        self.assertEqual(status_code, 201)

        # Check event saved in Supabase
        saved_events = self.mock_store["security_events"]
        self.assertEqual(len(saved_events), 1)
        self.assertEqual(saved_events[0]["event_id"], "EVT-ML-001")
        self.assertTrue(saved_events[0]["anomaly"])
        self.assertIn(saved_events[0]["risk_level"], ("high", "critical"))

        # Check incident generated
        incidents = self.mock_store["security_incidents"]
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["event_id"], "EVT-ML-001")

        # Check alert generated
        alerts = self.mock_store["alerts"]
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["event_id"], "EVT-ML-001")
        self.assertFalse(alerts[0]["is_read"])

    # 9. Standalone Random Forest model prediction test
    def test_09_random_forest_standalone_predict(self):
        from ml.random_forest_predict import predict_random_forest

        sample_event = {
            "is_sensitive": 1,
            "is_read": 0,
            "is_download": 1,
            "is_share": 0,
            "is_external": 1,
            "hour": 23,
            "day_of_week": 6,
            "is_weekend": 1,
            "employee_activities_24h": 40,
            "downloads_24h": 20,
            "external_activities_24h": 15,
            "sensitive_accesses_24h": 7
        }

        result = predict_random_forest(sample_event)
        self.assertIsInstance(result, dict)
        self.assertEqual(result["model"], "Random Forest")
        self.assertIn("risk_score", result)
        self.assertIn(result["prediction"], ("Normal", "Suspicious"))
        self.assertIn(result["risk_level"], ("Low", "Medium", "High"))

    # 10. Dual-model ensemble agreement test in VishnuIsolationForestAdapter
    def test_10_dual_model_ensemble_agreement(self):
        adapter = get_ml_adapter()
        self.assertTrue(adapter.is_loaded)
        self.assertIsNotNone(adapter.rf_model, "Random Forest model should be loaded in dual-model adapter")

        # Test extreme anomalous event where both models agree
        anomalous_event = {
            "actor_id": "EMP002",
            "actor_type": "employee",
            "event_type": "file_share",
            "resource": "executive_payroll_q3.xlsx",
            "is_sensitive": True,
            "action": "download",
            "destination": "external_cloud_drive",
            "timestamp": "2026-11-01T02:30:00Z",
            "employee_activities_24h": 45,
            "downloads_24h": 22,
            "external_activities_24h": 18,
            "sensitive_accesses_24h": 12
        }

        res = adapter.score(anomalous_event)
        self.assertTrue(res.anomaly)
        # Should include both Random Forest and Isolation Forest factors
        factors_str = " ".join(res.factors)
        self.assertIn("Isolation Forest", factors_str)
        self.assertIn("Random Forest", factors_str)

    # 11. Unified incident schema normalization adherence
    def test_11_unified_predictions_schema(self):
        from ml.unified_predictions import normalize_employee

        raw_item = {
            "actor_id": "EMP005",
            "event_type": "employee_file_access",
            "resource": "financial_records.xlsx",
            "action": "download",
            "prediction": "Suspicious",
            "risk_level": "High",
            "reasons": ["Flagged by Random Forest", "Models disagree; manual review recommended"],
            "recommended_action": "Restrict access and review incident",
            "timestamp": "2026-10-29T20:00:00Z",
            "model": "Random Forest",
            "risk_score": 0.69,
            "models_agree": False,
            "isolation_forest": {
                "risk_score": 1.0,
                "anomaly_score": -0.595,
                "prediction": "Normal"
            }
        }

        normalized = normalize_employee(raw_item, 42)
        self.assertEqual(normalized["incident_id"], "EMP-00042")
        self.assertEqual(normalized["source"], "employee")
        self.assertEqual(normalized["prediction"], "Suspicious")
        self.assertEqual(normalized["details"]["primary_model"], "Random Forest")
        self.assertFalse(normalized["details"]["models_agree"])

if __name__ == "__main__":
    unittest.main()
