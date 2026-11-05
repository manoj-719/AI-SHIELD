"""
AI Shield - Machine Learning Anomaly Detection Adapter.
Defines the contract for ML anomaly scoring and risk evaluation.
Integrates Vishnu's Isolation Forest employee anomaly detection model
and API threat detection rules.
"""

import os
import json
import joblib
import pandas as pd
import numpy as np
from pathlib import Path
from typing import Dict, Any, Optional
from collections import defaultdict, deque
from datetime import datetime, timezone

class MLAnomalyResult:
    """Standardized output returned by ML anomaly detection."""
    def __init__(
        self,
        anomaly: bool = False,
        risk_score: float = 0.0,
        risk_level: str = "low",
        confidence: float = 0.85,
        factors: Optional[list] = None
    ):
        self.anomaly = bool(anomaly)
        self.risk_score = round(float(risk_score), 2)
        self.risk_level = risk_level.lower()
        self.confidence = float(confidence)
        self.factors = factors or []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "anomaly": self.anomaly,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "confidence": self.confidence,
            "factors": self.factors
        }


class VishnuIsolationForestAdapter:
    """
    Production ML Anomaly Detection Adapter integrating Vishnu's Dual-Model Ensemble
    (Random Forest supervised classification + Isolation Forest unsupervised anomaly detection)
    and API threat detection rules.
    """
    def __init__(
        self,
        model_path: Optional[Path] = None,
        threshold_path: Optional[Path] = None,
        rf_model_path: Optional[Path] = None,
        feature_names_path: Optional[Path] = None
    ):
        project_root = Path(__file__).resolve().parent.parent.parent
        self.model_dir = project_root / "ml" / "saved_model"
        self.model_path = model_path or (self.model_dir / "isolation_forest.pkl")
        self.threshold_path = threshold_path or (self.model_dir / "anomaly_threshold.txt")
        self.rf_model_path = rf_model_path or (self.model_dir / "random_forest_model.pkl")
        self.feature_names_path = feature_names_path or (self.model_dir / "feature_names.json")

        self.model = None
        self.threshold = -0.60017
        self.rf_model = None
        self.rf_features = None
        self.is_loaded = False
        self.load_error = None
        
        # In-memory rolling history of activities per actor_id (last 24 hours)
        self.actor_history = defaultdict(deque)

        self._load_model()

    def _load_model(self):
        try:
            if self.model_path.exists() and self.threshold_path.exists():
                self.model = joblib.load(self.model_path)
                with open(self.threshold_path, "r", encoding="utf-8") as f:
                    self.threshold = float(f.read().strip())
                self.is_loaded = True
            else:
                self.is_loaded = False
                self.load_error = f"Model artifact not found at {self.model_path}"
        except Exception as e:
            self.is_loaded = False
            self.load_error = f"Failed to load Isolation Forest: {str(e)}"

        # Optionally load Random Forest model (Vishnu's dual-model supervised classifier)
        try:
            if self.rf_model_path.exists() and self.feature_names_path.exists():
                self.rf_model = joblib.load(self.rf_model_path)
                with open(self.feature_names_path, "r", encoding="utf-8") as f:
                    self.rf_features = json.load(f)
            else:
                self.rf_model = None
                self.rf_features = None
        except Exception as e:
            print(f"[MLAdapter] Notice: Random Forest secondary model bypassed: {e}")
            self.rf_model = None
            self.rf_features = None

    def score(self, event: Dict[str, Any]) -> MLAnomalyResult:
        # 1. Respect explicit pre-computed upstream ML scores if passed
        in_anomaly = event.get("anomaly")
        in_risk_score = event.get("risk_score")
        if in_risk_score is not None:
            score = float(in_risk_score)
            is_anomaly = bool(in_anomaly) if in_anomaly is not None else (score >= 60.0)
            level = "critical" if score >= 80.0 else ("high" if score >= 60.0 else ("medium" if score >= 30.0 else "low"))
            return MLAnomalyResult(
                anomaly=is_anomaly,
                risk_score=score,
                risk_level=level,
                confidence=0.90,
                factors=["Upstream ML score preserved"]
            )

        # 2. Check for API threat pattern (Vishnu detect_api.py logic)
        actor_type = str(event.get("actor_type", "")).lower()
        event_type = str(event.get("event_type", "")).lower()
        if actor_type == "external_bot" or "api" in event_type or event.get("is_authorized") is False:
            return self._score_api_threat(event)

        # 3. If model is unavailable, return degraded fallback (NEVER silently treat as safe)
        if not self.is_loaded:
            is_sensitive = bool(event.get("is_sensitive", False))
            return MLAnomalyResult(
                anomaly=is_sensitive,
                risk_score=55.0 if is_sensitive else 35.0,
                risk_level="medium" if is_sensitive else "low",
                confidence=0.50,
                factors=[f"ML model unavailable ({self.load_error}) - degraded fallback applied"]
            )

        # 4. Feature Extraction & Prediction using Vishnu's Dual-Model Ensemble
        try:
            features = self._extract_features(event)
            feature_cols = self.rf_features or [
                "is_sensitive", "is_read", "is_download", "is_share", "is_external",
                "hour", "day_of_week", "is_weekend",
                "employee_activities_24h", "downloads_24h", "external_activities_24h", "sensitive_accesses_24h"
            ]
            input_df = pd.DataFrame([[features[name] for name in feature_cols]], columns=feature_cols)

            anomaly_score = float(self.model.score_samples(input_df)[0])
            is_suspicious_if = bool(anomaly_score < self.threshold)

            # Evaluate Random Forest if loaded
            rf_prob = 0.0
            is_suspicious_rf = False
            if self.rf_model is not None:
                try:
                    rf_prob = float(self.rf_model.predict_proba(input_df)[0][1])
                    is_suspicious_rf = bool(rf_prob >= 0.30)
                except Exception:
                    pass

            is_suspicious = is_suspicious_if or is_suspicious_rf

            factors = []
            if is_suspicious:
                if is_suspicious_if:
                    factors.append(f"Employee activity flagged as anomalous by Isolation Forest (score: {round(anomaly_score, 4)}, threshold: {round(self.threshold, 4)})")
                if is_suspicious_rf:
                    factors.append(f"Employee activity flagged by Random Forest (probability: {round(rf_prob, 4)})")
                if is_suspicious_if and is_suspicious_rf:
                    factors.append("Dual ML models agree on anomalous classification")
                elif is_suspicious_if != is_suspicious_rf:
                    factors.append("Models disagree; manual review recommended")

                if features["is_sensitive"] and features["is_external"]:
                    risk_score = 85.0
                    risk_level = "critical"
                    factors.append("Sensitive corporate document accessed with external destination")
                elif features["is_sensitive"]:
                    risk_score = 75.0
                    risk_level = "high"
                    factors.append("Anomalous access pattern involving sensitive internal asset")
                elif features["is_weekend"]:
                    risk_score = 65.0
                    risk_level = "high"
                    factors.append("Off-hours weekend activity deviation from nominal baseline")
                else:
                    risk_score = 60.0
                    risk_level = "medium"
                    factors.append("Behavioral statistical divergence from standard employee baseline")
                confidence = 0.92
            else:
                if features["is_sensitive"]:
                    risk_score = 35.0
                    risk_level = "medium"
                    factors.append("Internal access to sensitive document within nominal baseline")
                else:
                    risk_score = 10.0
                    risk_level = "low"
                    factors.append("Routine employee activity consistent with dual-model baseline")
                confidence = 0.95

            return MLAnomalyResult(
                anomaly=is_suspicious,
                risk_score=risk_score,
                risk_level=risk_level,
                confidence=confidence,
                factors=factors
            )

        except Exception as e:
            # Exception safety: do NOT silently treat failed predictions as safe!
            return MLAnomalyResult(
                anomaly=True,
                risk_score=60.0,
                risk_level="medium",
                confidence=0.50,
                factors=[f"ML prediction exception: {str(e)} - flagged for security review"]
            )

    def _extract_features(self, event: Dict[str, Any]) -> Dict[str, Any]:
        action = str(event.get("action", "")).lower()
        destination = str(event.get("destination", "")).lower()
        is_sensitive = 1 if bool(event.get("is_sensitive", False)) else 0
        is_read = 1 if action == "read" else 0
        is_download = 1 if action == "download" else 0
        is_share = 1 if action == "share" else 0

        is_internal = not destination or any(kw in destination for kw in ("internal", "local", "intranet", "workstation", "laptop", "corp", "none"))
        is_external = 1 if bool(destination) and not is_internal else 0

        # Parse timestamp safely
        ts_val = event.get("timestamp")
        try:
            if ts_val:
                dt = datetime.fromisoformat(str(ts_val).replace("Z", "+00:00"))
            else:
                dt = datetime.now(timezone.utc)
        except Exception:
            dt = datetime.now(timezone.utc)

        hour = dt.hour
        day_of_week = dt.weekday()
        is_weekend = 1 if day_of_week >= 5 else 0

        # Rolling 24h history for this actor
        actor_id = str(event.get("actor_id", "unknown"))
        history = self.actor_history[actor_id]

        if "employee_activities_24h" in event:
            activities_24h = int(event.get("employee_activities_24h", 0))
            downloads_24h = int(event.get("downloads_24h", 0))
            external_24h = int(event.get("external_activities_24h", 0))
            sensitive_24h = int(event.get("sensitive_accesses_24h", 0))
        else:
            cutoff = dt.timestamp() - (24 * 3600)
            while history and history[0]["time"] < cutoff:
                history.popleft()

            activities_24h = len(history)
            downloads_24h = sum(1 for h in history if h["action"] == "download")
            external_24h = sum(1 for h in history if h["is_external"] == 1)
            sensitive_24h = sum(1 for h in history if h["is_sensitive"] == 1)

            history.append({
                "time": dt.timestamp(),
                "action": action,
                "is_external": is_external,
                "is_sensitive": is_sensitive
            })

        return {
            "is_sensitive": is_sensitive,
            "is_read": is_read,
            "is_download": is_download,
            "is_share": is_share,
            "is_external": is_external,
            "hour": hour,
            "day_of_week": day_of_week,
            "is_weekend": is_weekend,
            "employee_activities_24h": activities_24h,
            "downloads_24h": downloads_24h,
            "external_activities_24h": external_24h,
            "sensitive_accesses_24h": sensitive_24h
        }

    def _score_api_threat(self, event: Dict[str, Any]) -> MLAnomalyResult:
        reasons = []
        actor_type = str(event.get("actor_type", "")).lower()
        is_sensitive = bool(event.get("is_sensitive", False))
        is_authorized = event.get("is_authorized", True)
        status_code = int(event.get("status_code", 200)) if event.get("status_code") is not None else 200
        req_count = int(event.get("request_count_60s", 1))
        denied_count = int(event.get("denied_count_60s", 0))

        if actor_type in ("external", "external_bot") and is_sensitive:
            reasons.append("External bot accessing sensitive endpoint")
        if is_authorized is False or status_code in (401, 403):
            reasons.append("Unauthorized API request")
        if req_count >= 30:
            reasons.append("High API request frequency")
        if denied_count >= 5:
            reasons.append("Repeated denied API requests")

        if len(reasons) >= 3:
            return MLAnomalyResult(
                anomaly=True,
                risk_score=90.0,
                risk_level="critical",
                confidence=0.95,
                factors=reasons
            )
        elif len(reasons) == 2:
            return MLAnomalyResult(
                anomaly=True,
                risk_score=75.0,
                risk_level="high",
                confidence=0.90,
                factors=reasons
            )
        elif len(reasons) == 1:
            return MLAnomalyResult(
                anomaly=True,
                risk_score=50.0,
                risk_level="medium",
                confidence=0.85,
                factors=reasons
            )
        else:
            return MLAnomalyResult(
                anomaly=False,
                risk_score=15.0,
                risk_level="low",
                confidence=0.95,
                factors=["API request within normal limits"]
            )


class MockMLAnomalyAdapter:
    """
    Reference mock adapter for testing ML integration with static heuristics.
    """
    def score(self, event: Dict[str, Any]) -> MLAnomalyResult:
        in_anomaly = event.get("anomaly")
        in_risk_score = event.get("risk_score")
        if in_risk_score is not None:
            score = float(in_risk_score)
            is_anomaly = bool(in_anomaly) if in_anomaly is not None else (score >= 60.0)
            level = "critical" if score >= 80.0 else ("high" if score >= 60.0 else ("medium" if score >= 30.0 else "low"))
            return MLAnomalyResult(
                anomaly=is_anomaly,
                risk_score=score,
                risk_level=level,
                confidence=0.90,
                factors=["Upstream ML score preserved"]
            )

        destination = str(event.get("destination", "")).lower()
        is_sensitive = bool(event.get("is_sensitive", False))
        actor_type = str(event.get("actor_type", "")).lower()

        is_internal = not destination or any(kw in destination for kw in ("internal", "local", "intranet", "workstation", "laptop", "corp", "none"))
        is_external = bool(destination) and not is_internal

        if is_sensitive and is_external:
            return MLAnomalyResult(
                anomaly=True,
                risk_score=85.0,
                risk_level="critical",
                confidence=0.94,
                factors=["Sensitive data destination is external", "High exfiltration probability"]
            )
        elif actor_type == "agent" and is_sensitive:
            return MLAnomalyResult(
                anomaly=True,
                risk_score=75.0,
                risk_level="high",
                confidence=0.88,
                factors=["Agent access to sensitive asset outside nominal baseline"]
            )
        elif is_sensitive:
            return MLAnomalyResult(
                anomaly=False,
                risk_score=35.0,
                risk_level="medium",
                confidence=0.80,
                factors=["Internal access to sensitive document"]
            )
        else:
            return MLAnomalyResult(
                anomaly=False,
                risk_score=10.0,
                risk_level="low",
                confidence=0.95,
                factors=["Standard routine activity within baseline"]
            )


# Global active adapter (default to production Vishnu Isolation Forest adapter)
_active_ml_adapter = None

def get_ml_adapter():
    """Return the currently registered ML adapter (instantiates singleton on first call)."""
    global _active_ml_adapter
    if _active_ml_adapter is None:
        _active_ml_adapter = VishnuIsolationForestAdapter()
    return _active_ml_adapter

def set_ml_adapter(adapter):
    """Register a custom or mock ML adapter."""
    global _active_ml_adapter
    _active_ml_adapter = adapter

def reset_ml_adapter():
    """Reset to production Vishnu Isolation Forest adapter."""
    global _active_ml_adapter
    _active_ml_adapter = VishnuIsolationForestAdapter()

