
import joblib
import numpy as np
import pandas as pd
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODEL_DIR = PROJECT_ROOT / "ml" / "saved_model"

MODEL_PATH = MODEL_DIR / "isolation_forest.pkl"
THRESHOLD_PATH = MODEL_DIR / "anomaly_threshold.txt"

model = joblib.load(MODEL_PATH)

with open(THRESHOLD_PATH, "r", encoding="utf-8") as file:
    THRESHOLD = float(file.read().strip())


def predict_event(event_features):

    required_features = [
        "is_sensitive",
        "is_read",
        "is_download",
        "is_share",
        "is_external",
        "hour",
        "day_of_week",
        "is_weekend",
        "employee_activities_24h",
        "downloads_24h",
        "external_activities_24h",
        "sensitive_accesses_24h"
    ]

    missing = set(required_features) - set(event_features)

    if missing:
        raise ValueError(f"Missing features: {sorted(missing)}")

    input_data = pd.DataFrame(
        [[event_features[name] for name in required_features]],
        columns=required_features
    )

    anomaly_score = float(model.score_samples(input_data)[0])
    is_suspicious = anomaly_score < THRESHOLD

    if not is_suspicious:
        risk_level = "Low"
        action = "Allow activity"
    elif event_features["is_sensitive"] and event_features["is_external"]:
        risk_level = "High"
        action = "Restrict access and review incident"
    else:
        risk_level = "Medium"
        action = "Flag activity for security review"

    return {
        "risk_score": round(
            float(np.clip(1 - model.decision_function(input_data)[0], 0, 1)),
            4
        ),
        "anomaly_score": round(anomaly_score, 6),
        "prediction": "Suspicious" if is_suspicious else "Normal",
        "risk_level": risk_level,
        "recommended_action": action,
        "model": "Isolation Forest"
    }


if __name__ == "__main__":

    sample_event = {
        "is_sensitive": 1,
        "is_read": 0,
        "is_download": 1,
        "is_share": 0,
        "is_external": 1,
        "hour": 2,
        "day_of_week": 6,
        "is_weekend": 1,
        "employee_activities_24h": 15,
        "downloads_24h": 8,
        "external_activities_24h": 4,
        "sensitive_accesses_24h": 7
    }

    print(predict_event(sample_event))
