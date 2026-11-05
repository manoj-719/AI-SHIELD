import joblib
import pandas as pd
from pathlib import Path

# Locate saved model files
PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODEL_DIR = PROJECT_ROOT / "ml" / "saved_model"

MODEL_PATH = MODEL_DIR / "isolation_forest.pkl"
THRESHOLD_PATH = MODEL_DIR / "anomaly_threshold.txt"

# Load trained model and threshold
model = joblib.load(MODEL_PATH)

with open(THRESHOLD_PATH, "r") as file:
    threshold = float(file.read().strip())


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

    # Check whether all required features are present
    missing = set(required_features) - set(event_features)

    if missing:
        raise ValueError(f"Missing features: {missing}")

    # Arrange features in the same order used during training
    input_data = pd.DataFrame(
        [[event_features[name] for name in required_features]],
        columns=required_features
    )

    # Generate anomaly score
    anomaly_score = model.score_samples(input_data)[0]

    # Lower scores indicate more anomalous activity
    is_suspicious = anomaly_score < threshold

    # Rule-based risk level
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
        "anomaly_score": round(float(anomaly_score), 4),
        "prediction": "Suspicious" if is_suspicious else "Normal",
        "risk_level": risk_level,
        "recommended_action": action
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

    result = predict_event(sample_event)

    print("\n========== AI SHIELD THREAT DETECTION ==========")

    for key, value in result.items():
        print(f"{key}: {value}")

    print("================================================")