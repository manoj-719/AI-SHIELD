
import json
import joblib
import pandas as pd
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODEL_DIR = PROJECT_ROOT / "ml" / "saved_model"

MODEL_PATH = MODEL_DIR / "random_forest_model.pkl"
FEATURE_PATH = MODEL_DIR / "feature_names.json"

model = joblib.load(MODEL_PATH)

with open(FEATURE_PATH, "r", encoding="utf-8") as file:
    FEATURE_NAMES = json.load(file)

# Exploratory threshold from Colab; validate before production use.
THRESHOLD = 0.30


def predict_random_forest(event_features):
    missing = set(FEATURE_NAMES) - set(event_features)

    if missing:
        raise ValueError(f"Missing features: {sorted(missing)}")

    input_data = pd.DataFrame(
        [[event_features[name] for name in FEATURE_NAMES]],
        columns=FEATURE_NAMES
    )

    probability = float(model.predict_proba(input_data)[0][1])
    is_suspicious = probability >= THRESHOLD

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
        "risk_score": round(probability, 4),
        "prediction": "Suspicious" if is_suspicious else "Normal",
        "risk_level": risk_level,
        "recommended_action": action,
        "model": "Random Forest"
    }
