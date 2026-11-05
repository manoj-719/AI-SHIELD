
import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

EMPLOYEE_FILE = PROJECT_ROOT / "ml" / "predictions.jsonl"
API_FILE = PROJECT_ROOT / "ml" / "api_predictions.jsonl"
OUTPUT_FILE = PROJECT_ROOT / "ml" / "unified_predictions.jsonl"


# ==========================================
# 1. LOAD PREDICTIONS
# ==========================================

def load_predictions(file_path):
    predictions = []

    if not file_path.exists():
        raise FileNotFoundError(
            f"Prediction file not found: {file_path}"
        )

    with open(file_path, "r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            if line.strip():
                try:
                    predictions.append(json.loads(line))
                except json.JSONDecodeError as error:
                    raise ValueError(
                        f"Invalid JSON in {file_path}, line {line_number}"
                    ) from error

    return predictions


# ==========================================
# 2. NORMALIZE EMPLOYEE PREDICTIONS
# ==========================================

def normalize_employee(item, index):
    isolation_forest = item.get("isolation_forest") or {}

    return {
        "incident_id": f"EMP-{index:05d}",
        "source": "employee",
        "actor_id": item.get("actor_id"),
        "event_type": item.get("event_type"),
        "resource": item.get("resource"),
        "action": item.get("action"),
        "prediction": item.get("prediction"),
        "risk_level": item.get("risk_level"),
        "reason": item.get("reasons", []),
        "recommended_action": item.get("recommended_action"),
        "timestamp": item.get("timestamp"),
        "details": {
            "primary_model": item.get("model"),
            "random_forest_score": item.get("risk_score"),
            "isolation_forest": isolation_forest,
            "models_agree": item.get("models_agree"),
            "anomaly_score": isolation_forest.get("anomaly_score")
        }
    }


# ==========================================
# 3. NORMALIZE API PREDICTIONS
# ==========================================

def normalize_api(item, index):
    return {
        "incident_id": f"API-{index:05d}",
        "source": "api",
        "actor_id": item.get("actor_id"),
        "event_type": item.get("event_type"),
        "resource": item.get("endpoint"),
        "action": item.get("method"),
        "prediction": item.get("prediction"),
        "risk_level": item.get("risk_level"),
        "reason": item.get("reasons", []),
        "recommended_action": item.get("recommended_action"),
        "timestamp": item.get("timestamp"),
        "details": {
            "actor_type": item.get("actor_type"),
            "source_ip": item.get("source_ip"),
            "status_code": item.get("status_code"),
            "request_count_60s": item.get("request_count_60s"),
            "denied_count_60s": item.get("denied_count_60s")
        }
    }


# ==========================================
# 4. COMBINE EMPLOYEE AND API PREDICTIONS
# ==========================================

def create_unified_predictions():
    employee_predictions = load_predictions(EMPLOYEE_FILE)
    api_predictions = load_predictions(API_FILE)

    unified = []

    for index, item in enumerate(employee_predictions, start=1):
        unified.append(normalize_employee(item, index))

    for index, item in enumerate(api_predictions, start=1):
        unified.append(normalize_api(item, index))

    # Sort chronologically; missing timestamps go last
    unified.sort(
        key=lambda item: item.get("timestamp") or "9999"
    )

    return unified


# ==========================================
# 5. SAVE UNIFIED PREDICTIONS
# ==========================================

def save_predictions(predictions):
    with open(OUTPUT_FILE, "w", encoding="utf-8") as file:
        for prediction in predictions:
            file.write(json.dumps(prediction) + "\n")


# ==========================================
# 6. GENERATE SECURITY SUMMARY
# ==========================================

def generate_summary(predictions):
    total_events = len(predictions)

    suspicious_events = [
        item for item in predictions
        if item.get("prediction") == "Suspicious"
    ]

    normal_events = [
        item for item in predictions
        if item.get("prediction") == "Normal"
    ]

    risk_counts = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0
    }

    for item in predictions:
        risk = item.get("risk_level", "Low")

        if risk in risk_counts:
            risk_counts[risk] += 1

    employee_count = sum(
        item.get("source") == "employee"
        for item in predictions
    )

    api_count = sum(
        item.get("source") == "api"
        for item in predictions
    )

    print("\n========== AI SHIELD SECURITY SUMMARY ==========")
    print("Total events:", total_events)
    print("Employee events:", employee_count)
    print("API events:", api_count)
    print("Suspicious events:", len(suspicious_events))
    print("Normal events:", len(normal_events))

    print("\nRisk distribution:")

    for risk, count in risk_counts.items():
        print(f"{risk}: {count}")

    print("================================================")


# ==========================================
# 7. MAIN EXECUTION
# ==========================================

if __name__ == "__main__":
    print("Starting unified threat pipeline...")

    unified_predictions = create_unified_predictions()

    save_predictions(unified_predictions)

    generate_summary(unified_predictions)

    print("\nUnified threat pipeline completed!")
    print("Output file:", OUTPUT_FILE)
