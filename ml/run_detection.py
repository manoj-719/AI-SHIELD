
import json
from pathlib import Path

from generate_data import load_events, extract_features
from predict import predict_event
from random_forest_predict import predict_random_forest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_FILE = PROJECT_ROOT / "ml" / "predictions.jsonl"


def run_detection():

    events = load_events()
    dataset = extract_features(events)

    results = []

    for index, event in enumerate(events):

        event_features = dataset.iloc[index].drop(
            labels=["simulated_suspicious"],
            errors="ignore"
        ).to_dict()

        # Primary model: Random Forest
        rf_result = predict_random_forest(event_features)

        # Secondary model: Isolation Forest
        if_result = predict_event(event_features)

        rf_suspicious = rf_result["prediction"] == "Suspicious"
        if_suspicious = if_result["prediction"] == "Suspicious"

        # Random Forest remains the primary prediction.
        final_prediction = rf_result["prediction"]

        # Agreement information for review.
        agreement = rf_suspicious == if_suspicious

        reasons = []

        if rf_suspicious:
            reasons.append("Flagged by Random Forest")

        if if_suspicious:
            reasons.append("Flagged as anomalous by Isolation Forest")

        if not agreement:
            reasons.append("Models disagree; manual review recommended")

        result = {
            "actor_id": event["actor_id"],
            "event_type": event["event_type"],
            "resource": event["resource"],
            "action": event["action"],
            "timestamp": event.get("timestamp"),

            # Preserve the primary model's existing output fields.
            **rf_result,

            # Include secondary model results.
            "isolation_forest": if_result,
            "models_agree": agreement,
            "reasons": reasons
        }

        results.append(result)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as file:
        for result in results:
            file.write(json.dumps(result) + "\n")

    print("\n========== AI SHIELD DUAL MODEL DETECTION ==========")
    print("Total events:", len(results))
    print(
        "Random Forest suspicious:",
        sum(r["prediction"] == "Suspicious" for r in results)
    )
    print(
        "Isolation Forest suspicious:",
        sum(r["isolation_forest"]["prediction"] == "Suspicious" for r in results)
    )
    print(
        "Models agree:",
        sum(r["models_agree"] for r in results)
    )
    print(
        "Models disagree:",
        sum(not r["models_agree"] for r in results)
    )
    print("Results saved to:", OUTPUT_FILE)
    print("====================================================")


if __name__ == "__main__":
    run_detection()
