import json
from pathlib import Path

from generate_data import load_events, extract_features
from predict import predict_event

PROJECT_ROOT = Path(__file__).resolve().parent.parent

OUTPUT_FILE = PROJECT_ROOT / "ml" / "predictions.jsonl"


def run_detection():

    # Load employee events
    events = load_events()

    # Convert events into ML features
    dataset = extract_features(events)

    results = []

    # Process each event
    for index, event in enumerate(events):

        # Get the corresponding feature row
        event_features = dataset.iloc[index].drop(
            labels=["simulated_suspicious"]
        ).to_dict()

        # Predict whether the event is suspicious
        prediction = predict_event(event_features)

        # Generate an explanation for the prediction
        reasons = []

        if prediction["prediction"] == "Suspicious":
            reasons.append(
                "Employee activity flagged as anomalous by Isolation Forest"
            )

        # Combine original event and prediction
        result = {
            "actor_id": event["actor_id"],
            "event_type": event["event_type"],
            "resource": event["resource"],
            "action": event["action"],
            "timestamp": event.get("timestamp"),
            "reasons": reasons,
            **prediction
        }

        results.append(result)

    # Save results as JSONL
    with open(OUTPUT_FILE, "w", encoding="utf-8") as file:
        for result in results:
            file.write(json.dumps(result) + "\n")

    print("Employee detection completed!")
    print("Total events:", len(results))
    print(
        "Suspicious events:",
        sum(item["prediction"] == "Suspicious" for item in results)
    )
    print("Results saved to:", OUTPUT_FILE)


if __name__ == "__main__":
    run_detection()