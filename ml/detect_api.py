
import json
from pathlib import Path
from collections import defaultdict, deque
from datetime import datetime, timedelta

PROJECT_ROOT = Path(__file__).resolve().parent.parent

INPUT_FILE = PROJECT_ROOT / "simulators" / "api_events.jsonl"
OUTPUT_FILE = PROJECT_ROOT / "ml" / "api_predictions.jsonl"


def detect_api_threats(events):
    request_history = defaultdict(deque)
    denied_history = defaultdict(deque)

    results = []

    # Process events chronologically
    events.sort(key=lambda event: event["timestamp"])

    for event in events:
        actor_id = event["actor_id"]
        timestamp = datetime.fromisoformat(event["timestamp"])

        # Remove requests older than 60 seconds
        cutoff = timestamp - timedelta(seconds=60)

        history = request_history[actor_id]
        while history and history[0] < cutoff:
            history.popleft()

        denied = denied_history[actor_id]
        while denied and denied[0] < cutoff:
            denied.popleft()

        # Add current request
        history.append(timestamp)

        if event["status_code"] in [401, 403]:
            denied.append(timestamp)

        # Count requests in the last 60 seconds
        request_count = len(history)
        denied_count = len(denied)

        # Detect threats
        reasons = []

        if event["actor_type"] == "external_bot" and event["is_sensitive"]:
            reasons.append("External bot accessing sensitive endpoint")

        if not event["is_authorized"]:
            reasons.append("Unauthorized API request")

        if request_count >= 30:
            reasons.append("High API request frequency")

        if denied_count >= 5:
            reasons.append("Repeated denied API requests")

        # Calculate risk
        if len(reasons) >= 3:
            risk_level = "Critical"
        elif len(reasons) == 2:
            risk_level = "High"
        elif len(reasons) == 1:
            risk_level = "Medium"
        else:
            risk_level = "Low"

        # Recommend an action
        recommended_action = "Allow request"

        if risk_level == "Critical":
            recommended_action = "Block request and alert administrator"
        elif risk_level == "High":
            recommended_action = "Temporarily restrict access and alert administrator"
        elif risk_level == "Medium":
            recommended_action = "Flag request for security review"

        # Build prediction result
        result = {
            "event_type": event["event_type"],
            "actor_id": actor_id,
            "actor_type": event["actor_type"],
            "source_ip": event["source_ip"],
            "endpoint": event["endpoint"],
            "method": event["method"],
            "status_code": event["status_code"],
            "timestamp": event["timestamp"],
            "request_count_60s": request_count,
            "denied_count_60s": denied_count,
            "prediction": "Suspicious" if reasons else "Normal",
            "risk_level": risk_level,
            "reasons": reasons,
            "recommended_action": recommended_action
        }

        results.append(result)

    return results


def load_events():
    events = []

    with open(INPUT_FILE, "r", encoding="utf-8") as file:
        for line in file:
            if line.strip():
                events.append(json.loads(line))

    return events


def save_predictions(results):
    with open(OUTPUT_FILE, "w", encoding="utf-8") as file:
        for result in results:
            file.write(json.dumps(result) + "\n")


if __name__ == "__main__":
    events = load_events()
    predictions = detect_api_threats(events)
    save_predictions(predictions)

    suspicious_count = sum(
        item["prediction"] == "Suspicious"
        for item in predictions
    )

    print("API threat detection completed!")
    print("Total requests:", len(predictions))
    print("Suspicious requests:", suspicious_count)
    print("Normal requests:", len(predictions) - suspicious_count)
    print("Results saved to:", OUTPUT_FILE)
