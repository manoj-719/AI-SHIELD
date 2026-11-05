import json
import pandas as pd
from pathlib import Path
from collections import defaultdict, deque

PROJECT_ROOT = Path(__file__).resolve().parent.parent

INPUT_FILE = PROJECT_ROOT / "simulators" / "employee_events.jsonl"
OUTPUT_FILE = PROJECT_ROOT / "ml" / "employee_dataset.csv"


def load_events():
    events = []

    with open(INPUT_FILE, "r", encoding="utf-8") as file:
        for line in file:
            events.append(json.loads(line))

    return events


def extract_features(events):
    # Process events in chronological order
    events.sort(key=lambda event: event["timestamp"])

    # Store each employee's previous activities
    employee_history = defaultdict(deque)

    rows = []

    for event in events:
        timestamp = pd.to_datetime(event["timestamp"], utc=True)
        employee = event["actor_id"]

        history = employee_history[employee]

        # Keep only activities from the previous 24 hours
        cutoff = timestamp - pd.Timedelta(hours=24)

        while history and history[0]["timestamp"] < cutoff:
            history.popleft()

        # Calculate previous activity patterns
        total_activities = len(history)

        downloads = sum(
            item["action"] == "download" for item in history
        )

        external_activities = sum(
            item["destination"] == "external" for item in history
        )

        sensitive_accesses = sum(
            item["is_sensitive"] for item in history
        )

        row = {
            "is_sensitive": int(event["is_sensitive"]),
            "is_read": int(event["action"] == "read"),
            "is_download": int(event["action"] == "download"),
            "is_share": int(event["action"] == "share"),
            "is_external": int(event["destination"] == "external"),

            "hour": timestamp.hour,
            "day_of_week": timestamp.day_of_week,
            "is_weekend": int(timestamp.day_of_week >= 5),

            "employee_activities_24h": total_activities,
            "downloads_24h": downloads,
            "external_activities_24h": external_activities,
            "sensitive_accesses_24h": sensitive_accesses,

            # Keep this only for evaluation, not model training
            "simulated_suspicious": int(
                event["simulated_suspicious"]
            )
        }

        rows.append(row)

        # Add the current activity to employee history
        history.append({
            "timestamp": timestamp,
            "action": event["action"],
            "destination": event["destination"],
            "is_sensitive": event["is_sensitive"]
        })

    return pd.DataFrame(rows)


if __name__ == "__main__":
    events = load_events()
    dataset = extract_features(events)

    dataset.to_csv(OUTPUT_FILE, index=False)

    print("Improved dataset preparation completed!")
    print("Total records:", len(dataset))
    print("Total features:", len(dataset.columns) - 1)
    print("Dataset saved to:", OUTPUT_FILE)
    print(dataset.head())