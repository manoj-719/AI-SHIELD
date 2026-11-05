import json
import random
from pathlib import Path
from datetime import datetime, timedelta, timezone

random.seed(42)

# Available API endpoints
endpoints = {
    "/api/employees": {
        "sensitive": True,
        "allowed_methods": ["GET"]
    },
    "/api/payroll": {
        "sensitive": True,
        "allowed_methods": ["GET"]
    },
    "/api/customers": {
        "sensitive": True,
        "allowed_methods": ["GET", "POST"]
    },
    "/api/reports": {
        "sensitive": False,
        "allowed_methods": ["GET"]
    },
    "/api/public": {
        "sensitive": False,
        "allowed_methods": ["GET"]
    }
}

# Simulated API users and bots
actors = {
    "EMP001": {
        "type": "employee",
        "ip": "10.0.0.11"
    },
    "EMP002": {
        "type": "employee",
        "ip": "10.0.0.12"
    },
    "BOT001": {
        "type": "authorized_bot",
        "ip": "10.0.0.50"
    },
    "BOT002": {
        "type": "authorized_bot",
        "ip": "10.0.0.51"
    },
    "BOT003": {
        "type": "external_bot",
        "ip": "203.0.113.25"
    }
}

def create_api_event(actor_id, endpoint, method, timestamp, suspicious=False):
    actor = actors[actor_id]
    endpoint_info = endpoints[endpoint]

    authorized = (
        actor["type"] != "external_bot"
        and method in endpoint_info["allowed_methods"]
    )

    status_code = 200 if authorized else 403

    return {
        "event_type": "api_request",
        "actor_id": actor_id,
        "actor_type": actor["type"],
        "source_ip": actor["ip"],
        "endpoint": endpoint,
        "method": method,
        "status_code": status_code,
        "timestamp": timestamp.isoformat(),
        "is_sensitive": endpoint_info["sensitive"],
        "is_authorized": authorized,
        "simulated_suspicious": suspicious,
        "source": "api_request_simulator"
    }

def generate_api_traffic():
    events = []
    base_time = datetime.now(timezone.utc)

    # 1. Generate normal API traffic
    normal_actors = ["EMP001", "EMP002", "BOT001", "BOT002"]

    for i in range(500):
        actor_id = random.choice(normal_actors)
        endpoint = random.choice(list(endpoints.keys()))
        allowed_methods = endpoints[endpoint]["allowed_methods"]
        method = random.choice(allowed_methods)

        timestamp = base_time + timedelta(seconds=i * 5)

        event = create_api_event(
            actor_id, endpoint, method, timestamp
        )
        events.append(event)

    # 2. Generate suspicious external bot traffic
    for i in range(40):
        endpoint = random.choice([
            "/api/employees",
            "/api/payroll",
            "/api/customers"
        ])

        timestamp = base_time + timedelta(minutes=50, seconds=i)

        event = create_api_event(
            "BOT003",
            endpoint,
            "GET",
            timestamp,
            suspicious=True
        )
        events.append(event)

    # 3. Generate suspicious method attempts
    for i in range(20):
        timestamp = base_time + timedelta(minutes=55, seconds=i * 2)

        event = create_api_event(
            "EMP001",
            "/api/payroll",
            "DELETE",
            timestamp,
            suspicious=True
        )
        events.append(event)

    events.sort(key=lambda event: event["timestamp"])
    return events

if __name__ == "__main__":
    events = generate_api_traffic()

    output_file = Path(__file__).resolve().parent / "api_events.jsonl"

    with open(output_file, "w", encoding="utf-8") as file:
        for event in events:
            file.write(json.dumps(event) + "\n")

    print("API traffic simulation completed!")
    print("Total events:", len(events))
    print(
        "Suspicious events:",
        sum(event["simulated_suspicious"] for event in events)
    )
    print("Saved to:", output_file)