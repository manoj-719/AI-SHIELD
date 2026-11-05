
import json
import random
from pathlib import Path
from datetime import datetime, timedelta, timezone

random.seed(42)

# Employee roles and their normal file access
employees = {
    "EMP001": {"role": "HR", "files": [
        "employee_records.csv", "salary_details.xlsx"
    ]},
    "EMP002": {"role": "HR", "files": [
        "employee_records.csv", "salary_details.xlsx"
    ]},
    "EMP003": {"role": "Finance", "files": [
        "financial_records.xlsx", "company_report.pdf"
    ]},
    "EMP004": {"role": "Finance", "files": [
        "financial_records.xlsx", "company_report.pdf"
    ]},
    "EMP005": {"role": "Sales", "files": [
        "customer_data.csv", "company_report.pdf"
    ]},
    "EMP006": {"role": "Sales", "files": [
        "customer_data.csv", "company_report.pdf"
    ]},
    "EMP007": {"role": "Developer", "files": [
        "project_notes.txt", "public_policy.pdf"
    ]},
    "EMP008": {"role": "Developer", "files": [
        "project_notes.txt", "public_policy.pdf"
    ]}
}

# Remaining employees have general access
for i in range(9, 21):
    employees[f"EMP{i:03d}"] = {
        "role": "General",
        "files": ["company_report.pdf", "public_policy.pdf"]
    }

file_sensitivity = {
    "employee_records.csv": True,
    "salary_details.xlsx": True,
    "financial_records.xlsx": True,
    "customer_data.csv": True,
    "company_report.pdf": False,
    "project_notes.txt": False,
    "public_policy.pdf": False
}

actions = ["read", "download", "share"]


def create_event(employee, resource, action, destination,
                 timestamp, suspicious=False):

    return {
        "event_type": "employee_file_access",
        "actor_type": "employee",
        "actor_id": employee,
        "resource": resource,
        "is_sensitive": file_sensitivity[resource],
        "action": action,
        "destination": destination,
        "timestamp": timestamp.isoformat(),
        "source": "employee_simulator",
        "description": (
            f"{employee} performed {action} "
            f"on {resource} to {destination}"
        ),
        "simulated_suspicious": suspicious
    }


def generate_employee_activity(count=1000):

    events = []
    start_time = datetime.now(timezone.utc) - timedelta(days=7)

    employee_ids = list(employees.keys())

    # Generate ordinary employee activity
    for _ in range(count):

        employee = random.choice(employee_ids)
        profile = employees[employee]

        resource = random.choice(profile["files"])
        action = random.choices(
            actions, weights=[70, 20, 10]
        )[0]

        timestamp = start_time + timedelta(
            minutes=random.randint(0, 7 * 24 * 60)
        )

        events.append(
            create_event(
                employee,
                resource,
                action,
                "internal",
                timestamp
            )
        )

    # Inject separate suspicious scenarios
    suspicious_count = max(1, int(count * 0.10))

    for _ in range(suspicious_count):

        employee = random.choice(employee_ids)

        # Scenario 1: Bulk sensitive downloads
        if random.random() < 0.4:
            resource = random.choice([
                "customer_data.csv",
                "salary_details.xlsx",
                "financial_records.xlsx"
            ])
            action = "download"
            destination = "external"

        # Scenario 2: Unusual external sharing
        elif random.random() < 0.5:
            resource = "employee_records.csv"
            action = "share"
            destination = "external"

        # Scenario 3: Access outside normal role
        else:
            resource = random.choice([
                "salary_details.xlsx",
                "financial_records.xlsx",
                "customer_data.csv"
            ])
            action = "download"
            destination = "internal"

        timestamp = start_time + timedelta(
            minutes=random.randint(0, 7 * 24 * 60)
        )

        events.append(
            create_event(
                employee,
                resource,
                action,
                destination,
                timestamp,
                suspicious=True
            )
        )

    events.sort(key=lambda event: event["timestamp"])

    return events


if __name__ == "__main__":

    activities = generate_employee_activity(1000)

    output_path = Path(__file__).with_name("employee_events.jsonl")

    with open(output_path, "w", encoding="utf-8") as file:
        for event in activities:
            file.write(json.dumps(event) + "\n")

    print("Employee simulation completed!")
    print("Total activities:", len(activities))
    print("Suspicious examples:", sum(
        event["simulated_suspicious"] for event in activities
    ))
    print("Saved to:", output_path)
