# AI Shield – ML Integration Guide

## 1. Overview

The ML module provides employee anomaly detection and API threat detection for the AI Shield platform.

It generates a unified incident file that the backend can consume to display security events on the dashboard.

## 2. Output File

**Main integration file:**

`ml/unified_predictions.jsonl`

Format: JSON Lines (JSONL)

Each line represents one security event.

The backend should read this file line by line and parse each line as an independent JSON object.

## 3. Unified Incident Schema

Each incident follows this structure:

```json
{
  "incident_id": "EMP-00071",
  "source": "employee",
  "actor_id": "EMP004",
  "event_type": "employee_file_access",
  "resource": "financial_records.xlsx",
  "action": "share",
  "prediction": "Suspicious",
  "risk_level": "Medium",
  "reason": [
    "Employee activity flagged as anomalous by Isolation Forest"
  ],
  "recommended_action": "Flag activity for security review",
  "timestamp": "2026-10-29T19:26:53.911858+00:00",
  "details": {
    "anomaly_score": -0.6064
  }
}
```

## 4. Field Descriptions

| Field | Description |
|---|---|
| incident_id | Unique incident identifier |
| source | Detection source: employee or api |
| actor_id | Employee or bot identifier |
| event_type | Type of monitored event |
| resource | File name or API endpoint |
| action | File action or HTTP method |
| prediction | Normal or Suspicious |
| risk_level | Low, Medium, High or Critical |
| reason | Explanation for detection |
| recommended_action | Suggested security response |
| timestamp | Original event timestamp |
| details | Additional source-specific information |

## 5. Detection Sources

### Employee Detection

- Method: Isolation Forest anomaly detection.
- Input: Simulated employee activity events.
- Output: Anomaly score, prediction, risk level and recommended action.
- Anomaly scores are model scores, not probabilities.

### API Threat Detection

- Method: Rule-based detection.
- Detects suspicious external bot access, unauthorized requests, high request rates and repeated denied requests.
- Output includes request counts, denied counts and detection reasons.

## 6. Backend Integration

The backend should:

1. Read `ml/unified_predictions.jsonl`.
2. Parse each JSON line.
3. Store incidents in the backend database.
4. Display incidents on the security dashboard.
5. Show risk levels and detection reasons.
6. Display recommended actions to the security administrator.

Use `incident_id` to identify records and avoid duplicate insertion.

Use `timestamp` to sort incidents chronologically.

## 7. Important Notes

- This version uses simulated employee and API activity.
- Employee detection uses a trained Isolation Forest model.
- API detection uses predefined security rules.
- Recommended actions are suggestions; they do not automatically block real employee actions or API requests.
- The model has been evaluated on synthetic data, not validated in a real company environment.

## 8. Run the Detection Pipeline

From the project root:

```powershell
python ml/run_detection.py
python ml/detect_api.py
python ml/unified_predictions.py
```

The final unified output is generated at:

`ml/unified_predictions.jsonl`
