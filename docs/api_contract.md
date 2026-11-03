# AI Shield — API Contract

## 1. Purpose
All modules must use this common event structure when sending security events to the backend.

## 2. Common Security Event Schema

```json
{
  "event_id": "EVT001",
  "event_type": "file_share",
  "actor_type": "employee",
  "actor_id": "employee_01",
  "resource": "customer_records.csv",
  "is_sensitive": true,
  "action": "share",
  "destination": "personal_email",
  "timestamp": "2026-11-04T10:30:00",
  "source": "employee_simulator",
  "description": "Attempted external file sharing"
}
```

## 3. Field Definitions

| Field | Type | Description |
|---|---|---|
| event_id | string | Unique event identifier |
| event_type | string | Type of security event |
| actor_type | string | employee, agent, or external |
| actor_id | string | Person, agent, or client identifier |
| resource | string | File or API resource |
| is_sensitive | boolean | Whether sensitive data is involved |
| action | string | read, write, share, delete, request |
| destination | string | Internal or external destination |
| timestamp | string | ISO 8601 timestamp |
| source | string | Module that generated the event |
| description | string | Human-readable event description |

## 4. Backend Detection Output

The backend may add:

- rule_result
- anomaly
- risk_score
- risk_level
- recommended_action

## 5. Important Rules

1. Use the same field names across all modules.
2. Do not rename fields without team approval.
3. Use synthetic data for demonstrations.
4. ML provides an anomaly signal; it must never override a hard security denial.
5. Simulated actions must not be described as real-world monitoring or blocking.