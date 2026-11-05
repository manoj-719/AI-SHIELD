from collections import defaultdict
from datetime import datetime, timezone

VIOLATION_LIMIT = 3

agent_violations = defaultdict(list)


def record_violation(agent_name):
    now = datetime.now(timezone.utc)
    agent_violations[agent_name].append(now)
    count = len(agent_violations[agent_name])

    is_suspicious = count >= VIOLATION_LIMIT

    try:
        from security.agent_persistence import record_agent_violation_db
        record_agent_violation_db(agent_name, now.isoformat(), count=count)
    except Exception as e:
        print(f"[ViolationTracker] Notice: Persistent violation record error: {e}")

    return {
        "agent": agent_name,
        "violation_count": count,
        "suspicious": is_suspicious,
        "message": (
            "Repeated unauthorized attempts detected"
            if count >= VIOLATION_LIMIT
            else "Violation recorded"
        )
    }
