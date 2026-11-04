from collections import defaultdict
from datetime import datetime, timezone

VIOLATION_LIMIT = 3

agent_violations = defaultdict(list)


def record_violation(agent_name):
    now = datetime.now(timezone.utc)

    agent_violations[agent_name].append(now)

    count = len(agent_violations[agent_name])

    return {
        "agent": agent_name,
        "violation_count": count,
        "suspicious": count >= VIOLATION_LIMIT,
        "message": (
            "Repeated unauthorized attempts detected"
            if count >= VIOLATION_LIMIT
            else "Violation recorded"
        )
    }