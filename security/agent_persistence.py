"""
AI Shield - AI Agent Persistence Manager.
Persists AI agent security status, violation histories, and suspension state
to the Supabase PostgreSQL database (public.ai_agents table), with a local fail-safe
cache (quarantine/agent_registry_cache.json) for maximum resiliency.

Guarantees:
1. An agent suspended after 3 violations remains suspended across application restarts.
2. If Supabase is unavailable and local cache is missing/corrupted, fail closed:
   never silently grant access to an unverifiable agent.
3. Unknown agents are never treated as valid or active.
4. Changes to agent status and violations are durably written to Supabase (via atomic upsert)
   and cache (via atomic temp-file replace).
"""

import os
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional, Tuple, List

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CACHE_FILE = PROJECT_ROOT / "quarantine" / "agent_registry_cache.json"

_table_check_done = False
_table_exists_in_supabase = True


def _get_supabase_client():
    """Retrieve Supabase client safely from backend.database."""
    try:
        from backend.database import get_supabase_client
        return get_supabase_client()
    except Exception:
        return None


def _is_table_available(sb) -> bool:
    """Check if the ai_agents table exists in Supabase."""
    global _table_check_done, _table_exists_in_supabase
    if _table_check_done:
        return _table_exists_in_supabase

    try:
        sb.table("ai_agents").select("id").limit(1).execute()
        _table_exists_in_supabase = True
    except Exception as e:
        err_msg = str(e)
        if "PGRST205" in err_msg or "schema cache" in err_msg or "relation" in err_msg:
            print("[AgentPersistence] Notice: Remote Supabase table 'public.ai_agents' pending migration 002. Operating with fail-safe local persistence.")
            _table_exists_in_supabase = False
        else:
            _table_exists_in_supabase = False

    _table_check_done = True
    return _table_exists_in_supabase


def _load_local_cache() -> Dict[str, Any]:
    """
    Read local agent state cache from JSON file.
    Safely handles missing, empty, or corrupted cache files without raising unhandled exceptions.
    """
    if not CACHE_FILE.exists():
        return {}

    try:
        content = CACHE_FILE.read_text(encoding="utf-8").strip()
        if not content:
            return {}
        data = json.loads(content)
        if isinstance(data, dict):
            return data
        print(f"[AgentPersistence] Warning: Corrupted cache format (expected dict, got {type(data)}).")
        return {}
    except Exception as e:
        print(f"[AgentPersistence] Warning: Corrupted cache detected in {CACHE_FILE}: {e}. Discarding invalid cache.")
        return {}


def _save_local_cache(cache_data: Dict[str, Any]) -> bool:
    """
    Atomically save agent state cache to JSON file using a temporary file and os.replace.
    Ensures that interrupted or failed writes do not corrupt or destroy the existing valid cache.
    Returns True on success, False on failure.
    """
    try:
        CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        temp_file = CACHE_FILE.with_suffix(f".tmp_{os.getpid()}")

        # Write, flush and sync to temporary file in the same directory
        with open(temp_file, "w", encoding="utf-8") as f:
            json.dump(cache_data, f, indent=4)
            f.flush()
            os.fsync(f.fileno())

        # Atomic replacement on filesystem with retry for Windows/OneDrive locks
        replaced = False
        for attempt in range(5):
            try:
                os.replace(temp_file, CACHE_FILE)
                replaced = True
                break
            except (PermissionError, OSError):
                if attempt < 4:
                    import time
                    time.sleep(0.05)
                else:
                    raise
        return replaced
    except Exception as e:
        print(f"[AgentPersistence] Warning: Failed atomic write to local cache: {e}")
        try:
            if "temp_file" in locals() and temp_file.exists():
                temp_file.unlink()
        except Exception:
            pass
        return False


def get_persistent_agent_state(agent_name: str, client=None) -> Tuple[str, Optional[Dict[str, Any]]]:
    """
    Fetch an agent's persistent state with strict fail-closed classification:
    Returns (state_category, record_dict):
    - ("active", record): Validly verified as active in Supabase or local cache.
    - ("suspended", record): Validly verified as suspended in Supabase or local cache.
    - ("unverifiable", None): Supabase unreachable AND no local cache entry exists.
    """
    sb = client or _get_supabase_client()

    # 1. Primary Store: Supabase PostgreSQL
    if sb is not None and _is_table_available(sb):
        try:
            res = sb.table("ai_agents").select("*").eq("agent_name", agent_name).execute()
            if res.data:
                record = res.data[0]
                # Mirror latest database state into atomic local cache
                cache = _load_local_cache()
                cache[agent_name] = record
                _save_local_cache(cache)

                is_active = (record.get("status") != "suspended") and bool(record.get("is_active", True))
                return ("active" if is_active else "suspended", record)
        except Exception as e:
            print(f"[AgentPersistence] Warning: Supabase lookup for '{agent_name}' failed: {e}")

    # 2. Resilient Secondary Store: Local Persistent Cache
    cache = _load_local_cache()
    if agent_name in cache:
        record = cache[agent_name]
        is_active = (record.get("status") != "suspended") and bool(record.get("is_active", True))
        return ("active" if is_active else "suspended", record)

    # 3. Fail-Closed Edge Case: State cannot be verified
    # Supabase is unreachable and no valid record exists in the local cache
    return ("unverifiable", None)


def get_persistent_agent(agent_name: str, client=None) -> Optional[Dict[str, Any]]:
    """
    Fetch persistent agent record. Returns record dict if found, else None.
    """
    state, record = get_persistent_agent_state(agent_name, client=client)
    return record


def save_agent_status(
    agent_name: str,
    active: bool,
    reason: Optional[str] = None,
    violation_count: Optional[int] = None,
    client=None
) -> Dict[str, Any]:
    """
    Durably save an agent's active/suspended status to Supabase (atomic upsert) and local cache.
    Reactivating an agent resets violation count and history.
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    status_str = "active" if active else "suspended"

    existing = get_persistent_agent(agent_name, client=client) or {}
    if active:
        # Reactivating agent resets violation count and history
        v_count = 0
        v_history = []
        try:
            from security.violation_tracker import agent_violations
            agent_violations[agent_name].clear()
        except Exception:
            pass
    else:
        v_count = violation_count if violation_count is not None else existing.get("violation_count", 0)
        v_history = existing.get("violation_history", [])

    payload = {
        "agent_name": agent_name,
        "status": status_str,
        "is_active": bool(active),
        "violation_count": v_count,
        "violation_history": v_history,
        "suspended_at": None if active else (existing.get("suspended_at") or now_iso),
        "suspension_reason": None if active else (reason or existing.get("suspension_reason") or "Suspended by policy"),
        "updated_at": now_iso
    }

    # 1. Update local cache immediately via atomic replacement
    cache = _load_local_cache()
    cache[agent_name] = payload
    _save_local_cache(cache)

    # 2. Update Supabase via atomic upsert on conflict(agent_name)
    sb = client or _get_supabase_client()
    if sb is not None and _is_table_available(sb):
        try:
            if hasattr(sb.table("ai_agents"), "upsert"):
                sb.table("ai_agents").upsert(payload, on_conflict="agent_name").execute()
            else:
                check = sb.table("ai_agents").select("id").eq("agent_name", agent_name).execute()
                if check.data:
                    sb.table("ai_agents").update(payload).eq("agent_name", agent_name).execute()
                else:
                    sb.table("ai_agents").insert(payload).execute()
        except Exception as e:
            try:
                check = sb.table("ai_agents").select("id").eq("agent_name", agent_name).execute()
                if check.data:
                    sb.table("ai_agents").update(payload).eq("agent_name", agent_name).execute()
                else:
                    sb.table("ai_agents").insert(payload).execute()
            except Exception as e2:
                print(f"[AgentPersistence] Warning: Failed to persist agent status for '{agent_name}' to Supabase: {e2}")

    return payload


def record_agent_violation_db(
    agent_name: str,
    violation_timestamp: str,
    count: Optional[int] = None,
    client=None
) -> Tuple[int, bool]:
    """
    Record an unauthorized access violation in the persistent store.
    Returns (new_violation_count, is_suspicious).
    If violation_count >= 3, automatically marks the agent as suspended in the database.
    """
    from security.violation_tracker import VIOLATION_LIMIT

    existing = get_persistent_agent(agent_name, client=client) or {}
    current_count = count if count is not None else (existing.get("violation_count", 0) + 1)
    v_history = list(existing.get("violation_history", []))
    v_history.append(violation_timestamp)

    is_suspicious = current_count >= VIOLATION_LIMIT
    is_active = not is_suspicious if is_suspicious else existing.get("is_active", True)
    status_str = "suspended" if is_suspicious else ("active" if is_active else "suspended")
    now_iso = datetime.now(timezone.utc).isoformat()

    payload = {
        "agent_name": agent_name,
        "status": status_str,
        "is_active": is_active,
        "violation_count": current_count,
        "violation_history": v_history,
        "suspended_at": now_iso if is_suspicious else existing.get("suspended_at"),
        "suspension_reason": "Agent automatically suspended after repeated violations" if is_suspicious else existing.get("suspension_reason"),
        "updated_at": now_iso
    }

    # 1. Update local cache via atomic replacement
    cache = _load_local_cache()
    cache[agent_name] = payload
    _save_local_cache(cache)

    # 2. Update Supabase via atomic upsert
    sb = client or _get_supabase_client()
    if sb is not None and _is_table_available(sb):
        try:
            if hasattr(sb.table("ai_agents"), "upsert"):
                sb.table("ai_agents").upsert(payload, on_conflict="agent_name").execute()
            else:
                check = sb.table("ai_agents").select("id").eq("agent_name", agent_name).execute()
                if check.data:
                    sb.table("ai_agents").update(payload).eq("agent_name", agent_name).execute()
                else:
                    sb.table("ai_agents").insert(payload).execute()
        except Exception as e:
            try:
                check = sb.table("ai_agents").select("id").eq("agent_name", agent_name).execute()
                if check.data:
                    sb.table("ai_agents").update(payload).eq("agent_name", agent_name).execute()
                else:
                    sb.table("ai_agents").insert(payload).execute()
            except Exception as e2:
                print(f"[AgentPersistence] Warning: Failed to record violation for '{agent_name}' to Supabase: {e2}")

    return current_count, is_suspicious


def sync_agent_registry_from_db(agent_registry: Dict[str, Any], client=None) -> None:
    """
    Synchronize in-memory AGENT_REGISTRY with persistent database state.
    Preserves existing suspensions across server restarts.
    Never overwrites an existing suspended status with active.
    """
    for agent_name, details in agent_registry.items():
        state, record = get_persistent_agent_state(agent_name, client=client)
        if state == "suspended":
            details["active"] = False
        elif state == "active":
            details["active"] = True
        elif state == "unverifiable":
            # Fail closed: unverifiable state must not default to active
            details["active"] = False
        else:
            try:
                save_agent_status(
                    agent_name=agent_name,
                    active=details.get("active", True),
                    reason=None,
                    violation_count=0,
                    client=client
                )
            except Exception:
                pass


def reset_agent_persistence(client=None) -> None:
    """Reset persistent store for all registered agents (used in test teardown)."""
    global _table_check_done, _table_exists_in_supabase
    _table_check_done = False
    _table_exists_in_supabase = True

    from security.agent_guard import AGENT_REGISTRY

    cache = {}
    for agent_name in AGENT_REGISTRY:
        AGENT_REGISTRY[agent_name]["active"] = True
        payload = {
            "agent_name": agent_name,
            "status": "active",
            "is_active": True,
            "violation_count": 0,
            "violation_history": [],
            "suspended_at": None,
            "suspension_reason": None,
            "updated_at": datetime.now(timezone.utc).isoformat()
        }
        cache[agent_name] = payload

    _save_local_cache(cache)

    sb = client or _get_supabase_client()
    if sb is not None and _is_table_available(sb):
        try:
            for agent_name, payload in cache.items():
                if hasattr(sb.table("ai_agents"), "upsert"):
                    sb.table("ai_agents").upsert(payload, on_conflict="agent_name").execute()
                else:
                    check = sb.table("ai_agents").select("id").eq("agent_name", agent_name).execute()
                    if check.data:
                        sb.table("ai_agents").update(payload).eq("agent_name", agent_name).execute()
                    else:
                        sb.table("ai_agents").insert(payload).execute()
        except Exception:
            pass
