"""
AI Shield - Security Rule Integration Adapter Interface.
Integrates Manoj's Security Module (security/) with AI-SHIELD's central event processing pipeline.

Components integrated:
- security.agent_guard: Autonomous AI agent access controls & permission boundaries
- security.dlp_engine: Data Loss Prevention (DLP) checks & quarantine for sensitive transfers
- security.data_classifier: Regex pattern matching and sensitive keyword classification
- security.incident_analyzer: Deep incident severity, explanation, and recommendation analysis
- security.violation_tracker: Repeated violation tracking & automatic rogue agent suspension
"""

from typing import Dict, Any, Optional, List
from pathlib import Path

# Import Manoj's security modules
from security.agent_guard import (
    AGENT_REGISTRY,
    check_permission,
    process_agent_request,
    is_sensitive_file,
    set_agent_status
)
from security.dlp_engine import BLOCKED_DESTINATIONS, evaluate_file_transfer
from security.data_classifier import SENSITIVE_KEYWORDS, scan_file
from security.incident_analyzer import analyze_incident
from security.violation_tracker import agent_violations, record_violation


class SecurityRuleResult:
    """Standardized result returned by security rule evaluation."""
    def __init__(
        self,
        rule_result: str = "allowed",
        hard_denial: bool = False,
        recommended_action: str = "none",
        rule_violations: Optional[List[str]] = None,
        incident_analysis: Optional[Dict[str, Any]] = None
    ):
        self.rule_result = rule_result
        self.hard_denial = hard_denial
        self.recommended_action = recommended_action
        self.rule_violations = rule_violations or []
        self.incident_analysis = incident_analysis or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_result": self.rule_result,
            "hard_denial": self.hard_denial,
            "recommended_action": self.recommended_action,
            "rule_violations": self.rule_violations,
            "incident_analysis": self.incident_analysis
        }


class ManojSecurityEngineAdapter:
    """
    Production security adapter wrapping Manoj's security module.
    Enforces DLP, agent boundaries, sensitive data classification, and quarantine.
    """
    def __init__(self):
        self.name = "ManojSecurityEngineAdapter"

    def _is_sensitive_resource(self, resource: str, is_sensitive_flag: bool) -> bool:
        """Determine if a resource is sensitive using multiple classification layers."""
        if is_sensitive_flag:
            return True

        file_name = Path(resource).name if resource else ""
        if file_name and is_sensitive_file(file_name):
            return True

        lower_res = resource.lower()
        if any(kw in lower_res for kw in SENSITIVE_KEYWORDS):
            return True

        admin_keywords = ["admin", "payroll", "secret", "credential", "keys", "private"]
        if any(kw in lower_res for kw in admin_keywords):
            return True

        if resource:
            try:
                p = Path(resource)
                if p.is_file():
                    scan_res = scan_file(p)
                    if scan_res.get("is_sensitive", False):
                        return True
            except Exception:
                pass

        return False

    def _is_external_destination(self, destination: str) -> bool:
        """Determine if destination violates internal boundary policies."""
        if not destination:
            return False

        dest_lower = destination.lower().strip()
        if dest_lower in BLOCKED_DESTINATIONS:
            return True

        internal_indicators = ("internal", "local", "intranet", "workstation", "laptop", "corp", "none")
        if any(ind in dest_lower for ind in internal_indicators):
            return False

        external_indicators = ("external", "public", "personal", "cloud", "remote", "@", "dropbox", "drive", "usb")
        if any(ext in dest_lower for ext in external_indicators):
            return True

        return True

    def evaluate(self, event: Dict[str, Any]) -> SecurityRuleResult:
        """
        Evaluate an event against Manoj's security module.
        Strictly enforces:
        1. Agent Guard (ACL, action limits, destination limits, auto-suspension)
        2. DLP Engine (external sharing of sensitive files blocked & quarantined)
        3. Incident Analysis (deep severity, human-readable explanation, recommendations)
        """
        actor_type = str(event.get("actor_type", "")).strip().lower()
        actor_id = str(event.get("actor_id", "")).strip()
        resource = str(event.get("resource", "")).strip()
        destination = str(event.get("destination", "")).strip()
        action = str(event.get("action", "read")).strip().lower()
        is_sensitive_flag = bool(event.get("is_sensitive", False))
        event_type = str(event.get("event_type", "")).strip().lower()

        file_name = Path(resource).name if resource else ""
        is_sensitive = self._is_sensitive_resource(resource, is_sensitive_flag)
        is_external = self._is_external_destination(destination)

        # -------------------------------------------------------------
        # RULE 1: AI AGENT ACCESS CONTROL (security.agent_guard)
        # -------------------------------------------------------------
        if actor_type == "agent" or actor_id in AGENT_REGISTRY:
            agent_name = actor_id
            target_file = file_name or resource

            # Process request through Manoj's agent guard (handles tracking & suspension)
            agent_eval = process_agent_request(
                agent_name=agent_name,
                file_name=target_file,
                action=action,
                destination=destination or "internal"
            )

            if not agent_eval["allowed"]:
                reason = agent_eval.get("reason", "Unauthorized agent activity")
                rule_violations = [f"ACL-002: {reason} (actor: {agent_name}, resource: {target_file})"]

                analysis = analyze_incident({
                    "event_type": "unauthorized_agent_access",
                    "is_sensitive": is_sensitive,
                    "action": action,
                    "destination": destination,
                    "actor_id": agent_name,
                    "event_id": event.get("event_id", "")
                })

                return SecurityRuleResult(
                    rule_result="flagged_unauthorized_agent_access",
                    hard_denial=True,
                    recommended_action="revoke_agent_token_and_isolate",
                    rule_violations=rule_violations,
                    incident_analysis=analysis
                )

            # Agent request allowed by policy
            if is_sensitive and not is_external:
                return SecurityRuleResult(
                    rule_result="allowed_with_audit",
                    hard_denial=False,
                    recommended_action="log_sensitive_access",
                    rule_violations=[]
                )
            return SecurityRuleResult(
                rule_result="allowed",
                hard_denial=False,
                recommended_action="none",
                rule_violations=[]
            )

        # -------------------------------------------------------------
        # RULE 2: PRE-FLAGGED EXPLICIT EVENT TYPES
        # -------------------------------------------------------------
        if event_type == "unauthorized_agent_access":
            analysis = analyze_incident(event)
            return SecurityRuleResult(
                rule_result="flagged_unauthorized_agent_access",
                hard_denial=True,
                recommended_action="revoke_agent_token_and_isolate",
                rule_violations=["ACL-002: Autonomous agent unauthorized access blocked"],
                incident_analysis=analysis
            )

        if event_type == "dlp_blocked_transfer":
            analysis = analyze_incident(event)
            return SecurityRuleResult(
                rule_result="flagged_dlp_external_share",
                hard_denial=True,
                recommended_action="quarantine_attachment_and_notify_manager",
                rule_violations=["DLP-001: Data Loss Prevention policy blocked external file transfer"],
                incident_analysis=analysis
            )

        # -------------------------------------------------------------
        # RULE 3: DATA LOSS PREVENTION (security.dlp_engine)
        # -------------------------------------------------------------
        if is_sensitive and is_external:
            # Check if file physically exists on disk and can be quarantined
            try:
                p = Path(resource)
                if p.is_file():
                    evaluate_file_transfer(resource, destination)
            except Exception:
                pass

            analysis = analyze_incident({
                "event_type": "dlp_blocked_transfer",
                "is_sensitive": True,
                "action": action,
                "destination": destination,
                "actor_id": actor_id,
                "event_id": event.get("event_id", "")
            })

            return SecurityRuleResult(
                rule_result="flagged_dlp_external_share",
                hard_denial=True,
                recommended_action="quarantine_attachment_and_notify_manager",
                rule_violations=["DLP-001: Unauthorized external transfer of sensitive resource (DLP Policy Violation)"],
                incident_analysis=analysis
            )

        # -------------------------------------------------------------
        # RULE 4: SENSITIVE INTERNAL ACCESS (MONITORED)
        # -------------------------------------------------------------
        if is_sensitive and not is_external:
            return SecurityRuleResult(
                rule_result="allowed_with_audit",
                hard_denial=False,
                recommended_action="log_sensitive_access",
                rule_violations=[]
            )

        # -------------------------------------------------------------
        # DEFAULT: NOMINAL / STANDARD ACCESS
        # -------------------------------------------------------------
        return SecurityRuleResult(
            rule_result="allowed",
            hard_denial=False,
            recommended_action="none",
            rule_violations=[]
        )


class MockSecurityRuleAdapter:
    """
    Mock adapter for unit testing without production security rules.
    """
    def evaluate(self, event: Dict[str, Any]) -> SecurityRuleResult:
        resource = str(event.get("resource", "")).lower()
        destination = str(event.get("destination", "")).lower()
        is_sensitive = bool(event.get("is_sensitive", False))
        actor_type = str(event.get("actor_type", "")).lower()
        action = str(event.get("action", "")).lower()

        is_internal = not destination or any(kw in destination for kw in ("internal", "local", "intranet", "workstation", "laptop", "corp", "none"))
        is_external = bool(destination) and not is_internal

        if is_sensitive and is_external:
            return SecurityRuleResult(
                rule_result="flagged_dlp_external_share",
                hard_denial=True,
                recommended_action="quarantine_attachment_and_notify_manager",
                rule_violations=["DLP-001: Unauthorized external transfer of sensitive resource"]
            )

        sensitive_keywords = ["admin", "payroll", "secret", "credential", "keys", "private"]
        if actor_type == "agent" and (is_sensitive or any(kw in resource for kw in sensitive_keywords)):
            return SecurityRuleResult(
                rule_result="flagged_unauthorized_agent_access",
                hard_denial=True,
                recommended_action="revoke_agent_token_and_isolate",
                rule_violations=["ACL-002: Autonomous agent accessed restricted administrative resource"]
            )

        if is_sensitive and is_internal and action in ("read", "write", "download", "access", "view"):
            return SecurityRuleResult(
                rule_result="allowed_with_audit",
                hard_denial=False,
                recommended_action="log_sensitive_access",
                rule_violations=[]
            )

        return SecurityRuleResult(
            rule_result="allowed",
            hard_denial=False,
            recommended_action="none",
            rule_violations=[]
        )


# Global adapter registry defaulting to Manoj's security adapter
_active_security_adapter = ManojSecurityEngineAdapter()

def get_security_adapter():
    """Return the currently registered security rule adapter."""
    global _active_security_adapter
    return _active_security_adapter

def set_security_adapter(adapter):
    """Register a custom security adapter."""
    global _active_security_adapter
    _active_security_adapter = adapter

def reset_security_adapter():
    """Reset to default Manoj security adapter and restore agent registry state."""
    global _active_security_adapter
    try:
        from security.agent_guard import AGENT_REGISTRY
        from security.violation_tracker import agent_violations
        from security.agent_persistence import reset_agent_persistence
        reset_agent_persistence()
        for agent in AGENT_REGISTRY:
            AGENT_REGISTRY[agent]["active"] = True
        agent_violations.clear()
    except Exception:
        pass
    _active_security_adapter = ManojSecurityEngineAdapter()
