"""
AI Shield - Security Rule Integration Adapter Interface.
Defines the contract for security rule engines, DLP checks, and access controls.

NOTE: This file contains a clearly-labeled MockSecurityRuleAdapter for Phase 2 integration
testing. When teammates complete the security module (in `security/`), it can be plugged in
via `set_security_adapter(custom_adapter)`.
"""

from typing import Dict, Any, Optional

class SecurityRuleResult:
    """Standardized result returned by security rule evaluation."""
    def __init__(
        self,
        rule_result: str = "allowed",
        hard_denial: bool = False,
        recommended_action: str = "none",
        rule_violations: Optional[list] = None
    ):
        self.rule_result = rule_result
        self.hard_denial = hard_denial
        self.recommended_action = recommended_action
        self.rule_violations = rule_violations or []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_result": self.rule_result,
            "hard_denial": self.hard_denial,
            "recommended_action": self.recommended_action,
            "rule_violations": self.rule_violations
        }


class MockSecurityRuleAdapter:
    """
    Temporary reference adapter for testing the event pipeline integration.
    Simulates security rules (DLP checks, unauthorized agent access, policy violations)
    without performing actual operating-system level enforcement.
    """
    def evaluate(self, event: Dict[str, Any]) -> SecurityRuleResult:
        resource = str(event.get("resource", "")).lower()
        destination = str(event.get("destination", "")).lower()
        is_sensitive = bool(event.get("is_sensitive", False))
        actor_type = str(event.get("actor_type", "")).lower()
        action = str(event.get("action", "")).lower()

        # Identify if destination is internal or external
        is_internal = not destination or any(kw in destination for kw in ("internal", "local", "intranet", "workstation", "laptop", "corp", "none"))
        is_external = bool(destination) and not is_internal

        # Rule 1: Sensitive file shared to external destination (DLP Violation)
        if is_sensitive and is_external:
            return SecurityRuleResult(
                rule_result="flagged_dlp_external_share",
                hard_denial=True,
                recommended_action="quarantine_attachment_and_notify_manager",
                rule_violations=["DLP-001: Unauthorized external transfer of sensitive resource"]
            )

        # Rule 2: Unauthorized Agent Access
        # Autonomous agents are restricted from accessing sensitive admin/payroll/credential resources
        sensitive_keywords = ["admin", "payroll", "secret", "credential", "keys", "private"]
        if actor_type == "agent" and (is_sensitive or any(kw in resource for kw in sensitive_keywords)):
            return SecurityRuleResult(
                rule_result="flagged_unauthorized_agent_access",
                hard_denial=True,
                recommended_action="revoke_agent_token_and_isolate",
                rule_violations=["ACL-002: Autonomous agent accessed restricted administrative resource"]
            )

        # Rule 3: Internal access to sensitive files (Monitored, but allowed)
        if is_sensitive and is_internal and action in ("read", "write", "download", "access", "view"):
            return SecurityRuleResult(
                rule_result="allowed_with_audit",
                hard_denial=False,
                recommended_action="log_sensitive_access",
                rule_violations=[]
            )

        # Default: Normal allowed action
        return SecurityRuleResult(
            rule_result="allowed",
            hard_denial=False,
            recommended_action="none",
            rule_violations=[]
        )


# Global adapter registry
_active_security_adapter = MockSecurityRuleAdapter()

def get_security_adapter():
    """Return the currently registered security rule adapter."""
    global _active_security_adapter
    return _active_security_adapter

def set_security_adapter(adapter):
    """
    Register a custom security adapter (e.g., when teammates provide `security/rule_engine.py`).
    Adapter must implement `.evaluate(event: dict) -> SecurityRuleResult`.
    """
    global _active_security_adapter
    _active_security_adapter = adapter

def reset_security_adapter():
    """Reset to default reference adapter."""
    global _active_security_adapter
    _active_security_adapter = MockSecurityRuleAdapter()
