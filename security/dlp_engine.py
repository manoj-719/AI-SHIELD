
from pathlib import Path
from security.data_classifier import scan_file
from security.quarantine_manager import quarantine_file

BLOCKED_DESTINATIONS = {
    "personal_email",
    "public_link",
    "external_app",
    "unknown"
}


def evaluate_file_transfer(file_path, destination):

    path = Path(file_path)

    if not path.is_file():
        return {
            "allowed": False,
            "status": "blocked",
            "reason": "File does not exist"
        }

    try:
        scan_result = scan_file(path)

    except (ValueError, OSError) as error:
        return {
            "allowed": False,
            "status": "blocked",
            "reason": f"Security scan failed: {error}"
        }

    is_sensitive = scan_result["is_sensitive"]
    is_external = destination in BLOCKED_DESTINATIONS

    if is_sensitive and is_external:

        reason = "Sensitive data cannot be transferred externally"

        quarantine_record = quarantine_file(
            path,
            reason
        )

        return {
            "allowed": False,
            "status": "quarantined",
            "reason": reason,
            "quarantine": quarantine_record,
            "scan_result": scan_result
        }

    return {
        "allowed": True,
        "status": "allowed",
        "reason": "Transfer passed DLP policy",
        "scan_result": scan_result
    }