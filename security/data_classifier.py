
import re
from pathlib import Path

# Patterns for detecting potentially sensitive information.
PATTERNS = {
    "email": re.compile(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
    ),

    "indian_phone": re.compile(
        r"(?<!\d)(?:\+91[\s-]?)?[6-9]\d{9}(?!\d)"
    ),

    "pan_like": re.compile(
        r"\b[A-Z]{5}[0-9]{4}[A-Z]\b",
        re.IGNORECASE
    ),

    "aadhaar_like": re.compile(
        r"(?<!\d)\d{4}[\s-]?\d{4}[\s-]?\d{4}(?!\d)"
    )
}

SENSITIVE_KEYWORDS = [
    "salary",
    "bank account",
    "customer records",
    "employee records",
    "credit card",
    "confidential",
    "personal information",
    "financial details"
]

SUPPORTED_EXTENSIONS = {".txt", ".csv"}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB


def scan_file(file_path):

    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError("File does not exist")

    if path.suffix.lower() not in SUPPORTED_EXTENSIONS:
        raise ValueError("Only TXT and CSV files are supported")

    if path.stat().st_size > MAX_FILE_SIZE:
        raise ValueError("File exceeds the 5 MB scanning limit")

    content = path.read_text(
        encoding="utf-8-sig",
        errors="replace"
    )

    findings = {}

    # Count matches without storing the actual sensitive values.
    for category, pattern in PATTERNS.items():
        matches = pattern.findall(content)
        findings[category] = len(matches)

    keyword_count = 0
    lower_content = content.lower()

    for keyword in SENSITIVE_KEYWORDS:
        keyword_count += lower_content.count(keyword)

    findings["sensitive_keywords"] = keyword_count

    total_matches = sum(findings.values())

    return {
        "file_name": path.name,
        "is_sensitive": total_matches > 0,
        "total_findings": total_matches,
        "findings": findings
    }
