import json
import re

from redactor import PATTERNS


SENSITIVE_FIELD_NAMES = {
    "agent",
    "case_id",
    "case_ids",
    "command_line",
    "description",
    "email",
    "host",
    "hostname",
    "ip",
    "path",
    "raw_case",
    "summary",
    "title",
    "user",
    "username",
}

INTERNAL_DOMAIN_PATTERN = re.compile(
    r"(?i)\b(?:[a-z0-9-]+\.)+(?:internal|local|lan|corp|home|intranet)\b"
)


def detect_leaks(payload: dict, known_sensitive_values: list[str] | None = None) -> list[str]:
    """Return only leak categories; never return the sensitive matches."""
    findings = set()
    for key in payload:
        if key.lower() in SENSITIVE_FIELD_NAMES:
            findings.add("SENSITIVE_FIELD_NAME")

    serialized = json.dumps(payload, sort_keys=True)
    for category, pattern in PATTERNS:
        if pattern.search(serialized):
            findings.add(category)
    if INTERNAL_DOMAIN_PATTERN.search(serialized):
        findings.add("INTERNAL_DOMAIN")

    for value in known_sensitive_values or []:
        value = str(value).strip()
        if len(value) >= 3 and value.lower() in serialized.lower():
            findings.add("KNOWN_SENSITIVE_VALUE")

    return sorted(findings)
