import re
from dataclasses import dataclass, field


PATTERNS = [
    ("SECRET", re.compile(r"(?i)\b(?:bearer\s+)?(?:api[_-]?key|token|secret|password)\s*[:=]\s*[^\s,;]+")),
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("IP", re.compile(r"(?<![\w.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\w.])")),
    ("URL", re.compile(r"(?i)\bhttps?://[^\s\]\[\"'<>]+")),
    ("UNC_PATH", re.compile(r"\\\\[^\\\s]+\\[^\s,;]+")),
    ("WINDOWS_PATH", re.compile(r"(?i)\b[A-Z]:\\(?:[^\\\r\n]+\\)*[^\r\n,;]+")),
    ("UNIX_PATH", re.compile(r"(?<!\w)/(?:home|Users|var|opt|srv|etc|tmp)/[^\s,;]+")),
]


@dataclass
class RedactionResult:
    value: object
    counts: dict[str, int] = field(default_factory=dict)


def redact_text(text: str) -> RedactionResult:
    redacted = text
    counts: dict[str, int] = {}
    for category, pattern in PATTERNS:
        redacted, count = pattern.subn(f"<{category}_REDACTED>", redacted)
        if count:
            counts[category] = counts.get(category, 0) + count
    return RedactionResult(redacted, counts)


def redact_value(value: object) -> RedactionResult:
    """Recursively redact strings without retaining an identifier mapping."""
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        output = []
        counts: dict[str, int] = {}
        for item in value:
            result = redact_value(item)
            output.append(result.value)
            for category, count in result.counts.items():
                counts[category] = counts.get(category, 0) + count
        return RedactionResult(output, counts)
    if isinstance(value, dict):
        output = {}
        counts: dict[str, int] = {}
        for key, item in value.items():
            result = redact_value(item)
            output[key] = result.value
            for category, count in result.counts.items():
                counts[category] = counts.get(category, 0) + count
        return RedactionResult(output, counts)
    return RedactionResult(value, {})
