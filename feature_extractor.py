import json

from ai_schema import AIAnalysisRequest
from alert_bucket import classify_alert_bucket


def _combined_text(cases: list[dict]) -> str:
    allowed_fields = ["title", "description", "summary", "tags"]
    relevant_cases = [
        {field: case.get(field) for field in allowed_fields if case.get(field)}
        for case in cases
    ]
    return json.dumps(relevant_cases, default=str).lower()


def extract_ai_features(
    cluster_key: str,
    cases: list[dict],
    lookback_days: int,
) -> AIAnalysisRequest:
    """Convert raw cases into a small allowlisted request with no identifiers."""
    rule_id, host, indicator = cluster_key.split("|", 2)
    text = _combined_text(cases)
    bucket = classify_alert_bucket(cluster_key, cases)["bucket"]

    context_flags = []
    risk_flags = []

    if any(term in text for term in ["approved", "allowlisted", "known benign"]):
        context_flags.append("approved_software")
    if any(term in text for term in ["signed binary", "digitally signed", "signed process"]):
        context_flags.append("signed_binary")
    if any(term in text for term in ["expected parent", "parent:services.exe", "scheduled task"]):
        context_flags.append("expected_parent_process")
    if any(term in text for term in ["consistent", "repeated scheduled", "same activity"]):
        context_flags.append("consistent_execution_pattern")
    if any(term in text for term in ["confirmed benign", "benign indicator", "allowlisted indicator"]):
        context_flags.append("known_benign_indicator")

    if any(term in text for term in ["encodedcommand", "encoded command"]):
        risk_flags.append("encoded_command")
    if any(term in text for term in ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"]):
        risk_flags.append("office_child_process")
    if bucket == "identity_privilege":
        risk_flags.append("privileged_activity")
    if bucket == "ioc" and "allowlisted" not in text and "confirmed benign" not in text:
        risk_flags.append("malicious_indicator")
    if bucket == "cloud" and any(term in text for term in ["iam", "public", "administrator"]):
        risk_flags.append("sensitive_cloud_action")

    if not context_flags:
        risk_flags.append("unknown_context")

    request = AIAnalysisRequest(
        schema_version="1.0",
        alert_bucket=bucket,
        occurrence_count=len(cases),
        lookback_days=lookback_days,
        same_rule=rule_id != "unknown_rule",
        same_host=host != "unknown_agent",
        same_indicator=indicator != "generic",
        disposition="false_positive_or_duplicate",
        context_flags=sorted(set(context_flags)),
        risk_flags=sorted(set(risk_flags)),
    )
    request.validate()
    return request
