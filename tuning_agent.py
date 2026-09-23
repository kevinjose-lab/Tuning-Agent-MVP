
import os
import json
import hashlib
import datetime as dt
import re
from collections import defaultdict

import requests
from dotenv import load_dotenv

from pathlib import Path
from ai_pipeline import get_provider, run_ai_pipeline
from ai_usage import write_usage_record
from feature_extractor import extract_ai_features
from alert_bucket import classify_alert_bucket

env_path = Path(__file__).resolve().parent / ".env"
load_dotenv(dotenv_path=env_path)

THEHIVE_URL = os.getenv("THEHIVE_URL", "").rstrip("/")
THEHIVE_API_KEY = os.getenv("THEHIVE_API_KEY")
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")

AI_MODE = os.getenv("AI_MODE", "redaction-only").lower()
AI_INPUT_COST_PER_MILLION_TOKENS = float(
    os.getenv("AI_INPUT_COST_PER_MILLION_TOKENS", "0")
)
AI_OUTPUT_COST_PER_MILLION_TOKENS = float(
    os.getenv("AI_OUTPUT_COST_PER_MILLION_TOKENS", "0")
)
AI_MAX_INPUT_TOKENS = int(os.getenv("AI_MAX_INPUT_TOKENS", "1000"))
AI_MAX_OUTPUT_TOKENS = int(os.getenv("AI_MAX_OUTPUT_TOKENS", "500"))

LOOKBACK_DAYS = int(os.getenv("LOOKBACK_DAYS", "14"))
MIN_OCCURRENCES = int(os.getenv("MIN_OCCURRENCES", "5"))

STATE_FILE = Path(__file__).resolve().parent / "sent_recommendations.json"
AI_USAGE_FILE = Path(__file__).resolve().parent / "ai_usage.jsonl"

print("Discord webhook loaded:", bool(DISCORD_WEBHOOK_URL))
print("Current working directory:", os.getcwd())

HEADERS = {
    "Authorization": f"Bearer {THEHIVE_API_KEY}",
    "Content-Type": "application/json",
    "Accept": "application/json",
}


def post_discord(message: str) -> None:
    """Post one tuning recommendation to the Discord approval channel."""
    payload = {
        "username": "Tuning Agent",
        "embeds": [
            {
                "title": "🚨 Tuning Recommendation — Pending Approval",
                "description": message[:4000],
                "color": 16753920,
                "footer": {
                    "text": "Reply with APPROVE / REJECT / REVIEW / DRIFT plus the Recommendation ID and optional notes."
                },
            }
        ],
    }

    response = requests.post(
        DISCORD_WEBHOOK_URL,
        headers={"Content-Type": "application/json"},
        json=payload,
        timeout=20,
    )
    response.raise_for_status()


def case_matches_fp_or_duplicate(case: dict) -> bool:
    """Return True when a case contains language/tags that indicate FP or duplicate."""
    text = json.dumps(case).lower()

    disposition_terms = [
        "false positive",
        "false_positive",
        "duplicate",
        "duplicated",
        "disposition:false-positive",
        "disposition:duplicate",
    ]

    if any(term in text for term in disposition_terms):
        return True

    # Accept FP as a standalone tag/token, but do not match unrelated words such
    # as "Proofpoint" that happen to contain the letters "fp".
    return re.search(r"(?<![a-z0-9])fp(?![a-z0-9])", text) is not None


def case_is_within_lookback(
    case: dict,
    lookback_days: int = LOOKBACK_DAYS,
    now: dt.datetime | None = None,
) -> bool:
    """Return whether a case creation timestamp falls inside the lookback window.

    TheHive commonly returns epoch milliseconds in ``_createdAt``. ISO-8601 and
    epoch-second values are accepted as well. Cases without a usable timestamp
    are retained so schema differences do not silently hide candidates.
    """
    raw_timestamp = case.get("_createdAt", case.get("createdAt"))
    if raw_timestamp in (None, ""):
        return True

    try:
        if isinstance(raw_timestamp, (int, float)):
            seconds = raw_timestamp / 1000 if raw_timestamp > 10_000_000_000 else raw_timestamp
            created_at = dt.datetime.fromtimestamp(seconds, tz=dt.UTC)
        else:
            timestamp_text = str(raw_timestamp).strip().replace("Z", "+00:00")
            created_at = dt.datetime.fromisoformat(timestamp_text)
            if created_at.tzinfo is None:
                created_at = created_at.replace(tzinfo=dt.UTC)
            else:
                created_at = created_at.astimezone(dt.UTC)
    except (TypeError, ValueError, OverflowError):
        return True

    reference_time = now or dt.datetime.now(dt.UTC)
    return created_at >= reference_time - dt.timedelta(days=lookback_days)


def build_cluster_key(case: dict) -> str:
    """Build the grouping key used to find repeated cases for the same activity."""
    tags = case.get("tags", []) or []
    tags_joined = " ".join(tags).lower()

    rule_id = "unknown_rule"
    agent = "unknown_agent"
    cve = "none"
    path = "none"
    process = "none"

    for tag in tags:
        tag_lower = tag.lower()

        if tag_lower.startswith("rule:"):
            rule_id = tag.split(":", 1)[1]

        if tag_lower.startswith("agent:"):
            agent = tag.split(":", 1)[1]

        if tag_lower.startswith("cve:"):
            cve = tag.split(":", 1)[1]

        if tag_lower.startswith("path:"):
            path = tag.split(":", 1)[1]

        if tag_lower.startswith("process:"):
            process = tag.split(":", 1)[1]

    title = str(case.get("title", "")).lower()

    if rule_id == "unknown_rule" and "23506" in title + tags_joined:
        rule_id = "23506"

    # Prefer the most specific stable indicator available for the cluster.
    if cve != "none":
        return f"{rule_id}|{agent}|cve:{cve}"

    if path != "none":
        return f"{rule_id}|{agent}|path:{path}"

    if process != "none":
        return f"{rule_id}|{agent}|process:{process}"

    return f"{rule_id}|{agent}|generic"


def get_recent_cases() -> list[dict]:
    """
    Pull recent TheHive cases using the query API.
    This grabs recent cases first; filtering happens locally in the script.
    """

    url = f"{THEHIVE_URL}/api/v1/query"

    query = {
        "query": [
            {
                "_name": "listCase"
            },
            {
                "_name": "sort",
                "_fields": [
                    {
                        "_createdAt": "desc"
                    }
                ]
            },
            {
                "_name": "page",
                "from": 0,
                "to": 100
            }
        ]
    }

    response = requests.post(
        url,
        headers=HEADERS,
        json=query,
        timeout=30,
        verify=False,
    )

    response.raise_for_status()
    data = response.json()

    print(f"TheHive returned {len(data)} case(s)")
    return data


def recommendation_id(cluster_key: str) -> str:
    """Create a stable, readable recommendation ID from the cluster key."""
    today = dt.datetime.now(dt.UTC).strftime("%Y%m%d")
    digest = hashlib.sha256(cluster_key.encode()).hexdigest()[:6]

    safe_key = cluster_key.lower()
    safe_key = safe_key.replace("|", "-")
    safe_key = safe_key.replace(":", "-")
    safe_key = safe_key.replace("\\", "-")
    safe_key = safe_key.replace("/", "-")
    safe_key = safe_key.replace(" ", "-")
    safe_key = safe_key.replace(".", "-")

    while "--" in safe_key:
        safe_key = safe_key.replace("--", "-")

    safe_key = safe_key.strip("-")

    return f"TR-{today}-{safe_key}-{digest}"


def get_case_reference(case: dict) -> str:
    """
    Return the best human-readable case reference from a TheHive case object.
    TheHive versions may use different fields.
    """

    for key in ["caseId", "number", "_id", "id"]:
        value = case.get(key)
        if value:
            return str(value)

    title = case.get("title")
    if title:
        return str(title)[:80]

    return "unknown"


def validate_ai_analysis(ai_result: dict) -> list[str]:
    issues = []

    recommended_decision = str(ai_result.get("recommended_decision", "REVIEW")).upper()

    if recommended_decision in ["REVIEW", "REJECT"]:
        return issues

    combined = " ".join([
        str(ai_result.get("why_related", "")),
        str(ai_result.get("risk", "")),
    ]).lower()

    dangerous_phrases = [
        "suppress the entire rule",
        "disable the rule",
        "suppress all",
        "ignore all",
        "all powershell",
        "all vulnerability",
        "global suppression",
        "globally suppress",
    ]

    for phrase in dangerous_phrases:
        if phrase in combined:
            issues.append(f"Unsafe broad tuning phrase detected: {phrase}")

    return issues

def build_recommendation(cluster_key: str, cases: list[dict]) -> tuple[str, str, str, dict]:
    """Build a recommendation while keeping raw case data outside the AI boundary."""
    rec_id = recommendation_id(cluster_key)
    rule_id, agent, indicator = cluster_key.split("|", 2)
    bucket_info = classify_alert_bucket(cluster_key, cases)
    case_ids = [get_case_reference(c) for c in cases[:10]]
    case_count = len(cases)

    request = extract_ai_features(cluster_key, cases, LOOKBACK_DAYS)
    pipeline_result = run_ai_pipeline(
        request=request,
        provider=get_provider(AI_MODE, max_output_tokens=AI_MAX_OUTPUT_TOKENS),
        known_sensitive_values=[rule_id, agent, indicator, *case_ids],
        max_input_tokens=AI_MAX_INPUT_TOKENS,
        max_output_tokens=AI_MAX_OUTPUT_TOKENS,
    )
    analysis = pipeline_result.analysis
    ai_result = {
        "recommended_decision": analysis.decision,
        "why_related": analysis.rationale,
        "recommended_tuning": "Use exact-match local tuning only after analyst approval.",
        "expected_impact": "Potential reduction of repeated cases within the exact local scope.",
        "risk": analysis.risk,
        "validation_steps": analysis.validation_steps,
        "safety_notes": analysis.safety_notes,
        "provider": analysis.provider,
        "model": analysis.model,
        "input_tokens": analysis.input_tokens,
        "output_tokens": analysis.output_tokens,
        "blocked_categories": pipeline_result.blocked_categories,
    }
    usage_record = write_usage_record(
        path=AI_USAGE_FILE,
        recommendation_id=rec_id,
        provider=analysis.provider,
        model=analysis.model,
        input_tokens=analysis.input_tokens,
        output_tokens=analysis.output_tokens,
        input_cost_per_million=AI_INPUT_COST_PER_MILLION_TOKENS,
        output_cost_per_million=AI_OUTPUT_COST_PER_MILLION_TOKENS,
        blocked_categories=pipeline_result.blocked_categories,
    )
    ai_result["estimated_cost_usd"] = usage_record.estimated_cost_usd

    safety_issues = validate_ai_analysis(ai_result)
    if safety_issues:
        ai_result["recommended_decision"] = "REVIEW"
        ai_result["safety_notes"] = (
            ai_result.get("safety_notes", "")
            + "\nSafety validation issues:\n- "
            + "\n- ".join(safety_issues)
        )

    recommended_decision = str(ai_result.get("recommended_decision", "REVIEW")).upper()
    proposed_logic = ""

    if recommended_decision == "APPROVE":
        proposed_logic = (
            f'<rule id="100238" level="13" frequency="2" timeframe="86400" ignore="86400">\n'
            f'  <if_matched_sid>{rule_id}</if_matched_sid>\n'
            f'  <same_agent />\n'
            f'  <!-- Match same benign indicator: {indicator} -->\n'
            f'  <description>Repeated benign activity on same agent suppressed for 24 hours</description>\n'
            f'</rule>'
    )

    if recommended_decision in ["REVIEW", "REJECT"]:
        proposed_logic = (
            "No tuning logic generated because the analysis recommended "
            f"{recommended_decision}. This activity should remain under investigation or review."
        )
        
    message = (
        f"**Recommendation ID:** `{rec_id}`\n\n"
        f"**Detection / Rule**\n"
        f"**Alert Bucket**\n"
        f"- Bucket: `{bucket_info.get('bucket')}`\n"
        f"- Label: {bucket_info.get('label')}\n"
        f"- Tuning Goal: {bucket_info.get('tuning_goal')}\n\n"
        f"- Source: Wazuh\n"
        f"- Rule ID: `{rule_id}`\n"
        f"- Rule Name: Repeated vulnerability detection / related activity\n"
        f"- Severity: Review required\n\n"
        f"**Summary**\n"
        f"Over the last **{LOOKBACK_DAYS} days**, **{case_count} cases** were closed as "
        f"**False Positive** or **Duplicate** for the same or similar activity.\n\n"
        f"**Correlation Criteria**\n"
        f"- Rule ID: `{rule_id}`\n"
        f"- Agent / Host: `{agent}`\n"
        f"- Indicator: `{indicator}`\n"
        f"- Disposition Pattern: False Positive / Duplicate\n\n"
        f"**Evidence**\n"
        f"- Case Count: `{case_count}`\n"
        f"- Example Case IDs: `{', '.join(case_ids)}`\n\n"
        f"**Why These Cases Appear Related**\n"
        f"{ai_result.get('why_related', 'Review required.')}\n\n"
        f"**Suggested Tuning**\n"
        f"{ai_result.get('recommended_tuning', 'Review required.')}\n\n"
        f"**Proposed Logic**\n"
        f"```xml\n{proposed_logic}\n```\n\n"
        f"**AI Analysis Mode**\n"
        f"`{ai_result.get('provider', 'disabled')}` / `{ai_result.get('model', 'none')}`\n\n"
        f"**AI Recommended Decision**\n"
        f"`{ai_result.get('recommended_decision', 'REVIEW')}`\n\n"
        f"**AI Usage / Estimated Cost**\n"
        f"- Input Tokens: `{ai_result.get('input_tokens', 0)}`\n"
        f"- Output Tokens: `{ai_result.get('output_tokens', 0)}`\n"
        f"- Estimated Cost (USD): `${ai_result.get('estimated_cost_usd', 0):.8f}`\n\n"
        f"**Safety Notes**\n"
        f"{ai_result.get('safety_notes', 'None')}\n\n"
        f"**Human Approval Needed**\n"
        f"Reply with one of:\n\n"
        f"`APPROVE {rec_id} <why this is safe>`\n"
        f"`REJECT {rec_id} <why this is unsafe>`\n"
        f"`REVIEW {rec_id} <what needs more validation>`\n"
        f"`DRIFT {rec_id} <what changed from the previous tuning context>`\n\n"
        f"**Decision Guidance**\n"
        f"- Use `APPROVE` when the tuning is narrow, validated, and safe to track as an approved example.\n"
        f"- Use `REJECT` when the recommendation is unsafe, too broad, or missing required evidence.\n"
        f"- Use `REVIEW` when more analyst validation is needed before deciding.\n"
        f"- Use `DRIFT` when a similar tuning may have been valid before, but the current alert changed, such as version, path, user, parent process, cloud resource, region, or indicator.\n"
    )

    return rec_id, message, proposed_logic, ai_result


def load_state() -> dict:
    """Load recommendation history so the same cluster is not sent repeatedly."""
    if not STATE_FILE.exists():
        return {}

    with open(STATE_FILE, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            print(f"Warning: {STATE_FILE} is empty or invalid JSON; starting with empty state.")
            return {}


def save_state(state: dict) -> None:
    """Save recommendation history after a new recommendation is sent."""
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)


def already_sent(state: dict, cluster_key: str) -> bool:
    """Check whether this cluster already has a pending/handled recommendation."""
    return cluster_key in state


def main():
    """Run the tuning-agent workflow end to end."""
    if not DISCORD_WEBHOOK_URL:
        raise RuntimeError("Missing DISCORD_WEBHOOK_URL in .env")

    state = load_state()

    # Pull recent cases first, then do local filtering/grouping for tuning candidates.
    cases = get_recent_cases()
    print(f"Loaded cases: {len(cases)}")
    print(f"MIN_OCCURRENCES: {MIN_OCCURRENCES}")

    recent_cases = [case for case in cases if case_is_within_lookback(case)]
    print(f"Cases inside {LOOKBACK_DAYS}-day lookback: {len(recent_cases)}")

    candidates = [case for case in recent_cases if case_matches_fp_or_duplicate(case)]
    print(f"FP/Duplicate candidates: {len(candidates)}")

    grouped = defaultdict(list)
    for case in candidates:
        grouped[build_cluster_key(case)].append(case)

    sent = 0

    for cluster_key, grouped_cases in grouped.items():
        print(f"Cluster {cluster_key}: {len(grouped_cases)} cases")
        bucket_info = classify_alert_bucket(cluster_key, grouped_cases)

        if len(grouped_cases) < MIN_OCCURRENCES:
            continue

        if already_sent(state, cluster_key):
            print(f"Skipping {cluster_key}; recommendation already sent.")
            continue

        # Build and send one human-reviewable recommendation for each qualifying cluster.
        rec_id, message, proposed_logic, ai_result = build_recommendation(cluster_key, grouped_cases)
        print(f"Sending recommendation {rec_id}")
        post_discord(message)

        rule_id, agent, indicator = cluster_key.split("|", 2)

        state[cluster_key] = {
            "recommendation_id": rec_id,
            "status": "Pending Approval",
            "sent_at": dt.datetime.now(dt.UTC).isoformat(),

            "rule_id": rule_id,
            "rule_name": "Repeated vulnerability detection / related activity",

            "host": agent,
            "agent": agent,
            "indicator": indicator,
            "cve": indicator.replace("cve:", "") if indicator.startswith("cve:") else "",

            "case_count": len(grouped_cases),
            "detection_count": len(grouped_cases),
            "lookback_days": LOOKBACK_DAYS,
            "disposition": "False Positive / Duplicate",

            "suggested_tuning": "Suppress repeated Wazuh detections for the same rule, same host, and same benign indicator for 24 hours.",
            "tuning_suggestion": "Suppress repeated Wazuh detections for the same rule, same host, and same benign indicator for 24 hours.",
            "proposed_logic": proposed_logic,
            "risk": "Medium-Low",

            "case_refs": [get_case_reference(c) for c in grouped_cases[:10]],
            "ai_recommended_decision": ai_result.get("recommended_decision", "REVIEW"),
            "ai_safety_notes": ai_result.get("safety_notes", ""),
            "ai_provider": ai_result.get("provider", "disabled"),
            "ai_model": ai_result.get("model", "none"),
            "ai_input_tokens": ai_result.get("input_tokens", 0),
            "ai_output_tokens": ai_result.get("output_tokens", 0),
            "ai_estimated_cost_usd": ai_result.get("estimated_cost_usd", 0),
            "ai_blocked_categories": ai_result.get("blocked_categories", []),

            "alert_bucket": bucket_info.get("bucket"),
            "alert_bucket_label": bucket_info.get("label"),
            "bucket_tuning_goal": bucket_info.get("tuning_goal"),
        }

        # Save immediately after each send so a rerun will not duplicate the same recommendation.
        save_state(state)
        sent += 1

    print(f"Sent {sent} tuning recommendation(s).")


if __name__ == "__main__":
    main()
