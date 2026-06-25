
import os
import json
import hashlib
import datetime as dt
from collections import defaultdict

import requests
from dotenv import load_dotenv

from pathlib import Path
from knowledge_retriever import retrieve_knowledge
from alert_bucket import classify_alert_bucket

env_path = Path(__file__).resolve().parent / ".env"
load_dotenv(dotenv_path=env_path)

THEHIVE_URL = os.getenv("THEHIVE_URL", "").rstrip("/")
THEHIVE_API_KEY = os.getenv("THEHIVE_API_KEY")
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")

OLLAMA_URL = os.getenv("OLLAMA_URL", "").rstrip("/")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5:7b")
USE_QWEN = os.getenv("USE_QWEN", "false").lower() == "true"

LOOKBACK_DAYS = int(os.getenv("LOOKBACK_DAYS", "14"))
MIN_OCCURRENCES = int(os.getenv("MIN_OCCURRENCES", "5"))

STATE_FILE = Path(__file__).resolve().parent / "sent_recommendations.json"

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

    fp_terms = [
        "false positive",
        "false_positive",
        "fp",
        "duplicate",
        "duplicated",
        "disposition:false-positive",
        "disposition:duplicate",
    ]

    return any(term in text for term in fp_terms)


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


def build_qwen_tuning_prompt(cluster_key: str, cases: list[dict]) -> str:
    rule_id, agent, indicator = cluster_key.split("|", 2)
    bucket_info = classify_alert_bucket(cluster_key, cases)
    knowledge_context = retrieve_knowledge(
        f"{rule_id} {agent} {indicator} tuning false positive duplicate suppression"
    )

    case_summaries = []

    for case in cases[:10]:
        case_ref = get_case_reference(case)
        title = case.get("title", "No title")
        tags = case.get("tags", [])
        summary = case.get("summary", case.get("description", ""))

        case_summaries.append(
            f"- Case: {case_ref}\n"
            f"  Title: {title}\n"
            f"  Tags: {tags}\n"
            f"  Summary/Notes: {summary}"
        )

    joined_cases = "\n".join(case_summaries)

    return f"""
You are a Senior SOC detection tuning analyst.

Use the internal tuning knowledge below to draft a tuning recommendation.

Knowledge Context:
{knowledge_context}

Case Cluster Context:
- Detection source: Wazuh
- Rule ID: {rule_id}
- Agent/Host: {agent}
- Correlation indicator: {indicator}
- Case count: {len(cases)}
- These cases were closed as False Positive or Duplicate.
- The output is for human approval only.

Alert Bucket:
- Bucket: {bucket_info["bucket"]}
- Label: {bucket_info["label"]}
- Preferred Grouping: {bucket_info["preferred_grouping"]}
- Tuning Goal: {bucket_info["tuning_goal"]}

Bucket-Specific Rules:
- If bucket is vulnerability: group by agent + CVE + package. Do not hide the vulnerability from inventory.
- If bucket is IOC: do not tune malicious indicators unless confirmed benign/allowlisted.
- If bucket is authentication: preserve visibility for privileged users, new source IPs, external sources, and high failure volume.
- If bucket is endpoint_process: never broadly suppress PowerShell, LOLBins, Office-child processes, or encoded commands.
- If bucket is cloud: preserve visibility for new principals, new regions, sensitive IAM actions, and public exposure changes.
- If bucket is network: preserve visibility for new destinations, unusual ports, and suspicious protocols.
- If bucket is email: do not suppress broad phishing detections; tune only known benign sender/campaign patterns.
- If bucket is identity_privilege: treat privilege changes as high risk and prefer REVIEW unless clearly approved admin workflow.

Cases:
{joined_cases}

Rules:
- Do not suppress an entire rule globally.
- Do not suppress all activity from a host.
- Do not suppress all PowerShell or all vulnerability detections.
- Proposed logic must be narrow.
- Proposed logic must include the rule ID.
- Proposed logic must include the host/agent if available.
- Proposed logic must include the correlation indicator if available.
- Include a risk or blind spot.
- Include validation steps.
- If this should not be tuned, set recommended_decision to "REVIEW" or "REJECT".

Return valid JSON only. No markdown outside JSON.

JSON schema:
{{
  "recommended_decision": "APPROVE|REVIEW|REJECT",
  "why_related": "string",
  "recommended_tuning": "string",
  "proposed_logic": "string",
  "expected_impact": "string",
  "risk": "string",
  "validation_steps": ["string", "string", "string"],
  "safety_notes": "string"
}}
"""


def ask_qwen_json(prompt: str) -> dict:
    if not USE_QWEN:
        return {
            "recommended_decision": "REVIEW",
            "why_related": "Qwen assessment disabled.",
            "recommended_tuning": "Template-only recommendation generated.",
            "proposed_logic": "",
            "expected_impact": "Review required.",
            "risk": "Risk assessment unavailable because Qwen is disabled.",
            "validation_steps": ["Manually validate before approval."],
            "safety_notes": "LLM disabled."
        }

    if not OLLAMA_URL:
        return {
            "recommended_decision": "REVIEW",
            "why_related": "Qwen assessment unavailable: OLLAMA_URL is not configured.",
            "recommended_tuning": "Template-only recommendation generated.",
            "proposed_logic": "",
            "expected_impact": "Review required.",
            "risk": "Risk assessment unavailable.",
            "validation_steps": ["Manually validate before approval."],
            "safety_notes": "Ollama URL missing."
        }

    try:
        response = requests.post(
            f"{OLLAMA_URL}/api/generate",
            json={
                "model": OLLAMA_MODEL,
                "prompt": prompt,
                "stream": False,
                "format": "json"
            },
            timeout=120,
        )
        response.raise_for_status()

        raw = response.json().get("response", "").strip()
        return json.loads(raw)

    except Exception as exc:
        return {
            "recommended_decision": "REVIEW",
            "why_related": f"Qwen JSON generation failed: {exc}",
            "recommended_tuning": "Template-only fallback required.",
            "proposed_logic": "",
            "expected_impact": "Review required.",
            "risk": "Could not generate LLM risk assessment.",
            "validation_steps": ["Manually validate before approval."],
            "safety_notes": "Qwen failed or returned invalid JSON."
        }

def validate_qwen_tuning(qwen_result: dict, rule_id: str, agent: str, indicator: str) -> list[str]:
    issues = []

    recommended_decision = str(qwen_result.get("recommended_decision", "REVIEW")).upper()

    if recommended_decision in ["REVIEW", "REJECT"]:
        return issues

    combined = " ".join([
        str(qwen_result.get("recommended_tuning", "")),
        str(qwen_result.get("proposed_logic", "")),
        str(qwen_result.get("risk", "")),
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

    if rule_id.lower() not in combined:
        issues.append("Proposed tuning does not reference the rule ID.")

    if agent and agent != "unknown_agent" and agent.lower() not in combined:
        issues.append("Proposed tuning does not reference the agent/host.")

    indicator_value = indicator.split(":", 1)[-1].lower()
    if indicator_value and indicator_value != "generic" and indicator_value not in combined:
        issues.append("Proposed tuning does not reference the correlation indicator.")

    return issues

def build_recommendation(cluster_key: str, cases: list[dict]) -> tuple[str, str, str, dict]:
    """Turn a repeated case cluster into a Discord message and proposed Wazuh logic."""
    rec_id = recommendation_id(cluster_key)
    rule_id, agent, indicator = cluster_key.split("|", 2)
    bucket_info = classify_alert_bucket(cluster_key, cases)
    case_ids = [get_case_reference(c) for c in cases[:10]]
    case_count = len(cases)

    qwen_prompt = build_qwen_tuning_prompt(cluster_key, cases)
    qwen_result = ask_qwen_json(qwen_prompt)

    safety_issues = validate_qwen_tuning(
        qwen_result=qwen_result,
        rule_id=rule_id,
        agent=agent,
        indicator=indicator,
    )

    if safety_issues:
        qwen_result["recommended_decision"] = "REVIEW"
        qwen_result["safety_notes"] = (
            qwen_result.get("safety_notes", "")
            + "\nSafety validation issues:\n- "
            + "\n- ".join(safety_issues)
        )

    recommended_decision = str(qwen_result.get("recommended_decision", "REVIEW")).upper()
    proposed_logic = qwen_result.get("proposed_logic", "").strip()

    if not proposed_logic and recommended_decision == "APPROVE":
        proposed_logic = (
            f'<rule id="100238" level="13" frequency="2" timeframe="86400" ignore="86400">\n'
            f'  <if_matched_sid>{rule_id}</if_matched_sid>\n'
            f'  <same_agent />\n'
            f'  <!-- Match same benign indicator: {indicator} -->\n'
            f'  <description>Repeated benign activity on same agent suppressed for 24 hours</description>\n'
            f'</rule>'
    )

    if not proposed_logic and recommended_decision in ["REVIEW", "REJECT"]:
        proposed_logic = (
        "No tuning logic generated because the LLM recommended "
        f"{recommended_decision}. This activity should remain under investigation or review."
    )
        
    validation_steps = qwen_result.get("validation_steps", [])
    if isinstance(validation_steps, list):
        validation_steps_text = "\n".join(f"- {step}" for step in validation_steps)
    else:
        validation_steps_text = str(validation_steps)

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
        f"{qwen_result.get('why_related', 'Review required.')}\n\n"
        f"**Suggested Tuning**\n"
        f"{qwen_result.get('recommended_tuning', 'Review required.')}\n\n"
        f"**Proposed Logic**\n"
        f"```xml\n{proposed_logic}\n```\n\n"
        f"**Expected Impact**\n"
        f"{qwen_result.get('expected_impact', 'Review required.')}\n\n"
        f"**Risk Assessment**\n"
        f"{qwen_result.get('risk', 'Risk review required.')}\n\n"
        f"**Validation Steps**\n"
        f"{validation_steps_text}\n\n"
        f"**LLM Recommended Decision**\n"
        f"`{qwen_result.get('recommended_decision', 'REVIEW')}`\n\n"
        f"**Safety Notes**\n"
        f"{qwen_result.get('safety_notes', 'None')}\n\n"
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

    return rec_id, message, proposed_logic, qwen_result


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

    candidates = [case for case in cases if case_matches_fp_or_duplicate(case)]
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
        rec_id, message, proposed_logic, qwen_result = build_recommendation(cluster_key, grouped_cases)
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
            "llm_recommended_decision": qwen_result.get("recommended_decision", "REVIEW"),
            "llm_safety_notes": qwen_result.get("safety_notes", ""),
            "qwen_generated": True,

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
