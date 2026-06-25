import os
import re
import json
import datetime as dt

import requests
import discord
from dotenv import load_dotenv
from feedback_interpreter import interpret_feedback

load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATE_FILE = os.path.join(BASE_DIR, "sent_recommendations.json")
APPROVED_KB_FILE = os.path.join(BASE_DIR, "knowledge_base", "approved_tuning_examples.md")
REJECTED_KB_FILE = os.path.join(BASE_DIR, "knowledge_base", "rejected_tuning_examples.md")
STALE_KB_FILE = os.path.join(BASE_DIR, "knowledge_base", "stale_tuning_examples.md")
FEEDBACK_CHANGE_LOG = os.path.join(BASE_DIR, "knowledge_base", "feedback_change_log.md")

print(f"[DEBUG] approval_bot.py path: {__file__}")
print(f"[DEBUG] STATE_FILE: {STATE_FILE}")

DISCORD_BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN")
APPROVAL_CHANNEL_ID = int(os.getenv("APPROVAL_CHANNEL_ID", "0"))

APPS_SCRIPT_WEBHOOK_URL = os.getenv("APPS_SCRIPT_WEBHOOK_URL")
APPS_SCRIPT_SECRET = os.getenv("APPS_SCRIPT_SECRET")
APPROVER = os.getenv("APPROVER", "Kevin")


def load_state():
    """Load recommendations that were already sent to Discord for review."""
    if not os.path.exists(STATE_FILE):
        return {}

    with open(STATE_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def save_state(state) -> None:
    """Persist recommendation status changes back to the local state file."""
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)


def normalize_id(value: str) -> str:
    """Normalize recommendation IDs so Discord replies can include backticks/case changes."""
    return str(value).strip().lower().replace("`", "")


def find_recommendation(state, rec_id):
    """Find a recommendation by ID in either dict-style or list-style saved state."""
    wanted = normalize_id(rec_id)

    if isinstance(state, dict):
        for key, value in state.items():
            if normalize_id(key) == wanted:
                return key, value

            if isinstance(value, dict):
                for field in ["recommendation_id", "rec_id", "id"]:
                    if normalize_id(value.get(field, "")) == wanted:
                        return key, value

    if isinstance(state, list):
        for index, item in enumerate(state):
            if not isinstance(item, dict):
                continue

            for field in ["recommendation_id", "rec_id", "id"]:
                if normalize_id(item.get(field, "")) == wanted:
                    return index, item

    return None, None


def send_to_apps_script(
    rec_id: str,
    rec: dict,
    decision: str,
    approver: str,
    notes: str = "",
) -> None:
    """Send an approved recommendation to the Google Apps Script webhook."""
    if not APPS_SCRIPT_WEBHOOK_URL or not APPS_SCRIPT_SECRET:
        raise RuntimeError("Apps Script webhook URL or secret is not configured.")

    payload = {
        "secret": APPS_SCRIPT_SECRET,
        "approved_time": dt.datetime.utcnow().isoformat() + "Z",
        "recommendation_id": rec_id,

        "decision": decision.title(),
        "status": decision.title(),

        "host": rec.get("host", rec.get("agent", "")),
        "agent": rec.get("agent", ""),

        "rule_id": rec.get("rule_id", ""),
        "rule_name": rec.get("rule_name", "Repeated vulnerability detection / related activity"),

        "detection_count": rec.get("detection_count", rec.get("case_count", "")),
        "case_count": rec.get("case_count", ""),

        "lookback_days": rec.get("lookback_days", ""),
        "disposition": rec.get("disposition", "False Positive / Duplicate"),

        "tuning_suggestion": rec.get(
            "tuning_suggestion",
            rec.get("suggested_tuning", "")
        ),

        "suggested_tuning": rec.get("suggested_tuning", ""),
        "proposed_logic": rec.get("proposed_logic", ""),

        "risk": rec.get("risk", ""),
        "approver": approver,
        "notes": notes,
    }

    response = requests.post(
        APPS_SCRIPT_WEBHOOK_URL,
        headers={"Content-Type": "application/json"},
        json=payload,
        timeout=20,
    )

    response.raise_for_status()

    result = response.json()
    if not result.get("ok"):
        raise RuntimeError(f"Apps Script error: {result}")


intents = discord.Intents.default()
intents.message_content = True

client = discord.Client(intents=intents)

def append_to_feedback_change_log(rec_id: str, rec: dict, reviewer: str, notes: str = "") -> None:
    os.makedirs(os.path.dirname(FEEDBACK_CHANGE_LOG), exist_ok=True)

    entry = f"""

---

## Feedback Change Candidate — {rec_id}

Time: {dt.datetime.utcnow().isoformat()}Z  
Reviewer: {reviewer}  
Decision: {rec.get("decision", "")}  
Status: {rec.get("status", "")}  

### Scope

- Alert Bucket: {rec.get("alert_bucket", "")}
- Rule ID: {rec.get("rule_id", "")}
- Host / Agent: {rec.get("host", rec.get("agent", ""))}
- Indicator: {rec.get("indicator", "")}

### Analyst Notes

{notes if notes else "No analyst notes provided."}

### Proposed Behavior Change

- Type: {rec.get("behavior_change_type", "")}
- Scope: {rec.get("behavior_change_scope", "")}
- Affected Fields: {", ".join(rec.get("affected_fields", []))}
- Avoid Pattern: {rec.get("avoid_pattern", "")}
- Required Future Constraints: {", ".join(rec.get("required_future_constraints", []))}

### Overbias Control

- Overbias Risk: {rec.get("overbias_risk", "")}
- Guardrail: {rec.get("overbias_guardrail", "")}
- Needs Eval: {rec.get("needs_eval", False)}
- Promoted To Global KB: {rec.get("promote_to_global_kb", False)}

"""
    with open(FEEDBACK_CHANGE_LOG, "a", encoding="utf-8") as f:
        f.write(entry)

@client.event
async def on_ready():
    """Confirm the bot connected to Discord successfully."""
    print(f"Approval bot logged in as {client.user}")


def append_to_approved_knowledge_base(
    rec_id: str,
    rec: dict,
    approver: str,
    notes: str = "",
) -> None:
    """Record approved tuning examples so future recommendations can reuse good patterns."""
    os.makedirs(os.path.dirname(APPROVED_KB_FILE), exist_ok=True)

    proposed_logic = rec.get("proposed_logic", "")
    indented_logic = "\n".join(f"    {line}" for line in proposed_logic.splitlines())

    entry = f"""

---

## Approved Tuning — {rec_id}

Approved Time: {dt.datetime.utcnow().isoformat()}Z  
Approver: {approver}  
Decision: Approved  

### Detection / Rule

- Rule ID: {rec.get("rule_id", "")}
- Rule Name: {rec.get("rule_name", "")}
- Host / Agent: {rec.get("host", rec.get("agent", ""))}
- Indicator: {rec.get("indicator", "")}
- CVE: {rec.get("cve", "")}
- Case Count: {rec.get("case_count", "")}
- Lookback Days: {rec.get("lookback_days", "")}
- Disposition Pattern: {rec.get("disposition", "")}

### Tuning Suggestion

{rec.get("tuning_suggestion", rec.get("suggested_tuning", ""))}

### Proposed Logic

{indented_logic}

### Risk

{rec.get("risk", "")}

### Approval Notes

{notes if notes else "No approval notes provided."}

### Future Guidance

This tuning was approved because multiple cases showed the same or similar activity and were closed as False Positive or Duplicate. Future recommendations should prefer similarly narrow tuning based on rule, host, and stable benign indicators instead of broad rule suppression.
"""

    with open(APPROVED_KB_FILE, "a", encoding="utf-8") as f:
        f.write(entry)


def append_to_rejected_knowledge_base(
    rec_id: str,
    rec: dict,
    approver: str,
    notes: str = "",
) -> None:
    """Record rejected tuning examples so future recommendations avoid risky patterns."""
    os.makedirs(os.path.dirname(REJECTED_KB_FILE), exist_ok=True)

    proposed_logic = rec.get("proposed_logic", "")
    indented_logic = "\n".join(f"    {line}" for line in proposed_logic.splitlines())

    entry = f"""

---

## Rejected Tuning — {rec_id}

Rejected Time: {dt.datetime.utcnow().isoformat()}Z  
Reviewer: {approver}  
Decision: Rejected  

### Detection / Rule

- Rule ID: {rec.get("rule_id", "")}
- Rule Name: {rec.get("rule_name", "")}
- Host / Agent: {rec.get("host", rec.get("agent", ""))}
- Indicator: {rec.get("indicator", "")}
- CVE: {rec.get("cve", "")}
- Case Count: {rec.get("case_count", "")}
- Lookback Days: {rec.get("lookback_days", "")}
- Disposition Pattern: {rec.get("disposition", "")}

### Original Tuning Suggestion

{rec.get("tuning_suggestion", rec.get("suggested_tuning", ""))}

### Proposed Logic

{indented_logic}

### Risk

{rec.get("risk", "")}

### Rejection Reason / Reviewer Notes

{notes if notes else "No rejection notes provided."}

### Future Guidance

This tuning was rejected. Future recommendations should avoid repeating this logic unless new evidence changes the risk assessment. The agent should prefer narrower scope, better validation, or additional evidence before suggesting a similar tuning again.
"""

    with open(REJECTED_KB_FILE, "a", encoding="utf-8") as f:
        f.write(entry)


def append_to_stale_knowledge_base(
    rec_id: str,
    rec: dict,
    reviewer: str,
    notes: str = "",
) -> None:
    """Record stale/drift tuning examples so future recommendations avoid blindly reusing old approvals."""
    os.makedirs(os.path.dirname(STALE_KB_FILE), exist_ok=True)

    proposed_logic = rec.get("proposed_logic", "")
    indented_logic = "\n".join(f"    {line}" for line in proposed_logic.splitlines())

    entry = f"""

---

## Stale / Drifted Tuning — {rec_id}

Marked Time: {dt.datetime.utcnow().isoformat()}Z  
Reviewer: {reviewer}  
Decision: Stale / Drift  

### Detection / Rule

- Rule ID: {rec.get("rule_id", "")}
- Rule Name: {rec.get("rule_name", "")}
- Host / Agent: {rec.get("host", rec.get("agent", ""))}
- Indicator: {rec.get("indicator", "")}
- Alert Bucket: {rec.get("alert_bucket", "")}
- Case Count: {rec.get("case_count", "")}
- Lookback Days: {rec.get("lookback_days", "")}

### Original Tuning Suggestion

{rec.get("tuning_suggestion", rec.get("suggested_tuning", ""))}

### Proposed Logic

{indented_logic if indented_logic else "    No proposed logic recorded."}

### Stale / Drift Reason

{notes if notes else "No stale/drift notes provided."}

### Structured Behavior Change

- Behavior Change Type: {rec.get("behavior_change_type", "")}
- Behavior Change Scope: {rec.get("behavior_change_scope", "")}
- Affected Fields: {", ".join(rec.get("affected_fields", []))}
- Avoid Pattern: {rec.get("avoid_pattern", "")}
- Required Future Constraints: {", ".join(rec.get("required_future_constraints", []))}
- Overbias Risk: {rec.get("overbias_risk", "")}
- Overbias Guardrail: {rec.get("overbias_guardrail", "")}
- Needs Eval: {rec.get("needs_eval", False)}

### Future Guidance

This rejection is a scoped candidate lesson, not a global rule. Future recommendations should apply it only when the alert bucket, core fields, and risk pattern are similar. The overbias guardrail must be checked before using this lesson to influence a recommendation.
"""

    with open(STALE_KB_FILE, "a", encoding="utf-8") as f:
        f.write(entry)


def parse_decision_message(content: str) -> tuple[str, str, str]:
    """
    Parse Discord commands like:
    APPROVE TR-123 optional analyst notes
    REJECT TR-123 optional analyst notes
    REVIEW TR-123 optional analyst notes
    STALE TR-123 optional analyst notes
    DRIFT TR-123 optional analyst notes
    """
    parts = content.strip().split(maxsplit=2)

    if len(parts) < 2:
        return "", "", ""

    decision = parts[0].upper().strip()
    rec_id = parts[1].strip().replace("`", "")
    notes = parts[2].strip() if len(parts) >= 3 else ""

    allowed = {"APPROVE", "REJECT", "REVIEW", "STALE", "DRIFT"}
    if decision not in allowed:
        return "", "", ""

    if not rec_id.upper().startswith("TR-"):
        return "", "", ""

    return decision, rec_id, notes


def determine_feedback_lane(decision: str, notes: str = "") -> str:
    """Route analyst feedback to the right learning lane."""
    decision = decision.upper()
    notes_l = notes.lower()

    if decision == "APPROVE":
        return "knowledge_base_positive"

    if decision == "REJECT":
        return "knowledge_base_negative"

    if decision == "REVIEW":
        return "case_specific_note"

    if decision in {"STALE", "DRIFT"}:
        return "drift_feedback"

    if any(term in notes_l for term in ["parser", "missing field", "extract", "did not capture"]):
        return "parser_enrichment_improvement"

    if any(term in notes_l for term in ["never again", "regression", "bad recommendation"]):
        return "regression_eval_case"

    return "case_specific_note"


@client.event
async def on_message(message: discord.Message):
    """Handle Discord approval commands and update the matching recommendation."""
    if message.author.bot:
        return

    # Only process commands in the configured approval channel.
    if APPROVAL_CHANNEL_ID and message.channel.id != APPROVAL_CHANNEL_ID:
        return

    content = message.content.strip()
    decision, rec_id, notes = parse_decision_message(content)

    if not decision or not rec_id:
        return

    state = load_state()

    matched_key, rec = find_recommendation(state, rec_id)

    if rec is None:
        await message.reply(
            f"Recommendation `{rec_id}` was not found in sent_recommendations.json.",
            mention_author=True,
        )
        return

    if rec.get("status") in ["Approved", "Rejected"]:
        await message.reply(
            f"`{rec_id}` already has status `{rec.get('status')}`.",
            mention_author=True,
        )
        return

    try:
        username = str(message.author)

        if decision == "APPROVE":
            send_to_apps_script(
                rec_id=rec_id,
                rec=rec,
                decision=decision,
                approver=username,
                notes=notes,
            )

            append_to_approved_knowledge_base(
                rec_id=rec_id,
                rec=rec,
                approver=username,
                notes=notes,
            )

        elif decision == "REJECT":
            append_to_rejected_knowledge_base(
                rec_id=rec_id,
                rec=rec,
                approver=username,
                notes=notes,
            )

        elif decision in {"STALE", "DRIFT"}:
            append_to_stale_knowledge_base(
                rec_id=rec_id,
                rec=rec,
                reviewer=username,
                notes=notes,
            )

        # Update local state for APPROVE, REJECT, REVIEW, STALE, and DRIFT decisions.
        now = dt.datetime.utcnow().isoformat() + "Z"
        feedback_lane = determine_feedback_lane(decision, notes)
        feedback_metadata = interpret_feedback(decision, rec, notes)
        rec["decision"] = decision
        rec["decision_at"] = now
        rec["feedback_lane"] = feedback_lane
        rec["analyst_notes"] = notes
        rec.update(feedback_metadata)

        if decision == "APPROVE":
            rec["status"] = "Approved"
            rec["approved_at"] = now
            rec["approved_by"] = username
            rec["approver"] = username
            rec["approval_notes"] = notes

        elif decision == "REJECT":
            rec["status"] = "Rejected"
            rec["rejected_at"] = now
            rec["rejected_by"] = username
            rec["reviewed_at"] = now
            rec["reviewed_by"] = username
            rec["rejection_notes"] = notes
            rec.pop("approver", None)

        elif decision == "REVIEW":
            rec["status"] = "Needs Review"
            rec["reviewed_at"] = now
            rec["reviewed_by"] = username
            rec["review_notes"] = notes or "Marked for additional human review from Discord."
            rec.pop("approver", None)

        elif decision in {"STALE", "DRIFT"}:
            rec["status"] = "Stale / Drift Detected"
            rec["drift_detected"] = True
            rec["drift_marked_at"] = now
            rec["drift_marked_by"] = username
            rec["drift_notes"] = notes or "Marked as stale or drifted from Discord."
            rec.pop("approver", None)

        if isinstance(state, dict):
            state[matched_key] = rec
        elif isinstance(state, list):
            state[matched_key] = rec

        save_state(state)

        if decision == "APPROVE":
            await message.reply(
                f"`{decision}` recorded for `{rec_id}`, written to Google Sheet, and added to approved knowledge base.",
                mention_author=True,
            )
        elif decision == "REJECT":
            await message.reply(
                f"`{decision}` recorded for `{rec_id}` and added to rejected knowledge base. It was not written to Google Sheet.",
                mention_author=True,
            )
        elif decision == "REVIEW":
            await message.reply(
                f"`{decision}` recorded for `{rec_id}`. Status set to `Needs Review`; no Google Sheet or KB entry was created.",
                mention_author=True,
            )
        elif decision in {"STALE", "DRIFT"}:
            await message.reply(
                f"`{decision}` recorded for `{rec_id}` and added to stale/drift knowledge base. It was not written to Google Sheet.",
                mention_author=True,
            )
        if decision in {"REJECT", "DRIFT", "STALE"}:
            append_to_feedback_change_log(rec_id, rec, username, notes)
            
    except Exception as exc:
        await message.reply(
            f"Failed to record `{decision}` for `{rec_id}`: `{exc}`",
            mention_author=True,
        )
    

if __name__ == "__main__":
    # Fail fast if required runtime configuration is missing.
    if not DISCORD_BOT_TOKEN:
        raise RuntimeError("Missing DISCORD_BOT_TOKEN in .env")

    if not APPS_SCRIPT_WEBHOOK_URL:
        print("[WARN] Missing APPS_SCRIPT_WEBHOOK_URL. APPROVE will fail until configured.")

    if not APPS_SCRIPT_SECRET:
        print("[WARN] Missing APPS_SCRIPT_SECRET. APPROVE will fail until configured.")

    client.run(DISCORD_BOT_TOKEN)
