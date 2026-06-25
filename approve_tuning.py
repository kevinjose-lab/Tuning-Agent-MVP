import os
import sys
import json
import datetime as dt

import requests
from dotenv import load_dotenv

load_dotenv()

STATE_FILE = "sent_recommendations.json"

APPS_SCRIPT_WEBHOOK_URL = os.getenv("APPS_SCRIPT_WEBHOOK_URL")
APPS_SCRIPT_SECRET = os.getenv("APPS_SCRIPT_SECRET")
APPROVER = os.getenv("APPROVER", "Kevin")


def load_state() -> dict:
    if not os.path.exists(STATE_FILE):
        raise FileNotFoundError(f"{STATE_FILE} not found. Run tuning_agent.py first.")

    with open(STATE_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def save_state(state: dict) -> None:
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)


def append_approval_via_apps_script(rec_id: str, rec: dict, notes: str = "") -> None:
    payload = {
        "secret": APPS_SCRIPT_SECRET,
        "approved_time": dt.datetime.utcnow().isoformat() + "Z",
        "recommendation_id": rec_id,
        "status": "Approved",
        "rule_id": rec.get("rule_id", ""),
        "agent": rec.get("agent", ""),
        "cve": rec.get("cve", ""),
        "case_count": rec.get("case_count", ""),
        "lookback_days": rec.get("lookback_days", ""),
        "suggested_tuning": rec.get("suggested_tuning", ""),
        "risk": rec.get("risk", ""),
        "approver": APPROVER,
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


def approve(rec_id: str, notes: str = "") -> None:
    if not APPS_SCRIPT_WEBHOOK_URL:
        raise RuntimeError("Missing APPS_SCRIPT_WEBHOOK_URL in .env")

    if not APPS_SCRIPT_SECRET:
        raise RuntimeError("Missing APPS_SCRIPT_SECRET in .env")

    state = load_state()

    if rec_id not in state:
        raise ValueError(f"Recommendation ID not found: {rec_id}")

    rec = state[rec_id]

    if rec.get("status") == "Approved":
        print(f"{rec_id} is already approved.")
        return

    append_approval_via_apps_script(rec_id, rec, notes)

    rec["status"] = "Approved"
    rec["approved_at"] = dt.datetime.utcnow().isoformat() + "Z"
    rec["approver"] = APPROVER
    rec["approval_notes"] = notes

    state[rec_id] = rec
    save_state(state)

    print(f"Approved {rec_id} and appended to Google Sheet.")


def main():
    if len(sys.argv) < 2:
        print('Usage: python approve_tuning.py TR-ID-HERE "optional notes"')
        sys.exit(1)

    rec_id = sys.argv[1]
    notes = sys.argv[2] if len(sys.argv) >= 3 else ""

    approve(rec_id, notes)


if __name__ == "__main__":
    main()