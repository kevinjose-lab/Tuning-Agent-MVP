import argparse
import datetime as dt
import os
import re
from pathlib import Path

import requests
import urllib3
from dotenv import load_dotenv


BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

THEHIVE_URL = os.getenv("THEHIVE_URL", "").rstrip("/")
THEHIVE_API_KEY = os.getenv("THEHIVE_API_KEY", "")
MIN_OCCURRENCES = int(os.getenv("MIN_OCCURRENCES", "5"))

RULE_ID = "999910"


def normalize_run_id(value: str) -> str:
    """Keep generated tags and hostnames simple and predictable."""
    normalized = re.sub(r"[^a-zA-Z0-9-]+", "-", value).strip("-").lower()
    if not normalized:
        raise ValueError("Run ID must contain at least one letter or number.")
    return normalized[:40]


def build_case_payload(case_number: int, run_id: str) -> dict:
    host = f"tuning-workflow-test-{run_id}"
    process = "inventory-agent.exe"
    process_path = rf"C:\Program Files\WorkflowTest\{run_id}\{process}"

    return {
        "title": f"WORKFLOW TEST FP - Approved inventory agent #{case_number} ({run_id})",
        "description": (
            "Synthetic case created for an end-to-end tuning-agent workflow test.\n\n"
            "The activity represents an approved, signed inventory agent running from its "
            "expected installation path on a dedicated test host. This is test data only.\n\n"
            f"Rule ID: {RULE_ID}\n"
            f"Host: {host}\n"
            f"Process: {process}\n"
            f"Path: {process_path}\n"
            "Parent Process: services.exe\n"
            "User: NT AUTHORITY\\SYSTEM\n"
            "Disposition: False Positive / Duplicate\n"
            "Analyst Notes: Known benign lab workflow; safe only when rule, host, and exact path match."
        ),
        "severity": 1,
        "tlp": 2,
        "pap": 2,
        "tags": [
            "wazuh",
            f"rule:{RULE_ID}",
            f"agent:{host}",
            f"process:{process}",
            f"path:{process_path}",
            "parent:services.exe",
            "user:NT AUTHORITY\\SYSTEM",
            "disposition:false-positive",
            "disposition:duplicate",
            "source:tuning-agent-workflow-test",
            "benign:approved-inventory-agent",
            f"workflow-test:{run_id}",
        ],
        "summary": (
            "Synthetic FP/duplicate: approved inventory agent on a dedicated test host. "
            "Tune only the exact rule, host, and executable path combination."
        ),
    }


def create_cases(run_id: str, count: int, dry_run: bool) -> None:
    if count < MIN_OCCURRENCES:
        raise ValueError(
            f"Count must be at least MIN_OCCURRENCES ({MIN_OCCURRENCES}) so the cluster qualifies."
        )

    payloads = [build_case_payload(i, run_id) for i in range(1, count + 1)]
    cluster = f"{RULE_ID}|tuning-workflow-test-{run_id}|path:{payloads[0]['tags'][4][5:]}"

    print(f"Run ID: {run_id}")
    print(f"Cases: {count}")
    print(f"Expected cluster: {cluster}")

    if dry_run:
        print("Dry run complete; no TheHive cases were created.")
        return

    if not THEHIVE_URL or not THEHIVE_API_KEY:
        raise RuntimeError("THEHIVE_URL and THEHIVE_API_KEY must be configured in .env")

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    headers = {
        "Authorization": f"Bearer {THEHIVE_API_KEY}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    for index, payload in enumerate(payloads, start=1):
        response = requests.post(
            f"{THEHIVE_URL}/api/v1/case",
            headers=headers,
            json=payload,
            timeout=30,
            verify=False,
        )
        response.raise_for_status()
        result = response.json()
        reference = result.get("number") or result.get("_id") or result.get("id") or "created"
        print(f"Case {index}/{count}: {reference}")

    print("Workflow test cluster created successfully.")
    print("Next: run `python tuning_agent.py`, then review the new recommendation in Discord.")


def main() -> None:
    default_run_id = dt.datetime.now(dt.UTC).strftime("%Y%m%d-%H%M%S")
    parser = argparse.ArgumentParser(description="Create a qualifying benign workflow-test cluster.")
    parser.add_argument("--run-id", default=default_run_id, help="Unique label shared by the test cases.")
    parser.add_argument("--count", type=int, default=MIN_OCCURRENCES)
    parser.add_argument("--dry-run", action="store_true", help="Validate and preview without creating cases.")
    args = parser.parse_args()

    create_cases(normalize_run_id(args.run_id), args.count, args.dry_run)


if __name__ == "__main__":
    main()
