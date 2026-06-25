import os
import requests
from dotenv import load_dotenv
from pathlib import Path

env_path = Path(__file__).resolve().parent / ".env"
load_dotenv(dotenv_path=env_path)

THEHIVE_URL = os.getenv("THEHIVE_URL", "").rstrip("/")
THEHIVE_API_KEY = os.getenv("THEHIVE_API_KEY")

HEADERS = {
    "Authorization": f"Bearer {THEHIVE_API_KEY}",
    "Content-Type": "application/json",
    "Accept": "application/json",
}

RULE_ID = "999903"
HOST = "test-linux-backup-agent"
PROCESS = "rsync"
PROCESS_PATH = "/usr/bin/rsync"

for i in range(1, 6):
    case_payload = {
        "title": f"TEST FP - Benign rsync backup activity #{i}",
        "description": (
            f"Benign test case #{i} for tuning-agent validation.\n\n"
            f"Observed repeated scheduled backup activity from rsync.\n"
            f"Rule ID: {RULE_ID}\n"
            f"Host: {HOST}\n"
            f"Process: {PROCESS}\n"
            f"Path: {PROCESS_PATH}\n\n"
            f"Disposition: False Positive / Duplicate\n"
            f"Analyst Notes: Expected scheduled backup behavior on lab endpoint."
        ),
        "severity": 1,
        "tlp": 2,
        "pap": 2,
        "tags": [
            "wazuh",
            f"rule:{RULE_ID}",
            f"agent:{HOST}",
            f"process:{PROCESS}",
            f"path:{PROCESS_PATH}",
            "disposition:false-positive",
            "disposition:duplicate",
            "source:test-seed",
            "benign:backup",
        ],
        "summary": "Closed as false positive/duplicate. Expected rsync backup activity.",
    }

    response = requests.post(
        f"{THEHIVE_URL}/api/v1/case",
        headers=HEADERS,
        json=case_payload,
        timeout=30,
        verify=False,
    )

    print(f"Case {i}: {response.status_code} {response.text[:200]}")
    response.raise_for_status()

print("Seeded 5 benign rsync backup FP/Duplicate cases.")
