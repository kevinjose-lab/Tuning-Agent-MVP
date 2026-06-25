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

RULE_ID = "999902"
HOST = "test-windows-agent"
PROCESS_PATH = r"C:\Windows\System32\wuauclt.exe"

for i in range(1, 6):
    case_payload = {
        "title": f"TEST FP - Windows Update process activity #{i}",
        "description": (
            f"Benign test case #{i} for tuning-agent validation.\n\n"
            f"Observed repeated Windows Update activity from known Microsoft binary.\n"
            f"Rule ID: {RULE_ID}\n"
            f"Host: {HOST}\n"
            f"Path: {PROCESS_PATH}\n\n"
            f"Disposition: False Positive / Duplicate\n"
            f"Analyst Notes: Expected Windows Update client behavior on lab endpoint."
        ),
        "severity": 1,
        "tlp": 2,
        "pap": 2,
        "tags": [
            "wazuh",
            f"rule:{RULE_ID}",
            f"agent:{HOST}",
            f"path:{PROCESS_PATH}",
            "disposition:false-positive",
            "disposition:duplicate",
            "source:test-seed",
            "benign:windows-update",
        ],
        "summary": "Closed as false positive/duplicate. Expected Windows Update client activity.",
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

print("Seeded 5 benign Windows Update FP/Duplicate cases.")
