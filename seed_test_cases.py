import os
import datetime as dt
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


def create_case(case_number: int):
    url = f"{THEHIVE_URL}/api/v1/case"

    payload = {
        "title": f"TEST TUNING CASE {case_number} - Wazuh rule 23506 repeated CVE finding",
        "description": (
            "Test case for tuning-agent MVP.\n\n"
            "Disposition target: Duplicate / False Positive.\n"
            "Activity: Repeated Wazuh vulnerability detector event.\n"
            "Rule: 23506\n"
            "Agent: k3s-worker-node-2\n"
            "CVE: CVE-2024-3094\n"
            "Package: xz-utils\n\n"
            "Analyst note: Closed as duplicate. Repeated known vulnerability finding."
        ),
        "severity": 2,
        "tlp": 2,
        "pap": 2,
        "tags": [
            "wazuh",
            "rule:23506",
            "agent:k3s-worker-node-2",
            "cve:CVE-2024-3094",
            "package:xz-utils",
            "disposition:duplicate",
            "source:tuning-agent-test",
        ],
    }

    response = requests.post(
        url,
        headers=HEADERS,
        json=payload,
        verify=False,
        timeout=30,
    )

    print(f"Case {case_number}: HTTP {response.status_code}")

    if not response.ok:
        print(response.text)
        response.raise_for_status()

    print(response.json())


def main():
    for i in range(1, 6):
        create_case(i)


if __name__ == "__main__":
    main()