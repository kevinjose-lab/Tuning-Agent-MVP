import os
import requests
from pathlib import Path
from dotenv import load_dotenv

env_path = Path(__file__).resolve().parent / ".env"
load_dotenv(dotenv_path=env_path)

THEHIVE_URL = os.getenv("THEHIVE_URL", "").rstrip("/")
THEHIVE_API_KEY = os.getenv("THEHIVE_API_KEY")

HEADERS = {
    "Authorization": f"Bearer {THEHIVE_API_KEY}",
    "Content-Type": "application/json",
    "Accept": "application/json",
}

BENIGN_PATH = r"C:\Program Files\Microsoft Defender\MpCmdRun.exe"


def create_case(case_number: int):
    url = f"{THEHIVE_URL}/api/v1/case"

    payload = {
        "title": f"TEST TUNING CASE {case_number} - Benign Defender path triggered detection",
        "description": (
            "Test case for tuning-agent benign path workflow.\n\n"
            "Disposition target: False Positive / Duplicate.\n"
            "Activity: Known legitimate Microsoft Defender command-line utility triggered repeated detection.\n"
            "Rule: 999901\n"
            "Agent: test-windows-agent\n"
            f"Process Path: {BENIGN_PATH}\n"
            "User: NT AUTHORITY\\SYSTEM\n\n"
            "Analyst note: Closed as false positive. Legitimate Defender maintenance activity from expected path."
        ),
        "severity": 2,
        "tlp": 2,
        "pap": 2,
        "tags": [
            "wazuh",
            "rule:999901",
            "agent:test-windows-agent",
            "process:MpCmdRun.exe",
            "path:C:\\Program Files\\Microsoft Defender\\MpCmdRun.exe",
            "user:NT AUTHORITY\\SYSTEM",
            "disposition:false-positive",
            "source:tuning-agent-test",
            "benign-path",
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

    result = response.json()
    print(result.get("_id") or result.get("id") or result.get("number") or result.get("title"))


def main():
    for i in range(1, 6):
        create_case(i)


if __name__ == "__main__":
    main()