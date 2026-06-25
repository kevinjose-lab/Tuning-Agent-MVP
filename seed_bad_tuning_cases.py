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

RULE_ID = "999903"
HOST = "test-windows-agent"
PROCESS_PATH = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"

for i in range(1, 6):
    case_payload = {
        "title": f"TEST DO NOT TUNE - Suspicious PowerShell EncodedCommand #{i}",
        "description": (
            f"Bad tuning test case #{i}.\n\n"
            f"This cluster is intentionally designed to be rejected.\n"
            f"It contains suspicious PowerShell activity that should NOT be broadly suppressed.\n\n"
            f"Rule ID: {RULE_ID}\n"
            f"Host: {HOST}\n"
            f"Process Path: {PROCESS_PATH}\n"
            f"Command Line: powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand TESTPAYLOAD{i}\n"
            f"Parent Process: WINWORD.EXE\n\n"
            f"Disposition: False Positive / Duplicate\n"
            f"Analyst Notes: Even though these test cases are marked FP/Duplicate, this is a risky pattern. "
            f"Do not approve broad suppression for PowerShell EncodedCommand from Office parent process."
        ),
        "severity": 3,
        "tlp": 2,
        "pap": 2,
        "tags": [
            "wazuh",
            f"rule:{RULE_ID}",
            f"agent:{HOST}",
            f"path:{PROCESS_PATH}",
            "process:powershell.exe",
            "parent:WINWORD.EXE",
            "command:EncodedCommand",
            "disposition:false-positive",
            "disposition:duplicate",
            "source:test-seed",
            "do-not-tune",
            "bad-tuning-example",
            "suspicious:powershell-encodedcommand",
        ],
        "summary": (
            "Closed as FP/Duplicate for testing only. This is intentionally a poor tuning candidate "
            "because PowerShell EncodedCommand from WINWORD.EXE is a suspicious pattern."
        ),
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

print("Seeded 5 bad tuning candidate cases.")
