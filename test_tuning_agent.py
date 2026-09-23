import datetime as dt
import tempfile
import unittest
from pathlib import Path

import tuning_agent
from alert_bucket import classify_alert_bucket


class CandidateSelectionTests(unittest.TestCase):
    def test_explicit_false_positive_matches(self):
        case = {"tags": ["disposition:false-positive"]}
        self.assertTrue(tuning_agent.case_matches_fp_or_duplicate(case))

    def test_standalone_fp_matches(self):
        case = {"summary": "Analyst disposition: FP"}
        self.assertTrue(tuning_agent.case_matches_fp_or_duplicate(case))

    def test_proofpoint_does_not_match_fp(self):
        case = {"source": "Proofpoint", "summary": "Message quarantined"}
        self.assertFalse(tuning_agent.case_matches_fp_or_duplicate(case))

    def test_lookback_accepts_epoch_milliseconds(self):
        now = dt.datetime(2026, 9, 21, tzinfo=dt.UTC)
        recent = now - dt.timedelta(days=2)
        case = {"_createdAt": int(recent.timestamp() * 1000)}
        self.assertTrue(tuning_agent.case_is_within_lookback(case, 14, now))

    def test_lookback_rejects_old_iso_timestamp(self):
        now = dt.datetime(2026, 9, 21, tzinfo=dt.UTC)
        case = {"createdAt": "2026-08-01T12:00:00Z"}
        self.assertFalse(tuning_agent.case_is_within_lookback(case, 14, now))


class ClusteringAndSafetyTests(unittest.TestCase):
    def test_cluster_prefers_cve(self):
        case = {
            "tags": [
                "rule:23506",
                "agent:worker-2",
                "cve:CVE-2024-3094",
                "path:/usr/lib/liblzma.so",
            ]
        }
        self.assertEqual(
            tuning_agent.build_cluster_key(case),
            "23506|worker-2|cve:CVE-2024-3094",
        )

    def test_vulnerability_bucket(self):
        result = classify_alert_bucket("23506|worker-2|cve:CVE-2024-3094", [])
        self.assertEqual(result["bucket"], "vulnerability")

    def test_thehive_metadata_does_not_change_process_bucket(self):
        case = {
            "title": "Approved inventory process",
            "description": "Known benign executable",
            "tags": ["process:inventory-agent.exe"],
            "permissions": ["manageCase", "manageAlert"],
            "extraData": {"privilege": "server metadata only"},
        }
        result = classify_alert_bucket(
            "999910|test-host|process:inventory-agent.exe",
            [case],
        )
        self.assertEqual(result["bucket"], "endpoint_process")

    def test_broad_ai_tuning_is_downgraded_by_validator(self):
        result = {
            "recommended_decision": "APPROVE",
            "recommended_tuning": "Globally suppress all events for rule 100 on host-a and calc.exe",
            "proposed_logic": "rule 100 host-a calc.exe",
            "risk": "low",
        }
        result["why_related"] = result["recommended_tuning"]
        issues = tuning_agent.validate_ai_analysis(result)
        self.assertTrue(any("broad tuning" in issue.lower() for issue in issues))

    def test_recommendation_includes_ai_cost(self):
        cases = [
            {
                "caseId": index,
                "title": "Approved inventory process",
                "description": "Known benign signed process with expected parent",
                "tags": [
                    "rule:999910",
                    "agent:test-host",
                    "process:inventory-agent.exe",
                    "disposition:false-positive",
                ],
            }
            for index in range(5)
        ]
        original_mode = tuning_agent.AI_MODE
        original_usage_file = tuning_agent.AI_USAGE_FILE
        try:
            tuning_agent.AI_MODE = "mock"
            with tempfile.TemporaryDirectory() as directory:
                tuning_agent.AI_USAGE_FILE = Path(directory) / "usage.jsonl"
                _, message, _, result = tuning_agent.build_recommendation(
                    "999910|test-host|process:inventory-agent.exe", cases
                )
            self.assertIn("AI Usage / Estimated Cost", message)
            self.assertNotIn("**Expected Impact**", message)
            self.assertNotIn("**Risk Assessment**", message)
            self.assertNotIn("**Validation Steps**", message)
            self.assertIn("estimated_cost_usd", result)
        finally:
            tuning_agent.AI_MODE = original_mode
            tuning_agent.AI_USAGE_FILE = original_usage_file


if __name__ == "__main__":
    unittest.main()
