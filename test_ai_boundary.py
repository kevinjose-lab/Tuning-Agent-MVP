import json
import tempfile
import unittest
from pathlib import Path

from ai_pipeline import get_provider, run_ai_pipeline
from ai_schema import AIAnalysisRequest
from ai_usage import estimate_cost, write_usage_record
from cost_analysis import summarize
from feature_extractor import extract_ai_features
from leakage_guard import detect_leaks
from redactor import redact_text
from seed_workflow_test_cases import build_case_payload
from tuning_agent import build_cluster_key


class RedactionTests(unittest.TestCase):
    def test_common_sensitive_values_are_redacted(self):
        source = (
            "john.smith@example.com 10.10.20.30 https://internal.example/admin "
            r"C:\Users\John\secret.ps1 token=super-secret"
        )
        result = redact_text(source)
        for sensitive in [
            "john.smith@example.com",
            "10.10.20.30",
            "https://internal.example/admin",
            "super-secret",
        ]:
            self.assertNotIn(sensitive, result.value)

    def test_leakage_guard_reports_categories_not_values(self):
        payload = {"message": "connect to 10.10.20.30"}
        findings = detect_leaks(payload)
        self.assertIn("IP", findings)
        self.assertNotIn("10.10.20.30", findings)


class ProviderBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.cases = [build_case_payload(i, "boundary-test") for i in range(1, 6)]
        self.cluster = build_cluster_key(self.cases[0])

    def test_feature_payload_contains_no_raw_identifiers(self):
        request = extract_ai_features(self.cluster, self.cases, 14)
        serialized = json.dumps(request.to_dict())
        for sensitive in [
            "999910",
            "tuning-workflow-test-boundary-test",
            "inventory-agent.exe",
            "WorkflowTest",
        ]:
            self.assertNotIn(sensitive, serialized)

    def test_thehive_metadata_does_not_create_feature_flags(self):
        cases = [
            {
                "title": "Routine process event",
                "tags": ["process:inventory-agent.exe"],
                "serverMetadata": {
                    "description": "approved signed binary encodedcommand winword.exe"
                },
            }
        ]
        request = extract_ai_features(
            "999910|test-host|process:inventory-agent.exe", cases, 14
        )
        self.assertEqual(request.context_flags, [])
        self.assertEqual(request.risk_flags, ["unknown_context"])

    def test_redaction_only_performs_no_external_request(self):
        request = extract_ai_features(self.cluster, self.cases, 14)
        result = run_ai_pipeline(request, get_provider("redaction-only"))
        self.assertEqual(result.analysis.provider, "redaction-only")
        self.assertEqual(result.analysis.decision, "REVIEW")
        self.assertEqual(result.blocked_categories, [])

    def test_known_value_leak_fails_closed(self):
        request = AIAnalysisRequest(
            schema_version="1.0",
            alert_bucket="internalhost",
            occurrence_count=5,
            lookback_days=14,
            same_rule=True,
            same_host=True,
            same_indicator=True,
            disposition="false_positive_or_duplicate",
        )
        result = run_ai_pipeline(
            request,
            get_provider("mock"),
            known_sensitive_values=["internalhost"],
        )
        self.assertEqual(result.analysis.provider, "blocked")
        self.assertIn("KNOWN_SENSITIVE_VALUE", result.blocked_categories)

    def test_unapproved_provider_is_rejected(self):
        with self.assertRaises(ValueError):
            get_provider("unapproved-provider")

    def test_input_limit_fails_closed(self):
        request = extract_ai_features(self.cluster, self.cases, 14)
        result = run_ai_pipeline(request, get_provider("mock"), max_input_tokens=1)
        self.assertEqual(result.analysis.provider, "blocked")
        self.assertIn("INPUT_TOKEN_LIMIT", result.blocked_categories)


class CostTests(unittest.TestCase):
    def test_cost_formula(self):
        self.assertEqual(estimate_cost(1_000_000, 500_000, 1.0, 2.0), 2.0)

    def test_usage_log_hashes_recommendation_id(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "usage.jsonl"
            write_usage_record(path, "TR-sensitive-id", "mock", "mock-v1", 100, 20, 1, 2)
            content = path.read_text()
            self.assertNotIn("TR-sensitive-id", content)

    def test_cost_summary_excludes_nonbillable_local_modes(self):
        records = [
            {"request_count": 0, "input_tokens": 1000, "output_tokens": 500},
            {"request_count": 1, "input_tokens": 200, "output_tokens": 100},
        ]
        result = summarize(records, 0.30, 2.50)
        self.assertEqual(result["input_tokens"], 200)
        self.assertEqual(result["output_tokens"], 100)
        self.assertEqual(result["billable_requests"], 1)
        self.assertEqual(result["nonbillable_records"], 1)


if __name__ == "__main__":
    unittest.main()
