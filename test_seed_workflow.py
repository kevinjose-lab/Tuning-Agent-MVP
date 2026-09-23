import unittest

from seed_workflow_test_cases import build_case_payload, normalize_run_id
from tuning_agent import build_cluster_key, case_matches_fp_or_duplicate


class WorkflowSeedTests(unittest.TestCase):
    def test_payload_qualifies_and_clusters_consistently(self):
        first = build_case_payload(1, "test-run")
        second = build_case_payload(2, "test-run")

        self.assertTrue(case_matches_fp_or_duplicate(first))
        self.assertEqual(build_cluster_key(first), build_cluster_key(second))
        self.assertIn("999910|tuning-workflow-test-test-run|path:", build_cluster_key(first))

    def test_different_runs_create_different_clusters(self):
        first = build_case_payload(1, "run-one")
        second = build_case_payload(1, "run-two")
        self.assertNotEqual(build_cluster_key(first), build_cluster_key(second))

    def test_run_id_is_sanitized(self):
        self.assertEqual(normalize_run_id(" Demo Run! "), "demo-run")


if __name__ == "__main__":
    unittest.main()
