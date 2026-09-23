import unittest

import approval_bot
from feedback_interpreter import interpret_feedback


class ApprovalParsingTests(unittest.TestCase):
    def test_parse_approve_with_backticks_and_notes(self):
        self.assertEqual(
            approval_bot.parse_decision_message("APPROVE `TR-123` narrow and validated"),
            ("APPROVE", "TR-123", "narrow and validated"),
        )

    def test_reject_invalid_command(self):
        self.assertEqual(approval_bot.parse_decision_message("SHIP TR-123"), ("", "", ""))

    def test_find_recommendation_by_embedded_id(self):
        state = {"cluster-key": {"recommendation_id": "TR-ABC", "status": "Pending Approval"}}
        key, rec = approval_bot.find_recommendation(state, "tr-abc")
        self.assertEqual(key, "cluster-key")
        self.assertEqual(rec["status"], "Pending Approval")

    def test_rejected_ioc_feedback_stays_scoped(self):
        result = interpret_feedback("REJECT", {"alert_bucket": "ioc"}, "not allowlisted")
        self.assertEqual(result["behavior_change_type"], "avoid_pattern")
        self.assertIn("indicator allowlisted", result["required_future_constraints"])


if __name__ == "__main__":
    unittest.main()
