import json
import unittest
from types import SimpleNamespace

from ai_pipeline import get_provider
from ai_schema import AIAnalysisRequest
from providers.vertex_ai_provider import VertexAIProvider


class FakeModels:
    def __init__(self, response=None, error=None):
        self.response = response
        self.error = error
        self.calls = []

    def generate_content(self, **kwargs):
        self.calls.append(kwargs)
        if self.error:
            raise self.error
        return self.response


class FakeClient:
    def __init__(self, response=None, error=None):
        self.models = FakeModels(response=response, error=error)


def request():
    return AIAnalysisRequest(
        schema_version="1.0",
        alert_bucket="endpoint_process",
        occurrence_count=5,
        lookback_days=14,
        same_rule=True,
        same_host=True,
        same_indicator=True,
        disposition="false_positive_or_duplicate",
        context_flags=["approved_software"],
        risk_flags=[],
    )


class VertexProviderTests(unittest.TestCase):
    def test_schema_constrained_request_and_token_usage(self):
        response = SimpleNamespace(
            text=json.dumps(
                {
                    "decision": "REVIEW",
                    "rationale": "Abstract pattern is consistent.",
                    "risk": "Approval context requires local validation.",
                    "validation_steps": ["Confirm approved software inventory."],
                }
            ),
            usage_metadata=SimpleNamespace(
                prompt_token_count=91,
                candidates_token_count=37,
            ),
            parsed={
                "decision": "REVIEW",
                "rationale": "Abstract pattern is consistent.",
                "risk": "Approval context requires local validation.",
                "validation_steps": ["Confirm approved software inventory."],
            },
        )
        client = FakeClient(response=response)
        provider = VertexAIProvider("project", "us-central1", "gemini-test", client=client)

        result = provider.analyze(request())

        self.assertEqual(result.input_tokens, 91)
        self.assertEqual(result.output_tokens, 37)
        call = client.models.calls[0]
        self.assertEqual(call["config"]["response_mime_type"], "application/json")
        self.assertEqual(call["config"]["temperature"], 0)
        self.assertEqual(call["config"]["thinking_config"]["thinking_budget"], 0)
        self.assertNotIn("hostname", call["contents"])

    def test_provider_error_fails_closed_without_error_details(self):
        client = FakeClient(error=RuntimeError("secret-project-name"))
        provider = VertexAIProvider("project", "us-central1", "gemini-test", client=client)

        result = provider.analyze(request())

        self.assertEqual(result.decision, "REVIEW")
        self.assertNotIn("secret-project-name", result.safety_notes)
        self.assertIn("RuntimeError", result.safety_notes)

    def test_invalid_json_preserves_usage_counts(self):
        response = SimpleNamespace(
            text="",
            parsed=None,
            usage_metadata=SimpleNamespace(
                prompt_token_count=80,
                candidates_token_count=12,
            ),
        )
        provider = VertexAIProvider(
            "project", "us-central1", "gemini-test", client=FakeClient(response=response)
        )

        result = provider.analyze(request())

        self.assertEqual(result.decision, "REVIEW")
        self.assertEqual(result.input_tokens, 80)
        self.assertEqual(result.output_tokens, 12)

    def test_missing_vertex_configuration_is_rejected(self):
        with self.assertRaises(ValueError):
            get_provider("vertex", project="", location="", model="")


if __name__ == "__main__":
    unittest.main()
