import json
from typing import Any

from ai_schema import AIAnalysisRequest, AIAnalysisResult


RESPONSE_SCHEMA = {
    "type": "OBJECT",
    "required": ["decision", "rationale", "risk", "validation_steps"],
    "properties": {
        "decision": {
            "type": "STRING",
            "enum": ["APPROVE", "REVIEW", "REJECT"],
        },
        "rationale": {"type": "STRING"},
        "risk": {"type": "STRING"},
        "validation_steps": {
            "type": "ARRAY",
            "minItems": 1,
            "maxItems": 5,
            "items": {"type": "STRING"},
        },
    },
}

SYSTEM_INSTRUCTION = """You are an advisory SOC detection-tuning reviewer.
You receive only abstract, de-identified features. Do not infer or invent identifiers.
Return an advisory decision, concise rationale, material risk, and validation steps.
Prefer REVIEW when context is unknown or any risk flag exists. Never create deployable
rules, suppression syntax, hostnames, usernames, IP addresses, paths, or case IDs.
Human approval is always required."""


class VertexAIProvider:
    name = "vertex-ai"

    def __init__(
        self,
        project: str,
        location: str,
        model: str,
        max_output_tokens: int = 500,
        client: Any | None = None,
    ) -> None:
        if not project or not location or not model:
            raise ValueError("Vertex AI requires project, location, and model configuration.")
        self.project = project
        self.location = location
        self.model = model
        self.max_output_tokens = max_output_tokens
        self._client = client

    def _get_client(self):
        if self._client is None:
            try:
                from google import genai
            except ImportError as exc:
                raise RuntimeError(
                    "The google-genai package is required for Vertex AI mode."
                ) from exc
            self._client = genai.Client(
                vertexai=True,
                project=self.project,
                location=self.location,
            )
        return self._client

    @staticmethod
    def _usage_counts(response: Any) -> tuple[int, int]:
        usage = getattr(response, "usage_metadata", None)
        if usage is None:
            return 0, 0
        input_tokens = int(getattr(usage, "prompt_token_count", 0) or 0)
        output_tokens = int(getattr(usage, "candidates_token_count", 0) or 0)
        return input_tokens, output_tokens

    def analyze(self, request: AIAnalysisRequest) -> AIAnalysisResult:
        request.validate()
        payload = json.dumps(request.to_dict(), sort_keys=True, separators=(",", ":"))
        response = None
        try:
            response = self._get_client().models.generate_content(
                model=self.model,
                contents=payload,
                config={
                    "system_instruction": SYSTEM_INSTRUCTION,
                    "temperature": 0,
                    "candidate_count": 1,
                    "max_output_tokens": self.max_output_tokens,
                    "thinking_config": {"thinking_budget": 0},
                    "response_mime_type": "application/json",
                    "response_schema": RESPONSE_SCHEMA,
                },
            )
            input_tokens, output_tokens = self._usage_counts(response)
            parsed = getattr(response, "parsed", None)
            if hasattr(parsed, "model_dump"):
                parsed = parsed.model_dump()
            if parsed is None:
                parsed = json.loads(response.text)
            elif isinstance(parsed, str):
                parsed = json.loads(parsed)
            if not isinstance(parsed, dict):
                raise ValueError("Vertex AI structured response was not an object.")
            result = AIAnalysisResult(
                decision=str(parsed["decision"]).upper(),
                rationale=str(parsed["rationale"]),
                risk=str(parsed["risk"]),
                validation_steps=list(parsed["validation_steps"]),
                provider=self.name,
                model=self.model,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                safety_notes="Vertex AI returned schema-constrained advisory output.",
            )
            result.validate()
            return result
        except Exception as exc:
            # Do not include exception text because authentication and transport
            # errors can contain project, account, or endpoint information.
            input_tokens, output_tokens = self._usage_counts(response)
            return AIAnalysisResult(
                decision="REVIEW",
                rationale="Vertex AI analysis was unavailable.",
                risk="No external AI assessment was accepted for this cluster.",
                validation_steps=["Review the cluster manually and check provider health locally."],
                provider=self.name,
                model=self.model,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                safety_notes=f"Vertex AI failed closed ({type(exc).__name__}).",
            )
