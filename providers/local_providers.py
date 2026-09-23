import json

from ai_schema import AIAnalysisRequest, AIAnalysisResult


def _token_estimate(value: object) -> int:
    return max(1, round(len(json.dumps(value, sort_keys=True)) / 4))


class DisabledProvider:
    name = "disabled"
    model = "none"

    def analyze(self, request: AIAnalysisRequest) -> AIAnalysisResult:
        return AIAnalysisResult(
            decision="REVIEW",
            rationale="External AI analysis is disabled.",
            risk="A human analyst must assess this cluster.",
            validation_steps=["Review the locally collected evidence before any tuning decision."],
            provider=self.name,
            model=self.model,
            input_tokens=0,
            output_tokens=0,
            safety_notes="No provider request was performed.",
        )


class RedactionOnlyProvider:
    name = "redaction-only"
    model = "none"

    def analyze(self, request: AIAnalysisRequest) -> AIAnalysisResult:
        return AIAnalysisResult(
            decision="REVIEW",
            rationale="The minimal outbound payload passed local validation.",
            risk="No AI assessment was performed in redaction-only mode.",
            validation_steps=["Inspect the payload schema and local leakage-check result."],
            provider=self.name,
            model=self.model,
            input_tokens=_token_estimate(request.to_dict()),
            output_tokens=0,
            safety_notes="Validated locally; no provider request was performed.",
        )


class MockProvider:
    name = "mock"
    model = "mock-v1"

    def analyze(self, request: AIAnalysisRequest) -> AIAnalysisResult:
        risky = bool(request.risk_flags)
        result = AIAnalysisResult(
            decision="REVIEW",
            rationale=(
                "The abstract cluster is consistent, but deterministic mock mode cannot approve tuning."
            ),
            risk=(
                "Risk flags require analyst validation."
                if risky
                else "Benign context has not been independently validated."
            ),
            validation_steps=[
                "Confirm the activity is approved in the local source of truth.",
                "Test the proposed scope against representative events.",
                "Verify nearby suspicious variants remain detectable.",
            ],
            provider=self.name,
            model=self.model,
            input_tokens=_token_estimate(request.to_dict()),
            output_tokens=85,
            safety_notes="Deterministic test response; no external AI request was performed.",
        )
        result.validate()
        return result
