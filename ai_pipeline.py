import json
import os
from dataclasses import dataclass

from ai_provider import AIProvider
from ai_schema import AIAnalysisRequest, AIAnalysisResult
from leakage_guard import detect_leaks
from providers import DisabledProvider, MockProvider, RedactionOnlyProvider, VertexAIProvider
from redactor import redact_value


@dataclass(frozen=True)
class PipelineResult:
    analysis: AIAnalysisResult
    outbound_payload: dict
    redaction_counts: dict[str, int]
    blocked_categories: list[str]


def get_provider(
    mode: str,
    project: str | None = None,
    location: str | None = None,
    model: str | None = None,
    max_output_tokens: int = 500,
) -> AIProvider:
    normalized = mode.strip().lower()
    providers = {
        "disabled": DisabledProvider,
        "mock": MockProvider,
        "redaction-only": RedactionOnlyProvider,
    }
    if normalized == "vertex":
        return VertexAIProvider(
            project=os.getenv("GOOGLE_CLOUD_PROJECT", "") if project is None else project,
            location=os.getenv("GOOGLE_CLOUD_LOCATION", "") if location is None else location,
            model=os.getenv("AI_MODEL", "") if model is None else model,
            max_output_tokens=max_output_tokens,
        )
    if normalized not in providers:
        raise ValueError(
            f"Unsupported AI_MODE {mode!r}. Use disabled, redaction-only, mock, or vertex."
        )
    return providers[normalized]()


def _blocked_result(categories: list[str]) -> AIAnalysisResult:
    return AIAnalysisResult(
        decision="REVIEW",
        rationale="The outbound AI payload was blocked by local leakage controls.",
        risk="Sensitive information may remain in the candidate payload.",
        validation_steps=["Review the local redaction rules before enabling an AI provider."],
        provider="blocked",
        model="none",
        safety_notes="Blocked categories: " + ", ".join(categories),
    )


def run_ai_pipeline(
    request: AIAnalysisRequest,
    provider: AIProvider,
    known_sensitive_values: list[str] | None = None,
    max_input_tokens: int = 1000,
    max_output_tokens: int = 500,
) -> PipelineResult:
    """Redact and inspect the exact serialized payload before provider dispatch."""
    request.validate()
    redaction = redact_value(request.to_dict())
    outbound_payload = redaction.value
    findings = detect_leaks(outbound_payload, known_sensitive_values)
    estimated_input_tokens = max(1, round(len(json.dumps(outbound_payload, sort_keys=True)) / 4))
    if estimated_input_tokens > max_input_tokens:
        findings = sorted(set(findings + ["INPUT_TOKEN_LIMIT"]))

    if findings:
        return PipelineResult(
            analysis=_blocked_result(findings),
            outbound_payload=outbound_payload,
            redaction_counts=redaction.counts,
            blocked_categories=findings,
        )

    # Reconstruct from the validated, redacted payload. This guarantees that the
    # provider sees exactly what the leakage guard inspected.
    outbound_request = AIAnalysisRequest(**json.loads(json.dumps(outbound_payload)))
    analysis = provider.analyze(outbound_request)
    analysis.validate()
    estimated_output_tokens = max(1, round(len(json.dumps(analysis.to_dict(), sort_keys=True)) / 4))
    if estimated_output_tokens > max_output_tokens:
        categories = ["OUTPUT_TOKEN_LIMIT"]
        return PipelineResult(
            analysis=_blocked_result(categories),
            outbound_payload=outbound_payload,
            redaction_counts=redaction.counts,
            blocked_categories=categories,
        )
    return PipelineResult(
        analysis=analysis,
        outbound_payload=outbound_payload,
        redaction_counts=redaction.counts,
        blocked_categories=[],
    )
