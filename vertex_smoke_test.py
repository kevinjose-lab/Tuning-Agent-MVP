import argparse
import json
import os
from pathlib import Path

from dotenv import load_dotenv

from ai_pipeline import get_provider, run_ai_pipeline
from ai_schema import AIAnalysisRequest


BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")


def synthetic_request() -> AIAnalysisRequest:
    return AIAnalysisRequest(
        schema_version="1.0",
        alert_bucket="endpoint_process",
        occurrence_count=5,
        lookback_days=14,
        same_rule=True,
        same_host=True,
        same_indicator=True,
        disposition="false_positive_or_duplicate",
        context_flags=["approved_software", "expected_parent_process"],
        risk_flags=[],
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Validate the Vertex boundary using identifier-free synthetic data."
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Perform one billable Vertex AI request. Without this flag, no network call occurs.",
    )
    parser.add_argument(
        "--show-payload",
        action="store_true",
        help="Print the exact post-redaction JSON payload. Never prints a redaction mapping.",
    )
    args = parser.parse_args()

    mode = "vertex" if args.live else "redaction-only"
    provider = get_provider(
        mode,
        project=os.getenv("GOOGLE_CLOUD_PROJECT", ""),
        location=os.getenv("GOOGLE_CLOUD_LOCATION", ""),
        model=os.getenv("AI_MODEL", ""),
        max_output_tokens=int(os.getenv("AI_MAX_OUTPUT_TOKENS", "500")),
    )
    result = run_ai_pipeline(
        synthetic_request(),
        provider,
        max_input_tokens=int(os.getenv("AI_MAX_INPUT_TOKENS", "1000")),
        max_output_tokens=int(os.getenv("AI_MAX_OUTPUT_TOKENS", "500")),
    )

    print("Mode:", mode)
    print("Outbound fields:", ", ".join(sorted(result.outbound_payload)))
    if args.show_payload:
        print("Exact post-redaction payload:")
        print(json.dumps(result.outbound_payload, indent=2, sort_keys=True))
    print("Leak findings:", result.blocked_categories)
    print("Decision:", result.analysis.decision)
    print("Provider:", result.analysis.provider)
    print("Model:", result.analysis.model)
    print("Input tokens:", result.analysis.input_tokens)
    print("Output tokens:", result.analysis.output_tokens)
    print("Safety notes:", result.analysis.safety_notes)

    if args.live and "failed closed" in result.analysis.safety_notes.lower():
        raise SystemExit(1)


if __name__ == "__main__":
    main()
