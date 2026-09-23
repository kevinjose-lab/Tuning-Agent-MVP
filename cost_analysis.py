import argparse
import json
import os
from pathlib import Path

from dotenv import load_dotenv

from ai_usage import estimate_cost


BASE_DIR = Path(__file__).resolve().parent
DEFAULT_USAGE_FILE = BASE_DIR / "ai_usage.jsonl"
load_dotenv(BASE_DIR / ".env")


def load_records(path: Path) -> list[dict]:
    if not path.exists():
        return []
    records = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            records.append(json.loads(line))
    return records


def summarize(records: list[dict], input_rate: float, output_rate: float) -> dict:
    billable_records = [record for record in records if int(record.get("request_count", 0)) > 0]
    total_input = sum(int(record.get("input_tokens", 0)) for record in billable_records)
    total_output = sum(int(record.get("output_tokens", 0)) for record in billable_records)
    billable_requests = sum(int(record.get("request_count", 0)) for record in billable_records)
    blocked_requests = sum(bool(record.get("blocked_by_redaction")) for record in records)
    observed = max(1, billable_requests)
    average_input = round(total_input / observed)
    average_output = round(total_output / observed)

    projections = {}
    for volume in [100, 1000, 10000]:
        projections[str(volume)] = estimate_cost(
            average_input * volume,
            average_output * volume,
            input_rate,
            output_rate,
        )

    return {
        "records": len(records),
        "billable_requests": billable_requests,
        "nonbillable_records": len(records) - len(billable_records),
        "blocked_requests": blocked_requests,
        "input_tokens": total_input,
        "output_tokens": total_output,
        "average_input_tokens": average_input,
        "average_output_tokens": average_output,
        "estimated_observed_cost_usd": estimate_cost(
            total_input, total_output, input_rate, output_rate
        ),
        "projected_cost_usd": projections,
        "rates_usd_per_million_tokens": {
            "input": input_rate,
            "output": output_rate,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Summarize AI token use and projected cost.")
    parser.add_argument("--usage-file", type=Path, default=DEFAULT_USAGE_FILE)
    args = parser.parse_args()
    input_rate = float(os.getenv("AI_INPUT_COST_PER_MILLION_TOKENS", "0"))
    output_rate = float(os.getenv("AI_OUTPUT_COST_PER_MILLION_TOKENS", "0"))
    print(json.dumps(summarize(load_records(args.usage_file), input_rate, output_rate), indent=2))


if __name__ == "__main__":
    main()
