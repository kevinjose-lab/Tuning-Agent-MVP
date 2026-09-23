import datetime as dt
import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class UsageRecord:
    timestamp: str
    provider: str
    model: str
    recommendation_id_hash: str
    input_tokens: int
    output_tokens: int
    request_count: int
    blocked_by_redaction: bool
    blocked_categories: list[str]
    estimated_cost_usd: float


def estimate_cost(
    input_tokens: int,
    output_tokens: int,
    input_cost_per_million: float,
    output_cost_per_million: float,
) -> float:
    return round(
        input_tokens / 1_000_000 * input_cost_per_million
        + output_tokens / 1_000_000 * output_cost_per_million,
        10,
    )


def write_usage_record(
    path: Path,
    recommendation_id: str,
    provider: str,
    model: str,
    input_tokens: int,
    output_tokens: int,
    input_cost_per_million: float,
    output_cost_per_million: float,
    blocked_categories: list[str] | None = None,
) -> UsageRecord:
    categories = sorted(set(blocked_categories or []))
    record = UsageRecord(
        timestamp=dt.datetime.now(dt.UTC).isoformat(),
        provider=provider,
        model=model,
        recommendation_id_hash=hashlib.sha256(recommendation_id.encode()).hexdigest(),
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        request_count=0 if categories else int(provider not in {"disabled", "redaction-only", "mock"}),
        blocked_by_redaction=bool(categories),
        blocked_categories=categories,
        estimated_cost_usd=estimate_cost(
            input_tokens,
            output_tokens,
            input_cost_per_million,
            output_cost_per_million,
        ),
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(asdict(record), sort_keys=True) + "\n")
    return record
