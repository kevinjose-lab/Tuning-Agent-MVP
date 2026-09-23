from dataclasses import asdict, dataclass, field


ALLOWED_DECISIONS = {"APPROVE", "REVIEW", "REJECT"}
ALLOWED_CONTEXT_FLAGS = {
    "approved_software",
    "consistent_execution_pattern",
    "expected_parent_process",
    "known_benign_indicator",
    "signed_binary",
}
ALLOWED_RISK_FLAGS = {
    "encoded_command",
    "external_source_present",
    "malicious_indicator",
    "office_child_process",
    "privileged_activity",
    "sensitive_cloud_action",
    "unknown_context",
}


@dataclass(frozen=True)
class AIAnalysisRequest:
    schema_version: str
    alert_bucket: str
    occurrence_count: int
    lookback_days: int
    same_rule: bool
    same_host: bool
    same_indicator: bool
    disposition: str
    context_flags: list[str] = field(default_factory=list)
    risk_flags: list[str] = field(default_factory=list)

    def validate(self) -> None:
        if self.schema_version != "1.0":
            raise ValueError("Unsupported AI request schema version.")
        if not self.alert_bucket or not self.alert_bucket.replace("_", "").isalnum():
            raise ValueError("Invalid alert bucket.")
        if self.occurrence_count < 0 or self.lookback_days < 0:
            raise ValueError("Counts cannot be negative.")
        if self.disposition != "false_positive_or_duplicate":
            raise ValueError("Unsupported disposition.")
        if not set(self.context_flags).issubset(ALLOWED_CONTEXT_FLAGS):
            raise ValueError("Request contains an unsupported context flag.")
        if not set(self.risk_flags).issubset(ALLOWED_RISK_FLAGS):
            raise ValueError("Request contains an unsupported risk flag.")

    def to_dict(self) -> dict:
        self.validate()
        return asdict(self)


@dataclass(frozen=True)
class AIAnalysisResult:
    decision: str
    rationale: str
    risk: str
    validation_steps: list[str]
    provider: str
    model: str
    input_tokens: int = 0
    output_tokens: int = 0
    safety_notes: str = ""

    def validate(self) -> None:
        if self.decision not in ALLOWED_DECISIONS:
            raise ValueError("AI result contains an unsupported decision.")
        if len(self.rationale) > 1000 or len(self.risk) > 1000:
            raise ValueError("AI result text exceeds the allowed length.")
        if len(self.validation_steps) > 10:
            raise ValueError("AI result contains too many validation steps.")
        if any(not isinstance(step, str) or len(step) > 500 for step in self.validation_steps):
            raise ValueError("AI result contains an invalid validation step.")

    def to_dict(self) -> dict:
        self.validate()
        return asdict(self)
