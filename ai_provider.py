from typing import Protocol

from ai_schema import AIAnalysisRequest, AIAnalysisResult


class AIProvider(Protocol):
    name: str
    model: str

    def analyze(self, request: AIAnalysisRequest) -> AIAnalysisResult:
        ...
