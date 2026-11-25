"""Data models for mcp-audit."""

import json
from dataclasses import asdict, dataclass, field
from enum import Enum


class Severity(Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class ToolInfo:
    name: str
    description: str
    input_schema: dict[str, object]


@dataclass
class ServerInfo:
    tools: list[ToolInfo]
    resources: list[str]
    prompts: list[str]


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: Severity
    confidence: float
    tool_name: str
    evidence: str
    fix: str

    def __post_init__(self) -> None:
        if not self.evidence.strip():
            raise ValueError("evidence must not be empty")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1")


@dataclass
class ScanResult:
    server_command: str
    tools: list[ToolInfo] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    score: int = 0

    @property
    def verdict(self) -> str:
        from mcp_audit.scoring import verdict

        return verdict(self.score)

    @property
    def severity_counts(self) -> dict[str, int]:
        counts = {severity.value: 0 for severity in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    def to_dict(self) -> dict[str, object]:
        data = asdict(self)
        data["findings"] = [
            {
                **finding,
                "severity": finding["severity"].name,
            }
            for finding in data["findings"]
        ]
        from mcp_audit.kb.retriever import KeywordRetriever

        retriever = KeywordRetriever()
        data["explanations"] = [
            {
                "rule_id": finding.rule_id,
                "tool_name": finding.tool_name,
                "pattern_id": explanation.pattern_id,
                "title": explanation.title,
                "why_it_matters": explanation.why_it_matters,
                "remediation": explanation.remediation,
            }
            for finding in self.findings
            if (explanation := retriever.explain(finding)) is not None
        ]
        data["verdict"] = self.verdict
        data["severity_counts"] = self.severity_counts
        return data

    def to_json(self) -> str:
        return json.dumps(self.to_dict())
