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

    def to_dict(self) -> dict[str, object]:
        data = asdict(self)
        data["findings"] = [
            {
                **finding,
                "severity": finding["severity"].name,
            }
            for finding in data["findings"]
        ]
        return data

    def to_json(self) -> str:
        return json.dumps(self.to_dict())
