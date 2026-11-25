"""Risk scoring support for mcp-audit."""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mcp_audit.models import Finding


WEIGHTS: dict[str, int] = {
    "CRITICAL": 40,
    "HIGH": 25,
    "MEDIUM": 10,
    "LOW": 3,
    "INFO": 0,
}


def score_findings(findings: list["Finding"]) -> int:
    """Score unique rule/tool findings and cap the result at 100."""
    seen: set[tuple[str, str]] = set()
    total = 0.0

    for finding in findings:
        key = (finding.rule_id, finding.tool_name)
        if key in seen:
            continue
        seen.add(key)
        severity = finding.severity.name
        total += WEIGHTS.get(severity, 0) * finding.confidence

    return min(100, round(total))


def verdict(score: int) -> str:
    """Return the verdict associated with a numeric score."""
    if score < 10:
        return "PASS"
    if score < 50:
        return "REVIEW"
    return "FAIL"
