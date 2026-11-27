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
    """Score findings with diminishing returns per rule, capped at 100."""
    rule_counts: dict[str, int] = {}
    rule_weights: dict[str, float] = {}
    rule_scores: dict[str, float] = {}

    for finding in findings:
        severity_weight = WEIGHTS.get(finding.severity.name, 0)
        rule_weight = rule_weights.setdefault(finding.rule_id, float(severity_weight))
        count = rule_counts.get(finding.rule_id, 0)
        increment = rule_weight * (1.0 if count == 0 else 0.25) * finding.confidence
        rule_scores[finding.rule_id] = min(
            rule_weight * 2.0,
            rule_scores.get(finding.rule_id, 0.0) + increment,
        )
        rule_counts[finding.rule_id] = count + 1

    total = 0.0
    for score in rule_scores.values():
        total += score

    return min(100, round(total))


def verdict(score: int) -> str:
    """Return the verdict associated with a numeric score."""
    if score < 10:
        return "PASS"
    if score < 50:
        return "REVIEW"
    return "FAIL"
