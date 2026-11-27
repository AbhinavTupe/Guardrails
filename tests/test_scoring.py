import pytest

from mcp_audit.models import Finding, Severity
from mcp_audit.scoring import score_findings, verdict


def finding(
    *,
    rule_id: str = "RULE-1",
    severity: Severity = Severity.HIGH,
    confidence: float = 1.0,
    tool_name: str = "tool",
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        confidence=confidence,
        tool_name=tool_name,
        evidence="Concrete evidence",
        fix="Apply the fix",
    )


def test_empty_findings_score_zero_and_pass() -> None:
    assert score_findings([]) == 0
    assert verdict(0) == "PASS"


def test_high_finding_confidence_point_nine_scores_twenty_two() -> None:
    assert score_findings([finding(confidence=0.9)]) == 22


def test_additional_findings_for_same_rule_have_diminishing_weight() -> None:
    assert score_findings([finding(), finding(tool_name="other")]) == 31


def test_same_rule_score_is_capped_at_twice_its_weight() -> None:
    assert score_findings([finding() for _ in range(10)]) == 50


def test_score_is_capped_at_one_hundred() -> None:
    findings = [
        finding(rule_id=f"RULE-{index}", severity=Severity.CRITICAL)
        for index in range(4)
    ]
    assert score_findings(findings) == 100


@pytest.mark.parametrize(
    ("score", "expected"),
    [(9, "PASS"), (10, "REVIEW"), (49, "REVIEW"), (50, "FAIL"), (100, "FAIL")],
)
def test_verdict_thresholds(score: int, expected: str) -> None:
    assert verdict(score) == expected
