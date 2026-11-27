import json
from pathlib import Path

from mcp_audit.models import ToolInfo
from mcp_audit.rules import load_all_rules, run_rules

ROOT = Path(__file__).resolve().parents[1]
CASE_PATH = ROOT / "testbed" / "regression" / "false_positives.json"
EXPECTED_PATH = ROOT / "testbed" / "expected_regression.json"


def test_benign_false_positive_regressions_have_no_findings() -> None:
    cases = json.loads(CASE_PATH.read_text(encoding="utf-8"))
    expected = json.loads(EXPECTED_PATH.read_text(encoding="utf-8"))
    assert set(cases) == set(expected)
    load_all_rules()

    for case_name, case in cases.items():
        assert expected[case_name] == []
        input_schema = case.get("input_schema", {})
        assert isinstance(input_schema, dict)
        tool = ToolInfo(
            name=str(case["name"]),
            description=str(case.get("description", "")),
            input_schema=input_schema,
        )
        assert run_rules([tool]) == [], case_name
