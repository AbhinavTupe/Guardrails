from __future__ import annotations

import json
import shlex
import sys
from dataclasses import dataclass
from pathlib import Path

from mcp_audit.cli import run_scan
from mcp_audit.models import Finding, ScanResult, Severity
from mcp_audit.rules import get_rule_category

ROOT = Path(__file__).resolve().parents[1]
TESTBED_DIR = ROOT / "testbed"
EXPECTED_PATH = TESTBED_DIR / "expected.json"
ADVERSARIAL_EXPECTED_PATH = TESTBED_DIR / "expected_adversarial.json"
UNSEEN_EXPECTED_PATH = TESTBED_DIR / "expected_unseen.json"
REPORT_PATH = ROOT / "docs" / "evaluation.md"
MINIMUM_SEVERITY = Severity.MEDIUM
REPORTED_CATEGORIES = {
    "file_write_delete",
    "poisoned_description",
    "shell_exec",
    "unrestricted_path",
}
V0_ADVERSARIAL_TABLE = [
    "| Category | TP | FP | FN | Precision | Recall |",
    "|---|---:|---:|---:|---:|---:|",
    "| file_write_delete | 0 | 1 | 0 | 0.000 | 0.000 |",
    "| poisoned_description | 1 | 0 | 3 | 1.000 | 0.250 |",
    "| shell_exec | 0 | 0 | 1 | 0.000 | 0.000 |",
    "| unrestricted_path | 0 | 0 | 1 | 0.000 | 0.000 |",
    "| **Overall** | **1** | **1** | **5** | **0.500** | **0.167** |",
]


@dataclass(frozen=True)
class CategoryMetrics:
    tp: int
    fp: int
    fn: int
    precision: float
    recall: float


@dataclass(frozen=True)
class ServerEvaluation:
    name: str
    static_categories: set[str]
    probe_categories: set[str]
    static_rule_ids: set[str]
    probe_rule_ids: set[str]


def calculate_precision_recall(tp: int, fp: int, fn: int) -> tuple[float, float]:
    """Calculate precision and recall, returning zero for undefined denominators."""
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return precision, recall


def calculate_metrics(tp: int, fp: int, fn: int) -> CategoryMetrics:
    precision, recall = calculate_precision_recall(tp, fp, fn)
    return CategoryMetrics(
        tp=tp,
        fp=fp,
        fn=fn,
        precision=precision,
        recall=recall,
    )


def finding_categories(findings: list[Finding]) -> set[str]:
    ranks = {
        Severity.INFO: 1,
        Severity.LOW: 2,
        Severity.MEDIUM: 3,
        Severity.HIGH: 4,
        Severity.CRITICAL: 5,
    }
    return {
        get_rule_category(finding.rule_id)
        for finding in findings
        if ranks[finding.severity] >= ranks[MINIMUM_SEVERITY]
    }


def finding_rule_ids(findings: list[Finding]) -> set[str]:
    ranks = {
        Severity.INFO: 1,
        Severity.LOW: 2,
        Severity.MEDIUM: 3,
        Severity.HIGH: 4,
        Severity.CRITICAL: 5,
    }
    return {
        finding.rule_id
        for finding in findings
        if ranks[finding.severity] >= ranks[MINIMUM_SEVERITY]
    }


def evaluate_server(server_file: str) -> ServerEvaluation:
    command = shlex.join([sys.executable, str(TESTBED_DIR / server_file)])
    static_result: ScanResult = run_scan(command, probe=False)
    probe_result: ScanResult = run_scan(command, probe=True)
    static_categories = finding_categories(static_result.findings)
    probe_categories = finding_categories(probe_result.findings)
    static_rule_ids = finding_rule_ids(static_result.findings)
    probe_rule_ids = finding_rule_ids(probe_result.findings)
    return ServerEvaluation(
        name=server_file,
        static_categories=static_categories,
        probe_categories=probe_categories,
        static_rule_ids=static_rule_ids,
        probe_rule_ids=probe_rule_ids,
    )


def calculate_category_metrics(
    expected_by_server: dict[str, set[str]],
    actual_by_server: dict[str, set[str]],
) -> dict[str, CategoryMetrics]:
    categories = sorted(
        REPORTED_CATEGORIES
        | (
            set().union(*expected_by_server.values(), *actual_by_server.values())
            if expected_by_server or actual_by_server
            else set()
        )
    )
    metrics: dict[str, CategoryMetrics] = {}
    for category in categories:
        tp = sum(
            category in expected_by_server.get(server, set())
            and category in actual_by_server.get(server, set())
            for server in set(expected_by_server) | set(actual_by_server)
        )
        fp = sum(
            category not in expected_by_server.get(server, set())
            and category in actual_by_server.get(server, set())
            for server in set(expected_by_server) | set(actual_by_server)
        )
        fn = sum(
            category in expected_by_server.get(server, set())
            and category not in actual_by_server.get(server, set())
            for server in set(expected_by_server) | set(actual_by_server)
        )
        metrics[category] = calculate_metrics(tp, fp, fn)
    return metrics


def overall_metrics(metrics: dict[str, CategoryMetrics]) -> CategoryMetrics:
    tp = sum(item.tp for item in metrics.values())
    fp = sum(item.fp for item in metrics.values())
    fn = sum(item.fn for item in metrics.values())
    return calculate_metrics(tp, fp, fn)


def build_known_misses(
    expected_path: Path,
    evaluations: dict[str, ServerEvaluation],
) -> list[str]:
    """List category misses and false alarms without modifying detection rules."""
    expected_data = json.loads(expected_path.read_text(encoding="utf-8"))
    if not isinstance(expected_data, dict):
        raise ValueError(f"{expected_path} must contain an object")

    wrong_cases: list[str] = []
    for server, value in expected_data.items():
        if not isinstance(value, dict) or not isinstance(value.get("categories"), list):
            continue
        expected = set(value["categories"])
        evaluation = evaluations[server]
        actual = evaluation.static_categories | evaluation.probe_categories
        rule_ids = evaluation.static_rule_ids | evaluation.probe_rule_ids
        missed = sorted(expected - actual)
        false = sorted(actual - expected)
        if missed:
            wrong_cases.append(
                f"- `{server}`: missed {', '.join(missed)} "
                f"(no qualifying rule fired; observed rule IDs: "
                f"{', '.join(sorted(rule_ids)) or 'none'})"
            )
        if false:
            wrong_cases.append(
                f"- `{server}`: false alarm for {', '.join(false)} "
                f"(rule IDs: {', '.join(sorted(rule_ids))})"
            )
    return wrong_cases


def build_evaluation_markdown(
    metrics: dict[str, CategoryMetrics],
    adversarial_metrics: dict[str, CategoryMetrics] | None = None,
    unseen_metrics: dict[str, CategoryMetrics] | None = None,
    unseen_evaluations: dict[str, ServerEvaluation] | None = None,
) -> str:
    def table(title: str, category_metrics: dict[str, CategoryMetrics]) -> list[str]:
        lines = [
            f"## {title}",
            "",
            "| Category | TP | FP | FN | Precision | Recall |",
            "|---|---:|---:|---:|---:|---:|",
        ]
        for category in sorted(category_metrics):
            item = category_metrics[category]
            lines.append(
                f"| {category} | {item.tp} | {item.fp} | {item.fn} | "
                f"{item.precision:.3f} | {item.recall:.3f} |"
            )
        overall = overall_metrics(category_metrics)
        lines.extend(
            [
                (
                    f"| **Overall** | **{overall.tp}** | **{overall.fp}** | "
                    f"**{overall.fn}** | **{overall.precision:.3f}** | "
                    f"**{overall.recall:.3f}** |"
                ),
                "",
            ]
        )
        return lines

    lines = ["# Testbed Evaluation", ""]
    lines.extend(table("Core Testbed", metrics))
    if adversarial_metrics is not None:
        lines.extend(
            [
                "## Adversarial Testbed — v0 (before fixes)",
                "",
                *V0_ADVERSARIAL_TABLE,
                "",
            ]
        )
        lines.extend(table("Adversarial Testbed — v1 (old cases)", adversarial_metrics))
    if unseen_metrics is not None:
        lines.extend(table("New Unseen Adversarial Testbed — v1", unseen_metrics))
    if unseen_evaluations is not None:
        unseen_expected = json.loads(UNSEEN_EXPECTED_PATH.read_text(encoding="utf-8"))
        lines.extend(
            [
                "### New unseen case outcomes",
                "",
                "| Server | Ground truth | Detected | Result |",
                "|---|---|---|---|",
            ]
        )
        for server, evaluation in sorted(unseen_evaluations.items()):
            expected = set(unseen_expected[server]["categories"])
            actual = evaluation.static_categories | evaluation.probe_categories
            lines.append(
                f"| `{server}` | {', '.join(sorted(expected)) or 'none'} | "
                f"{', '.join(sorted(actual)) or 'none'} | "
                f"{'PASS' if expected == actual else 'MISMATCH'} |"
            )
        lines.append("")
    lines.extend(
        [
            "## Version note",
            "",
            "The v1 fixes were made after seeing the v0 adversarial cases; v0 is "
            "retained as the pre-fix baseline. Unseen-case ground truth was recorded "
            "before the new servers were evaluated.",
            "",
            "## Severity Threshold",
            "",
            "Only findings with severity `MEDIUM`, `HIGH`, or `CRITICAL` are counted.",
            "",
            "## Method",
            "",
            "For each file in `testbed/expected.json`, "
            "`testbed/expected_adversarial.json`, and `testbed/expected_unseen.json`, "
            "mcp-audit launches each server and applies the same static rule path "
            "used by the CLI, then runs the CLI probe path with `--probe`. Finding "
            "rule IDs are mapped to the existing categories, plus category presence "
            "is evaluated per server.",
            "",
            "TP means a category is both expected and detected, FP means it is "
            "detected but not expected, and FN means it is expected but not detected.",
            "",
            "## Known misses and false alarms",
            "",
            "No known misses or false alarms.",
            "",
            "## Limitations",
            "",
            "- This is a tiny local testbed, not a representative benchmark.",
            "- Results are category-level presence checks and do not measure "
            "individual finding accuracy or severity calibration.",
            "- Probes are intentionally bounded and should only be enabled for local servers.",
            "",
            "## Future work",
            "",
            "- Paraphrase detection is not implemented; reliable detection requires an LLM.",
        ]
    )
    return "\n".join(lines) + "\n"


def evaluate_testbed(
    expected_path: Path = EXPECTED_PATH,
) -> tuple[dict[str, CategoryMetrics], dict[str, ServerEvaluation]]:
    expected_data = json.loads(expected_path.read_text(encoding="utf-8"))
    if not isinstance(expected_data, dict):
        raise ValueError("testbed/expected.json must contain an object")

    expected_by_server: dict[str, set[str]] = {}
    for server, value in expected_data.items():
        if isinstance(value, list):
            expected_by_server[server] = set(value)
        elif isinstance(value, dict) and isinstance(value.get("categories"), list):
            expected_by_server[server] = set(value["categories"])
    evaluations: dict[str, ServerEvaluation] = {}
    actual_by_server: dict[str, set[str]] = {}
    for server in expected_by_server:
        evaluation = evaluate_server(server)
        evaluations[server] = evaluation
        actual_by_server[server] = evaluation.static_categories | evaluation.probe_categories

    metrics = calculate_category_metrics(expected_by_server, actual_by_server)
    return metrics, evaluations


def main() -> int:
    metrics, core_evaluations = evaluate_testbed()
    adversarial_metrics, adversarial_evaluations = evaluate_testbed(ADVERSARIAL_EXPECTED_PATH)
    known_misses = build_known_misses(EXPECTED_PATH, core_evaluations)
    known_misses.extend(
        build_known_misses(
            ADVERSARIAL_EXPECTED_PATH,
            adversarial_evaluations,
        )
    )
    unseen_metrics, unseen_evaluations = evaluate_testbed(UNSEEN_EXPECTED_PATH)
    known_misses.extend(build_known_misses(UNSEEN_EXPECTED_PATH, unseen_evaluations))
    markdown = build_evaluation_markdown(
        metrics,
        adversarial_metrics,
        unseen_metrics,
        unseen_evaluations,
    )
    markdown = markdown.replace(
        "No known misses or false alarms.",
        "\n".join(known_misses) if known_misses else "No known misses or false alarms.",
    )
    REPORT_PATH.write_text(markdown, encoding="utf-8")
    print(f"Wrote evaluation to {REPORT_PATH.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
