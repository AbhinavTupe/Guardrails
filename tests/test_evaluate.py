from scripts.evaluate import (
    build_evaluation_markdown,
    calculate_category_metrics,
    calculate_metrics,
    calculate_precision_recall,
    overall_metrics,
)


def test_precision_recall_math() -> None:
    precision, recall = calculate_precision_recall(tp=8, fp=2, fn=4)

    assert precision == 0.8
    assert recall == 0.6666666666666666


def test_precision_recall_zero_denominator() -> None:
    assert calculate_precision_recall(tp=0, fp=0, fn=0) == (0.0, 0.0)
    assert calculate_precision_recall(tp=0, fp=3, fn=2) == (0.0, 0.0)


def test_category_and_overall_metrics() -> None:
    metrics = calculate_category_metrics(
        expected_by_server={
            "one": {"shell_exec", "file_write_delete"},
            "two": {"poisoned_description"},
        },
        actual_by_server={
            "one": {"shell_exec"},
            "two": {"poisoned_description", "network_access"},
        },
    )

    assert (metrics["shell_exec"].tp, metrics["shell_exec"].fp, metrics["shell_exec"].fn) == (
        1,
        0,
        0,
    )
    assert (
        metrics["file_write_delete"].tp,
        metrics["file_write_delete"].fp,
        metrics["file_write_delete"].fn,
    ) == (0, 0, 1)
    assert (
        metrics["network_access"].tp,
        metrics["network_access"].fp,
        metrics["network_access"].fn,
    ) == (0, 1, 0)

    overall = overall_metrics(metrics)
    assert (overall.tp, overall.fp, overall.fn) == (2, 1, 1)
    assert overall.precision == 2 / 3
    assert overall.recall == 2 / 3


def test_evaluation_markdown_has_required_sections_and_ascii_headings() -> None:
    core = calculate_category_metrics(
        expected_by_server={"clean_calc.py": set(), "vuln_shell.py": {"shell_exec"}},
        actual_by_server={"clean_calc.py": set(), "vuln_shell.py": {"shell_exec"}},
    )
    markdown = build_evaluation_markdown(core)

    assert "## Core" in markdown
    assert "## Adversarial v0 (before fixes)" in markdown
    assert "## Adversarial v1 snapshot" in markdown
    assert "## Current rules (v2)" in markdown
    assert "0.500 / 0.167" in markdown
    assert "1.000 / 0.833" in markdown
    assert "Reworded set: 2/2." in markdown
    assert "NOT held-out" in markdown
    assert "POI-004, CAP-001" in markdown
    assert "ground truth was written before evaluation" in markdown
    assert "\u2014" not in markdown


def test_evaluation_markdown_uses_na_for_empty_categories() -> None:
    markdown = build_evaluation_markdown(
        {"shell_exec": calculate_metrics(tp=0, fp=0, fn=0)}
    )

    assert "| shell_exec | 0 | 0 | 0 | n/a | n/a |" in markdown
