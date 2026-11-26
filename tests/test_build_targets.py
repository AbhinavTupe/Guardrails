from __future__ import annotations

import pytest

from scripts.build_targets import (
    EXCLUSION_TERMS,
    exclusion_reasons,
    filter_candidates,
    select_candidates,
)


@pytest.mark.parametrize("term", EXCLUSION_TERMS)
def test_exclusion_filter_is_case_insensitive_for_name_and_description(term: str) -> None:
    candidate: dict[str, object] = {"name": f"safe/{term.upper()}", "description": ""}

    assert exclusion_reasons(candidate) == [term]
    assert filter_candidates([candidate]) == ([], {term: 1}, 1)


def test_exclusion_filter_checks_description_and_preserves_safe_candidates() -> None:
    excluded: dict[str, object] = {
        "name": "safe/server",
        "description": "Offers COMPUTER USE tools",
    }
    safe: dict[str, object] = {"name": "safe/notes", "description": "Local notes"}

    kept, reasons, excluded_count = filter_candidates([excluded, safe])

    assert kept == [safe]
    assert reasons == {"computer use": 1}
    assert excluded_count == 1


def test_exclusion_filter_removes_local_testbeds() -> None:
    candidates: list[dict[str, object]] = [
        {"name": "vuln_shell"},
        {"name": "safe/server"},
    ]

    kept, reasons, excluded_count = filter_candidates(candidates)

    assert [candidate["name"] for candidate in kept] == ["safe/server"]
    assert reasons == {"testbed": 1}
    assert excluded_count == 1


def test_selection_caps_publishers_and_keeps_top_25_ranked_candidates() -> None:
    candidates: list[dict[str, object]] = [
        {"name": "a/1", "publisher": "a", "downloads": 100},
        {"name": "a/2", "publisher": "a", "downloads": 90},
        {"name": "a/3", "publisher": "a", "downloads": 80},
    ]
    candidates.extend(
        {"name": f"publisher-{index}/server", "publisher": f"publisher-{index}"}
        for index in range(30)
    )

    selected = select_candidates(candidates)

    assert len(selected) == 25
    assert [candidate["name"] for candidate in selected[:3]] == [
        "a/1",
        "a/2",
        "publisher-0/server",
    ]
