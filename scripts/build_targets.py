from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INPUT_PATH = ROOT / "docs" / "targets.candidates.json"
OUTPUT_PATH = ROOT / "docs" / "targets.json"
MAX_CANDIDATES = 25
MAX_PER_PUBLISHER = 2
EXCLUSION_TERMS = (
    "wallet",
    "crypto",
    "trading",
    "trade",
    "payment",
    "stripe",
    "billing",
    "token",
    "nomd",
    "computer use",
    "desktop control",
    "browser control",
)
TESTBED_NAMES = frozenset({"vuln_files", "vuln_poisoned", "vuln_shell"})
OFFICIAL_SOURCE_URL = "https://github.com/modelcontextprotocol/servers"
INSTALL_NOTE = "Installed on first launch by the pinned command."
OFFICIAL_TARGETS: tuple[dict[str, object], ...] = (
    {
        "name": "memory",
        "command": "npx -y @modelcontextprotocol/server-memory@2.2.1",
        "source_url": OFFICIAL_SOURCE_URL,
        "version": "2.2.1",
        "install_note": INSTALL_NOTE,
    },
    {
        "name": "filesystem",
        "command": "npx -y @modelcontextprotocol/server-filesystem@2.4.0 ./sandbox-empty",
        "source_url": OFFICIAL_SOURCE_URL,
        "version": "2.4.0",
        "install_note": INSTALL_NOTE,
    },
    {
        "name": "git",
        "command": "uvx mcp-server-git==2026.11.18",
        "source_url": OFFICIAL_SOURCE_URL,
        "version": "2026.11.18",
        "install_note": INSTALL_NOTE,
    },
    {
        "name": "fetch",
        "command": "uvx mcp-server-fetch==2026.11.18",
        "source_url": OFFICIAL_SOURCE_URL,
        "version": "2026.11.18",
        "install_note": INSTALL_NOTE,
    },
    {
        "name": "time",
        "command": "uvx mcp-server-time==2026.11.18",
        "source_url": OFFICIAL_SOURCE_URL,
        "version": "2026.11.18",
        "install_note": INSTALL_NOTE,
    },
)


def exclusion_reasons(candidate: dict[str, object]) -> list[str]:
    name = candidate.get("name")
    description = candidate.get("description")
    searchable_text = " ".join(
        value for value in (name, description) if isinstance(value, str)
    ).casefold()
    reasons = [term for term in EXCLUSION_TERMS if term in searchable_text]
    if isinstance(name, str) and name.casefold() in TESTBED_NAMES:
        reasons.append("testbed")
    return reasons


def filter_candidates(
    candidates: list[dict[str, object]],
) -> tuple[list[dict[str, object]], Counter[str], int]:
    kept: list[dict[str, object]] = []
    excluded_reasons: Counter[str] = Counter()
    excluded_count = 0
    for candidate in candidates:
        reasons = exclusion_reasons(candidate)
        if reasons:
            excluded_count += 1
            excluded_reasons.update(reasons)
        else:
            kept.append(candidate)
    return kept, excluded_reasons, excluded_count


def select_candidates(candidates: list[dict[str, object]]) -> list[dict[str, object]]:
    selected: list[dict[str, object]] = []
    publisher_counts: Counter[str] = Counter()
    for candidate in candidates:
        publisher = candidate.get("publisher")
        if not isinstance(publisher, str):
            continue
        if publisher_counts[publisher] >= MAX_PER_PUBLISHER:
            continue
        selected.append({**candidate, "install_note": INSTALL_NOTE})
        publisher_counts[publisher] += 1
        if len(selected) == MAX_CANDIDATES:
            break
    return selected


def load_candidates(path: Path = INPUT_PATH) -> list[dict[str, object]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("Candidate input must contain a JSON array")
    candidates: list[dict[str, object]] = []
    for entry in data:
        if not isinstance(entry, dict):
            raise ValueError("Each candidate must be a JSON object")
        candidates.append({str(key): value for key, value in entry.items()})
    return candidates


def build_targets(candidates: list[dict[str, object]]) -> tuple[
    list[dict[str, object]], Counter[str], int
]:
    filtered, excluded_reasons, excluded_count = filter_candidates(candidates)
    return [*select_candidates(filtered), *OFFICIAL_TARGETS], excluded_reasons, excluded_count


def main() -> None:
    targets, excluded_reasons, excluded_count = build_targets(load_candidates())
    OUTPUT_PATH.write_text(json.dumps(targets, indent=2) + "\n", encoding="utf-8")
    reasons = ", ".join(
        f"{reason}: {count}" for reason, count in sorted(excluded_reasons.items())
    )
    print(f"Excluded {excluded_count} candidates by reason: {reasons or 'none'}")
    print(f"Wrote {len(targets)} targets to {OUTPUT_PATH.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
