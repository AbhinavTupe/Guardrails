"""Shared description scanning helpers for poisoned-description rules."""

from collections.abc import Iterable

INVISIBLE_AND_BIDI = (
    "\u200b",
    "\u200c",
    "\u200d",
    "\u2060",
    "\ufeff",
    "\u202a",
    "\u202b",
    "\u202c",
    "\u202d",
    "\u202e",
    "\u2066",
    "\u2067",
    "\u2068",
    "\u2069",
)


def description_texts(tool_name_description: str, input_schema: object) -> list[str]:
    descriptions = [tool_name_description]

    def visit(value: object) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                if key == "description" and isinstance(child, str):
                    descriptions.append(child)
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)
        elif isinstance(value, tuple):
            for child in value:
                visit(child)

    visit(input_schema)
    return descriptions


def merge_ranges(ranges: Iterable[tuple[int, int]]) -> list[tuple[int, int]]:
    ordered = sorted((start, end) for start, end in ranges if end > start)
    merged: list[tuple[int, int]] = []
    for start, end in ordered:
        if not merged or start > merged[-1][1]:
            merged.append((start, end))
        else:
            previous_start, previous_end = merged[-1]
            merged[-1] = (previous_start, max(previous_end, end))
    return merged


def merge_match_contexts(
    text: str,
    ranges: Iterable[tuple[int, int]],
) -> list[tuple[int, int]]:
    ordered = sorted((start, end) for start, end in ranges if end > start)
    clusters: list[tuple[int, int]] = []
    for start, end in ordered:
        if not clusters:
            clusters.append((start, end))
            continue

        cluster_start, cluster_end = clusters[-1]
        current_context = _context_bounds(text, cluster_start, cluster_end)
        next_context = _context_bounds(text, start, end)
        combined_context = _context_bounds(
            text,
            min(cluster_start, start),
            max(cluster_end, end),
        )
        contexts_overlap = next_context[0] <= current_context[1]
        if contexts_overlap and combined_context[1] - combined_context[0] <= 100:
            clusters[-1] = (min(cluster_start, start), max(cluster_end, end))
        else:
            clusters.append((start, end))
    return clusters


def escape_evidence(text: str) -> str:
    escaped: list[str] = []
    for char in text:
        if char == "\n":
            escaped.append("\\n")
        elif char == "\t":
            escaped.append("\\t")
        elif char in INVISIBLE_AND_BIDI:
            escaped.append(f"\\u{ord(char):04X}")
        else:
            escaped.append(char)
    return "".join(escaped)


def evidence_for_range(text: str, start: int, end: int) -> str:
    context_start, context_end = _context_bounds(text, start, end)
    return escape_evidence(text[context_start:context_end])


def _context_bounds(text: str, start: int, end: int) -> tuple[int, int]:
    context_start = max(0, start - 30)
    context_end = min(len(text), end + 30)
    if context_start > 0:
        for position in range(context_start - 1, -1, -1):
            if text[position].isspace():
                context_start = position + 1
                break

    if context_end < len(text):
        for position in range(end, context_end):
            if text[position].isspace():
                context_end = position
                break

    return context_start, context_end
