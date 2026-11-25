"""Keyword-based retrieval for curated MCP security patterns."""

import json
import math
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, TypedDict, cast

from mcp_audit.models import Finding
from mcp_audit.rules.registry import RULES

MIN_SCORE = 0.05


class Pattern(TypedDict):
    id: str
    title: str
    category: str
    keywords: list[str]
    why_it_matters: str
    how_attackers_use_it: str
    remediation: str
    rule_ids: list[str]
    source: str


@dataclass(frozen=True)
class Explanation:
    pattern_id: str
    title: str
    why_it_matters: str
    remediation: str


class Retriever(Protocol):
    def explain(self, finding: Finding) -> Explanation | None:
        """Return the best matching explanation for a finding, if available."""


def _tokens(text: str) -> list[str]:
    return re.findall(r"[a-z0-9]+", text.casefold())


class KeywordRetriever:
    """Rank curated patterns using TF-IDF cosine similarity and metadata boosts."""

    def __init__(self) -> None:
        path = Path(__file__).with_name("patterns.json")
        self._patterns = cast(list[Pattern], json.loads(path.read_text(encoding="utf-8")))
        documents = [
            " ".join(
                [
                    pattern["title"],
                    *pattern["keywords"],
                    pattern["why_it_matters"],
                ]
            )
            for pattern in self._patterns
        ]
        tokenized = [_tokens(document) for document in documents]
        document_frequency: Counter[str] = Counter()
        for document in tokenized:
            document_frequency.update(set(document))

        self._idf = {
            token: math.log((len(tokenized) + 1) / (frequency + 1)) + 1
            for token, frequency in document_frequency.items()
        }
        self._vectors = [self._vector(document) for document in tokenized]

    def _vector(self, tokens: list[str]) -> dict[str, float]:
        counts = Counter(tokens)
        return {
            token: (1 + math.log(count)) * self._idf[token]
            for token, count in counts.items()
            if token in self._idf
        }

    @staticmethod
    def _cosine(left: dict[str, float], right: dict[str, float]) -> float:
        left_norm = math.sqrt(sum(value * value for value in left.values()))
        right_norm = math.sqrt(sum(value * value for value in right.values()))
        if not left_norm or not right_norm:
            return 0.0
        dot = sum(value * right.get(token, 0.0) for token, value in left.items())
        return dot / (left_norm * right_norm)

    def explain(self, finding: Finding) -> Explanation | None:
        query = self._vector(_tokens(f"{finding.rule_id} {finding.evidence} {finding.fix}"))
        definition = RULES.get(finding.rule_id)
        category = definition.category if definition is not None else None
        best_pattern: Pattern | None = None
        best_score = 0.0

        for pattern, vector in zip(self._patterns, self._vectors, strict=True):
            score = self._cosine(query, vector)
            if finding.rule_id in pattern["rule_ids"]:
                score += 0.35
            if category is not None and category == pattern["category"]:
                score += 0.15
            if score > best_score:
                best_pattern = pattern
                best_score = score

        if best_pattern is None or best_score < MIN_SCORE:
            return None
        return Explanation(
            pattern_id=best_pattern["id"],
            title=best_pattern["title"],
            why_it_matters=best_pattern["why_it_matters"],
            remediation=best_pattern["remediation"],
        )
