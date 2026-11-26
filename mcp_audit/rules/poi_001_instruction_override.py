"""Detect instruction-override prompts in MCP descriptions."""

import base64
import binascii
import re
import unicodedata

from mcp_audit.models import Finding, Severity, ToolInfo
from mcp_audit.rules._poi_common import (
    description_texts,
    escape_evidence,
)
from mcp_audit.rules.registry import register

PATTERN = re.compile(
    r"\b(?:ignore|disregard|bypass)\b.{0,40}\b(?:previous|prior|all|earlier)\b"
    r".{0,20}\b(?:instructions|rules)\b"
    r"|do\s+not\s+tell\s+(?:the\s+)?user"
    r"|don['’]t\s+mention\s+(?:this|it)",
    re.IGNORECASE,
)
BASE64_TOKEN = re.compile(r"(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{24,}={0,2})(?![A-Za-z0-9+/=])")
CONFUSABLES = str.maketrans(
    {
        "а": "a",
        "А": "A",
        "в": "b",
        "В": "B",
        "с": "c",
        "С": "C",
        "е": "e",
        "Е": "E",
        "н": "h",
        "Н": "H",
        "і": "i",
        "І": "I",
        "ї": "i",
        "Ї": "I",
        "к": "k",
        "К": "K",
        "м": "m",
        "М": "M",
        "о": "o",
        "О": "O",
        "р": "p",
        "Р": "P",
        "т": "t",
        "Т": "T",
        "х": "x",
        "Х": "X",
        "у": "y",
        "У": "Y",
        "Α": "A",
        "Β": "B",
        "Ε": "E",
        "Η": "H",
        "Ι": "I",
        "Κ": "K",
        "Μ": "M",
        "Ν": "N",
        "Ο": "O",
        "Ρ": "P",
        "Τ": "T",
        "Χ": "X",
        "Υ": "Y",
        "α": "a",
        "β": "b",
        "ε": "e",
        "ι": "i",
        "κ": "k",
        "ν": "v",
        "ο": "o",
        "ρ": "p",
        "τ": "t",
        "χ": "x",
        "υ": "y",
    }
)


def _normalize(text: str) -> str:
    return unicodedata.normalize("NFKC", text).translate(CONFUSABLES)


def _decode_printable(token: str) -> str | None:
    unpadded = token.rstrip("=")
    padded = unpadded + "=" * (-len(unpadded) % 4)
    try:
        decoded = base64.b64decode(padded, validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    return decoded if decoded and all(char.isprintable() for char in decoded) else None

@register(
    "POI-001",
    "Instruction override in description",
    "poisoned_description",
)
def check_instruction_override(tool: ToolInfo) -> list[Finding]:
    findings: list[Finding] = []
    descriptions = description_texts(tool.description, tool.input_schema)
    for description in descriptions:
        normalized = _normalize(description)
        if PATTERN.search(normalized):
            findings.append(
                Finding(
                    rule_id="POI-001",
                    severity=Severity.HIGH,
                    confidence=0.9,
                    tool_name=tool.name,
                    evidence=escape_evidence(description),
                    fix="Remove instruction-override language and keep the description factual.",
                )
            )
        for token_match in BASE64_TOKEN.finditer(description):
            token = token_match.group(1)
            decoded = _decode_printable(token)
            if decoded is None or not PATTERN.search(_normalize(decoded)):
                continue
            findings.append(
                Finding(
                    rule_id="POI-001",
                    severity=Severity.HIGH,
                    confidence=0.9,
                    tool_name=tool.name,
                    evidence=(
                        f"decoded from base64: {token!r} -> {escape_evidence(decoded)}"
                    ),
                    fix="Remove instruction-override language and keep the description factual.",
                )
            )
    return findings
