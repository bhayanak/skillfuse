"""Small text helpers used by parsers and rules."""

from __future__ import annotations

import re
from collections.abc import Iterator

_LINE_RE = re.compile(r"\r\n|\r|\n")


def offset_to_line_col(text: str, offset: int) -> tuple[int, int]:
    """Convert a 0-based character offset into 1-based (line, column)."""
    line = text.count("\n", 0, offset) + 1
    last_nl = text.rfind("\n", 0, offset)
    col = offset - (last_nl + 1) + 1
    return line, col


def iter_matches(pattern: re.Pattern[str], text: str) -> Iterator[tuple[re.Match[str], int, int]]:
    """Yield (match, line, col); the location points at the first non-whitespace character of the match."""
    for m in pattern.finditer(text):
        whole = m.group(0)
        lead = len(whole) - len(whole.lstrip())
        line, col = offset_to_line_col(text, m.start() + lead)
        yield m, line, col


def clip(text: str, limit: int = 160) -> str:
    text = text.strip().replace("\n", "\\n")
    return text if len(text) <= limit else text[: limit - 1] + "…"


def redact(text: str, keep: int = 4) -> str:
    """Mask the middle of a secret-looking token so reports never leak it verbatim."""
    if len(text) <= keep * 2 + 3:
        return "*" * len(text)
    return f"{text[:keep]}…{text[-keep:]}"


def line_of(text: str, lineno: int) -> str:
    lines = _LINE_RE.split(text)
    if 1 <= lineno <= len(lines):
        return lines[lineno - 1]
    return ""
