"""SC-HID-*: hidden or obfuscated content that a reviewer would not see but a model would read."""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterator

from skillchain.core.models import Category, Confidence, FileKind, Finding, Severity, SkillFile
from skillchain.core.textutil import iter_matches, offset_to_line_col
from skillchain.rules.base import TEXT_KINDS, RegexRule, Rule, RuleContext, rx

ZERO_WIDTH = {
    "\u200b": "ZERO WIDTH SPACE",
    "\u200c": "ZERO WIDTH NON-JOINER",
    "\u200d": "ZERO WIDTH JOINER",
    "\u200e": "LEFT-TO-RIGHT MARK",
    "\u200f": "RIGHT-TO-LEFT MARK",
    "\u2060": "WORD JOINER",
    "\u2061": "FUNCTION APPLICATION",
    "\u2062": "INVISIBLE TIMES",
    "\u2063": "INVISIBLE SEPARATOR",
    "\u2064": "INVISIBLE PLUS",
    "\ufeff": "ZERO WIDTH NO-BREAK SPACE",
    "\u180e": "MONGOLIAN VOWEL SEPARATOR",
    "\u00ad": "SOFT HYPHEN",
    "\u034f": "COMBINING GRAPHEME JOINER",
    "\u115f": "HANGUL CHOSEONG FILLER",
    "\u1160": "HANGUL JUNGSEONG FILLER",
    "\u3164": "HANGUL FILLER",
    "\uffa0": "HALFWIDTH HANGUL FILLER",
}
BIDI = {
    "\u202a": "LRE",
    "\u202b": "RLE",
    "\u202c": "PDF",
    "\u202d": "LRO",
    "\u202e": "RLO",
    "\u2066": "LRI",
    "\u2067": "RLI",
    "\u2068": "FSI",
    "\u2069": "PDI",
}
_TAG_RANGE = (0xE0000, 0xE007F)  # Unicode "tag" characters used for ASCII smuggling
_PUA_RANGES = ((0xE000, 0xF8FF), (0xF0000, 0xFFFFD), (0x100000, 0x10FFFD))

_INVISIBLE_RE = re.compile("[" + "".join(re.escape(c) for c in ZERO_WIDTH) + "]+")
_BIDI_RE = re.compile("[" + "".join(re.escape(c) for c in BIDI) + "]")
_HTML_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)
_IMPERATIVE_RE = re.compile(
    r"\b(you|assistant|agent|model|ai|ignore|disregard|always|never|must|should|run|execute|send|post|call|invoke|curl|wget|delete|install|read|copy|upload)\b",
    re.IGNORECASE,
)
_BASE64_RE = re.compile(
    r"(?<![A-Za-z0-9+/=])(?:[A-Za-z0-9+/]{4}){20,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"
)
_HEX_RE = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){48,}(?![0-9A-Fa-f])")
_SHA_LIKE_RE = re.compile(r"^(sha\d*:)?[0-9a-f]{40,128}$", re.IGNORECASE)
_URL_LIKE_RE = re.compile(r"https?://|data:image/|sha256|integrity=", re.IGNORECASE)


class InvisibleCharacters(Rule):
    id = "SC-HID-001"
    title = "Invisible Unicode characters"
    description = "Zero-width or filler code points that can hide instructions from human reviewers."
    severity = Severity.CRITICAL
    confidence = Confidence.DETERMINISTIC
    category = Category.HIDDEN_CONTENT
    applies_to = TEXT_KINDS
    remediation = "Strip the invisible characters; legitimate text almost never needs them."
    references = ("https://en.wikipedia.org/wiki/Zero-width_space",)

    def check(self, file: SkillFile, ctx: RuleContext) -> Iterator[Finding]:
        if file.kind not in self.applies_to:
            return
        seen: set[int] = set()
        for m, line, col in iter_matches(_INVISIBLE_RE, file.text):
            if line in seen:
                continue
            seen.add(line)
            names = sorted({ZERO_WIDTH.get(c, hex(ord(c))) for c in m.group(0)})
            yield self.finding(
                file,
                line=line,
                column=col,
                snippet=self._visible(file, line),
                message=f"{len(m.group(0))} invisible character(s): {', '.join(names)}",
            )
        for idx, ch in enumerate(file.text):
            cp = ord(ch)
            if _TAG_RANGE[0] <= cp <= _TAG_RANGE[1]:
                line, col = offset_to_line_col(file.text, idx)
                if line in seen:
                    continue
                seen.add(line)
                decoded = _decode_tags(file.text, idx)
                yield self.finding(
                    file,
                    line=line,
                    column=col,
                    snippet=decoded,
                    message="Unicode TAG characters smuggle ASCII text that is invisible when rendered",
                    severity=Severity.CRITICAL,
                )
        yield from self._private_use(file, seen)

    def _private_use(self, file: SkillFile, seen: set[int]) -> Iterator[Finding]:
        for idx, ch in enumerate(file.text):
            cp = ord(ch)
            if any(lo <= cp <= hi for lo, hi in _PUA_RANGES):
                line, col = offset_to_line_col(file.text, idx)
                if line in seen:
                    continue
                seen.add(line)
                yield self.finding(
                    file,
                    line=line,
                    column=col,
                    snippet=f"U+{cp:04X}",
                    message="Private-use-area code point (renders blank, may encode hidden payload)",
                    severity=Severity.MEDIUM,
                )

    @staticmethod
    def _visible(file: SkillFile, line: int) -> str:
        text = file.lines[line - 1] if 0 < line <= len(file.lines) else ""
        return _INVISIBLE_RE.sub("\u2423", text)


def _decode_tags(text: str, start: int) -> str:
    out: list[str] = []
    for ch in text[start : start + 400]:
        cp = ord(ch)
        if _TAG_RANGE[0] <= cp <= _TAG_RANGE[1]:
            if cp == 0xE007F:
                continue
            out.append(chr(cp - 0xE0000))
        elif out:
            break
    return "decoded: " + "".join(out)


class BidiOverride(Rule):
    id = "SC-HID-002"
    title = "Bidirectional text override (Trojan Source)"
    description = "Bidi control characters reorder how code/text is displayed versus how it is read."
    severity = Severity.HIGH
    confidence = Confidence.DETERMINISTIC
    category = Category.HIDDEN_CONTENT
    applies_to = TEXT_KINDS
    remediation = "Remove bidi control characters (U+202A–U+202E, U+2066–U+2069)."
    references = ("https://trojansource.codes/",)

    def check(self, file: SkillFile, ctx: RuleContext) -> Iterator[Finding]:
        if file.kind not in self.applies_to:
            return
        seen: set[int] = set()
        for m, line, col in iter_matches(_BIDI_RE, file.text):
            if line in seen:
                continue
            seen.add(line)
            yield self.finding(
                file,
                line=line,
                column=col,
                snippet=file.lines[line - 1] if line <= len(file.lines) else None,
                message=f"Bidi control character {BIDI[m.group(0)]} (U+{ord(m.group(0)):04X})",
            )


class HiddenHtmlComment(Rule):
    id = "SC-HID-003"
    title = "Instruction-like HTML comment"
    description = "HTML comments are invisible in rendered Markdown yet fully visible to the model."
    severity = Severity.MEDIUM
    confidence = Confidence.DETERMINISTIC
    category = Category.HIDDEN_CONTENT
    applies_to = frozenset({FileKind.INSTRUCTIONS})
    remediation = "Move instructions out of comments or delete them; reviewers must see what the model sees."

    def check(self, file: SkillFile, ctx: RuleContext) -> Iterator[Finding]:
        if file.kind not in self.applies_to:
            return
        for m, line, col in iter_matches(_HTML_COMMENT_RE, file.text):
            body = m.group(1).strip()
            if len(body) < 12:
                continue
            hits = len(_IMPERATIVE_RE.findall(body))
            if hits >= 2 or len(body) > 200:
                yield self.finding(
                    file,
                    line=line,
                    column=col,
                    snippet=body,
                    message=f"HTML comment ({len(body)} chars) contains {hits} instruction-like keyword(s)",
                    severity=Severity.HIGH if hits >= 4 else Severity.MEDIUM,
                )


class EncodedBlob(Rule):
    id = "SC-HID-004"
    title = "Large encoded blob"
    description = "Long base64/hex sequences can hide commands or payloads from review."
    severity = Severity.MEDIUM
    confidence = Confidence.DETERMINISTIC
    category = Category.HIDDEN_CONTENT
    applies_to = TEXT_KINDS
    remediation = "Replace encoded payloads with plain, reviewable text or fetch pinned artefacts by digest."

    def check(self, file: SkillFile, ctx: RuleContext) -> Iterator[Finding]:
        if file.kind not in self.applies_to:
            return
        seen: set[int] = set()
        for pattern, label in ((_BASE64_RE, "base64"), (_HEX_RE, "hex")):
            for m, line, col in iter_matches(pattern, file.text):
                if line in seen:
                    continue
                blob = m.group(0)
                context = file.lines[line - 1] if line <= len(file.lines) else ""
                if _SHA_LIKE_RE.match(blob) or _URL_LIKE_RE.search(context):
                    continue
                seen.add(line)
                yield self.finding(
                    file,
                    line=line,
                    column=col,
                    snippet=blob[:48] + "…",
                    message=f"{label} blob of {len(blob)} characters",
                    severity=Severity.HIGH if len(blob) > 400 else Severity.MEDIUM,
                )


_LATIN_WORD_RE = re.compile(r"[A-Za-z\u0400-\u04FF\u0370-\u03FF]{3,}")


class Homoglyphs(Rule):
    id = "SC-HID-005"
    title = "Mixed-script confusable characters"
    description = (
        "Words mixing Latin with Cyrillic/Greek look-alikes (e.g. 'сurl') evade simple pattern checks."
    )
    severity = Severity.MEDIUM
    confidence = Confidence.DETERMINISTIC
    category = Category.HIDDEN_CONTENT
    applies_to = frozenset({FileKind.INSTRUCTIONS, FileKind.SCRIPT, FileKind.CONFIG})
    remediation = "Normalise to a single script; mixed scripts inside one word are almost always deceptive."

    def check(self, file: SkillFile, ctx: RuleContext) -> Iterator[Finding]:
        if file.kind not in self.applies_to:
            return
        seen: set[int] = set()
        for m, line, col in iter_matches(_LATIN_WORD_RE, file.text):
            word = m.group(0)
            scripts = {_script(c) for c in word}
            if "Latin" in scripts and len(scripts) > 1 and line not in seen:
                seen.add(line)
                yield self.finding(
                    file,
                    line=line,
                    column=col,
                    snippet=word,
                    message=f"Word '{word}' mixes scripts: {', '.join(sorted(scripts))}",
                )


def _script(ch: str) -> str:
    try:
        name = unicodedata.name(ch)
    except ValueError:
        return "Unknown"
    for s in ("LATIN", "CYRILLIC", "GREEK"):
        if name.startswith(s):
            return s.title()
    return "Other"


class CssHiddenText(RegexRule):
    id = "SC-HID-006"
    title = "Visually hidden HTML content"
    description = "HTML that renders invisible (display:none, zero font, white-on-white, collapsed details)."
    severity = Severity.HIGH
    confidence = Confidence.DETERMINISTIC
    category = Category.HIDDEN_CONTENT
    applies_to = frozenset({FileKind.INSTRUCTIONS})
    remediation = "Remove hidden HTML; content for the model must be visible to the reviewer."
    patterns = (
        rx(
            r"<[^>]+style\s*=\s*[\"'][^\"']*(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0(?![.\d])|color\s*:\s*(#fff(fff)?|white|transparent)|position\s*:\s*absolute;?\s*(left|top)\s*:\s*-\d{3,})[^\"']*[\"']"
        ),
        rx(r"<(div|span|p)[^>]+\bhidden\b[^>]*>"),
        rx(r"<details>\s*<summary>\s*</summary>"),
    )


class OffscreenText(Rule):
    id = "SC-HID-007"
    title = "Off-screen text after excessive whitespace"
    description = "Hundreds of spaces push instructions beyond the visible editor width."
    severity = Severity.LOW
    confidence = Confidence.DETERMINISTIC
    category = Category.HIDDEN_CONTENT
    applies_to = frozenset({FileKind.INSTRUCTIONS, FileKind.SCRIPT})
    remediation = "Remove padding whitespace so every instruction is visible without horizontal scrolling."
    _RE = re.compile(r"^(?P<lead>\S.{0,120}?)(?P<pad>[ \t]{200,})(?P<tail>\S.*)$", re.MULTILINE)

    def check(self, file: SkillFile, ctx: RuleContext) -> Iterator[Finding]:
        if file.kind not in self.applies_to:
            return
        for m, line, col in iter_matches(self._RE, file.text):
            yield self.finding(
                file,
                line=line,
                column=col,
                snippet=m.group("tail"),
                message=f"{len(m.group('pad'))} whitespace characters precede hidden text",
            )


RULES = (
    InvisibleCharacters(),
    BidiOverride(),
    HiddenHtmlComment(),
    EncodedBlob(),
    Homoglyphs(),
    CssHiddenText(),
    OffscreenText(),
)
