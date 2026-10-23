"""Rule base classes and the registry."""

from __future__ import annotations

import re
from abc import ABC
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field

from skillfuse.core.config import ScanConfig
from skillfuse.core.models import (
    Category,
    Confidence,
    FileKind,
    Finding,
    Location,
    Severity,
    SkillFile,
    SkillPackage,
)
from skillfuse.core.textutil import clip, iter_matches

TEXT_KINDS: frozenset[FileKind] = frozenset(
    {FileKind.INSTRUCTIONS, FileKind.SCRIPT, FileKind.CONFIG, FileKind.DATA}
)
EXEC_KINDS: frozenset[FileKind] = frozenset({FileKind.INSTRUCTIONS, FileKind.SCRIPT, FileKind.CONFIG})


@dataclass(slots=True)
class RuleContext:
    package: SkillPackage
    config: ScanConfig = field(default_factory=ScanConfig)


@dataclass(frozen=True, slots=True)
class RuleDescriptor:
    """Static metadata about a rule ID, used by `rules list` and SARIF `tool.driver.rules`."""

    id: str
    title: str
    description: str
    severity: Severity
    confidence: Confidence
    category: Category
    remediation: str = ""
    references: tuple[str, ...] = ()


class Rule(ABC):
    """A rule inspects files (``check``) and/or the whole package (``check_package``)."""

    id: str
    title: str
    severity: Severity
    confidence: Confidence
    category: Category
    applies_to: frozenset[FileKind] = TEXT_KINDS
    remediation: str = ""
    references: tuple[str, ...] = ()
    capabilities: tuple[str, ...] = ()
    description: str = ""

    def check(self, file: SkillFile, ctx: RuleContext) -> Iterator[Finding]:
        yield from ()

    def check_package(self, ctx: RuleContext) -> Iterator[Finding]:
        yield from ()

    def descriptors(self) -> tuple[RuleDescriptor, ...]:
        return (
            RuleDescriptor(
                id=self.id,
                title=self.title,
                description=self.description or self.title,
                severity=self.severity,
                confidence=self.confidence,
                category=self.category,
                remediation=self.remediation,
                references=self.references,
            ),
        )

    def finding(
        self,
        file: SkillFile | None,
        *,
        line: int = 1,
        column: int = 1,
        snippet: str | None = None,
        message: str | None = None,
        severity: Severity | None = None,
        confidence: Confidence | None = None,
        capabilities: Iterable[str] | None = None,
        path: str | None = None,
        end_line: int | None = None,
    ) -> Finding:
        rel_path = path if path is not None else (file.path if file else "")
        offset = file.body_offset if (file and file.kind == FileKind.INSTRUCTIONS) else 0
        return Finding(
            rule_id=self.id,
            title=self.title,
            message=message or self.title,
            severity=severity or self.severity,
            confidence=confidence or self.confidence,
            category=self.category,
            location=Location(
                path=rel_path,
                line=line + offset,
                column=column,
                end_line=(end_line + offset) if end_line else None,
                snippet=clip(snippet) if snippet else None,
            ),
            capabilities=tuple(capabilities) if capabilities is not None else self.capabilities,
            remediation=self.remediation or None,
            references=self.references,
        )


Formatter = Callable[["re.Match[str]"], str]


class RegexRule(Rule):
    """Declarative rule: one finding per regex match, optionally de-duplicated per line."""

    patterns: tuple[re.Pattern[str], ...] = ()
    one_per_line: bool = True
    message_template: str | None = None
    exclude_patterns: tuple[re.Pattern[str], ...] = ()

    def check(self, file: SkillFile, ctx: RuleContext) -> Iterator[Finding]:
        if file.kind not in self.applies_to or not file.text:
            return
        seen_lines: set[int] = set()
        for pattern in self.patterns:
            for m, line, col in iter_matches(pattern, file.text):
                if self.one_per_line and line in seen_lines:
                    continue
                snippet = m.group(0)
                if any(x.search(snippet) for x in self.exclude_patterns):
                    continue
                seen_lines.add(line)
                yield self.finding(
                    file,
                    line=line,
                    column=col,
                    snippet=snippet,
                    message=self.render_message(m),
                )

    def render_message(self, m: re.Match[str]) -> str:
        if self.message_template:
            try:
                return self.message_template.format(match=clip(m.group(0), 80), **_named_groups(m))
            except (KeyError, IndexError):
                return self.message_template
        return self.title


def _named_groups(m: re.Match[str]) -> dict[str, str]:
    return {k: (v or "") for k, v in m.groupdict().items()}


def rx(pattern: str, flags: int = re.IGNORECASE | re.MULTILINE) -> re.Pattern[str]:
    return re.compile(pattern, flags)


class RuleRegistry:
    def __init__(self, rules: Iterable[Rule] = ()) -> None:
        self._rules: dict[str, Rule] = {}
        for rule in rules:
            self.register(rule)

    def register(self, rule: Rule) -> None:
        if rule.id in self._rules:
            msg = f"duplicate rule id {rule.id}"
            raise ValueError(msg)
        self._rules[rule.id] = rule

    def __iter__(self) -> Iterator[Rule]:
        return iter(sorted(self._rules.values(), key=lambda r: r.id))

    def __len__(self) -> int:
        return len(self._rules)

    def get(self, rule_id: str) -> Rule | None:
        return self._rules.get(rule_id)

    def descriptors(self) -> list[RuleDescriptor]:
        out = [d for r in self for d in r.descriptors()]
        return sorted(out, key=lambda d: d.id)

    def descriptor(self, rule_id: str) -> RuleDescriptor | None:
        return next((d for d in self.descriptors() if d.id == rule_id), None)

    def without(self, disabled: Iterable[str]) -> RuleRegistry:
        off = set(disabled)
        return RuleRegistry(r for r in self if r.id not in off and r.category.value not in off)
