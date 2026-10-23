"""User-defined rules loaded from YAML files.

Example ``rules/company.yaml``::

    rules:
      - id: SC-ACME-001
        title: Internal hostnames must not appear in skills
        severity: medium
        confidence: deterministic
        category: network
        applies_to: [instructions, script, config]
        patterns:
          - '\\b[a-z0-9-]+\\.corp\\.acme\\.internal\\b'
        remediation: Use the public API gateway instead.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

from skillfuse.core.models import Category, Confidence, FileKind, Severity
from skillfuse.rules.base import RegexRule


class CustomRuleSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^SC-[A-Z]+-\d{3}$")
    title: str
    description: str = ""
    severity: Severity = Severity.MEDIUM
    confidence: Confidence = Confidence.HEURISTIC
    category: Category = Category.PROMPT_INJECTION
    applies_to: list[FileKind] = Field(
        default_factory=lambda: [FileKind.INSTRUCTIONS, FileKind.SCRIPT, FileKind.CONFIG]
    )
    patterns: list[str] = Field(min_length=1)
    exclude_patterns: list[str] = Field(default_factory=list)
    remediation: str = ""
    references: list[str] = Field(default_factory=list)
    capabilities: list[str] = Field(default_factory=list)
    message: str | None = None

    @field_validator("patterns", "exclude_patterns")
    @classmethod
    def _compile_ok(cls, value: list[str]) -> list[str]:
        for p in value:
            try:
                re.compile(p)
            except re.error as exc:  # pragma: no cover - exercised via tests with bad regex
                msg = f"invalid regex {p!r}: {exc}"
                raise ValueError(msg) from exc
        return value


class CustomRulesFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rules: list[CustomRuleSpec]


def build_rule(spec: CustomRuleSpec) -> RegexRule:
    flags = re.IGNORECASE | re.MULTILINE
    attrs: dict[str, Any] = {
        "id": spec.id,
        "title": spec.title,
        "description": spec.description or spec.title,
        "severity": spec.severity,
        "confidence": spec.confidence,
        "category": spec.category,
        "applies_to": frozenset(spec.applies_to),
        "remediation": spec.remediation,
        "references": tuple(spec.references),
        "capabilities": tuple(spec.capabilities),
        "patterns": tuple(re.compile(p, flags) for p in spec.patterns),
        "exclude_patterns": tuple(re.compile(p, flags) for p in spec.exclude_patterns),
        "message_template": spec.message,
    }
    cls = type(f"Custom_{spec.id.replace('-', '_')}", (RegexRule,), attrs)
    instance = cls()
    if not isinstance(instance, RegexRule):  # pragma: no cover - type() guarantees this
        msg = "custom rule construction failed"
        raise TypeError(msg)
    return instance


def load_custom_rules(paths: list[Path]) -> list[RegexRule]:
    rules: list[RegexRule] = []
    for base in paths:
        files = sorted(base.glob("*.y*ml")) if base.is_dir() else [base]
        for path in files:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            spec = CustomRulesFile.model_validate(data)
            rules.extend(build_rule(r) for r in spec.rules)
    return rules
