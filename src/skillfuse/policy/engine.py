"""Policy schema (YAML) and evaluator producing allow / quarantine / block verdicts."""

from __future__ import annotations

import fnmatch
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field

from skillfuse.capabilities.taxonomy import covers
from skillfuse.core.models import (
    Category,
    Confidence,
    Decision,
    Finding,
    PolicyVerdict,
    Severity,
    SkillKind,
    SkillScan,
)


class FindingsCondition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    min_severity: Severity = Severity.INFO
    confidence: Confidence | None = None
    rule_ids: list[str] = Field(default_factory=list, description="Globs; any match counts.")
    categories: list[Category] = Field(default_factory=list)
    min_count: int = Field(default=1, ge=1)

    def matches(self, findings: list[Finding]) -> list[Finding]:
        out: list[Finding] = []
        for f in findings:
            if f.severity < self.min_severity:
                continue
            if self.confidence and f.confidence != self.confidence:
                continue
            if self.rule_ids and not any(fnmatch.fnmatchcase(f.rule_id, p) for p in self.rule_ids):
                continue
            if self.categories and f.category not in self.categories:
                continue
            out.append(f)
        return out if len(out) >= self.min_count else []


class CapabilitiesCondition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    any: list[str] = Field(default_factory=list)
    all: list[str] = Field(default_factory=list)
    none: list[str] = Field(default_factory=list)
    include_weak: bool = Field(default=False, description="Count prose-only (weak) capabilities too.")

    def matches(self, caps: tuple[str, ...]) -> tuple[bool, list[str]]:
        def has(c: str) -> bool:
            return any(covers(c, x) for x in caps)

        hits = [c for c in self.any if has(c)]
        if self.any and not hits:
            return False, []
        if self.all and not all(has(c) for c in self.all):
            return False, []
        if self.none and any(has(c) for c in self.none):
            return False, []
        return True, hits or list(self.all)


class When(BaseModel):
    model_config = ConfigDict(extra="forbid")

    findings: FindingsCondition | None = None
    capabilities: CapabilitiesCondition | None = None
    undeclared_capabilities: bool | list[str] | None = None
    publisher: list[str] | None = Field(default=None, description="Globs over the publisher string.")
    publisher_missing: bool | None = None
    signed: bool | None = None
    in_lock: bool | None = None
    kinds: list[SkillKind] | None = None
    names: list[str] | None = None


class PolicyRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    action: Decision
    when: When = Field(default_factory=When)
    final: bool = Field(default=False, description="Stop evaluating further rules when this one matches.")
    message: str | None = None


class PublisherLists(BaseModel):
    model_config = ConfigDict(extra="forbid")

    allow: list[str] = Field(default_factory=list)
    block: list[str] = Field(default_factory=list)


class CapabilityLists(BaseModel):
    model_config = ConfigDict(extra="forbid")

    deny: list[str] = Field(default_factory=list)
    quarantine: list[str] = Field(default_factory=list)


class RuleIdLists(BaseModel):
    model_config = ConfigDict(extra="forbid")

    block: list[str] = Field(default_factory=list)
    quarantine: list[str] = Field(default_factory=list)
    ignore: list[str] = Field(
        default_factory=list, description="Findings with these rule IDs are ignored by policy."
    )


class Policy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: int = 1
    name: str = "skillfuse-policy"
    default: Decision = Decision.ALLOW
    heuristic_can_block: bool = Field(
        default=False,
        description="If false, heuristic findings are ignored by `block` rules (they may still quarantine).",
    )
    rules: list[PolicyRule] = Field(default_factory=list)
    publishers: PublisherLists = Field(default_factory=PublisherLists)
    capabilities: CapabilityLists = Field(default_factory=CapabilityLists)
    rule_ids: RuleIdLists = Field(default_factory=RuleIdLists)

    @classmethod
    def load(cls, path: Path) -> Policy:
        data: Any = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if not isinstance(data, dict):
            msg = f"{path}: policy must be a mapping"
            raise ValueError(msg)
        return cls.model_validate(data)

    @classmethod
    def default_policy(cls) -> Policy:
        return cls.model_validate(DEFAULT_POLICY)


DEFAULT_POLICY: dict[str, Any] = {
    "version": 1,
    "name": "skillfuse-default",
    "default": "allow",
    "heuristic_can_block": False,
    "rules": [
        {
            "name": "block-deterministic-critical",
            "action": "block",
            "when": {"findings": {"min_severity": "critical", "confidence": "deterministic"}},
            "message": "Deterministic critical finding",
        },
        {
            "name": "quarantine-high",
            "action": "quarantine",
            "when": {"findings": {"min_severity": "high"}},
            "message": "High-severity finding requires review",
        },
        {
            "name": "quarantine-undeclared",
            "action": "quarantine",
            "when": {
                "undeclared_capabilities": [
                    "shell.exec",
                    "process.spawn",
                    "filesystem.write",
                    "filesystem.delete",
                    "network.egress",
                    "secrets.read",
                    "package.install",
                    "git.write",
                    "github.write",
                    "jira.write",
                    "confluence.write",
                    "slack.write",
                    "cloud.write",
                    "database.write",
                    "system",
                    "ssh.exec",
                    "email.send",
                ]
            },
            "message": "Uses write/exec/network capabilities it does not declare",
        },
    ],
    "capabilities": {"deny": ["system.persistence"], "quarantine": ["system.admin"]},
    "rule_ids": {"block": ["SC-SH-007", "SC-DYN-001"]},
}


class PolicyInput(BaseModel):
    """Everything the evaluator may consult besides the scan itself."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    signed: bool | None = None
    in_lock: bool | None = None


class PolicyEngine:
    def __init__(self, policy: Policy | None = None) -> None:
        self.policy = policy or Policy.default_policy()

    def evaluate(self, scan: SkillScan, extra: PolicyInput | None = None) -> PolicyVerdict:
        extra = extra or PolicyInput()
        pol = self.policy
        pkg = scan.package
        findings = [
            f
            for f in scan.findings
            if not any(fnmatch.fnmatchcase(f.rule_id, p) for p in pol.rule_ids.ignore)
        ]
        matched: list[tuple[Decision, str, str]] = []  # (action, rule name, reason)

        # --- shortcut lists -------------------------------------------------------------------------
        publisher = pkg.publisher or ""
        if publisher and any(fnmatch.fnmatchcase(publisher, p) for p in pol.publishers.block):
            matched.append((Decision.BLOCK, "publishers.block", f"publisher '{publisher}' is blocked"))
        if publisher and any(fnmatch.fnmatchcase(publisher, p) for p in pol.publishers.allow):
            matched.append((Decision.ALLOW, "publishers.allow", f"publisher '{publisher}' is trusted"))
        strong = scan.inferred.strong
        for cap in pol.capabilities.deny:
            if any(covers(cap, c) for c in strong):
                matched.append((Decision.BLOCK, "capabilities.deny", f"capability '{cap}' is denied"))
        for cap in pol.capabilities.quarantine:
            if any(covers(cap, c) for c in strong):
                matched.append(
                    (Decision.QUARANTINE, "capabilities.quarantine", f"capability '{cap}' requires review")
                )
        for f in findings:
            if any(fnmatch.fnmatchcase(f.rule_id, p) for p in pol.rule_ids.block) and (
                pol.heuristic_can_block or f.confidence == Confidence.DETERMINISTIC
            ):
                matched.append(
                    (Decision.BLOCK, "rule_ids.block", f"{f.rule_id} at {f.location.path}:{f.location.line}")
                )
            elif any(fnmatch.fnmatchcase(f.rule_id, p) for p in pol.rule_ids.quarantine + pol.rule_ids.block):
                matched.append(
                    (
                        Decision.QUARANTINE,
                        "rule_ids.quarantine",
                        f"{f.rule_id} at {f.location.path}:{f.location.line}",
                    )
                )

        # --- ordered rules --------------------------------------------------------------------------
        for rule in pol.rules:
            ok, reason = self._rule_matches(rule, scan, findings, extra)
            if not ok:
                continue
            matched.append((rule.action, rule.name, rule.message or reason))
            if rule.final:
                return PolicyVerdict(
                    skill=pkg.name,
                    decision=rule.action,
                    reasons=(f"{rule.name}: {rule.message or reason} (final)",),
                    matched_rules=(rule.name,),
                )

        if not matched:
            return PolicyVerdict(
                skill=pkg.name, decision=pol.default, reasons=("no policy rule matched",), matched_rules=()
            )
        decision = max((m[0] for m in matched), key=lambda d: d.rank)
        reasons = tuple(f"{name}: {reason}" for action, name, reason in matched if action == decision)
        return PolicyVerdict(
            skill=pkg.name,
            decision=decision,
            reasons=_dedupe(reasons)[:12],
            matched_rules=_dedupe(tuple(m[1] for m in matched)),
        )

    def _rule_matches(
        self, rule: PolicyRule, scan: SkillScan, findings: list[Finding], extra: PolicyInput
    ) -> tuple[bool, str]:
        w = rule.when
        pkg = scan.package
        reasons: list[str] = []
        if w.kinds is not None and pkg.kind not in w.kinds:
            return False, ""
        if w.names is not None and not any(fnmatch.fnmatchcase(pkg.name, p) for p in w.names):
            return False, ""
        if w.publisher is not None:
            if not pkg.publisher or not any(fnmatch.fnmatchcase(pkg.publisher, p) for p in w.publisher):
                return False, ""
            reasons.append(f"publisher '{pkg.publisher}'")
        if w.publisher_missing is not None and bool(pkg.publisher) == w.publisher_missing:
            return False, ""
        if w.signed is not None:
            if extra.signed is None or extra.signed != w.signed:
                return False, ""
            reasons.append("signed" if w.signed else "unsigned")
        if w.in_lock is not None:
            if extra.in_lock is None or extra.in_lock != w.in_lock:
                return False, ""
            reasons.append("in lockfile" if w.in_lock else "not in lockfile")
        if w.capabilities is not None:
            caps = scan.inferred.capabilities if w.capabilities.include_weak else scan.inferred.strong
            ok, hits = w.capabilities.matches(caps)
            if not ok:
                return False, ""
            reasons.append(f"capabilities {', '.join(hits)}" if hits else "capability condition")
        if w.undeclared_capabilities is not None:
            undeclared = [c for c in scan.diff.undeclared if c not in scan.inferred.weak]
            if isinstance(w.undeclared_capabilities, bool):
                if bool(undeclared) != w.undeclared_capabilities:
                    return False, ""
            else:
                hits = [c for c in undeclared if any(covers(p, c) for p in w.undeclared_capabilities)]
                if not hits:
                    return False, ""
                undeclared = hits
            if undeclared:
                reasons.append(f"undeclared {', '.join(undeclared)}")
        if w.findings is not None:
            pool = findings
            if rule.action == Decision.BLOCK and not self.policy.heuristic_can_block:
                pool = [f for f in findings if f.confidence == Confidence.DETERMINISTIC]
            matched_findings = w.findings.matches(pool)
            if not matched_findings:
                return False, ""
            top = matched_findings[0]
            reasons.append(
                f"{len(matched_findings)} finding(s), e.g. {top.rule_id} at {top.location.path}:{top.location.line}"
            )
        return True, "; ".join(reasons) or "matched"


def _dedupe(items: tuple[str, ...]) -> tuple[str, ...]:
    seen: dict[str, None] = {}
    for i in items:
        seen.setdefault(i, None)
    return tuple(seen)
