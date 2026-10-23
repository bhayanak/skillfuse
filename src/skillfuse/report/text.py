"""JSON and Markdown reporters."""

from __future__ import annotations

import json
from collections import Counter
from typing import Any

from skillfuse.core.models import Confidence, Finding, PolicyVerdict, ScanResult, Severity, SkillScan

_SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
_SEV_ICON = {
    Severity.CRITICAL: "🟥",
    Severity.HIGH: "🟧",
    Severity.MEDIUM: "🟨",
    Severity.LOW: "🟦",
    Severity.INFO: "⬜",
}


def finding_to_dict(f: Finding) -> dict[str, Any]:
    data = f.model_dump(mode="json")
    data["fingerprint"] = f.fingerprint
    return data


def skill_to_dict(s: SkillScan, verdict: PolicyVerdict | None = None) -> dict[str, Any]:
    return {
        "name": s.package.name,
        "kind": s.package.kind.value,
        "root": s.package.root,
        "entrypoint": s.package.entrypoint,
        "publisher": s.package.publisher,
        "version": s.package.version,
        "digest": s.digest,
        "files": len(s.package.files),
        "capabilities": {
            "inferred": list(s.inferred.capabilities),
            "weak": list(s.inferred.weak),
            "declared": list(s.declared.capabilities) if s.declared else None,
            "observed": list(s.observed.capabilities) if s.observed else None,
            "undeclared": list(s.diff.undeclared),
            "overdeclared": list(s.diff.overdeclared),
            "evidence": {k: list(v) for k, v in s.inferred.evidence.items()},
        },
        "summary": summarise(s.findings),
        "findings": [finding_to_dict(f) for f in s.findings],
        "verdict": verdict.model_dump(mode="json") if verdict else None,
    }


def summarise(findings: tuple[Finding, ...] | list[Finding]) -> dict[str, Any]:
    by_sev = Counter(f.severity.value for f in findings)
    by_conf = Counter(f.confidence.value for f in findings)
    return {
        "total": len(findings),
        "by_severity": {s.value: by_sev.get(s.value, 0) for s in _SEV_ORDER},
        "by_confidence": {c.value: by_conf.get(c.value, 0) for c in Confidence},
    }


def to_json(result: ScanResult, verdicts: dict[str, PolicyVerdict] | None = None) -> dict[str, Any]:
    verdicts = verdicts or {}
    return {
        "schema": "skillfuse/report/v1",
        "tool": {"name": "skillfuse", "version": result.tool_version},
        "started_at": result.started_at.isoformat(),
        "target": result.target,
        "summary": summarise(result.findings),
        "suppressed": result.suppressed,
        "errors": list(result.errors),
        "skills": [skill_to_dict(s, verdicts.get(s.package.name)) for s in result.skills],
    }


def render_json(result: ScanResult, verdicts: dict[str, PolicyVerdict] | None = None) -> str:
    return json.dumps(to_json(result, verdicts), indent=2)


def render_markdown(result: ScanResult, verdicts: dict[str, PolicyVerdict] | None = None) -> str:
    verdicts = verdicts or {}
    lines: list[str] = ["# SkillFuse report", ""]
    total = summarise(result.findings)
    lines.append(f"**Target:** `{result.target}`  ")
    lines.append(
        f"**Skills:** {len(result.skills)} · **Findings:** {total['total']} · **Suppressed:** {result.suppressed}"
    )
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|---|---|")
    for sev in _SEV_ORDER:
        lines.append(f"| {_SEV_ICON[sev]} {sev.value} | {total['by_severity'][sev.value]} |")
    lines.append("")
    for scan in result.skills:
        verdict = verdicts.get(scan.package.name)
        badge = f" — **{verdict.decision.value.upper()}**" if verdict else ""
        lines.append(f"## {scan.package.name} ({scan.package.kind.value}){badge}")
        lines.append("")
        lines.append(f"- Digest: `{scan.digest}`")
        lines.append(
            f"- Inferred capabilities: {', '.join(f'`{c}`' for c in scan.inferred.capabilities) or '_none_'}"
        )
        if scan.declared:
            lines.append(
                f"- Declared capabilities: {', '.join(f'`{c}`' for c in scan.declared.capabilities) or '_none_'}"
            )
        if scan.diff.undeclared:
            lines.append(f"- Undeclared: {', '.join(f'`{c}`' for c in scan.diff.undeclared)}")
        if verdict and verdict.reasons:
            lines.append("- Policy reasons:")
            lines.extend(f"  - {r}" for r in verdict.reasons)
        lines.append("")
        if not scan.findings:
            lines.append("_No findings._")
            lines.append("")
            continue
        lines.append("| Sev | Conf | Rule | Location | Message |")
        lines.append("|---|---|---|---|---|")
        for f in scan.findings:
            loc = f"`{f.location.path}:{f.location.line}`"
            msg = f.message.replace("|", "\\|")
            lines.append(
                f"| {_SEV_ICON[f.severity]} {f.severity.value} | {f.confidence.value[:3]} | `{f.rule_id}` | {loc} | {msg} |"
            )
        lines.append("")
    if result.errors:
        lines.append("## Errors")
        lines.extend(f"- {e}" for e in result.errors)
        lines.append("")
    return "\n".join(lines)
