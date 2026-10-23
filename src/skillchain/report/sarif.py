"""SARIF 2.1.0 output (GitHub Code Scanning compatible)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from skillchain import __version__
from skillchain.capabilities.manifest import MANIFEST_RULE_IDS
from skillchain.core.models import Confidence, Finding, ScanResult
from skillchain.rules import RuleRegistry, default_registry

SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
)
INFO_URI = "https://github.com/skillchain-dev/skillchain/blob/main/docs/rules.md"


def _rule_descriptors(registry: RuleRegistry, used: set[str]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for d in registry.descriptors():
        seen.add(d.id)
        out.append(
            {
                "id": d.id,
                "name": d.title.replace(" ", ""),
                "shortDescription": {"text": d.title},
                "fullDescription": {"text": d.description},
                "help": {
                    "text": d.remediation or d.description,
                    "markdown": f"**{d.title}**\n\n{d.description}\n\n{d.remediation}",
                },
                "helpUri": f"{INFO_URI}#{d.id.lower()}",
                "defaultConfiguration": {"level": d.severity.sarif_level},
                "properties": {
                    "tags": ["security", d.category.value, d.confidence.value],
                    "security-severity": d.severity.security_severity,
                    "precision": "very-high" if d.confidence == Confidence.DETERMINISTIC else "medium",
                    "problem.severity": d.severity.value,
                },
            }
        )
    for rid, title, sev in MANIFEST_RULE_IDS:
        seen.add(rid)
        out.append(
            {
                "id": rid,
                "name": title.replace(" ", ""),
                "shortDescription": {"text": title},
                "fullDescription": {"text": title},
                "helpUri": f"{INFO_URI}#{rid.lower()}",
                "defaultConfiguration": {"level": sev.sarif_level},
                "properties": {"tags": ["security", "manifest"], "security-severity": sev.security_severity},
            }
        )
    for rid in sorted(used - seen):  # sandbox / custom rule IDs not in the registry
        out.append({"id": rid, "shortDescription": {"text": rid}, "properties": {"tags": ["security"]}})
    return out


def _result(f: Finding, root_rel: str) -> dict[str, Any]:
    uri = f"{root_rel}/{f.location.path}".strip("/") if root_rel else f.location.path
    region: dict[str, Any] = {"startLine": f.location.line, "startColumn": f.location.column}
    if f.location.end_line:
        region["endLine"] = f.location.end_line
    if f.location.snippet:
        region["snippet"] = {"text": f.location.snippet}
    return {
        "ruleId": f.rule_id,
        "level": f.severity.sarif_level,
        "message": {"text": f.message + (f"\n\nRemediation: {f.remediation}" if f.remediation else "")},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"},
                    "region": region,
                }
            }
        ],
        "partialFingerprints": {"skillchain/v1": f.fingerprint},
        "properties": {
            "severity": f.severity.value,
            "confidence": f.confidence.value,
            "category": f.category.value,
            "capabilities": list(f.capabilities),
            "skill": f.skill,
            "tags": list(f.tags),
        },
    }


def to_sarif(
    result: ScanResult, registry: RuleRegistry | None = None, *, base_dir: Path | None = None
) -> dict[str, Any]:
    registry = registry or default_registry()
    base = (base_dir or Path(result.target)).resolve()
    results: list[dict[str, Any]] = []
    for scan in result.skills:
        root = Path(scan.package.root).resolve()
        try:
            rel = root.relative_to(base).as_posix() if root != base else ""
        except ValueError:
            rel = root.as_posix()
        rel = "" if rel == "." else rel
        results.extend(_result(f, rel) for f in scan.findings)
    used = {r["ruleId"] for r in results}
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SkillChain",
                        "version": __version__,
                        "semanticVersion": __version__,
                        "informationUri": "https://github.com/skillchain-dev/skillchain",
                        "rules": _rule_descriptors(registry, used),
                    }
                },
                "originalUriBaseIds": {"%SRCROOT%": {"uri": base.as_uri() + "/"}},
                "invocations": [
                    {
                        "executionSuccessful": not result.errors,
                        "startTimeUtc": result.started_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "toolExecutionNotifications": [
                            {"level": "error", "message": {"text": e}} for e in result.errors
                        ],
                    }
                ],
                "results": results,
                "properties": {
                    "skills": [
                        {
                            "name": s.package.name,
                            "kind": s.package.kind.value,
                            "digest": s.digest,
                            "capabilities": list(s.inferred.capabilities),
                            "declared": list(s.declared.capabilities) if s.declared else None,
                        }
                        for s in result.skills
                    ],
                    "suppressed": result.suppressed,
                },
            }
        ],
    }


def render_sarif(
    result: ScanResult, registry: RuleRegistry | None = None, *, base_dir: Path | None = None
) -> str:
    return json.dumps(to_sarif(result, registry, base_dir=base_dir), indent=2, sort_keys=False)
