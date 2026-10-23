"""Declared capability manifests and the declared-vs-inferred diff."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from typing import Any

from skillfuse.capabilities.taxonomy import covers, is_valid_capability
from skillfuse.core.models import (
    CapabilityManifest,
    Category,
    Confidence,
    Finding,
    Location,
    ManifestDiff,
    Severity,
    SkillPackage,
)

MANIFEST_KEYS = ("capabilities", "permissions", "requires")


def declared_manifest(pkg: SkillPackage) -> CapabilityManifest | None:
    """Read declared capabilities from ``skillfuse.yaml`` or the entrypoint frontmatter."""
    sources: list[tuple[str, Any]] = []
    manifest = pkg.metadata.get("__skillfuse_manifest__")
    if isinstance(manifest, dict):
        sources.append(("skillfuse.yaml", manifest))
    sources.append((pkg.entrypoint, pkg.metadata))
    for origin, data in sources:
        for key in MANIFEST_KEYS:
            raw = data.get(key)
            caps = _normalise(raw)
            if caps is not None:
                return CapabilityManifest(
                    capabilities=tuple(caps),
                    evidence=dict.fromkeys(caps, (f"{origin}: declared",)),
                    source="declared",
                )
    return None


def _normalise(raw: Any) -> list[str] | None:
    if raw is None:
        return None
    if isinstance(raw, str):
        items: Iterable[Any] = [p.strip() for p in raw.replace(",", " ").split()]
    elif isinstance(raw, list):
        items = raw
    elif isinstance(raw, dict):
        # {network: [egress], filesystem: {write: true}} style
        items = _flatten(raw)
    else:
        return None
    caps = sorted({str(i).strip().lower() for i in items if str(i).strip()})
    return caps


def _flatten(data: dict[str, Any], prefix: str = "") -> Iterator[str]:
    for key, value in data.items():
        name = f"{prefix}{key}".lower()
        if value is False or value is None:
            continue
        if isinstance(value, dict):
            yield from _flatten(value, name + ".")
        elif isinstance(value, list):
            for item in value:
                yield f"{name}.{str(item).lower()}"
        else:
            yield name


def diff_manifests(declared: CapabilityManifest | None, inferred: CapabilityManifest) -> ManifestDiff:
    if declared is None:
        return ManifestDiff(undeclared=inferred.capabilities, overdeclared=(), matched=())
    undeclared = tuple(
        c for c in inferred.capabilities if not any(covers(d, c) for d in declared.capabilities)
    )
    matched = tuple(c for c in inferred.capabilities if c not in undeclared)
    overdeclared = tuple(
        d for d in declared.capabilities if not any(covers(d, c) for c in inferred.capabilities)
    )
    return ManifestDiff(undeclared=undeclared, overdeclared=overdeclared, matched=matched)


def manifest_findings(
    pkg: SkillPackage,
    declared: CapabilityManifest | None,
    inferred: CapabilityManifest,
    diff: ManifestDiff,
    observed: CapabilityManifest | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    loc = Location(path=pkg.entrypoint)
    if declared is None:
        findings.append(
            Finding(
                rule_id="SC-MAN-002",
                title="No capability manifest",
                message=f"Skill declares no capabilities; inferred: {', '.join(inferred.capabilities) or 'none'}",
                severity=Severity.LOW if inferred.capabilities else Severity.INFO,
                confidence=Confidence.DETERMINISTIC,
                category=Category.MANIFEST,
                location=loc,
                capabilities=inferred.capabilities,
                remediation="Add a `capabilities:` list to the frontmatter or a `skillfuse.yaml` next to the entrypoint.",
            )
        )
    else:
        for bad in (c for c in declared.capabilities if not is_valid_capability(c)):
            findings.append(
                Finding(
                    rule_id="SC-MAN-005",
                    title="Unknown capability declared",
                    message=f"'{bad}' is not a known capability",
                    severity=Severity.LOW,
                    confidence=Confidence.DETERMINISTIC,
                    category=Category.MANIFEST,
                    location=loc,
                    remediation="Use names from the SkillFuse taxonomy (`skillfuse rules capabilities`).",
                )
            )
        for cap in diff.undeclared:
            ev = inferred.evidence.get(cap, ())
            weak = cap in inferred.weak
            findings.append(
                Finding(
                    rule_id="SC-MAN-001",
                    title="Undeclared capability",
                    message=f"Uses '{cap}' but does not declare it"
                    + (f" (e.g. {ev[0]})" if ev else "")
                    + (" — inferred from prose only" if weak else ""),
                    severity=Severity.MEDIUM if weak else Severity.HIGH,
                    confidence=Confidence.HEURISTIC if weak else Confidence.DETERMINISTIC,
                    category=Category.MANIFEST,
                    location=_loc_from_evidence(ev, pkg.entrypoint),
                    capabilities=(cap,),
                    remediation=f"Declare '{cap}' or remove the behaviour.",
                )
            )
        for cap in diff.overdeclared:
            findings.append(
                Finding(
                    rule_id="SC-MAN-003",
                    title="Over-declared capability",
                    message=f"Declares '{cap}' but no usage was inferred",
                    severity=Severity.INFO,
                    confidence=Confidence.DETERMINISTIC,
                    category=Category.MANIFEST,
                    location=loc,
                    capabilities=(cap,),
                    remediation="Tighten the manifest to what the skill actually needs.",
                )
            )
    if observed is not None:
        runtime_only = [
            c for c in observed.capabilities if not any(covers(i, c) for i in inferred.capabilities)
        ]
        for cap in runtime_only:
            ev = observed.evidence.get(cap, ())
            findings.append(
                Finding(
                    rule_id="SC-MAN-004",
                    title="Runtime behaviour not predicted by static analysis",
                    message=f"Sandbox observed '{cap}' which static analysis did not infer"
                    + (f": {ev[0]}" if ev else ""),
                    severity=Severity.CRITICAL,
                    confidence=Confidence.DETERMINISTIC,
                    category=Category.MANIFEST,
                    location=loc,
                    capabilities=(cap,),
                    remediation="Behaviour that only appears at runtime is the signature of obfuscation; review the scripts manually.",
                )
            )
    return findings


def _loc_from_evidence(evidence: tuple[str, ...], fallback: str) -> Location:
    if evidence:
        head = evidence[0]
        parts = head.split(":", 2)
        if len(parts) >= 2 and parts[1].strip().isdigit():
            return Location(
                path=parts[0], line=int(parts[1]), snippet=parts[2].strip() if len(parts) > 2 else None
            )
        return Location(path=parts[0], snippet=parts[-1].strip())
    return Location(path=fallback)


MANIFEST_RULE_IDS: tuple[tuple[str, str, Severity], ...] = (
    ("SC-MAN-001", "Undeclared capability", Severity.HIGH),
    ("SC-MAN-002", "No capability manifest", Severity.LOW),
    ("SC-MAN-003", "Over-declared capability", Severity.INFO),
    ("SC-MAN-004", "Runtime behaviour not predicted by static analysis", Severity.CRITICAL),
    ("SC-MAN-005", "Unknown capability declared", Severity.LOW),
)
