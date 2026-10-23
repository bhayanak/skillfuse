"""The static scan pipeline: discover → parse → rules → capabilities → manifest diff → suppressions."""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from pathlib import Path

from skillfuse import __version__
from skillfuse.capabilities import declared_manifest, diff_manifests, infer_capabilities, manifest_findings
from skillfuse.core.config import ScanConfig
from skillfuse.core.hashing import file_digest, tree_digest
from skillfuse.core.models import (
    CapabilityManifest,
    Finding,
    ScanResult,
    Severity,
    SkillFile,
    SkillPackage,
    SkillScan,
)
from skillfuse.formats import discover_packages
from skillfuse.rules import RuleContext, RuleRegistry, registry_for

_INLINE_SUPPRESS = re.compile(
    r"skillfuse:\s*ignore(?:\s*[\[(]?\s*(?P<ids>SC-[A-Z]+-\d{3}(?:\s*,\s*SC-[A-Z]+-\d{3})*)\s*[\])]?)?",
    re.IGNORECASE,
)
_STANDALONE_SUPPRESS = re.compile(
    r"^\s*(?:#|//|<!--|/\*|--|;|\*)?\s*skillfuse:\s*ignore[^\n]*$", re.IGNORECASE
)


class Scanner:
    def __init__(self, config: ScanConfig | None = None, registry: RuleRegistry | None = None) -> None:
        self.config = config or ScanConfig()
        self.registry = registry or registry_for(self.config)
        self._baseline = _load_baseline(self.config.resolve(self.config.baseline))

    def scan(self, target: Path, *, observed: dict[str, CapabilityManifest] | None = None) -> ScanResult:
        target = Path(target)
        if not target.exists():
            return ScanResult(
                tool_version=__version__, target=str(target), errors=(f"target does not exist: {target}",)
            )
        errors: list[str] = []
        suppressed = 0
        scans: list[SkillScan] = []
        try:
            packages = discover_packages(
                target, excludes=self.config.excludes, max_bytes=self.config.max_file_bytes
            )
        except OSError as exc:
            return ScanResult(
                tool_version=__version__, target=str(target), errors=(f"discovery failed: {exc}",)
            )
        for pkg in packages:
            try:
                scan, dropped = self.scan_package(pkg, observed=(observed or {}).get(pkg.name))
            except Exception as exc:
                errors.append(f"{pkg.name}: {type(exc).__name__}: {exc}")
                continue
            suppressed += dropped
            scans.append(scan)
        return ScanResult(
            tool_version=__version__,
            target=str(target),
            skills=tuple(scans),
            errors=tuple(errors),
            suppressed=suppressed,
        )

    def scan_package(
        self, pkg: SkillPackage, *, observed: CapabilityManifest | None = None
    ) -> tuple[SkillScan, int]:
        ctx = RuleContext(package=pkg, config=self.config)
        findings: list[Finding] = []
        for rule in self.registry:
            findings.extend(rule.check_package(ctx))
            for sf in pkg.files:
                if sf.kind in rule.applies_to or sf.is_symlink:
                    findings.extend(rule.check(sf, ctx))
        inferred = infer_capabilities(pkg)
        declared = declared_manifest(pkg)
        diff = diff_manifests(declared, inferred)
        findings.extend(manifest_findings(pkg, declared, inferred, diff, observed))
        findings = [f.with_skill(pkg.name) for f in findings]
        disabled = set(self.config.disabled_rules)
        if disabled:
            findings = [f for f in findings if f.rule_id not in disabled and f.category.value not in disabled]
        kept, dropped = self._apply_suppressions(pkg, findings)
        kept = [f for f in kept if f.severity >= Severity(self.config.min_severity)]
        kept.sort(key=lambda f: (-f.severity.rank, f.location.path, f.location.line, f.rule_id))
        digest = (
            tree_digest(pkg.root_path, excludes=self.config.excludes)
            if len(pkg.files) != 1
            else _single_digest(pkg)
        )
        return (
            SkillScan(
                package=pkg,
                digest=digest,
                findings=tuple(kept),
                inferred=inferred,
                declared=declared,
                observed=observed,
                diff=diff,
            ),
            dropped,
        )

    def _apply_suppressions(
        self, pkg: SkillPackage, findings: Iterable[Finding]
    ) -> tuple[list[Finding], int]:
        kept: list[Finding] = []
        dropped = 0
        files = {f.path: f for f in pkg.files}
        for finding in findings:
            if finding.fingerprint in self._baseline or _inline_suppressed(
                finding, files.get(finding.location.path)
            ):
                dropped += 1
                continue
            kept.append(finding)
        return kept, dropped


def _inline_suppressed(finding: Finding, sf: SkillFile | None) -> bool:
    if sf is None or not sf.text:
        return False
    idx = finding.location.line - 1 - (sf.body_offset if sf.kind.value == "instructions" else 0)
    lines = sf.lines
    if not 0 <= idx < len(lines):
        return False
    for candidate, standalone_only in ((lines[idx], False), (lines[idx - 1] if idx > 0 else "", True)):
        if standalone_only and not _STANDALONE_SUPPRESS.match(candidate):
            continue
        m = _INLINE_SUPPRESS.search(candidate)
        if m:
            ids = m.group("ids")
            if not ids or finding.rule_id.upper() in {i.strip().upper() for i in ids.split(",")}:
                return True
    return False


def _single_digest(pkg: SkillPackage) -> str:
    path = pkg.root_path / pkg.entrypoint
    return f"sha256:{file_digest(path)}" if path.exists() else "sha256:" + "0" * 64


def _load_baseline(path: Path | None) -> frozenset[str]:
    if path is None or not path.exists():
        return frozenset()
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        fps = data.get("fingerprints")
        if isinstance(fps, list):
            return frozenset(str(x) for x in fps)
        # Accept a full JSON report as a baseline
        skills = data.get("skills")
        if isinstance(skills, list):
            return frozenset(
                str(f.get("fingerprint"))
                for s in skills
                for f in (s.get("findings") or [])
                if isinstance(f, dict) and f.get("fingerprint")
            )
    if isinstance(data, list):
        return frozenset(str(x) for x in data)
    return frozenset()


def scan_path(target: Path, config: ScanConfig | None = None) -> ScanResult:
    cfg = config or ScanConfig.load(target)
    return Scanner(cfg).scan(target)
