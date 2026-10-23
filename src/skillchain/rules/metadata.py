"""SC-META-*: package hygiene (symlinks, binaries, metadata completeness)."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from skillchain.core.models import Category, Confidence, FileKind, Finding, Severity, SkillFile, SkillKind
from skillchain.rules.base import Rule, RuleContext


class MissingMetadata(Rule):
    id = "SC-META-001"
    title = "Missing name or description"
    description = "Skills without a name/description cannot be reasoned about by policy or by the host."
    severity = Severity.LOW
    confidence = Confidence.DETERMINISTIC
    category = Category.METADATA
    remediation = "Add `name` and `description` to the frontmatter."

    def check_package(self, ctx: RuleContext) -> Iterator[Finding]:
        pkg = ctx.package
        if pkg.kind not in {SkillKind.SKILL, SkillKind.AGENT, SkillKind.PROMPT}:
            return
        missing = [k for k in ("name", "description") if not pkg.metadata.get(k)]
        if pkg.metadata.get("__invalid_frontmatter__"):
            yield self.finding(
                None, path=pkg.entrypoint, message="Frontmatter is not valid YAML", severity=Severity.MEDIUM
            )
        elif missing:
            yield self.finding(
                None, path=pkg.entrypoint, message=f"Frontmatter missing: {', '.join(missing)}"
            )


class SymlinkEscape(Rule):
    id = "SC-META-002"
    title = "Symlink points outside the package"
    description = "A symlink that escapes the package root can read or write arbitrary host files."
    severity = Severity.HIGH
    confidence = Confidence.DETERMINISTIC
    category = Category.METADATA
    capabilities = ("filesystem.read",)
    remediation = "Replace the symlink with a copy of the intended file."

    def check(self, file: SkillFile, ctx: RuleContext) -> Iterator[Finding]:
        if not file.is_symlink:
            return
        root = Path(ctx.package.root).resolve()
        target = file.symlink_target or ""
        try:
            inside = Path(target).resolve().is_relative_to(root)
        except (OSError, ValueError):
            inside = False
        if not inside:
            yield self.finding(
                file,
                snippet=target,
                message=f"Symlink {file.path} -> {target} escapes the package",
            )


class BinaryArtifact(Rule):
    id = "SC-META-003"
    title = "Binary or executable artefact bundled"
    description = (
        "Opaque binaries cannot be reviewed; executables inside skills are a common dropper pattern."
    )
    severity = Severity.MEDIUM
    confidence = Confidence.DETERMINISTIC
    category = Category.METADATA
    applies_to = frozenset({FileKind.BINARY, FileKind.SCRIPT, FileKind.DATA})
    capabilities = ("shell.exec",)
    remediation = (
        "Ship source instead of binaries; if unavoidable, publish checksums and a provenance attestation."
    )
    _OK_BINARY = {
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".webp",
        ".ico",
        ".pdf",
        ".woff",
        ".woff2",
        ".ttf",
        ".svg",
        ".pptx",
        ".docx",
        ".xlsx",
    }

    def check(self, file: SkillFile, ctx: RuleContext) -> Iterator[Finding]:
        suffix = Path(file.path).suffix.lower()
        if file.kind == FileKind.BINARY and suffix not in self._OK_BINARY:
            yield self.finding(
                file,
                message=f"Binary file {file.path} ({file.size} bytes)",
                severity=Severity.HIGH if file.executable else Severity.MEDIUM,
            )
        elif file.executable and file.kind == FileKind.DATA and suffix == "":
            yield self.finding(
                file, message=f"Executable file without extension: {file.path}", severity=Severity.MEDIUM
            )


class OversizedPackage(Rule):
    id = "SC-META-004"
    title = "Unusually large skill package"
    description = "Large packages hide payloads and slow review."
    severity = Severity.INFO
    confidence = Confidence.DETERMINISTIC
    category = Category.METADATA
    remediation = "Keep skills small; move datasets and tooling into pinned external artefacts."

    def check_package(self, ctx: RuleContext) -> Iterator[Finding]:
        total = sum(f.size for f in ctx.package.files)
        if total > 5_000_000 or len(ctx.package.files) > 400:
            yield self.finding(
                None,
                path=ctx.package.entrypoint,
                message=f"{len(ctx.package.files)} files, {total / 1_000_000:.1f} MB",
            )


class SuspiciousFilenames(Rule):
    id = "SC-META-005"
    title = "Suspicious file placement"
    description = "Files that masquerade as something else or are hidden in dot-directories."
    severity = Severity.LOW
    confidence = Confidence.DETERMINISTIC
    category = Category.METADATA
    remediation = "Keep all package content in visible, descriptively named files."

    def check(self, file: SkillFile, ctx: RuleContext) -> Iterator[Finding]:
        parts = Path(file.path).parts
        name = parts[-1]
        hidden_dirs = [
            p
            for p in parts[:-1]
            if p.startswith(".")
            and p not in {".github", ".vscode", ".claude", ".claude-plugin", ".cursor", ".codex", ".agents"}
        ]
        if hidden_dirs and file.kind in {FileKind.SCRIPT, FileKind.BINARY}:
            yield self.finding(
                file, message=f"Executable content hidden in dot-directory {'/'.join(hidden_dirs)}"
            )
        if (
            name.count(".") >= 2
            and name.lower().endswith((".md", ".txt", ".json"))
            and file.kind == FileKind.SCRIPT
        ):
            yield self.finding(
                file, message=f"Script disguised with a document extension: {name}", severity=Severity.MEDIUM
            )


RULES = (MissingMetadata(), SymlinkEscape(), BinaryArtifact(), OversizedPackage(), SuspiciousFilenames())
