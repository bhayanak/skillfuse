"""Core data models shared across the scanner, sandbox, policy, and reporters."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class Severity(StrEnum):
    """Finding severity, ordered from least to most severe."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank >= other.rank

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank > other.rank

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank <= other.rank

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank

    @property
    def sarif_level(self) -> str:
        return {
            Severity.INFO: "note",
            Severity.LOW: "note",
            Severity.MEDIUM: "warning",
            Severity.HIGH: "error",
            Severity.CRITICAL: "error",
        }[self]

    @property
    def security_severity(self) -> str:
        """GitHub code-scanning ``security-severity`` score."""
        return {
            Severity.INFO: "0.0",
            Severity.LOW: "2.0",
            Severity.MEDIUM: "5.0",
            Severity.HIGH: "7.5",
            Severity.CRITICAL: "9.5",
        }[self]


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Confidence(StrEnum):
    """Whether a finding is a provable fact or an informed suspicion.

    ``deterministic`` findings are reproducible facts about the artefact (a zero-width character exists, a
    command pipes ``curl`` into ``sh``). ``heuristic`` findings are pattern-based suspicions about intent
    (an instruction *looks like* it asks the model to hide something). Policies can treat them differently.
    """

    DETERMINISTIC = "deterministic"
    HEURISTIC = "heuristic"


class Category(StrEnum):
    PROMPT_INJECTION = "prompt-injection"
    HIDDEN_CONTENT = "hidden-content"
    EXFILTRATION = "exfiltration"
    SHELL = "shell"
    NETWORK = "network"
    TOOL_OVERREACH = "tool-overreach"
    DEPENDENCY = "dependency"
    MANIFEST = "manifest"
    SANDBOX = "sandbox"
    METADATA = "metadata"


class FileKind(StrEnum):
    """What a file inside a skill package *is*, which decides which rules apply."""

    INSTRUCTIONS = "instructions"  # markdown bodies read by the model
    FRONTMATTER = "frontmatter"  # YAML metadata of markdown files
    SCRIPT = "script"  # sh/py/js/ts/ps1 executed by the host
    CONFIG = "config"  # json/yaml/toml configuration (mcp.json, plugin.json)
    DATA = "data"  # anything else textual
    BINARY = "binary"


class Location(BaseModel):
    model_config = ConfigDict(frozen=True)

    path: str = Field(description="Path relative to the skill package root (POSIX separators).")
    line: int = Field(default=1, ge=1)
    column: int = Field(default=1, ge=1)
    end_line: int | None = None
    end_column: int | None = None
    snippet: str | None = Field(
        default=None, description="Offending text, trimmed; never includes secrets verbatim."
    )


class Finding(BaseModel):
    model_config = ConfigDict(frozen=True)

    rule_id: str = Field(pattern=r"^SC-[A-Z]+-\d{3}$")
    title: str
    message: str
    severity: Severity
    confidence: Confidence
    category: Category
    location: Location
    capabilities: tuple[str, ...] = Field(default=(), description="Capability tags this finding implies.")
    remediation: str | None = None
    references: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    skill: str | None = Field(default=None, description="Skill package name the finding belongs to.")

    @property
    def fingerprint(self) -> str:
        """Stable identifier used for baselines/suppressions. Ignores line numbers so edits above don't churn."""
        raw = "|".join([self.rule_id, self.location.path, (self.location.snippet or "").strip()])
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]

    def with_skill(self, skill: str) -> Finding:
        return self.model_copy(update={"skill": skill})


class SkillFile(BaseModel):
    """A parsed file within a skill package."""

    model_config = ConfigDict(frozen=True)

    path: str
    kind: FileKind
    text: str = ""
    frontmatter: dict[str, Any] = Field(default_factory=dict)
    body_offset: int = Field(default=0, description="Line offset of the body when frontmatter was stripped.")
    language: str | None = None
    size: int = 0
    is_symlink: bool = False
    symlink_target: str | None = None
    executable: bool = False

    @property
    def lines(self) -> list[str]:
        return self.text.splitlines()


class SkillKind(StrEnum):
    SKILL = "skill"  # Agent Skills (SKILL.md)
    AGENT = "agent"  # .agent.md / .chatmode.md
    PROMPT = "prompt"  # .prompt.md
    INSTRUCTIONS = "instructions"  # .instructions.md, AGENTS.md, CLAUDE.md, copilot-instructions.md
    CURSOR_RULES = "cursor-rules"
    MCP_CONFIG = "mcp-config"
    PLUGIN = "plugin"  # plugin.json based bundles
    UNKNOWN = "unknown"


class SkillPackage(BaseModel):
    """A discovered unit of installable agent behaviour."""

    model_config = ConfigDict(frozen=True)

    name: str
    kind: SkillKind
    root: str = Field(description="Absolute filesystem path of the package root.")
    entrypoint: str = Field(description="Relative path of the primary definition file.")
    files: tuple[SkillFile, ...] = ()
    metadata: dict[str, Any] = Field(default_factory=dict)
    publisher: str | None = None
    version: str | None = None

    @property
    def root_path(self) -> Path:
        return Path(self.root)

    @property
    def description(self) -> str:
        value = self.metadata.get("description")
        return str(value) if value else ""

    @property
    def declared_tools(self) -> tuple[str, ...]:
        tools = self.metadata.get("tools")
        if isinstance(tools, list):
            return tuple(str(t) for t in tools)
        if isinstance(tools, str):
            return tuple(t.strip() for t in tools.split(",") if t.strip())
        return ()

    def file(self, rel: str) -> SkillFile | None:
        return next((f for f in self.files if f.path == rel), None)


class CapabilityManifest(BaseModel):
    """Capabilities a skill *declares* (from `skillchain.yaml` or frontmatter) or is *inferred* to use."""

    model_config = ConfigDict(frozen=True)

    capabilities: tuple[str, ...] = ()
    evidence: dict[str, tuple[str, ...]] = Field(
        default_factory=dict, description="capability -> list of `path:line reason` strings"
    )
    source: str = Field(default="inferred", description="inferred | declared | observed")
    weak: tuple[str, ...] = Field(
        default=(),
        description="Capabilities supported only by prose heuristics (no script/config/tool evidence).",
    )

    @field_validator("capabilities", "weak")
    @classmethod
    def _dedupe_sorted(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted(set(value)))

    @property
    def strong(self) -> tuple[str, ...]:
        return tuple(c for c in self.capabilities if c not in self.weak)

    def has(self, capability: str) -> bool:
        return capability in self.capabilities or any(
            c.startswith(capability + ".") for c in self.capabilities
        )


class ManifestDiff(BaseModel):
    model_config = ConfigDict(frozen=True)

    undeclared: tuple[str, ...] = Field(default=(), description="Inferred/observed but not declared.")
    overdeclared: tuple[str, ...] = Field(default=(), description="Declared but never inferred.")
    matched: tuple[str, ...] = ()

    @property
    def clean(self) -> bool:
        return not self.undeclared


class SkillScan(BaseModel):
    """Everything the static scanner learned about a single skill package."""

    model_config = ConfigDict(frozen=True)

    package: SkillPackage
    digest: str = Field(description="Deterministic sha256 tree digest of the package.")
    findings: tuple[Finding, ...] = ()
    inferred: CapabilityManifest = Field(default_factory=CapabilityManifest)
    declared: CapabilityManifest | None = None
    observed: CapabilityManifest | None = None
    diff: ManifestDiff = Field(default_factory=ManifestDiff)

    @property
    def max_severity(self) -> Severity | None:
        return max((f.severity for f in self.findings), default=None, key=lambda s: s.rank)

    def count(self, severity: Severity, confidence: Confidence | None = None) -> int:
        return sum(
            1
            for f in self.findings
            if f.severity == severity and (confidence is None or f.confidence == confidence)
        )


class ScanResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    tool_version: str
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    target: str
    skills: tuple[SkillScan, ...] = ()
    errors: tuple[str, ...] = ()
    suppressed: int = Field(default=0, description="Findings dropped by baseline or inline suppressions.")

    @property
    def findings(self) -> list[Finding]:
        return [f for s in self.skills for f in s.findings]

    @property
    def max_severity(self) -> Severity | None:
        return max((f.severity for f in self.findings), default=None, key=lambda s: s.rank)


class Decision(StrEnum):
    ALLOW = "allow"
    QUARANTINE = "quarantine"
    BLOCK = "block"

    @property
    def rank(self) -> int:
        return {Decision.ALLOW: 0, Decision.QUARANTINE: 1, Decision.BLOCK: 2}[self]


class PolicyVerdict(BaseModel):
    model_config = ConfigDict(frozen=True)

    skill: str
    decision: Decision
    reasons: tuple[str, ...] = ()
    matched_rules: tuple[str, ...] = ()
