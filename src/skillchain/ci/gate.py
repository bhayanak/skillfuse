"""CI gate semantics: combine scan, policy, and lock verification into one exit code plus annotations."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from skillchain.core.models import Confidence, Decision, Finding, PolicyVerdict, ScanResult, Severity
from skillchain.lockfile import LockStatus, LockVerification

EXIT_OK = 0
EXIT_FINDINGS = 1  # severity threshold exceeded
EXIT_BLOCKED = 2  # policy block
EXIT_QUARANTINE = 3  # policy quarantine (only when --fail-on-quarantine)
EXIT_LOCK = 4  # lockfile drift
EXIT_ERROR = 10


@dataclass(slots=True)
class GateConfig:
    fail_on: Severity | None = Severity.HIGH
    fail_on_heuristic: bool = False
    fail_on_quarantine: bool = False
    require_lock: bool = False


@dataclass(slots=True)
class GateOutcome:
    exit_code: int
    reasons: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.exit_code == EXIT_OK


def evaluate_gate(
    result: ScanResult,
    verdicts: dict[str, PolicyVerdict],
    lock: LockVerification | None,
    cfg: GateConfig,
) -> GateOutcome:
    reasons: list[str] = []
    code = EXIT_OK
    if result.errors:
        reasons.extend(f"error: {e}" for e in result.errors)
        code = max(code, EXIT_ERROR)
    blocked = [v for v in verdicts.values() if v.decision == Decision.BLOCK]
    quarantined = [v for v in verdicts.values() if v.decision == Decision.QUARANTINE]
    if blocked:
        reasons.extend(f"blocked: {v.skill} ({'; '.join(v.reasons[:2])})" for v in blocked)
        code = max(code, EXIT_BLOCKED)
    if quarantined and cfg.fail_on_quarantine:
        reasons.extend(f"quarantined: {v.skill} ({'; '.join(v.reasons[:2])})" for v in quarantined)
        code = max(code, EXIT_QUARANTINE)
    if cfg.fail_on is not None:
        over = [
            f
            for f in result.findings
            if f.severity >= cfg.fail_on
            and (cfg.fail_on_heuristic or f.confidence == Confidence.DETERMINISTIC)
        ]
        if over:
            reasons.append(f"{len(over)} finding(s) at or above {cfg.fail_on.value}")
            code = max(code, EXIT_FINDINGS)
    if lock is not None and not lock.ok:
        for r in lock.failures:
            if r.status == LockStatus.MISSING and not cfg.require_lock:
                continue
            reasons.append(f"lock {r.status.value}: {r.name} {'; '.join(r.details[:2])}")
            code = max(code, EXIT_LOCK)
    return GateOutcome(exit_code=code, reasons=reasons)


def github_annotation(f: Finding, root: Path | None = None) -> str:
    level = {Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning"}.get(
        f.severity, "notice"
    )
    path = f.location.path
    if root is not None:
        try:
            path = (root / f.location.path).resolve().relative_to(Path.cwd().resolve()).as_posix()
        except ValueError:
            path = (root / f.location.path).as_posix()
    msg = (
        f"{f.rule_id} [{f.confidence.value}] {f.message}".replace("%", "%25")
        .replace("\r", "%0D")
        .replace("\n", "%0A")
    )
    title = f.title.replace("%", "%25").replace(",", "%2C").replace(":", "%3A")
    return f"::{level} file={path},line={f.location.line},col={f.location.column},title={title}::{msg}"


def in_github_actions() -> bool:
    return os.environ.get("GITHUB_ACTIONS") == "true"


def write_step_summary(markdown: str) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with Path(path).open("a", encoding="utf-8") as fh:
            fh.write(markdown + "\n")


def set_output(name: str, value: str) -> None:
    path = os.environ.get("GITHUB_OUTPUT")
    if path:
        with Path(path).open("a", encoding="utf-8") as fh:
            fh.write(f"{name}={value}\n")
