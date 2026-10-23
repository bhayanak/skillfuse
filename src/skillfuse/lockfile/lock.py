"""``skillfuse.lock`` — the signed-off set of approved skills, their digests, capabilities and findings."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from skillfuse import __version__
from skillfuse.core.hashing import text_digest
from skillfuse.core.models import Decision, PolicyVerdict, ScanResult, SkillScan

LOCK_FILENAME = "skillfuse.lock"


class LockedSigner(BaseModel):
    model_config = ConfigDict(frozen=True)

    keyid: str | None = None
    publisher: str | None = None


class LockedSkill(BaseModel):
    model_config = ConfigDict(frozen=True)

    path: str
    kind: str
    entrypoint: str
    digest: str
    capabilities: tuple[str, ...] = ()
    declared: tuple[str, ...] | None = None
    decision: Decision = Decision.ALLOW
    findings: tuple[str, ...] = Field(default=(), description="Accepted finding fingerprints.")
    signer: LockedSigner | None = None


class Lockfile(BaseModel):
    model_config = ConfigDict(frozen=True, populate_by_name=True)

    schema_: str = Field(default="skillfuse/lock/v1", alias="schema")
    generated_at: str
    tool_version: str
    policy: dict[str, str | None] = Field(default_factory=dict)
    skills: dict[str, LockedSkill] = Field(default_factory=dict)

    def dump(self) -> str:
        return json.dumps(self.model_dump(mode="json", by_alias=True), indent=2, sort_keys=True) + "\n"

    @classmethod
    def load(cls, path: Path) -> Lockfile:
        return cls.model_validate(json.loads(path.read_text(encoding="utf-8")))

    def write(self, path: Path) -> None:
        path.write_text(self.dump(), encoding="utf-8")


class LockStatus(StrEnum):
    OK = "ok"
    MISSING = "missing"  # skill present in tree but not in lock
    REMOVED = "removed"  # skill in lock but no longer present
    DIGEST_CHANGED = "digest-changed"
    NEW_FINDINGS = "new-findings"
    NEW_CAPABILITIES = "new-capabilities"
    BLOCKED = "blocked"


class SkillLockResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    status: LockStatus
    details: tuple[str, ...] = ()


class LockVerification(BaseModel):
    model_config = ConfigDict(frozen=True)

    results: tuple[SkillLockResult, ...] = ()

    @property
    def ok(self) -> bool:
        return all(r.status == LockStatus.OK for r in self.results)

    @property
    def failures(self) -> list[SkillLockResult]:
        return [r for r in self.results if r.status != LockStatus.OK]


def _rel(root: str, base: Path) -> str:
    try:
        return Path(root).resolve().relative_to(base.resolve()).as_posix() or "."
    except ValueError:
        return Path(root).as_posix()


def generate_lock(
    result: ScanResult,
    verdicts: dict[str, PolicyVerdict],
    *,
    base: Path,
    policy_name: str | None = None,
    policy_text: str | None = None,
    signers: dict[str, LockedSigner] | None = None,
    include_blocked: bool = False,
) -> Lockfile:
    skills: dict[str, LockedSkill] = {}
    for scan in result.skills:
        verdict = verdicts.get(scan.package.name)
        decision = verdict.decision if verdict else Decision.ALLOW
        if decision == Decision.BLOCK and not include_blocked:
            continue
        skills[scan.package.name] = _locked(scan, decision, base, (signers or {}).get(scan.package.name))
    return Lockfile(
        generated_at=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        tool_version=__version__,
        policy={"name": policy_name, "digest": text_digest(policy_text) if policy_text else None},
        skills=dict(sorted(skills.items())),
    )


def _locked(scan: SkillScan, decision: Decision, base: Path, signer: LockedSigner | None) -> LockedSkill:
    return LockedSkill(
        path=_rel(scan.package.root, base),
        kind=scan.package.kind.value,
        entrypoint=scan.package.entrypoint,
        digest=scan.digest,
        capabilities=scan.inferred.capabilities,
        declared=scan.declared.capabilities if scan.declared else None,
        decision=decision,
        findings=tuple(sorted(f.fingerprint for f in scan.findings)),
        signer=signer,
    )


def verify_lock(
    lock: Lockfile, result: ScanResult, verdicts: dict[str, PolicyVerdict] | None = None
) -> LockVerification:
    verdicts = verdicts or {}
    results: list[SkillLockResult] = []
    seen: set[str] = set()
    for scan in result.skills:
        name = scan.package.name
        seen.add(name)
        locked = lock.skills.get(name)
        if locked is None:
            results.append(
                SkillLockResult(name=name, status=LockStatus.MISSING, details=("not present in lockfile",))
            )
            continue
        verdict = verdicts.get(name)
        if verdict and verdict.decision == Decision.BLOCK:
            results.append(SkillLockResult(name=name, status=LockStatus.BLOCKED, details=verdict.reasons))
            continue
        if locked.digest != scan.digest:
            changed_fps = sorted({f.fingerprint for f in scan.findings} - set(locked.findings))
            changed_caps = sorted(set(scan.inferred.capabilities) - set(locked.capabilities))
            details = [f"locked {locked.digest[:23]}… != current {scan.digest[:23]}…"]
            if changed_caps:
                details.append(f"new capabilities: {', '.join(changed_caps)}")
            if changed_fps:
                details.append(f"{len(changed_fps)} new finding(s)")
            results.append(
                SkillLockResult(name=name, status=LockStatus.DIGEST_CHANGED, details=tuple(details))
            )
            continue
        new_caps = sorted(set(scan.inferred.capabilities) - set(locked.capabilities))
        if new_caps:
            results.append(
                SkillLockResult(name=name, status=LockStatus.NEW_CAPABILITIES, details=tuple(new_caps))
            )
            continue
        new_findings = {f.fingerprint: f for f in scan.findings if f.fingerprint not in locked.findings}
        if new_findings:
            finding_details = tuple(
                f"{f.rule_id} {f.location.path}:{f.location.line}" for f in list(new_findings.values())[:10]
            )
            results.append(
                SkillLockResult(name=name, status=LockStatus.NEW_FINDINGS, details=finding_details)
            )
            continue
        results.append(SkillLockResult(name=name, status=LockStatus.OK))
    for name in lock.skills:
        if name not in seen:
            results.append(
                SkillLockResult(name=name, status=LockStatus.REMOVED, details=("in lockfile but not found",))
            )
    return LockVerification(results=tuple(results))
