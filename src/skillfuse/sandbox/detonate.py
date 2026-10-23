"""Detonation: run every executable entrypoint of a skill inside the fake workspace and turn observations into
``SC-DYN-*`` findings plus an *observed* capability manifest."""

from __future__ import annotations

import json
import re
import shlex
import tempfile
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from skillfuse.core.models import (
    CapabilityManifest,
    Category,
    Confidence,
    FileKind,
    Finding,
    Location,
    Severity,
    SkillPackage,
)
from skillfuse.sandbox.canary import generate_canaries
from skillfuse.sandbox.mock_http import MockHttpRecorder
from skillfuse.sandbox.runner import (
    ExecResult,
    RunnerConfig,
    choose_backend,
    run_docker,
    run_subprocess,
    sandbox_env,
)
from skillfuse.sandbox.shims import install_shims
from skillfuse.sandbox.workspace import FakeWorkspace, build_workspace

_INTERPRETERS = {
    "shell": ["sh"],
    "python": ["python3"],
    "javascript": ["node"],
    "typescript": ["node"],
}
_CODE_BLOCK = re.compile(r"```(?:bash|sh|shell|zsh|console)\s*\n(.*?)```", re.DOTALL | re.IGNORECASE)
_SAFE_PREFIX = re.compile(r"^\$\s?")

DYN_RULES: dict[str, tuple[str, Severity]] = {
    "SC-DYN-001": ("Canary secret exfiltrated", Severity.CRITICAL),
    "SC-DYN-002": ("Outbound network connection attempted", Severity.HIGH),
    "SC-DYN-003": ("Credential file read", Severity.HIGH),
    "SC-DYN-004": ("File written outside the workspace", Severity.HIGH),
    "SC-DYN-005": ("Privilege escalation attempted", Severity.HIGH),
    "SC-DYN-006": ("Persistence mechanism invoked", Severity.CRITICAL),
    "SC-DYN-007": ("Package installation attempted", Severity.MEDIUM),
    "SC-DYN-008": ("DNS lookup of external host", Severity.MEDIUM),
    "SC-DYN-009": ("Execution timed out", Severity.LOW),
    "SC-DYN-010": ("MCP tool invoked", Severity.MEDIUM),
    "SC-DYN-011": ("Sub-process spawned", Severity.LOW),
    "SC-DYN-012": ("Prompt-injection marker followed", Severity.CRITICAL),
}


@dataclass(slots=True)
class Detonation:
    skill: str
    backend: str
    executions: list[ExecResult] = field(default_factory=list)
    events: list[dict[str, Any]] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    observed: CapabilityManifest = field(default_factory=CapabilityManifest)
    canaries_leaked: list[str] = field(default_factory=list)
    files_changed: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "skill": self.skill,
            "backend": self.backend,
            "executions": [
                {
                    "command": e.command,
                    "returncode": e.returncode,
                    "duration": round(e.duration, 3),
                    "timed_out": e.timed_out,
                    "error": e.error,
                    "stderr_tail": e.stderr[-500:],
                }
                for e in self.executions
            ],
            "events": self.events[:500],
            "observed": list(self.observed.capabilities),
            "canaries_leaked": self.canaries_leaked,
            "files_changed": self.files_changed,
            "findings": [f.model_dump(mode="json") for f in self.findings],
        }


def plan_commands(
    pkg: SkillPackage, skill_dir: Path, *, include_markdown_blocks: bool = False
) -> list[tuple[list[str], str]]:
    """Return (command, source-path) pairs. Scripts run with their interpreter; optional markdown shell blocks run via sh -c."""
    cmds: list[tuple[list[str], str]] = []
    for sf in pkg.files:
        if sf.kind == FileKind.SCRIPT and sf.language in _INTERPRETERS and not sf.is_symlink:
            path = skill_dir / sf.path
            if path.name.lower() in {"makefile", "justfile", "dockerfile"}:
                continue
            cmds.append(([*_INTERPRETERS[sf.language], str(path)], sf.path))
    if include_markdown_blocks:
        for sf in pkg.files:
            if sf.kind != FileKind.INSTRUCTIONS:
                continue
            for m in _CODE_BLOCK.finditer(sf.text):
                lines = [
                    _SAFE_PREFIX.sub("", ln.strip())
                    for ln in m.group(1).splitlines()
                    if ln.strip() and not ln.strip().startswith("#")
                ]
                if lines:
                    cmds.append((["sh", "-c", "\n".join(lines)], sf.path))
    # Scripts referenced from instructions (e.g. "run `bash scripts/setup.sh`") that have no interpreter mapping
    return cmds


def detonate(
    pkg: SkillPackage,
    *,
    config: RunnerConfig | None = None,
    include_markdown_blocks: bool = False,
    keep: Path | None = None,
) -> Detonation:
    cfg = config or RunnerConfig()
    backend = choose_backend(cfg.backend)
    canaries = generate_canaries()
    tmp_ctx = tempfile.TemporaryDirectory(prefix="skillfuse-sbx-") if keep is None else None
    root = Path(tmp_ctx.name) if tmp_ctx else keep
    if root is None:  # pragma: no cover - defensive; one of the two branches always yields a path
        msg = "no sandbox root"
        raise RuntimeError(msg)
    root.mkdir(parents=True, exist_ok=True)
    det = Detonation(skill=pkg.name, backend=backend)
    try:
        ws = build_workspace(root, pkg.root_path, canaries)
        events = ws.log_dir / "events.jsonl"
        events.touch()
        bin_dir = install_shims(
            root / "bin", forward_http=cfg.forward_http_to_mock and backend == "subprocess"
        )
        before = ws.snapshot()
        commands = plan_commands(pkg, ws.skill_dir, include_markdown_blocks=include_markdown_blocks)
        if backend == "subprocess":
            with MockHttpRecorder(events, ca_dir=root / "ca") as mock:
                env = sandbox_env(ws, events, mock.address, bin_dir, cfg.extra_env, ca_file=mock.ca_file)
                for cmd, _src in commands:
                    det.executions.append(run_subprocess(cmd, ws, env, cfg))
        else:
            env = sandbox_env(ws, events, None, bin_dir, {**cfg.extra_env, "SKILLFUSE_BIN": str(bin_dir)})
            for cmd, _src in commands:
                det.executions.append(run_docker(cmd, ws, env, cfg))
        after = ws.snapshot()
        det.files_changed = sorted(_changed(before, after, ws))
        det.events = _read_events(events)
        _analyse(det, ws, pkg, commands)
    finally:
        if tmp_ctx is not None:
            tmp_ctx.cleanup()
    return det


def _is_loopback(host: str) -> bool:
    h = host.split(":", maxsplit=1)[0].strip("[]")
    return h in {"localhost", "::1", "0.0.0.0", ""} or h.startswith("127.")  # noqa: S104


def _changed(
    before: dict[str, tuple[int, int]], after: dict[str, tuple[int, int]], ws: FakeWorkspace
) -> list[str]:
    out: list[str] = []
    skill_prefix = str(ws.skill_dir)
    for path, meta in after.items():
        if path.startswith(skill_prefix) or "/logs/" in path:
            continue
        if path not in before or before[path] != meta:
            out.append(path.replace(str(ws.root), "$SANDBOX"))
    return out


def _read_events(path: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if not path.exists():
        return out
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def _analyse(
    det: Detonation, ws: FakeWorkspace, pkg: SkillPackage, commands: list[tuple[list[str], str]]
) -> None:
    observed: dict[str, list[str]] = defaultdict(list)
    src_by_cmd = {tuple(c): s for c, s in commands}
    default_src = commands[0][1] if commands else pkg.entrypoint

    def add(
        rule: str,
        msg: str,
        *,
        src: str = default_src,
        caps: tuple[str, ...] = (),
        severity: Severity | None = None,
        snippet: str | None = None,
    ) -> None:
        title, sev = DYN_RULES[rule]
        det.findings.append(
            Finding(
                rule_id=rule,
                title=title,
                message=msg,
                severity=severity or sev,
                confidence=Confidence.DETERMINISTIC,
                category=Category.SANDBOX,
                location=Location(path=src, snippet=snippet),
                capabilities=caps,
                remediation="Behaviour observed at runtime inside the sandbox; review the script and declare or remove it.",
                skill=pkg.name,
            )
        )
        for c in caps:
            if msg not in observed[c]:
                observed[c].append(msg)

    seen: set[tuple[str, str]] = set()
    sandbox_root = str(ws.root)
    last_host = "?"
    for ev in det.events:
        etype = str(ev.get("type", ""))
        blob = json.dumps(ev, default=str)
        host_here = str(ev.get("host") or "")
        if host_here and not _is_loopback(host_here):
            last_host = host_here
        leaked = ws.canaries.find(blob)
        if leaked and etype in {"http", "egress", "dns", "mcp_call"}:
            names = ", ".join(sorted({c.name for c in leaked}))
            key = ("DYN-001", names)
            if key not in seen:
                seen.add(key)
                det.canaries_leaked.extend(n for n in names.split(", ") if n not in det.canaries_leaked)
                dest = host_here if host_here and not _is_loopback(host_here) else last_host
                add(
                    "SC-DYN-001",
                    f"Canary {names} sent to {dest}",
                    caps=("network.egress", "secrets.read"),
                    snippet=str(ev.get("path") or ev.get("url") or ev.get("argv"))[:160],
                )
        if etype in {"http", "egress"}:
            host = str(ev.get("host") or "?")
            if _is_loopback(host):
                continue
            key = ("DYN-002", host)
            if key not in seen:
                seen.add(key)
                add(
                    "SC-DYN-002",
                    f"Connection to {host} via {ev.get('tool') or ev.get('method')}",
                    caps=("network.egress",),
                    snippet=str(ev.get("url") or ev.get("argv") or ev.get("path"))[:160],
                )
        elif etype == "dns":
            host = str(ev.get("host") or "?")
            if ("DYN-008", host) not in seen:
                seen.add(("DYN-008", host))
                add("SC-DYN-008", f"DNS lookup of {host}", caps=("network.egress",))
        elif etype == "file_read" and ev.get("credential"):
            p = str(ev.get("path", "")).replace(sandbox_root, "$SANDBOX")
            if ("DYN-003", p) not in seen:
                seen.add(("DYN-003", p))
                add(
                    "SC-DYN-003",
                    f"Read credential file {p}",
                    caps=("secrets.read", "filesystem.read"),
                    snippet=p,
                )
        elif etype == "file_write" and ev.get("outside_workspace"):
            p = str(ev.get("path", ""))
            if sandbox_root in p and "/logs/" not in p and ("DYN-004", p) not in seen:
                seen.add(("DYN-004", p))
                add(
                    "SC-DYN-004",
                    f"Wrote {p.replace(sandbox_root, '$SANDBOX')}",
                    caps=("filesystem.write",),
                    snippet=p.replace(sandbox_root, "$SANDBOX"),
                )
        elif etype == "privesc":
            add(
                "SC-DYN-005",
                f"{ev.get('tool')} {ev.get('argv', '')}"[:200],
                caps=("system.admin",),
                snippet=str(ev.get("argv"))[:160],
            )
        elif etype == "persistence":
            add(
                "SC-DYN-006",
                f"{ev.get('tool')} {ev.get('argv', '')}"[:200],
                caps=("system.persistence",),
                snippet=str(ev.get("argv"))[:160],
            )
        elif etype == "install":
            add(
                "SC-DYN-007",
                f"{ev.get('tool')} {ev.get('argv', '')}"[:200],
                caps=("package.install", "network.egress"),
                snippet=str(ev.get("argv"))[:160],
            )
        elif etype == "mcp_call":
            add(
                "SC-DYN-010",
                f"MCP tool '{ev.get('tool')}' called",
                caps=("mcp.tools",),
                snippet=json.dumps(ev.get("arguments"))[:160],
            )
        elif etype == "spawn":
            argv = ev.get("argv") or []
            text = " ".join(argv) if isinstance(argv, list) else str(argv)
            if ("DYN-011", text) not in seen:
                seen.add(("DYN-011", text))
                add(
                    "SC-DYN-011",
                    f"Spawned: {text[:120]}",
                    caps=("process.spawn", "shell.exec") if ev.get("shell") else ("process.spawn",),
                    snippet=text[:160],
                )
        elif etype == "fs":
            text = f"{ev.get('tool')} {ev.get('argv', '')}"
            if ev.get("tool") == "rm" and ("-r" in text or "-R" in text):
                observed["filesystem.delete"].append(text[:120])
            if ev.get("tool") == "chmod":
                observed["filesystem.write"].append(text[:120])
        elif etype == "git":
            text = str(ev.get("argv", ""))
            if re.search(r"\b(push|commit|rebase|reset|tag|merge)\b", text):
                observed["git.write"].append(text[:120])
            else:
                observed["git.read"].append(text[:120])
        elif etype == "cloud":
            observed["cloud.read"].append(f"{ev.get('tool')} {ev.get('argv', '')}"[:120])
    # Persistence files touched in fake HOME
    for changed in det.files_changed:
        if any(
            x in changed
            for x in (
                ".bashrc",
                ".zshrc",
                ".profile",
                "authorized_keys",
                "LaunchAgents",
                "systemd",
                "crontab",
            )
        ):
            add(
                "SC-DYN-006",
                f"Modified {changed}",
                caps=("system.persistence", "filesystem.write"),
                snippet=changed,
            )
        elif "/home/" in changed:
            add("SC-DYN-004", f"Modified {changed} in fake HOME", caps=("filesystem.write",), snippet=changed)
    # Injection marker: did any outbound payload include the README marker? (model-free proxy for PI)
    marker = next((c for c in ws.canaries.canaries if c.name == "injection_marker"), None)
    if marker and any(
        marker.value in json.dumps(ev, default=str)
        for ev in det.events
        if ev.get("type") in {"http", "egress", "mcp_call"}
    ):
        add(
            "SC-DYN-012",
            "Outbound payload contained the workspace prompt-injection marker",
            caps=("network.egress",),
        )
    for ex in det.executions:
        if ex.timed_out:
            add(
                "SC-DYN-009",
                f"{' '.join(shlex.quote(c) for c in ex.command[:3])} exceeded the time limit",
                src=src_by_cmd.get(tuple(ex.command), default_src),
                caps=(),
            )
    det.observed = CapabilityManifest(
        capabilities=tuple(sorted(observed)),
        evidence={k: tuple(v[:8]) for k, v in sorted(observed.items())},
        source="observed",
    )
    det.findings.sort(key=lambda f: (-f.severity.rank, f.rule_id))
