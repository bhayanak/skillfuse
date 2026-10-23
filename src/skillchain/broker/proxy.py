"""Runtime permission broker: an MCP stdio proxy that sits between a host and a real MCP server.

Every ``tools/call`` is mapped to capabilities, evaluated against a :class:`BrokerPolicy`, and either forwarded,
denied (JSON-RPC error returned to the host), or held for interactive approval. Observed behaviour is
compared with the skill's approved capability set to raise behaviour-drift alerts.
"""

from __future__ import annotations

import contextlib
import json
import re
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TextIO

import yaml
from pydantic import BaseModel, ConfigDict, Field

from skillchain.capabilities.taxonomy import WRITE_CAPABILITIES, capabilities_for_tool, covers
from skillchain.core.models import Decision

_SECRET_ARG = re.compile(
    r"(AKIA[A-Z0-9]{16}|ghp_[A-Za-z0-9]{30,}|sk-[A-Za-z0-9_-]{30,}|xox[abprs]-[A-Za-z0-9-]{10,}|-----BEGIN [A-Z ]*PRIVATE KEY)"
)


class BrokerPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = "broker"
    default: Decision = Decision.ALLOW
    approved_capabilities: list[str] = Field(
        default_factory=list, description="Capabilities the skill was approved for (e.g. from the lockfile)."
    )
    deny_capabilities: list[str] = Field(default_factory=list)
    ask_capabilities: list[str] = Field(default_factory=lambda: sorted(WRITE_CAPABILITIES))
    deny_tools: list[str] = Field(default_factory=list, description="Glob patterns over tool names.")
    allow_tools: list[str] = Field(default_factory=list)
    max_calls_per_minute: int = Field(default=120, ge=1)
    block_secret_arguments: bool = True
    drift_is_quarantine: bool = Field(
        default=True,
        description="Calls outside approved capabilities require approval instead of being allowed.",
    )

    @classmethod
    def load(cls, path: Path) -> BrokerPolicy:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        return cls.model_validate(data)


@dataclass(slots=True)
class CallDecision:
    tool: str
    capabilities: tuple[str, ...]
    decision: Decision
    reasons: tuple[str, ...]
    drift: bool = False


@dataclass(slots=True)
class BrokerStats:
    calls: int = 0
    allowed: int = 0
    denied: int = 0
    asked: int = 0
    drift_alerts: int = 0
    per_tool: dict[str, int] = field(default_factory=dict)
    observed_capabilities: set[str] = field(default_factory=set)
    timestamps: list[float] = field(default_factory=list)


Approver = Callable[[CallDecision, dict[str, Any]], bool]


def _glob(name: str, patterns: list[str]) -> bool:
    import fnmatch

    return any(fnmatch.fnmatchcase(name.lower(), p.lower()) for p in patterns)


def decide(
    tool: str, arguments: dict[str, Any] | None, policy: BrokerPolicy, stats: BrokerStats
) -> CallDecision:
    caps = capabilities_for_tool(tool) or ("mcp.tools",)
    reasons: list[str] = []
    now = time.monotonic()
    stats.timestamps = [t for t in stats.timestamps if now - t < 60]
    if len(stats.timestamps) >= policy.max_calls_per_minute:
        return CallDecision(
            tool, caps, Decision.BLOCK, (f"rate limit {policy.max_calls_per_minute}/min exceeded",)
        )
    if _glob(tool, policy.deny_tools):
        return CallDecision(tool, caps, Decision.BLOCK, ("tool is on the deny list",))
    if policy.block_secret_arguments and arguments and _SECRET_ARG.search(json.dumps(arguments)):
        return CallDecision(tool, caps, Decision.BLOCK, ("arguments contain credential material",))
    for d in policy.deny_capabilities:
        if any(covers(d, c) for c in caps):
            return CallDecision(tool, caps, Decision.BLOCK, (f"capability '{d}' is denied",))
    drift = bool(policy.approved_capabilities) and not all(
        any(covers(a, c) for a in policy.approved_capabilities) for c in caps
    )
    if drift:
        reasons.append(f"behaviour drift: {', '.join(caps)} not in approved set")
    if _glob(tool, policy.allow_tools) and not drift:
        return CallDecision(tool, caps, Decision.ALLOW, ("tool is on the allow list",), drift)
    ask = any(any(covers(a, c) for a in policy.ask_capabilities) for c in caps) or (
        drift and policy.drift_is_quarantine
    )
    if ask:
        reasons.append("requires approval")
        return CallDecision(tool, caps, Decision.QUARANTINE, tuple(reasons), drift)
    return CallDecision(tool, caps, policy.default, tuple(reasons) or ("default",), drift)


class Broker:
    """Proxy JSON-RPC lines between ``host`` (stdin/stdout) and a spawned MCP server."""

    def __init__(
        self,
        server_cmd: list[str],
        policy: BrokerPolicy,
        *,
        approver: Approver | None = None,
        audit_log: Path | None = None,
        host_in: TextIO | None = None,
        host_out: TextIO | None = None,
        alert: Callable[[str], None] | None = None,
    ) -> None:
        self.server_cmd = server_cmd
        self.policy = policy
        self.approver = approver or (lambda _d, _a: False)
        self.audit_log = audit_log
        self.host_in = host_in or sys.stdin
        self.host_out = host_out or sys.stdout
        self.alert = alert or (lambda m: print(m, file=sys.stderr))  # noqa: T201
        self.stats = BrokerStats()
        self._lock = threading.Lock()

    def _audit(self, record: dict[str, Any]) -> None:
        if self.audit_log is None:
            return
        record["ts"] = time.time()
        with self.audit_log.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, default=str) + "\n")

    def handle_host_message(self, raw: str) -> tuple[str | None, str | None]:
        """Return (forward_to_server, reply_to_host)."""
        try:
            msg = json.loads(raw)
        except json.JSONDecodeError:
            return raw, None
        if msg.get("method") != "tools/call":
            return raw, None
        params = msg.get("params") or {}
        tool = str(params.get("name") or "")
        arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else None
        with self._lock:
            d = decide(tool, arguments, self.policy, self.stats)
            self.stats.calls += 1
            self.stats.timestamps.append(time.monotonic())
            self.stats.per_tool[tool] = self.stats.per_tool.get(tool, 0) + 1
            self.stats.observed_capabilities.update(d.capabilities)
            if d.drift:
                self.stats.drift_alerts += 1
                self.alert(
                    f"[skillchain-broker] DRIFT: {tool} -> {', '.join(d.capabilities)} ({'; '.join(d.reasons)})"
                )
        final = d.decision
        if d.decision == Decision.QUARANTINE:
            self.stats.asked += 1
            final = Decision.ALLOW if self.approver(d, arguments or {}) else Decision.BLOCK
        self._audit(
            {
                "tool": tool,
                "capabilities": list(d.capabilities),
                "decision": final.value,
                "reasons": list(d.reasons),
                "drift": d.drift,
                "id": msg.get("id"),
            }
        )
        if final == Decision.ALLOW:
            self.stats.allowed += 1
            return raw, None
        self.stats.denied += 1
        err = {
            "jsonrpc": "2.0",
            "id": msg.get("id"),
            "error": {
                "code": -32001,
                "message": f"skillchain broker denied '{tool}': {'; '.join(d.reasons)}",
                "data": {"capabilities": list(d.capabilities)},
            },
        }
        return None, json.dumps(err)

    def run(self) -> int:
        proc = subprocess.Popen(
            self.server_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1
        )
        if proc.stdin is None or proc.stdout is None:  # pragma: no cover - PIPE guarantees both
            msg = "failed to open server pipes"
            raise RuntimeError(msg)
        server_in, server_out = proc.stdin, proc.stdout

        def pump_server() -> None:
            for line in server_out:
                self.host_out.write(line)
                self.host_out.flush()

        t = threading.Thread(target=pump_server, daemon=True)
        t.start()
        try:
            for line in self.host_in:
                if not line.strip():
                    continue
                fwd, reply = self.handle_host_message(line.rstrip("\n"))
                if fwd is not None:
                    server_in.write(fwd + "\n")
                    server_in.flush()
                if reply is not None:
                    self.host_out.write(reply + "\n")
                    self.host_out.flush()
        finally:
            with contextlib.suppress(OSError):
                server_in.close()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        return proc.returncode or 0
