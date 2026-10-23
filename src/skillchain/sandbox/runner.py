"""Execution backends: ``subprocess`` (always available, shim-based observation) and ``docker`` (real isolation)."""

from __future__ import annotations

import contextlib
import os
import resource
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from skillchain.sandbox.workspace import FakeWorkspace

SHIMS_DIR = Path(__file__).parent / "shims"
DOCKER_IMAGE = "python:3.12-slim"


@dataclass(slots=True)
class ExecResult:
    command: list[str]
    returncode: int | None
    stdout: str
    stderr: str
    duration: float
    timed_out: bool = False
    backend: str = "subprocess"
    error: str | None = None


@dataclass(slots=True)
class RunnerConfig:
    timeout: float = 60.0
    backend: str = "auto"  # auto | subprocess | docker
    cpu_seconds: int = 30
    memory_bytes: int = 1 << 30
    max_procs: int = 128
    forward_http_to_mock: bool = True
    docker_image: str = DOCKER_IMAGE
    extra_env: dict[str, str] = field(default_factory=dict)


def choose_backend(requested: str) -> str:
    if requested == "docker" or (requested == "auto" and os.environ.get("SKILLCHAIN_PREFER_DOCKER") == "1"):
        if shutil.which("docker") and _docker_ok():
            return "docker"
        if requested == "docker":
            msg = "docker backend requested but docker is not available"
            raise RuntimeError(msg)
    return "subprocess"


def _docker_ok() -> bool:
    try:
        return (
            subprocess.run(["docker", "info"], capture_output=True, timeout=10, check=False).returncode == 0
        )
    except (OSError, subprocess.TimeoutExpired):
        return False


def sandbox_env(
    ws: FakeWorkspace, events: Path, mock_addr: str | None, bin_dir: Path, extra: dict[str, str]
) -> dict[str, str]:
    env: dict[str, str] = {
        "HOME": str(ws.home),
        "USER": "sandbox",
        "LOGNAME": "sandbox",
        "SHELL": "/bin/sh",
        "TMPDIR": str(ws.tmp),
        "TMP": str(ws.tmp),
        "TEMP": str(ws.tmp),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": f"{bin_dir}:/usr/local/bin:/usr/bin:/bin:/opt/homebrew/bin",
        "PWD": str(ws.workspace),
        "CI": "false",
        "TERM": "dumb",
        "SKILLCHAIN_SANDBOX": "1",
        "SKILLCHAIN_EVENTS": str(events),
        "SKILLCHAIN_WORKSPACE": str(ws.workspace),
        "SKILLCHAIN_MOCK_ADDR": mock_addr or "",
        "PYTHONPATH": str(SHIMS_DIR / "python"),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONUNBUFFERED": "1",
        "NODE_OPTIONS": f"--require {SHIMS_DIR / 'node' / 'preload.cjs'}",
        # proxies: anything that honours them goes to the recorder; everything else is caught by shims
        "GIT_TERMINAL_PROMPT": "0",
        "PIP_NO_INPUT": "1",
        "npm_config_yes": "true",
    }
    if mock_addr:
        env.update(
            {
                "HTTP_PROXY": f"http://{mock_addr}",
                "HTTPS_PROXY": f"http://{mock_addr}",
                "http_proxy": f"http://{mock_addr}",
                "https_proxy": f"http://{mock_addr}",
                "NO_PROXY": "127.0.0.1,localhost",
            }
        )
    env.update(ws.canaries.env)
    env.update(extra)
    return env


def _limits(cfg: RunnerConfig) -> None:  # pragma: no cover - runs in the child
    with contextlib.suppress(ValueError, OSError):
        resource.setrlimit(resource.RLIMIT_CPU, (cfg.cpu_seconds, cfg.cpu_seconds + 5))
    if sys.platform != "darwin":
        # RLIMIT_AS breaks many runtimes on macOS; RLIMIT_NPROC is per-user there and would starve the child.
        with contextlib.suppress(ValueError, OSError):
            resource.setrlimit(resource.RLIMIT_AS, (cfg.memory_bytes, cfg.memory_bytes))
        with contextlib.suppress(ValueError, OSError):
            soft, hard = resource.getrlimit(resource.RLIMIT_NPROC)
            limit = max(cfg.max_procs, 512)
            if soft == resource.RLIM_INFINITY or soft > limit:
                resource.setrlimit(resource.RLIMIT_NPROC, (limit, hard))
    with contextlib.suppress(ValueError, OSError):
        resource.setrlimit(resource.RLIMIT_FSIZE, (256 << 20, 256 << 20))
    os.setsid()


def run_subprocess(
    command: list[str], ws: FakeWorkspace, env: dict[str, str], cfg: RunnerConfig
) -> ExecResult:
    start = time.monotonic()
    try:
        proc = subprocess.Popen(
            command,
            cwd=ws.workspace,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            text=True,
            preexec_fn=lambda: _limits(cfg),  # noqa: PLW1509
        )
    except OSError as exc:
        return ExecResult(command, None, "", "", 0.0, error=str(exc))
    try:
        out, err = proc.communicate(timeout=cfg.timeout)
        timed_out = False
    except subprocess.TimeoutExpired:
        _kill_group(proc)
        out, err = proc.communicate()
        timed_out = True
    return ExecResult(
        command, proc.returncode, out[-64_000:], err[-64_000:], time.monotonic() - start, timed_out
    )


def _kill_group(proc: subprocess.Popen[str]) -> None:
    try:
        os.killpg(proc.pid, 9)
    except (ProcessLookupError, PermissionError, OSError):
        proc.kill()


def run_docker(command: list[str], ws: FakeWorkspace, env: dict[str, str], cfg: RunnerConfig) -> ExecResult:
    """Run inside a throwaway container with no network. The sandbox root is bind-mounted at the same path so
    event/log paths stay valid; shims are mounted read-only."""
    start = time.monotonic()
    env_args: list[str] = []
    for k, v in env.items():
        if k in {"PATH"}:
            continue
        env_args += ["-e", f"{k}={v}"]
    bin_dir = Path(env.get("SKILLCHAIN_BIN", str(ws.root / "bin")))
    docker_cmd = [
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        str(cfg.max_procs),
        "--memory",
        str(cfg.memory_bytes),
        "--cpus",
        "1",
        "--tmpfs",
        "/tmp:rw,size=256m",  # noqa: S108
        "-v",
        f"{ws.root}:{ws.root}:rw",
        "-v",
        f"{SHIMS_DIR}:{SHIMS_DIR}:ro",
        "-w",
        str(ws.workspace),
        "-e",
        f"PATH={bin_dir}:/usr/local/bin:/usr/bin:/bin",
        *env_args,
        cfg.docker_image,
        *command,
    ]
    try:
        proc = subprocess.run(
            docker_cmd, capture_output=True, text=True, timeout=cfg.timeout + 30, check=False
        )
    except subprocess.TimeoutExpired as exc:
        return ExecResult(
            command,
            None,
            (exc.stdout or b"").decode() if isinstance(exc.stdout, bytes) else (exc.stdout or ""),
            "",
            time.monotonic() - start,
            True,
            backend="docker",
        )
    except OSError as exc:
        return ExecResult(command, None, "", "", 0.0, backend="docker", error=str(exc))
    return ExecResult(
        command,
        proc.returncode,
        proc.stdout[-64_000:],
        proc.stderr[-64_000:],
        time.monotonic() - start,
        backend="docker",
    )
