"""Dynamic detonation of skills in a canary-seeded fake workspace."""

from skillfuse.sandbox.canary import Canary, CanarySet, generate_canaries
from skillfuse.sandbox.detonate import DYN_RULES, Detonation, detonate, plan_commands
from skillfuse.sandbox.runner import ExecResult, RunnerConfig, choose_backend
from skillfuse.sandbox.workspace import FakeWorkspace, build_workspace

__all__ = [
    "DYN_RULES",
    "Canary",
    "CanarySet",
    "Detonation",
    "ExecResult",
    "FakeWorkspace",
    "RunnerConfig",
    "build_workspace",
    "choose_backend",
    "detonate",
    "generate_canaries",
    "plan_commands",
]
