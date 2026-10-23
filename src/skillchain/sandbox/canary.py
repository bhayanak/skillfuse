"""Canary secrets: unique, recognisable tokens whose appearance anywhere outside the sandbox proves exfiltration."""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class Canary:
    name: str
    value: str
    kind: str  # env | file | content


@dataclass(slots=True)
class CanarySet:
    run_id: str
    canaries: list[Canary] = field(default_factory=list)

    @property
    def env(self) -> dict[str, str]:
        return {c.name: c.value for c in self.canaries if c.kind == "env"}

    @property
    def values(self) -> list[str]:
        return [c.value for c in self.canaries]

    def find(self, text: str) -> list[Canary]:
        return [c for c in self.canaries if c.value in text]


def _token(prefix: str, run_id: str, n: int = 12) -> str:
    return f"{prefix}{run_id}{secrets.token_hex(n // 2).upper()}"


def generate_canaries(run_id: str | None = None) -> CanarySet:
    run_id = run_id or secrets.token_hex(4).upper()
    cs = CanarySet(run_id=run_id)
    env = {
        "AWS_ACCESS_KEY_ID": f"AKIASKCN{run_id}{secrets.token_hex(4).upper()}"[:20],
        "AWS_SECRET_ACCESS_KEY": _token("skcn/", run_id, 24),
        "GITHUB_TOKEN": "ghp_" + _token("SKCN", run_id, 28),
        "OPENAI_API_KEY": "sk-" + _token("skcn", run_id, 32),
        "ANTHROPIC_API_KEY": "sk-ant-" + _token("skcn", run_id, 32),
        "SLACK_BOT_TOKEN": "xoxb-" + _token("skcn-", run_id, 20),
        "JIRA_API_TOKEN": _token("ATATT3SKCN", run_id, 40),
        "DATABASE_URL": f"postgres://skcn:{_token('pw', run_id, 10)}@db.internal:5432/app",
        "NPM_TOKEN": "npm_" + _token("SKCN", run_id, 28),
    }
    for k, v in env.items():
        cs.canaries.append(Canary(name=k, value=v, kind="env"))
    cs.canaries.append(Canary(name="ssh_private_key", value=_token("SKCNSSH", run_id, 32), kind="file"))
    cs.canaries.append(
        Canary(name="aws_credentials_file", value=_token("skcn/aws/", run_id, 24), kind="file")
    )
    cs.canaries.append(Canary(name="netrc_password", value=_token("skcnnetrc", run_id, 16), kind="file"))
    cs.canaries.append(Canary(name="git_credentials", value=_token("skcngit", run_id, 16), kind="file"))
    cs.canaries.append(Canary(name="dotenv_secret", value=_token("skcnenv", run_id, 16), kind="file"))
    cs.canaries.append(Canary(name="injection_marker", value=f"SKCN-INJECT-{run_id}", kind="content"))
    cs.canaries.append(Canary(name="workspace_secret", value=_token("skcnws", run_id, 16), kind="content"))
    return cs
