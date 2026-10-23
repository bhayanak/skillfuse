"""Parsers for machine-readable configuration bundled with skills (MCP configs, plugin manifests)."""

from __future__ import annotations

import json
import re
from typing import Any

import yaml

_LINE_COMMENT = re.compile(r"(?m)^\s*//.*$")
_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_TRAILING_COMMA = re.compile(r",(\s*[}\]])")


def parse_jsonc(text: str) -> Any:
    """Parse JSON with comments and trailing commas (VS Code style). Falls back to YAML."""
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    stripped = _BLOCK_COMMENT.sub("", _LINE_COMMENT.sub("", text))
    stripped = _TRAILING_COMMA.sub(r"\1", stripped)
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        try:
            return yaml.safe_load(text)
        except yaml.YAMLError:
            return None


class McpServer:
    """Normalised view over the many MCP config dialects."""

    __slots__ = ("args", "command", "env", "headers", "name", "transport", "url")

    def __init__(self, name: str, raw: dict[str, Any]) -> None:
        self.name = name
        self.command: str | None = _str_or_none(raw.get("command"))
        args = raw.get("args") or []
        self.args: list[str] = [str(a) for a in args] if isinstance(args, list) else []
        self.url: str | None = _str_or_none(raw.get("url") or raw.get("serverUrl") or raw.get("endpoint"))
        env = raw.get("env") or raw.get("environment") or {}
        self.env: dict[str, str] = {str(k): str(v) for k, v in env.items()} if isinstance(env, dict) else {}
        headers = raw.get("headers") or {}
        self.headers: dict[str, str] = (
            {str(k): str(v) for k, v in headers.items()} if isinstance(headers, dict) else {}
        )
        self.transport: str = str(
            raw.get("type") or raw.get("transport") or ("http" if self.url else "stdio")
        )

    @property
    def command_line(self) -> str:
        return " ".join([self.command or "", *self.args]).strip()


def extract_mcp_servers(data: Any) -> list[McpServer]:
    if not isinstance(data, dict):
        return []
    servers: Any = data.get("servers") or data.get("mcpServers") or data.get("mcp_servers")
    if servers is None and all(isinstance(v, dict) and ("command" in v or "url" in v) for v in data.values()):
        servers = data
    if not isinstance(servers, dict):
        return []
    return [McpServer(str(name), raw) for name, raw in servers.items() if isinstance(raw, dict)]


def _str_or_none(value: Any) -> str | None:
    return str(value) if value is not None else None
