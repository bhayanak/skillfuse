"""Capability taxonomy and the tool-name → capability mapping tables.

Capabilities are dotted, hierarchical strings. A declared parent (``network``) covers its children
(``network.egress``). The taxonomy is intentionally small and host-agnostic; host-specific tool names are
mapped onto it via :data:`TOOL_CAPABILITIES`.
"""

from __future__ import annotations

import fnmatch
import re
from typing import Final

CAPABILITIES: Final[dict[str, str]] = {
    "network.egress": "Make outbound network requests",
    "network.listen": "Open listening sockets",
    "filesystem.read": "Read files outside the skill package",
    "filesystem.write": "Create or modify files",
    "filesystem.delete": "Delete files or directories",
    "shell.exec": "Execute shell commands",
    "process.spawn": "Spawn external processes / servers",
    "env.read": "Read environment variables",
    "secrets.read": "Access credential material (tokens, keys, credential files)",
    "package.install": "Install packages or dependencies",
    "git.read": "Read git history / status",
    "git.write": "Commit, push, or rewrite git history",
    "github.read": "Read GitHub issues, PRs, repos",
    "github.write": "Create/modify GitHub issues, PRs, comments, releases",
    "jira.read": "Read Jira issues",
    "jira.write": "Create/modify/transition Jira issues",
    "confluence.read": "Read Confluence pages",
    "confluence.write": "Create/modify Confluence pages",
    "slack.read": "Read Slack messages",
    "slack.write": "Send Slack messages / files",
    "cloud.read": "Read cloud resources (AWS/Azure/GCP)",
    "cloud.write": "Create/modify/delete cloud resources",
    "database.read": "Query databases",
    "database.write": "Modify database contents or schema",
    "browser.automation": "Drive a web browser",
    "mcp.tools": "Invoke MCP tools",
    "mcp.server": "Define or launch MCP servers",
    "system.admin": "Elevated privileges / system configuration",
    "system.persistence": "Install persistent hooks, services, or scheduled tasks",
    "ssh.exec": "Execute commands on remote hosts over SSH",
    "email.send": "Send e-mail",
    "ai.model": "Call external LLM/AI APIs",
}

# Glob patterns over tool names (case-insensitive) → capabilities. First match wins per capability set union.
TOOL_CAPABILITIES: Final[tuple[tuple[str, tuple[str, ...]], ...]] = (
    # VS Code / Copilot built-ins
    ("runcommands", ("shell.exec",)),
    ("run_in_terminal", ("shell.exec",)),
    ("runtasks", ("shell.exec",)),
    ("terminal*", ("shell.exec",)),
    ("execution_subagent", ("shell.exec",)),
    ("editfiles", ("filesystem.write",)),
    ("edit_file", ("filesystem.write",)),
    ("create_file", ("filesystem.write",)),
    ("createfile", ("filesystem.write",)),
    ("replace_string_in_file", ("filesystem.write",)),
    ("multi_replace_string_in_file", ("filesystem.write",)),
    ("create_directory", ("filesystem.write",)),
    ("readfile", ("filesystem.read",)),
    ("read_file", ("filesystem.read",)),
    ("codebase", ("filesystem.read",)),
    ("search", ("filesystem.read",)),
    ("fetch", ("network.egress",)),
    ("fetch_webpage", ("network.egress",)),
    ("websearch", ("network.egress",)),
    ("openbrowser*", ("browser.automation", "network.egress")),
    ("open_browser_page", ("browser.automation", "network.egress")),
    ("playwright*", ("browser.automation", "network.egress")),
    ("mcp_playwright*", ("browser.automation", "network.egress")),
    ("mcp_chrome*", ("browser.automation", "network.egress")),
    ("githubrepo", ("github.read", "network.egress")),
    ("github_repo", ("github.read", "network.egress")),
    ("github-pull-request_create*", ("github.write", "network.egress")),
    ("github-pull-request_*", ("github.read", "network.egress")),
    ("mcp_github_*create*", ("github.write", "network.egress")),
    ("mcp_github_*update*", ("github.write", "network.egress")),
    ("mcp_github_*", ("github.read", "network.egress")),
    ("mcp_atlassian*createjira*", ("jira.write", "network.egress")),
    ("mcp_atlassian*editjira*", ("jira.write", "network.egress")),
    ("mcp_atlassian*transitionjira*", ("jira.write", "network.egress")),
    ("mcp_atlassian*addcomment*", ("jira.write", "network.egress")),
    ("mcp_atlassian*addoredit*", ("jira.write", "network.egress")),
    ("mcp_atlassian*jira*", ("jira.read", "network.egress")),
    ("mcp_atlassian*createconfluence*", ("confluence.write", "network.egress")),
    ("mcp_atlassian*updateconfluence*", ("confluence.write", "network.egress")),
    ("mcp_atlassian*confluence*", ("confluence.read", "network.egress")),
    ("mcp_atlassian*executewrite*", ("jira.write", "confluence.write", "network.egress")),
    ("mcp_atlassian*executedestructive*", ("jira.write", "confluence.write", "network.egress")),
    ("mcp_atlassian*", ("jira.read", "confluence.read", "network.egress")),
    ("mcp_slack*send*", ("slack.write", "network.egress")),
    ("mcp_slack*post*", ("slack.write", "network.egress")),
    ("mcp_slack*upload*", ("slack.write", "network.egress")),
    ("mcp_slack*", ("slack.read", "network.egress")),
    ("mcp_ssh*", ("ssh.exec", "network.egress")),
    ("mcp_*sql*", ("database.read", "network.egress")),
    ("dbclient-*", ("database.read", "network.egress")),
    ("mcp_mongodb*", ("database.read", "network.egress")),
    ("mcp_*aws*", ("cloud.read", "network.egress")),
    ("mcp_*azure*", ("cloud.read", "network.egress")),
    ("mcp_*gcp*", ("cloud.read", "network.egress")),
    ("mcp_*", ("mcp.tools", "network.egress")),
    # Claude Code
    ("bash", ("shell.exec",)),
    ("write", ("filesystem.write",)),
    ("edit", ("filesystem.write",)),
    ("multiedit", ("filesystem.write",)),
    ("notebookedit", ("filesystem.write",)),
    ("read", ("filesystem.read",)),
    ("glob", ("filesystem.read",)),
    ("grep", ("filesystem.read",)),
    ("webfetch", ("network.egress",)),
    ("websearch", ("network.egress",)),
    # Cursor
    ("run_terminal_cmd", ("shell.exec",)),
    ("edit_file", ("filesystem.write",)),
    ("delete_file", ("filesystem.delete",)),
    ("web_search", ("network.egress",)),
    # Generic
    ("*shell*", ("shell.exec",)),
    ("*exec*", ("shell.exec",)),
    ("*command*", ("shell.exec",)),
    ("*delete*", ("filesystem.delete",)),
    ("*write*", ("filesystem.write",)),
    ("*edit*", ("filesystem.write",)),
    ("*http*", ("network.egress",)),
    ("*fetch*", ("network.egress",)),
    ("*browser*", ("browser.automation", "network.egress")),
)

WRITE_CAPABILITIES: Final[frozenset[str]] = frozenset(
    {
        "filesystem.write",
        "filesystem.delete",
        "shell.exec",
        "process.spawn",
        "package.install",
        "git.write",
        "github.write",
        "jira.write",
        "confluence.write",
        "slack.write",
        "cloud.write",
        "database.write",
        "system.admin",
        "system.persistence",
        "ssh.exec",
        "email.send",
    }
)

_VALID_RE = re.compile(r"^[a-z][a-z0-9]*(\.[a-z][a-z0-9_-]*)*$")


def is_valid_capability(name: str) -> bool:
    return bool(_VALID_RE.match(name)) and (
        name in CAPABILITIES or name.split(".", maxsplit=1)[0] in {c.split(".")[0] for c in CAPABILITIES}
    )


def capabilities_for_tool(tool: str) -> tuple[str, ...]:
    """Map a host tool name to capabilities. Unknown tools map to ``mcp.tools`` if MCP-shaped, else empty."""
    name = tool.strip().lower()
    if not name:
        return ()
    for pattern, caps in TOOL_CAPABILITIES:
        if fnmatch.fnmatchcase(name, pattern):
            return caps
    return ()


def covers(declared: str, used: str) -> bool:
    """``network`` covers ``network.egress``; ``filesystem.write`` covers only itself."""
    return used == declared or used.startswith(declared + ".")
