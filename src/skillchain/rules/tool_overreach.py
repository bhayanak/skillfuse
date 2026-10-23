"""SC-TOOL-*: tool declarations that exceed the stated purpose, and risky MCP server definitions."""

from __future__ import annotations

import re
from collections.abc import Iterator

from skillchain.core.models import Category, Confidence, FileKind, Finding, Severity, SkillFile
from skillchain.formats.configs import extract_mcp_servers, parse_jsonc
from skillchain.rules.base import Rule, RuleContext

READ_ONLY_HINTS = re.compile(
    r"\b(read[- ]only|review(er|s|ing)?|analy[sz]e|analysis|explain|summari[sz]e|document(ation)?|lint|audit|inspect|report|explore|q&a|question)\b",
    re.IGNORECASE,
)
WRITE_TOOL_HINTS = re.compile(
    r"(edit|write|create|delete|remove|run|exec|terminal|shell|command|push|commit|deploy|transition|update|send|post|upload|install|destructive|sudo)",
    re.IGNORECASE,
)
NETWORK_TOOL_HINTS = re.compile(r"(fetch|http|web|browser|url|request|curl|download)", re.IGNORECASE)
_SECRET_VALUE = re.compile(r"^(?!\$\{?[A-Z_]+\}?$)(?!\$\{input:)(?!\$\{env:)(?!<).{12,}$")
_SECRET_KEY = re.compile(r"(token|secret|password|passwd|api[_-]?key|auth|credential|cookie)", re.IGNORECASE)
_UNPINNED_RUNNER = re.compile(r"^(npx|uvx|pipx|bunx|dlx|pnpm)$", re.IGNORECASE)


class WildcardTools(Rule):
    id = "SC-TOOL-001"
    title = "Over-broad tool grant"
    description = "Agent/prompt grants all tools or an unusually large tool set."
    severity = Severity.MEDIUM
    confidence = Confidence.DETERMINISTIC
    category = Category.TOOL_OVERREACH
    capabilities = ("mcp.tools",)
    remediation = "Enumerate the minimal tools the task needs."

    def check_package(self, ctx: RuleContext) -> Iterator[Finding]:
        pkg = ctx.package
        tools = pkg.declared_tools
        if not tools:
            return
        entry = pkg.file(pkg.entrypoint)
        wild = [t for t in tools if t in {"*", "all", "**"} or t.endswith("/*") or t.endswith(".*")]
        if wild:
            yield self.finding(
                entry,
                path=pkg.entrypoint,
                snippet=", ".join(wild),
                message=f"Wildcard tool grant: {', '.join(wild)}",
            )
        elif len(tools) > 25:
            yield self.finding(
                entry,
                path=pkg.entrypoint,
                snippet=", ".join(tools[:6]) + "…",
                message=f"{len(tools)} tools granted; large grants widen blast radius",
                severity=Severity.LOW,
            )


class PurposeMismatch(Rule):
    id = "SC-TOOL-002"
    title = "Tools exceed stated purpose"
    description = "Description reads as read-only/analytical, yet write/exec/network tools are granted."
    severity = Severity.HIGH
    confidence = Confidence.HEURISTIC
    category = Category.TOOL_OVERREACH
    capabilities = ("mcp.tools",)
    remediation = "Either narrow the tools or make the description honest about what the agent can do."

    def check_package(self, ctx: RuleContext) -> Iterator[Finding]:
        pkg = ctx.package
        tools = pkg.declared_tools
        desc = pkg.description
        if not tools or not desc or not READ_ONLY_HINTS.search(desc) or WRITE_TOOL_HINTS.search(desc):
            return
        risky = sorted({t for t in tools if WRITE_TOOL_HINTS.search(t)})
        if risky:
            yield self.finding(
                pkg.file(pkg.entrypoint),
                path=pkg.entrypoint,
                snippet=", ".join(risky),
                message=f"Description sounds read-only but grants: {', '.join(risky)}",
            )


class McpInlineSecrets(Rule):
    id = "SC-TOOL-003"
    title = "Secret literal in MCP server environment"
    description = (
        "MCP server config embeds a token/password instead of referencing an input or environment variable."
    )
    severity = Severity.HIGH
    confidence = Confidence.DETERMINISTIC
    category = Category.TOOL_OVERREACH
    applies_to = frozenset({FileKind.CONFIG})
    capabilities = ("secrets.read",)
    remediation = "Use `${input:…}` / `${env:…}` references so secrets never live in the config file."

    def check(self, file: SkillFile, ctx: RuleContext) -> Iterator[Finding]:
        if file.kind != FileKind.CONFIG:
            return
        for server in extract_mcp_servers(parse_jsonc(file.text)):
            for key, value in {**server.env, **server.headers}.items():
                if _SECRET_KEY.search(key) and _SECRET_VALUE.match(value.strip()):
                    line = _find_line(file.text, key)
                    yield self.finding(
                        file,
                        line=line,
                        snippet=f"{key}=<redacted>",
                        message=f"Server '{server.name}' sets {key} to a literal value",
                    )


class McpUnpinnedRunner(Rule):
    id = "SC-TOOL-004"
    title = "MCP server launched from an unpinned package"
    description = "`npx -y pkg` / `uvx pkg` fetch and execute the latest published version at every start."
    severity = Severity.MEDIUM
    confidence = Confidence.DETERMINISTIC
    category = Category.TOOL_OVERREACH
    applies_to = frozenset({FileKind.CONFIG})
    capabilities = ("process.spawn", "package.install", "network.egress")
    remediation = (
        "Pin an exact version (`npx -y pkg@1.2.3`, `uvx pkg==1.2.3`) or install the server explicitly."
    )

    def check(self, file: SkillFile, ctx: RuleContext) -> Iterator[Finding]:
        if file.kind != FileKind.CONFIG:
            return
        for server in extract_mcp_servers(parse_jsonc(file.text)):
            cmd = (server.command or "").rsplit("/", 1)[-1]
            if not _UNPINNED_RUNNER.match(cmd):
                continue
            pkg_arg = next(
                (a for a in server.args if not a.startswith("-") and a not in {"exec", "dlx", "run"}), None
            )
            if pkg_arg is None:
                continue
            pinned = "@" in pkg_arg.lstrip("@") or "==" in pkg_arg or re.search(r"[~^><=]\d", pkg_arg)
            if not pinned:
                yield self.finding(
                    file,
                    line=_find_line(file.text, pkg_arg),
                    snippet=server.command_line,
                    message=f"Server '{server.name}' runs unpinned package '{pkg_arg}' via {cmd}",
                )


class McpRiskyCommand(Rule):
    id = "SC-TOOL-005"
    title = "MCP server command from untrusted location"
    description = (
        "Server binary lives in a temp dir, is fetched at launch, or is a bare shell with inline code."
    )
    severity = Severity.HIGH
    confidence = Confidence.DETERMINISTIC
    category = Category.TOOL_OVERREACH
    applies_to = frozenset({FileKind.CONFIG})
    capabilities = ("process.spawn", "shell.exec")
    remediation = "Launch servers from a reviewed, installed location."
    _BAD = re.compile(
        r"(^|/)(tmp|temp|Downloads|var/tmp)(/|$)|^(curl|wget|bash|sh|zsh|cmd|powershell|pwsh)$", re.IGNORECASE
    )

    def check(self, file: SkillFile, ctx: RuleContext) -> Iterator[Finding]:
        if file.kind != FileKind.CONFIG:
            return
        for server in extract_mcp_servers(parse_jsonc(file.text)):
            cmd = server.command or ""
            if not cmd:
                continue
            base = cmd.rsplit("/", 1)[-1]
            if self._BAD.search(cmd) or (
                base in {"sh", "bash", "zsh", "pwsh", "powershell", "cmd"} and "-c" in server.args
            ):
                yield self.finding(
                    file,
                    line=_find_line(file.text, cmd),
                    snippet=server.command_line,
                    message=f"Server '{server.name}' command '{cmd}' is a shell or untrusted path",
                )


class DestructiveToolsWithoutGuard(Rule):
    id = "SC-TOOL-006"
    title = "Destructive tools granted without confirmation guidance"
    description = "Agent grants delete/destructive/force tools but its instructions never mention confirming with the user."
    severity = Severity.MEDIUM
    confidence = Confidence.HEURISTIC
    category = Category.TOOL_OVERREACH
    remediation = "Add explicit 'ask before destructive actions' guidance or drop the tools."
    _DESTRUCTIVE = re.compile(
        r"(delete|destroy|destructive|remove|drop|force|reset|wipe|purge)", re.IGNORECASE
    )
    _GUARD = re.compile(
        r"\b(confirm|confirmation|ask (the )?user|approval|approve|permission|double[- ]check)\b",
        re.IGNORECASE,
    )

    def check_package(self, ctx: RuleContext) -> Iterator[Finding]:
        pkg = ctx.package
        destructive = sorted({t for t in pkg.declared_tools if self._DESTRUCTIVE.search(t)})
        if not destructive:
            return
        entry = pkg.file(pkg.entrypoint)
        body = entry.text if entry else ""
        if not self._GUARD.search(body):
            yield self.finding(
                entry,
                path=pkg.entrypoint,
                snippet=", ".join(destructive),
                message=f"Destructive tools {', '.join(destructive)} granted with no confirmation guidance",
            )


class HookExecution(Rule):
    id = "SC-TOOL-007"
    title = "Lifecycle hook executes commands"
    description = "Plugin/skill hooks run shell commands automatically on session or tool events."
    severity = Severity.MEDIUM
    confidence = Confidence.DETERMINISTIC
    category = Category.TOOL_OVERREACH
    applies_to = frozenset({FileKind.CONFIG})
    capabilities = ("shell.exec", "process.spawn")
    remediation = "Hooks run without a prompt; keep them minimal, reviewed, and declared in the manifest."

    def check(self, file: SkillFile, ctx: RuleContext) -> Iterator[Finding]:
        if file.kind != FileKind.CONFIG:
            return
        data = parse_jsonc(file.text)
        if not isinstance(data, dict):
            return
        hooks = data.get("hooks")
        if not isinstance(hooks, dict | list):
            return
        for event, command in _iter_hook_commands(hooks):
            yield self.finding(
                file,
                line=_find_line(file.text, command[:40]),
                snippet=command,
                message=f"Hook '{event}' runs: {command}",
            )


def _iter_hook_commands(hooks: object, event: str = "hooks") -> Iterator[tuple[str, str]]:
    if isinstance(hooks, dict):
        for key, value in hooks.items():
            if key in {"command", "cmd", "run", "script"} and isinstance(value, str):
                yield event, value
            else:
                yield from _iter_hook_commands(value, str(key))
    elif isinstance(hooks, list):
        for item in hooks:
            if isinstance(item, str):
                yield event, item
            else:
                yield from _iter_hook_commands(item, event)


def _find_line(text: str, needle: str) -> int:
    idx = text.find(needle)
    return text.count("\n", 0, idx) + 1 if idx >= 0 else 1


RULES = (
    WildcardTools(),
    PurposeMismatch(),
    McpInlineSecrets(),
    McpUnpinnedRunner(),
    McpRiskyCommand(),
    DestructiveToolsWithoutGuard(),
    HookExecution(),
)
