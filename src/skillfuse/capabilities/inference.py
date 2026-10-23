"""Infer the capability manifest of a skill from its files, tool declarations, and MCP configuration."""

from __future__ import annotations

import re
from collections import defaultdict

from skillfuse.capabilities.taxonomy import capabilities_for_tool
from skillfuse.core.models import CapabilityManifest, FileKind, SkillFile, SkillPackage
from skillfuse.core.textutil import clip, iter_matches
from skillfuse.formats.configs import extract_mcp_servers, parse_jsonc

# (capability, regex, applies to scripts?, applies to instructions?)
_PATTERNS: tuple[tuple[str, re.Pattern[str], bool, bool], ...] = (
    # network
    (
        "network.egress",
        re.compile(
            r"\b(curl|wget|http|https|fetch|axios|requests\.(get|post|put|patch|delete)|httpx|urllib\.request|urlopen|Invoke-WebRequest|Invoke-RestMethod|iwr|irm|net/http|http\.client|aiohttp|websocket|grpc)\b",
            re.I,
        ),
        True,
        False,
    ),
    ("network.egress", re.compile(r"\bhttps?://[^\s)>\]\"']+", re.I), True, False),
    (
        "network.egress",
        re.compile(
            r"\b(call|hit|query|fetch|download|post\s+to|send\s+to|upload\s+to)\s+(the\s+)?(api|endpoint|url|webhook|server|service)\b",
            re.I,
        ),
        False,
        True,
    ),
    (
        "network.listen",
        re.compile(
            r"\b(\.listen\s*\(|socket\.bind|http\.server|HTTPServer|uvicorn|flask\.run|app\.run\(|nc\s+-l|ncat\s+-l|python\s+-m\s+http\.server)",
            re.I,
        ),
        True,
        False,
    ),
    # filesystem
    (
        "filesystem.write",
        re.compile(
            r"(\bopen\s*\([^)]*[\"'](w|a|x)[bt+]*[\"']|\bwriteFile(Sync)?\b|\bwrite_text\b|\bwrite_bytes\b|\bshutil\.(copy|move|copytree)|\bos\.(rename|replace|makedirs|mkdir)|\bmkdir\b|\bcp\s+-|\bmv\s|\btee\s|(?<![-=>])>>?\s*[^\s&|>=]|\bSet-Content\b|\bOut-File\b|\bNew-Item\b)",
            re.I,
        ),
        True,
        False,
    ),
    (
        "filesystem.write",
        re.compile(
            r"\b(create|write|edit|modify|update|save|generate|overwrite|append\s+to)\s+(the\s+|a\s+|an\s+|new\s+|each\s+|every\s+){0,2}(file|files|document|script|config|configuration|directory|folder)\b",
            re.I,
        ),
        False,
        True,
    ),
    (
        "filesystem.write",
        re.compile(
            r"\b(write|save|append|output)\b[^.\n]{0,40}\b(to|into)\s+`?[\w./-]+\.(md|txt|json|ya?ml|toml|py|js|ts|sh|csv|xml|html)\b",
            re.I,
        ),
        False,
        True,
    ),
    (
        "filesystem.delete",
        re.compile(
            r"(\brm\s+-|\brmdir\b|\bunlink\b|\bos\.remove\b|\bshutil\.rmtree\b|\bfs\.(rm|unlink|rmdir)(Sync)?\b|\bRemove-Item\b|\bdel\s+/[fq])",
            re.I,
        ),
        True,
        False,
    ),
    (
        "filesystem.delete",
        re.compile(
            r"\b(delete|remove|clean\s+up|purge|wipe)\s+(the\s+|all\s+|any\s+|every\s+){0,2}(file|files|directory|directories|folder|folders|cache|artefacts|artifacts)\b",
            re.I,
        ),
        False,
        True,
    ),
    (
        "filesystem.read",
        re.compile(
            r"(\bopen\s*\([^)]*[\"']r|\bread_text\b|\bread_bytes\b|\breadFile(Sync)?\b|\bcat\s+[~/.]|\bless\s|\bhead\s|\btail\s|\bGet-Content\b|\bos\.listdir\b|\bglob\.glob\b|\bPath\([^)]*\)\.read)",
            re.I,
        ),
        True,
        False,
    ),
    (
        "filesystem.read",
        re.compile(r"(~/|\$HOME/|%USERPROFILE%|/etc/|/var/|/usr/(?!bin/env\b)|/opt/|C:\\\\Users)", re.I),
        True,
        True,
    ),
    # shell / process
    (
        "shell.exec",
        re.compile(
            r"(\bsubprocess\.(run|call|Popen|check_output|check_call)|\bos\.(system|popen|exec[lv]p?e?)\b|\bchild_process\b|\bexecSync\b|\bspawn(Sync)?\s*\(|\bexec\s*\(|\bInvoke-Expression\b|\biex\b|\bsystem\s*\(|\bbash\s+-c|\bsh\s+-c|\beval\s)",
            re.I,
        ),
        True,
        False,
    ),
    ("shell.exec", re.compile(r"(^|\n)\s*(\$|>)\s*[a-z][\w.-]*\s", re.M), False, True),
    (
        "shell.exec",
        re.compile(
            r"\b(run|execute|invoke)\s+(the\s+following\s+|this\s+|these\s+|the\s+)?(command|commands|script|shell|terminal)\b",
            re.I,
        ),
        False,
        True,
    ),
    ("shell.exec", re.compile(r"```(ba|z)?sh\b|```shell\b|```console\b|```powershell\b", re.I), False, True),
    (
        "process.spawn",
        re.compile(
            r"\b(npx|uvx|pipx\s+run|docker\s+(run|compose|exec)|nohup|setsid|systemctl\s+start|&\s*$)",
            re.I | re.M,
        ),
        True,
        True,
    ),
    # env / secrets
    (
        "env.read",
        re.compile(
            r"(\bos\.environ\b|\bos\.getenv\b|\bprocess\.env\b|\$\{?[A-Z][A-Z0-9_]{2,}\}?|\$env:|\bprintenv\b|\bGet-ChildItem\s+Env:)",
            re.M,
        ),
        True,
        False,
    ),
    ("env.read", re.compile(r"\b(environment\s+variable|env\s+var)s?\b", re.I), False, True),
    (
        "secrets.read",
        re.compile(
            r"(\.aws/credentials|\.ssh/id_|\.netrc|\.git-credentials|\.npmrc|\.pypirc|\.docker/config\.json|\.kube/config|\.env\b|keychain|\bsecurity\s+find-|/etc/shadow|credentials\.json|serviceaccount/token)",
            re.I,
        ),
        True,
        True,
    ),
    (
        "secrets.read",
        re.compile(
            r"\b(API[_ ]?KEY|ACCESS[_ ]?TOKEN|SECRET[_ ]?KEY|AUTH[_ ]?TOKEN|PASSWORD|PRIVATE[_ ]?KEY|GITHUB_TOKEN|AWS_SECRET_ACCESS_KEY|OPENAI_API_KEY|ANTHROPIC_API_KEY)\b"
        ),
        True,
        True,
    ),
    # packages
    (
        "package.install",
        re.compile(
            r"\b(pip3?\s+install|uv\s+(pip\s+)?(install|add|sync)|pipx\s+install|npm\s+(install|i|ci|add)|yarn\s+(add|install)|pnpm\s+(add|install)|bun\s+(add|install)|cargo\s+install|gem\s+install|go\s+(get|install)|brew\s+install|apt(-get)?\s+install|dnf\s+install|yum\s+install|choco\s+install|winget\s+install|poetry\s+add)\b",
            re.I,
        ),
        True,
        True,
    ),
    # git
    (
        "git.write",
        re.compile(
            r"\bgit\s+(commit|push|rebase|merge|cherry-pick|reset|tag|checkout\s+-b|branch\s+-[dD]|stash|am|apply)\b",
            re.I,
        ),
        True,
        True,
    ),
    (
        "git.read",
        re.compile(r"\bgit\s+(log|status|diff|show|blame|rev-parse|ls-files|describe|fetch|clone)\b", re.I),
        True,
        True,
    ),
    # github / jira / confluence / slack via CLI or API
    (
        "github.write",
        re.compile(
            r"\bgh\s+(pr\s+(create|merge|close|comment|review|edit)|issue\s+(create|close|comment|edit)|release\s+(create|upload|delete)|repo\s+(create|delete|edit)|api\s+(-X\s*)?(POST|PUT|PATCH|DELETE))\b",
            re.I,
        ),
        True,
        True,
    ),
    (
        "github.read",
        re.compile(
            r"\bgh\s+(pr\s+(list|view|checks|diff|status)|issue\s+(list|view)|repo\s+(view|clone)|api\s+(?!(-X\s*)?(POST|PUT|PATCH|DELETE))|search|run\s+(list|view)|release\s+(list|view))\b",
            re.I,
        ),
        True,
        True,
    ),
    (
        "github.write",
        re.compile(
            r"api\.github\.com/[^\s]*\b(POST|PUT|PATCH|DELETE)\b|\b(POST|PUT|PATCH|DELETE)\b[^\n]*api\.github\.com",
            re.I,
        ),
        True,
        True,
    ),
    (
        "jira.write",
        re.compile(
            r"\b(create|update|edit|transition|close|resolve|assign|comment\s+on)\s+(the\s+|a\s+|an\s+)?(jira\s+)?(ticket|issue|bug|story|epic)s?\b[^\n]*\bjira\b|\bjira\b[^\n]*\b(create|update|edit|transition|close|resolve|assign|comment\s+on)\s+(the\s+|a\s+)?(ticket|issue)s?\b",
            re.I,
        ),
        True,
        True,
    ),
    (
        "jira.write",
        re.compile(
            r"/rest/api/[23]/issue\b[^\n]*\b(POST|PUT|DELETE)\b|\b(POST|PUT|DELETE)\b[^\n]*/rest/api/[23]/issue",
            re.I,
        ),
        True,
        True,
    ),
    (
        "jira.read",
        re.compile(r"\b(jql|/rest/api/[23]/search|atlassian\.net/browse/|jira\.[a-z0-9.-]+/browse/)", re.I),
        True,
        True,
    ),
    (
        "confluence.write",
        re.compile(
            r"\b(create|update|publish|edit)\s+(the\s+|a\s+)?(confluence\s+)?(page|pages|live\s+doc)s?\b[^\n]*\bconfluence\b|\bconfluence\b[^\n]*\b(create|update|publish|edit)\s+(the\s+|a\s+)?(page|pages)\b|/wiki/rest/api/content\b[^\n]*\b(POST|PUT)\b",
            re.I,
        ),
        True,
        True,
    ),
    (
        "confluence.read",
        re.compile(r"\b(confluence|/wiki/rest/api/content|/wiki/spaces/)\b", re.I),
        True,
        True,
    ),
    (
        "slack.write",
        re.compile(
            r"\b(hooks\.slack\.com|chat\.postMessage|files\.upload|slack\s+(send|post|message)|send\s+(a\s+)?(slack\s+)?message\s+to\s+(the\s+)?(slack|channel))\b",
            re.I,
        ),
        True,
        True,
    ),
    (
        "slack.read",
        re.compile(
            r"\b(slack\.com/api/(conversations|search|users)|read\s+(the\s+)?slack\s+(channel|thread|messages))\b",
            re.I,
        ),
        True,
        True,
    ),
    # cloud
    (
        "cloud.write",
        re.compile(
            r"\b(aws\s+\w+\s+(create|delete|put|update|terminate|run-instances|start|stop)|az\s+\w+\s+(create|delete|update|start|stop)|gcloud\s+\w+\s+(create|delete|update)|terraform\s+(apply|destroy)|kubectl\s+(apply|delete|create|scale|rollout|exec|patch)|helm\s+(install|upgrade|uninstall))\b",
            re.I,
        ),
        True,
        True,
    ),
    (
        "cloud.read",
        re.compile(
            r"\b(aws\s+\w+\s+(describe|list|get)|az\s+\w+\s+(list|show)|gcloud\s+\w+\s+(list|describe)|terraform\s+(plan|show)|kubectl\s+(get|describe|logs))\b",
            re.I,
        ),
        True,
        True,
    ),
    # database
    (
        "database.write",
        re.compile(
            r"\b(INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM|DROP\s+(TABLE|DATABASE|COLLECTION)|ALTER\s+TABLE|TRUNCATE|insertOne|insertMany|updateOne|updateMany|deleteOne|deleteMany|\.drop\(\))\b",
            re.I,
        ),
        True,
        True,
    ),
    (
        "database.read",
        re.compile(
            r"\b(SELECT\s+[\w*,\s]+\s+FROM|psql\s|mysql\s+-|mongosh|sqlite3\s|\.find\(\{|\.aggregate\(\[)",
            re.I,
        ),
        True,
        True,
    ),
    # ssh / browser / email / ai
    (
        "ssh.exec",
        re.compile(
            r"\b(ssh\s+(-\w+\s+)*[\w.-]+@[\w.-]+|paramiko|fabric\.Connection|scp\s|sftp\s|ssh2|asyncssh)\b",
            re.I,
        ),
        True,
        True,
    ),
    (
        "browser.automation",
        re.compile(
            r"\b(playwright|puppeteer|selenium|webdriver|chromedriver|headless\s+chrome|open\s+(the\s+)?browser|navigate\s+to\s+the\s+(page|url))\b",
            re.I,
        ),
        True,
        True,
    ),
    (
        "email.send",
        re.compile(
            r"\b(smtplib|sendmail|nodemailer|SendGrid|ses\s+send-email|send\s+(an\s+)?e-?mail)\b", re.I
        ),
        True,
        True,
    ),
    (
        "ai.model",
        re.compile(
            r"\b(api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com|openai\.ChatCompletion|anthropic\.Anthropic|ollama|huggingface\.co/api)\b",
            re.I,
        ),
        True,
        True,
    ),
    (
        "system.admin",
        re.compile(
            r"(^|[;&|`(\s])(sudo|doas|su\s+-|runas|Start-Process\s+[^\n]*-Verb\s+RunAs)\b", re.I | re.M
        ),
        True,
        True,
    ),
    (
        "system.persistence",
        re.compile(
            r"\b(crontab|launchctl|systemctl\s+enable|schtasks|Register-ScheduledTask|\.bashrc|\.zshrc|\.profile|authorized_keys|\.git/hooks|core\.hooksPath)\b",
            re.I,
        ),
        True,
        True,
    ),
    (
        "mcp.tools",
        re.compile(
            r"\b(mcp_[a-z0-9_-]+|tools/call|use\s+the\s+[\w-]+\s+tool|call\s+the\s+[\w-]+\s+tool)\b", re.I
        ),
        False,
        True,
    ),
)


_NEGATION = re.compile(
    r"\b(never|do\s+not|don'?t|must\s+not|should\s+not|without|avoid|not)\s+(\w+\s+){0,3}$", re.I
)


def infer_capabilities(pkg: SkillPackage) -> CapabilityManifest:
    evidence: dict[str, list[str]] = defaultdict(list)
    strong: set[str] = set()

    for tool in pkg.declared_tools:
        for cap in capabilities_for_tool(tool):
            _add(evidence, cap, f"{pkg.entrypoint}: tool '{tool}'")
            strong.add(cap)

    for sf in pkg.files:
        if sf.kind == FileKind.SCRIPT:
            strong.update(_scan_text(sf, evidence, is_script=True))
        elif sf.kind == FileKind.INSTRUCTIONS:
            _scan_text(sf, evidence, is_script=False)
            strong.update(_scan_frontmatter(sf, evidence))
        elif sf.kind == FileKind.CONFIG:
            strong.update(_scan_config(sf, evidence))

    caps = tuple(sorted(evidence))
    return CapabilityManifest(
        capabilities=caps,
        evidence={k: tuple(v[:8]) for k, v in sorted(evidence.items())},
        source="inferred",
        weak=tuple(c for c in caps if c not in strong),
    )


def _add(evidence: dict[str, list[str]], cap: str, note: str) -> None:
    if note not in evidence[cap]:
        evidence[cap].append(note)


def _scan_text(sf: SkillFile, evidence: dict[str, list[str]], *, is_script: bool) -> set[str]:
    found: set[str] = set()
    if not sf.text:
        return found
    for cap, pattern, for_script, for_instr in _PATTERNS:
        if (is_script and not for_script) or (not is_script and not for_instr):
            continue
        for m, line, _ in iter_matches(pattern, sf.text):
            if not is_script and _NEGATION.search(sf.text[max(0, m.start() - 40) : m.start()]):
                continue
            offset = sf.body_offset if sf.kind == FileKind.INSTRUCTIONS else 0
            _add(evidence, cap, f"{sf.path}:{line + offset}: {clip(m.group(0), 60)}")
            found.add(cap)
            if len(evidence[cap]) >= 8:
                break
    return found


def _scan_frontmatter(sf: SkillFile, evidence: dict[str, list[str]]) -> set[str]:
    found: set[str] = set()
    fm = sf.frontmatter
    tools = fm.get("tools")
    tool_list: list[str] = []
    if isinstance(tools, list):
        tool_list = [str(t) for t in tools]
    elif isinstance(tools, str):
        tool_list = [t.strip() for t in tools.split(",") if t.strip()]
    for tool in tool_list:
        for cap in capabilities_for_tool(tool):
            _add(evidence, cap, f"{sf.path}: tool '{tool}'")
            found.add(cap)
    if fm.get("allowed-tools") or fm.get("allowed_tools"):
        raw = fm.get("allowed-tools") or fm.get("allowed_tools")
        items = raw if isinstance(raw, list) else str(raw).split()
        for tool in items:
            for cap in capabilities_for_tool(str(tool).split("(")[0]):
                _add(evidence, cap, f"{sf.path}: allowed-tool '{tool}'")
                found.add(cap)
    if fm.get("hooks"):
        _add(evidence, "shell.exec", f"{sf.path}: hooks declared")
        found.add("shell.exec")
    return found


def _scan_config(sf: SkillFile, evidence: dict[str, list[str]]) -> set[str]:
    data = parse_jsonc(sf.text)
    servers = extract_mcp_servers(data)
    for server in servers:
        _add(evidence, "mcp.server", f"{sf.path}: server '{server.name}'")
        if server.command:
            _add(evidence, "process.spawn", f"{sf.path}: '{server.command_line}'")
            base = server.command.rsplit("/", 1)[-1].lower()
            if base in {"npx", "uvx", "pipx", "bunx"}:
                _add(evidence, "package.install", f"{sf.path}: {base} fetches '{server.name}' on start")
                _add(evidence, "network.egress", f"{sf.path}: {base} downloads '{server.name}'")
            if base in {"sh", "bash", "zsh", "cmd", "powershell", "pwsh"}:
                _add(evidence, "shell.exec", f"{sf.path}: server '{server.name}' runs a shell")
        if server.url:
            _add(evidence, "network.egress", f"{sf.path}: url {server.url}")
        for key in server.env:
            _add(evidence, "env.read", f"{sf.path}: env {key}")
            if re.search(r"(token|secret|password|key|credential)", key, re.I):
                _add(evidence, "secrets.read", f"{sf.path}: env {key}")
    if isinstance(data, dict):
        if data.get("hooks"):
            _add(evidence, "shell.exec", f"{sf.path}: hooks")
            _add(evidence, "process.spawn", f"{sf.path}: hooks")
        for key in ("tools", "allowedTools", "allowed_tools"):
            tools = data.get(key)
            if isinstance(tools, list):
                for tool in tools:
                    for cap in capabilities_for_tool(str(tool)):
                        _add(evidence, cap, f"{sf.path}: tool '{tool}'")
    # Scripts embedded in config strings (e.g. package.json scripts, hooks commands)
    if sf.text:
        for cap, pattern, for_script, _ in _PATTERNS:
            if not for_script or cap not in {"shell.exec", "network.egress", "package.install"}:
                continue
            m = pattern.search(sf.text)
            if m and cap not in evidence:
                line = sf.text.count("\n", 0, m.start()) + 1
                _add(evidence, cap, f"{sf.path}:{line}: {clip(m.group(0), 60)}")
    return {k for k, notes in evidence.items() if any(n.startswith(sf.path) for n in notes)}
