"""SC-SH-*: dangerous shell constructs in scripts and in commands quoted inside instructions."""

from __future__ import annotations

from skillfuse.core.models import Category, Confidence, Severity
from skillfuse.rules.base import EXEC_KINDS, RegexRule, rx


class PipeToShell(RegexRule):
    id = "SC-SH-001"
    title = "Remote script piped to a shell"
    description = "Downloads content and executes it without inspection or pinning."
    severity = Severity.CRITICAL
    confidence = Confidence.DETERMINISTIC
    category = Category.SHELL
    applies_to = EXEC_KINDS
    capabilities = ("shell.exec", "network.egress")
    remediation = "Download to a file, verify its digest/signature, then execute a pinned version."
    references = ("https://cwe.mitre.org/data/definitions/494.html",)
    patterns = (
        rx(r"\b(curl|wget|fetch|Invoke-WebRequest|iwr)\b[^\n|]*\|\s*(sudo\s+)?(ba|z|k|da)?sh\b"),
        rx(r"\b(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(python[23]?|node|perl|ruby|php)\b"),
        rx(r"\b(iwr|Invoke-WebRequest|Invoke-RestMethod|irm)\b[^\n|]*\|\s*(iex|Invoke-Expression)\b"),
        rx(r"\b(ba|z)?sh\s+<\s*\(\s*(curl|wget)\b"),
        rx(r"\b(ba|z)?sh\s+-c\s+[\"']?\$\(\s*(curl|wget)\b"),
        rx(r"\beval\s+[\"']?\$\(\s*(curl|wget)\b"),
        rx(r"\bsource\s+<\s*\(\s*(curl|wget)\b"),
    )


class DestructiveFilesystem(RegexRule):
    id = "SC-SH-002"
    title = "Destructive filesystem operation"
    description = "Recursive deletes of broad paths, disk wipes, fork bombs."
    severity = Severity.CRITICAL
    confidence = Confidence.DETERMINISTIC
    category = Category.SHELL
    applies_to = EXEC_KINDS
    capabilities = ("filesystem.delete", "shell.exec")
    remediation = "Scope deletes to files the skill created; never touch $HOME, /, or unquoted variables."
    patterns = (
        rx(
            r"\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f?|-[a-zA-Z]*f[a-zA-Z]*r)\s+(--no-preserve-root\s+)?(/|~|\$HOME|\$\{HOME\}|\.\.|\*|/\*|~/\*|\$HOME/\*)(\s|$|;|&)"
        ),
        rx(r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*\s+(\"?\$\{?[A-Za-z_][A-Za-z0-9_]*\}?\"?/?\*?)(\s|$|;|&)"),
        rx(r"\b(mkfs(\.[a-z0-9]+)?|wipefs|shred)\s+[^\n]*(/dev/|-[a-z]*z)"),
        rx(r"\bdd\s+if=[^\n]*of=/dev/(sd|nvme|disk|hd|mmcblk)"),
        rx(r">\s*/dev/(sd|nvme|disk|hd)[a-z0-9]*\b"),
        rx(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:"),
        rx(r"\b(chmod|chown)\s+-R\s+[^\n]*\s(/|~|\$HOME)(\s|$)"),
        rx(r"\bgit\s+(push\s+[^\n]*(--force|-f)\b|reset\s+--hard\b|clean\s+-[a-z]*f[a-z]*d|branch\s+-D\b)"),
        rx(r"\bRemove-Item\s+[^\n]*-Recurse[^\n]*-Force[^\n]*(\$HOME|~|C:\\|\$env:USERPROFILE)"),
    )
    message_template = "Destructive command '{match}'"


class PrivilegeEscalation(RegexRule):
    id = "SC-SH-003"
    title = "Privilege escalation or permissive modes"
    description = "sudo/su usage, world-writable or setuid permissions."
    severity = Severity.HIGH
    confidence = Confidence.DETERMINISTIC
    category = Category.SHELL
    applies_to = EXEC_KINDS
    capabilities = ("shell.exec", "system.admin")
    remediation = "Skills should not require elevated privileges; if unavoidable, declare `system.admin`."
    patterns = (
        rx(r"(^|[;&|`(\s])sudo\s+(-[A-Za-z]+\s+)*[a-zA-Z/.]"),
        rx(r"(^|[;&|`(\s])su\s+(-|-l|--login|root)\b"),
        rx(r"\bchmod\s+(-[a-zA-Z]+\s+)*(777|666|a\+rwx|o\+w|[ugoa]*\+s|[42][0-7]{3})\b"),
        rx(r"\bchown\s+(-[a-zA-Z]+\s+)*root\b"),
        rx(r"\bsetcap\s+cap_"),
        rx(r"\bStart-Process\b[^\n]*-Verb\s+RunAs\b"),
    )


class ObfuscatedExecution(RegexRule):
    id = "SC-SH-004"
    title = "Obfuscated command execution"
    description = "Decodes or constructs code at runtime and executes it."
    severity = Severity.CRITICAL
    confidence = Confidence.DETERMINISTIC
    category = Category.SHELL
    applies_to = EXEC_KINDS
    capabilities = ("shell.exec",)
    remediation = "Write commands in plain text so they can be reviewed."
    patterns = (
        rx(
            r"\b(base64|b64decode|openssl\s+enc|xxd\s+-r|od\s+-An)\b[^\n|]*\|\s*(sudo\s+)?((ba|z|k)?sh|python[23]?|node|perl|eval)\b"
        ),
        rx(r"\beval\s+[\"']?\$\((?!\s*(cat|echo|ls|pwd|dirname|basename|git\s+rev-parse|which|command)\b)"),
        rx(r"\beval\s+\"\$[A-Za-z_]"),
        rx(r"\b(ba|z)?sh\s+-c\s+[\"']?\$\((?!\s*(cat|echo|dirname|basename))"),
        rx(r"\bexec\s*\(\s*(base64|codecs|bytes\.fromhex|zlib|marshal|compile)\b"),
        rx(r"\bexec\s*\(\s*[\"'](\\x[0-9a-f]{2}){4,}"),
        rx(r"\b(python[23]?|node)\s+-[ce]\s+[\"'][^\"']*\b(base64|fromhex|unhexlify|atob|Buffer\.from)\b"),
        rx(r"\bnew\s+Function\s*\(\s*(atob|Buffer\.from|decodeURIComponent)\b"),
        rx(r"\bString\.fromCharCode\s*\((\s*\d+\s*,){8,}"),
        rx(r"\b(iex|Invoke-Expression)\s*\(?\s*\[System\.Text\.Encoding\]"),
        rx(r"(^|\s)-EncodedCommand\s+[A-Za-z0-9+/=]{20,}|\s-enc\s+[A-Za-z0-9+/=]{20,}"),
        rx(r"\$\{[A-Za-z_]+\^+\}|\$\{[A-Za-z_]+:0:1\}\$\{[A-Za-z_]+:1"),
        rx(r"\b(ba|z)?sh\s+-c\s+[\"']?\$\{?[A-Za-z_]+\}?\s*[\"']?\s*$"),
    )


class Persistence(RegexRule):
    id = "SC-SH-005"
    title = "Persistence mechanism"
    description = "Installs scheduled tasks, services, shell-rc hooks, SSH keys, or git hooks."
    severity = Severity.HIGH
    confidence = Confidence.DETERMINISTIC
    category = Category.SHELL
    applies_to = EXEC_KINDS
    capabilities = ("system.persistence", "filesystem.write")
    remediation = "Skills must not outlive the task; remove persistence."
    patterns = (
        rx(r"\bcrontab\s+(-\s*$|-\s*[;&|)]|-[er]\b|-l\s*\||(?!-)\S+\s*$)"),
        rx(
            r">>?\s*~?/?(\.bashrc|\.zshrc|\.profile|\.bash_profile|\.zprofile|\.config/fish/config\.fish|\.bash_logout)\b"
        ),
        rx(r"\becho\b[^\n]*>>\s*~?/?\.ssh/authorized_keys"),
        rx(r"(>>?|tee\s+(-a\s+)?)\s*~?/?\.ssh/authorized_keys"),
        rx(r"\blaunchctl\s+(load|bootstrap)\b|\bLaunchAgents/[^\n]*\.plist"),
        rx(
            r"\bsystemctl\s+(enable|--user\s+enable)\b|/etc/systemd/system/[^\n]*\.service|~?/?\.config/systemd/user/"
        ),
        rx(r"\bschtasks\s+/create\b|\bRegister-ScheduledTask\b|\bNew-ScheduledTask\b"),
        rx(r"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
        rx(r"\.git/hooks/(pre-commit|post-checkout|post-merge|pre-push|post-commit)\b"),
        rx(r"\bgit\s+config\s+(--global\s+)?core\.hooksPath\b"),
        rx(r"/etc/(rc\.local|init\.d/|profile\.d/)"),
        rx(r"\b(npm|pnpm|yarn)\s+config\s+set\s+[^\n]*\b(script-shell|prefix)\b"),
    )


class SecurityControlTampering(RegexRule):
    id = "SC-SH-006"
    title = "Security control tampering"
    description = "Disables TLS verification, shell history, git hooks, firewalls, or scanners."
    severity = Severity.HIGH
    confidence = Confidence.DETERMINISTIC
    category = Category.SHELL
    applies_to = EXEC_KINDS
    capabilities = ("shell.exec",)
    remediation = "Keep security controls enabled; fix the underlying problem instead."
    patterns = (
        rx(
            r"\b(unset\s+HISTFILE|HISTFILE=/dev/null|set\s+\+o\s+history|history\s+-c|HISTSIZE=0|export\s+HISTCONTROL=ignorespace)\b"
        ),
        rx(
            r"\b(GIT_SSL_NO_VERIFY|NODE_TLS_REJECT_UNAUTHORIZED|PYTHONHTTPSVERIFY|CURL_INSECURE)\s*=\s*[\"']?(1|0|true|false)"
        ),
        rx(r"\bcurl\b[^\n]*\s(-k|--insecure)\b"),
        rx(r"\bwget\b[^\n]*--no-check-certificate\b"),
        rx(r"\bverify\s*=\s*False\b"),
        rx(r"\brejectUnauthorized\s*:\s*false\b"),
        rx(r"\bgit\s+(commit|push|merge|rebase)\b[^\n]*--no-verify\b"),
        rx(r"\bgit\s+config\s+[^\n]*(http\.sslVerify|core\.hooksPath)\s+(false|/dev/null)"),
        rx(
            r"\b(ufw\s+disable|iptables\s+-F|setenforce\s+0|systemctl\s+(stop|disable)\s+(firewalld|apparmor|auditd|falco))\b"
        ),
        rx(
            r"\bSet-MpPreference\s+-Disable|\bSet-ExecutionPolicy\s+(Unrestricted|Bypass)|-ExecutionPolicy\s+Bypass"
        ),
        rx(r"\bcsrutil\s+disable|\bspctl\s+--master-disable|\bxattr\s+-[a-z]*d\s+com\.apple\.quarantine"),
        rx(r"\bdefaults\s+write\s+com\.apple\.LaunchServices\s+LSQuarantine\s+-bool\s+(false|NO)"),
        rx(r"\bpip\s+install\b[^\n]*--trusted-host\b"),
    )


class ReverseShell(RegexRule):
    id = "SC-SH-007"
    title = "Reverse or bind shell"
    description = "Opens an interactive shell to/from a remote host."
    severity = Severity.CRITICAL
    confidence = Confidence.DETERMINISTIC
    category = Category.SHELL
    applies_to = EXEC_KINDS
    capabilities = ("shell.exec", "network.egress")
    remediation = "Remove immediately; this is never legitimate inside a skill."
    patterns = (
        rx(r"/dev/(tcp|udp)/[\w.\-]+/\d+"),
        rx(r"\b(nc|ncat|netcat)\b[^\n]*\s(-e|-c)\s+/bin/(ba)?sh"),
        rx(r"\b(ba)?sh\s+-i\s+[>&]+\s*/dev/tcp"),
        rx(r"\bsocat\b[^\n]*\b(exec|system):"),
        rx(r"\bmkfifo\s+[^\n]*\|\s*(nc|ncat|netcat)\b"),
        rx(r"\bpty\.spawn\s*\(\s*[\"']/bin/(ba)?sh"),
        rx(r"\bsubprocess\.(call|Popen|run)\s*\(\s*\[?\s*[\"']/bin/(ba)?sh[\"']\s*,\s*[\"']-i"),
        rx(r"\bnet\.connect\s*\([^\n]*\bchild_process\b"),
        rx(r"\bexec\s+5<>/dev/tcp"),
    )


class DownloadThenExecute(RegexRule):
    id = "SC-SH-008"
    title = "Downloaded artefact made executable"
    description = "Fetches a binary/script and marks it executable (two-step pipe-to-shell)."
    severity = Severity.HIGH
    confidence = Confidence.DETERMINISTIC
    category = Category.SHELL
    applies_to = EXEC_KINDS
    capabilities = ("shell.exec", "network.egress", "filesystem.write")
    remediation = "Verify a pinned checksum/signature before `chmod +x` and execution."
    patterns = (
        rx(r"\b(curl|wget)\b[^\n]*(-o|-O|--output)\s*\S+[^\n]*(&&|;)\s*chmod\s+\+?x"),
        rx(r"\bchmod\s+\+x\s+[^\n]*(&&|;)\s*\./\S+[^\n]*\n?[^\n]*\b(curl|wget)\b"),
        rx(r"\b(curl|wget)\b[^\n]*\s/tmp/\S+[^\n]*\n[^\n]*\bchmod\s+\+x\s+/tmp/"),
    )


RULES = (
    PipeToShell(),
    DestructiveFilesystem(),
    PrivilegeEscalation(),
    ObfuscatedExecution(),
    Persistence(),
    SecurityControlTampering(),
    ReverseShell(),
    DownloadThenExecute(),
)
