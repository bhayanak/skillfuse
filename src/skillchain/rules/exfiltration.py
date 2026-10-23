"""SC-EXF-*: credential access, environment harvesting, hard-coded secrets, and exfiltration correlation."""

from __future__ import annotations

import re
from collections.abc import Iterator

from skillchain.core.models import Category, Confidence, FileKind, Finding, Severity, SkillFile
from skillchain.core.textutil import clip, iter_matches, redact
from skillchain.rules.base import EXEC_KINDS, RegexRule, Rule, RuleContext, rx

CREDENTIAL_PATHS = (
    r"~?/?\.aws/(credentials|config)",
    r"~?/?\.ssh/(id_(rsa|ed25519|ecdsa|dsa)|authorized_keys|known_hosts|config)",
    r"~?/?\.netrc",
    r"~?/?\.git-credentials",
    r"~?/?\.npmrc",
    r"~?/?\.pypirc",
    r"~?/?\.docker/config\.json",
    r"~?/?\.kube/config",
    r"~?/?\.config/gh/hosts\.yml",
    r"~?/?\.config/gcloud/",
    r"~?/?\.azure/",
    r"~?/?\.gnupg/",
    r"~?/?\.password-store",
    r"~?/?\.vault-token",
    r"~?/?\.terraform\.d/credentials",
    r"\bLibrary/Keychains\b",
    r"\bsecurity\s+find-(generic|internet)-password\b",
    r"/etc/(shadow|passwd|sudoers)\b",
    r"\.env(\.local|\.production|\.prod)?\b(?![a-zA-Z])",
    r"\bid_rsa\b",
    r"\bcredentials\.json\b",
    r"\bserviceaccount/token\b",
    r"\$HOME/\.(aws|ssh|config|docker|kube|netrc|npmrc|git-credentials|pypirc)",
)
_CRED_RE = rx("(" + "|".join(CREDENTIAL_PATHS) + ")")
_ENV_PREFIX = r"(?:\bexport\s+)?"


class CredentialFileAccess(RegexRule):
    id = "SC-EXF-001"
    title = "Credential file referenced"
    description = "References well-known credential stores (AWS, SSH, kube, npm, .env, keychain, …)."
    severity = Severity.HIGH
    confidence = Confidence.DETERMINISTIC
    category = Category.EXFILTRATION
    applies_to = EXEC_KINDS
    capabilities = ("secrets.read", "filesystem.read")
    remediation = "Skills should receive credentials via the host's secret mechanism, never by reading credential files."
    patterns = (_CRED_RE,)
    message_template = "References credential store '{match}'"
    exclude_patterns = (rx(r"^\.env\.(example|sample|template)$"),)


class EnvironmentHarvesting(RegexRule):
    id = "SC-EXF-002"
    title = "Environment variable harvesting"
    description = "Dumps or serialises the whole process environment, which typically contains tokens."
    severity = Severity.MEDIUM
    confidence = Confidence.DETERMINISTIC
    category = Category.EXFILTRATION
    applies_to = EXEC_KINDS
    capabilities = ("env.read", "secrets.read")
    remediation = "Read only the specific variables you need."
    patterns = (
        rx(r"(^|[;&|`$(\s])(env|printenv|set)\s*(\||>|$|;|\)|`)"),
        rx(r"\b(dict|list|json\.dumps|print|str|repr)\s*\(\s*os\.environ\s*\)"),
        rx(r"\bos\.environ\.(items|copy|keys)\s*\("),
        rx(r"\bJSON\.stringify\s*\(\s*process\.env\s*\)"),
        rx(r"\bObject\.(entries|keys|values|assign)\s*\(\s*(\{\s*\}\s*,\s*)?process\.env\s*\)"),
        rx(r"\bGet-ChildItem\s+Env:|\[Environment\]::GetEnvironmentVariables\(\)"),
        rx(r"\bcat\s+/proc/(self|\d+)/environ\b"),
        rx(r"\$\{?\(?\s*env\s*\)?\}?\s*\|\s*(curl|wget|nc|base64)"),
    )


class SecretPatterns(Rule):
    id = "SC-EXF-003"
    title = "Hard-coded secret"
    description = "Credential material committed inside the skill package."
    severity = Severity.HIGH
    confidence = Confidence.DETERMINISTIC
    category = Category.EXFILTRATION
    applies_to = frozenset({FileKind.INSTRUCTIONS, FileKind.SCRIPT, FileKind.CONFIG, FileKind.DATA})
    capabilities = ("secrets.read",)
    remediation = "Remove the secret, rotate it, and source credentials from the host at runtime."
    references = ("https://cwe.mitre.org/data/definitions/798.html",)
    _PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
        ("AWS access key", re.compile(r"\b(AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA)[A-Z0-9]{16}\b")),
        ("GitHub token", re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b")),
        ("GitHub fine-grained PAT", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,}\b")),
        ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
        (
            "Slack webhook",
            re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{20,}"),
        ),
        ("OpenAI key", re.compile(r"\bsk-(proj-)?[A-Za-z0-9_-]{32,}\b")),
        ("Anthropic key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{32,}\b")),
        ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
        ("Stripe key", re.compile(r"\b(sk|rk)_(live|test)_[A-Za-z0-9]{20,}\b")),
        ("npm token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
        ("PyPI token", re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}\b")),
        (
            "Private key block",
            re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY( BLOCK)?-----"),
        ),
        ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
        ("Atlassian API token", re.compile(r"\bATATT3[A-Za-z0-9_-]{50,}\b")),
        (
            "Generic assignment",
            re.compile(
                r"(?i)\b(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password|passwd|pwd)\b\s*[:=]\s*[\"']([A-Za-z0-9+/=_\-\.]{16,})[\"']"
            ),
        ),
    )
    _PLACEHOLDER = re.compile(
        r"(?i)(example|sample|placeholder|your[_-]?|xxxx|\$\{|\{\{|<[a-z_-]+>|changeme|dummy|redacted|\*{4,}|000000|canary|fake|test[_-]?token)"
    )

    def check(self, file: SkillFile, ctx: RuleContext) -> Iterator[Finding]:
        if file.kind not in self.applies_to:
            return
        seen: set[tuple[int, str]] = set()
        for label, pattern in self._PATTERNS:
            for m, line, col in iter_matches(pattern, file.text):
                token = m.group(2) if label == "Generic assignment" else m.group(0)
                if self._PLACEHOLDER.search(token) or (line, label) in seen:
                    continue
                seen.add((line, label))
                yield self.finding(
                    file,
                    line=line,
                    column=col,
                    snippet=redact(token) if label != "Private key block" else token,
                    message=f"{label} detected ({redact(token) if label != 'Private key block' else 'PEM block'})",
                    severity=Severity.CRITICAL
                    if label in {"Private key block", "AWS access key"}
                    else Severity.HIGH,
                )


_OUTBOUND_SEND = rx(
    r"(\bcurl\b[^\n|;]*\s(-d|--data|--data-binary|--data-raw|--data-urlencode|-F|--form|-T|--upload-file|-X\s*(POST|PUT|PATCH))\b"
    r"|\bwget\b[^\n|;]*\s--post-(data|file)\b"
    r"|\brequests\.(post|put|patch)\s*\("
    r"|\bhttpx\.(post|put|patch)\s*\("
    r"|\burllib\.request\.(urlopen|Request)\s*\([^\n]*data\s*="
    r"|\bfetch\s*\([^\n]*method\s*:\s*[\"'](POST|PUT|PATCH)"
    r"|\baxios\.(post|put|patch)\s*\("
    r"|\bInvoke-(RestMethod|WebRequest)\b[^\n]*-Method\s+(Post|Put|Patch)"
    r"|\b(nc|ncat|netcat)\s+[^\n]*\d{2,5}\b"
    r"|\b(scp|rsync|sftp)\s+[^\n]*\S+@\S+:"
    r"|\bsmtplib\.|\bsendmail\b|\bmail\s+-s\b)"
)


class OutboundDataTransfer(RegexRule):
    id = "SC-EXF-004"
    title = "Outbound data transfer"
    description = "Sends request bodies or files to a remote endpoint."
    severity = Severity.MEDIUM
    confidence = Confidence.DETERMINISTIC
    category = Category.EXFILTRATION
    applies_to = EXEC_KINDS
    capabilities = ("network.egress",)
    remediation = "Declare `network.egress` and the destination hosts in the capability manifest."
    patterns = (_OUTBOUND_SEND,)
    message_template = "Outbound transfer via '{match}'"


class ExfiltrationCorrelation(Rule):
    """Heuristic correlation: a file that both reads secrets *and* sends data outward."""

    id = "SC-EXF-005"
    title = "Credential read combined with outbound transfer"
    description = "The same file references credential material and performs outbound transfers — classic exfiltration shape."
    severity = Severity.CRITICAL
    confidence = Confidence.HEURISTIC
    category = Category.EXFILTRATION
    applies_to = EXEC_KINDS
    capabilities = ("secrets.read", "network.egress")
    remediation = "Separate credential handling from network code and justify both in the manifest."

    def check(self, file: SkillFile, ctx: RuleContext) -> Iterator[Finding]:
        if file.kind not in self.applies_to or not file.text:
            return
        cred = next(iter_matches(_CRED_RE, file.text), None)
        env = any(p.search(file.text) for p in EnvironmentHarvesting.patterns)
        send = next(iter_matches(_OUTBOUND_SEND, file.text), None)
        if send is None or (cred is None and not env):
            return
        _, line, col = send
        what = f"credential path '{clip(cred[0].group(0), 40)}'" if cred else "environment dump"
        yield self.finding(
            file,
            line=line,
            column=col,
            snippet=send[0].group(0),
            message=f"File reads {what} and performs outbound transfer '{clip(send[0].group(0), 60)}'",
        )


class CovertChannel(RegexRule):
    id = "SC-EXF-006"
    title = "DNS/ICMP covert channel"
    description = "Encodes data into DNS lookups or ping payloads to bypass HTTP egress controls."
    severity = Severity.HIGH
    confidence = Confidence.DETERMINISTIC
    category = Category.EXFILTRATION
    applies_to = EXEC_KINDS
    capabilities = ("network.egress",)
    remediation = "Remove the covert channel."
    patterns = (
        rx(
            r"\b(nslookup|dig|host|drill)\s+[^\n]*(\$\(|`|\$\{|\$[A-Za-z_])[^\n]*\.(com|net|org|io|xyz|me|sh)\b"
        ),
        rx(r"\b(nslookup|dig|host)\s+[^\n]*\b(base64|xxd|od)\b"),
        rx(r"\bping\s+[^\n]*-p\s+[0-9a-f]{8,}"),
        rx(r"\bsocket\.gethostbyname\s*\(\s*[^\"')]*\+"),
        rx(r"\bdns\.(resolve|lookup)\s*\(\s*[^\"')]*\+"),
    )


RULES = (
    CredentialFileAccess(),
    EnvironmentHarvesting(),
    SecretPatterns(),
    OutboundDataTransfer(),
    ExfiltrationCorrelation(),
    CovertChannel(),
)
