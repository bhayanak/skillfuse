"""SC-DEP-*: dependency installation hygiene."""

from __future__ import annotations

import re
from collections.abc import Iterator

from skillchain.core.models import Category, Confidence, Finding, Severity, SkillFile
from skillchain.core.textutil import iter_matches
from skillchain.rules.base import EXEC_KINDS, RegexRule, Rule, RuleContext, rx

_PIP_INSTALL = re.compile(
    r"\b(?:pip3?|python[23]?\s+-m\s+pip|uv\s+pip|uv\s+add|pipx\s+install|poetry\s+add|conda\s+install)\s+(?:install\s+)?(?P<args>[^\n|;&]+)",
    re.IGNORECASE,
)
_NPM_INSTALL = re.compile(
    r"\b(?:npm\s+(?:install|i|add)|yarn\s+(?:add|global\s+add)|pnpm\s+(?:add|install)|bun\s+(?:add|install))\s+(?P<args>[^\n|;&]+)",
    re.IGNORECASE,
)
_OTHER_INSTALL = re.compile(
    r"\b(?:cargo\s+install|gem\s+install|go\s+install|brew\s+install|apt(?:-get)?\s+install|dnf\s+install|yum\s+install|choco\s+install|winget\s+install)\s+(?P<args>[^\n|;&]+)",
    re.IGNORECASE,
)
_FLAG = re.compile(r"^-")
_PIN_PY = re.compile(r"(==|===|~=|>=|<=|!=|@)")
_PIN_NPM = re.compile(r"^(@[^/]+/)?[^@]+@.+$")
_LOCK_HINT = re.compile(
    r"(requirements.*\.txt|-r\s|\.lock|package\.json|pyproject|uv\.lock|Pipfile|--frozen|npm\s+ci|--locked)"
)


def _tokens(args: str) -> list[str]:
    return [t.strip("\"'") for t in args.split() if t and not _FLAG.match(t)]


class UnpinnedInstall(Rule):
    id = "SC-DEP-001"
    title = "Unpinned dependency install"
    description = "Installs a package without an exact version, so behaviour can change silently."
    severity = Severity.MEDIUM
    confidence = Confidence.DETERMINISTIC
    category = Category.DEPENDENCY
    applies_to = EXEC_KINDS
    capabilities = ("package.install", "network.egress")
    remediation = "Pin exact versions (and ideally hashes) or install from a lockfile."
    references = ("https://slsa.dev/spec/v1.0/requirements#dependencies",)

    def check(self, file: SkillFile, ctx: RuleContext) -> Iterator[Finding]:
        if file.kind not in self.applies_to or not file.text:
            return
        for pattern, pin in ((_PIP_INSTALL, _PIN_PY), (_NPM_INSTALL, _PIN_NPM), (_OTHER_INSTALL, None)):
            for m, line, col in iter_matches(pattern, file.text):
                args = m.group("args")
                if _LOCK_HINT.search(args) or "-e" in args.split():
                    continue
                unpinned = [
                    t
                    for t in _tokens(args)
                    if (pin is None or not pin.search(t))
                    and not t.startswith(("git+", "http", "./", "/", "."))
                ]
                if unpinned:
                    yield self.finding(
                        file,
                        line=line,
                        column=col,
                        snippet=m.group(0),
                        message=f"Unpinned: {', '.join(unpinned[:5])}",
                        severity=Severity.LOW if pin is None else Severity.MEDIUM,
                    )


class VcsOrUrlInstall(RegexRule):
    id = "SC-DEP-002"
    title = "Dependency installed from VCS or URL"
    description = "Installing from git/http bypasses registry provenance and is usually unpinned."
    severity = Severity.HIGH
    confidence = Confidence.DETERMINISTIC
    category = Category.DEPENDENCY
    applies_to = EXEC_KINDS
    capabilities = ("package.install", "network.egress")
    remediation = "Install a published release pinned to a version and hash, or vendor the code."
    patterns = (
        rx(
            r"\b(pip3?|uv\s+pip|uv\s+add|pipx)\s+(install\s+)?[^\n]*\b(git\+(https?|ssh)://\S+|https?://\S+\.(whl|tar\.gz|zip))"
        ),
        rx(
            r"\b(npm\s+(install|i|add)|yarn\s+add|pnpm\s+add)\s+[^\n]*\b(github:\S+|git\+\S+|https?://\S+|git://\S+|[\w-]+/[\w.-]+#\S+)"
        ),
        rx(r"\bgo\s+(install|get)\s+[^\n]*@(latest|master|main)\b"),
        rx(r"\bcargo\s+install\s+[^\n]*--git\b"),
    )
    exclude_patterns = (rx(r"@[0-9a-f]{40}\b"), rx(r"@v?\d+\.\d+\.\d+"), rx(r"#[0-9a-f]{40}\b"))


class UnpinnedClone(RegexRule):
    id = "SC-DEP-003"
    title = "Repository cloned without a pinned revision"
    description = "`git clone` of a moving branch means the executed code can change at any time."
    severity = Severity.MEDIUM
    confidence = Confidence.DETERMINISTIC
    category = Category.DEPENDENCY
    applies_to = EXEC_KINDS
    capabilities = ("network.egress", "filesystem.write")
    remediation = (
        "Clone then `git checkout <commit-sha>`, or download a tagged archive and verify its digest."
    )
    patterns = (
        rx(
            r"\bgit\s+clone\s+(?![^\n]*(--branch|-b)\s+v?\d)(?![^\n]*checkout\s+[0-9a-f]{7,})[^\n]*\b(https?|git|ssh)(://|@)[^\s]+"
        ),
    )


class CustomIndex(RegexRule):
    id = "SC-DEP-004"
    title = "Custom package index or registry"
    description = "Redirects package resolution to a non-default index (dependency-confusion vector)."
    severity = Severity.MEDIUM
    confidence = Confidence.DETERMINISTIC
    category = Category.DEPENDENCY
    applies_to = EXEC_KINDS
    capabilities = ("package.install", "network.egress")
    remediation = "Use the organisation-approved registry via configuration, not ad-hoc flags."
    patterns = (
        rx(r"--(extra-)?index-url\s*[= ]\s*\S+"),
        rx(r"\bPIP_(EXTRA_)?INDEX_URL\s*="),
        rx(r"\bnpm\s+(config\s+set\s+registry|install\s+[^\n]*--registry)\b"),
        rx(r"\b(npm_config_registry|NPM_CONFIG_REGISTRY)\s*="),
        rx(r"^\s*registry\s*=\s*https?://(?!registry\.npmjs\.org)", re.IGNORECASE | re.MULTILINE),
        rx(r"\bUV_(EXTRA_)?INDEX_URL\s*="),
    )


class TrustBypassInstall(RegexRule):
    id = "SC-DEP-005"
    title = "Package-manager trust bypass"
    description = "Flags that disable integrity checks or install into the system interpreter."
    severity = Severity.MEDIUM
    confidence = Confidence.DETERMINISTIC
    category = Category.DEPENDENCY
    applies_to = EXEC_KINDS
    capabilities = ("package.install",)
    remediation = "Remove the flag; use a virtual environment and keep integrity checks on."
    patterns = (
        rx(r"(^|\s)--break-system-packages\b"),
        rx(r"(^|\s)--ignore-scripts\b(?![^\n]*#\s*safe)"),
        rx(r"\bnpm\s+[^\n]*--(unsafe-perm|no-audit|no-package-lock|force)\b"),
        rx(r"\bpip\s+[^\n]*--(no-deps|pre|user)\b[^\n]*--(trusted-host|no-cache-dir)\b"),
        rx(r"\bNODE_TLS_REJECT_UNAUTHORIZED\s*=\s*0\b"),
        rx(r"\bstrict-ssl\s*=\s*false\b"),
    )


RULES = (UnpinnedInstall(), VcsOrUrlInstall(), UnpinnedClone(), CustomIndex(), TrustBypassInstall())
