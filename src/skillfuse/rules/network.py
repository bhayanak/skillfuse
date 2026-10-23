"""SC-NET-*: URL and endpoint hygiene."""

from __future__ import annotations

import fnmatch
import ipaddress
import re
from collections.abc import Iterator
from urllib.parse import urlsplit

from skillfuse.core.models import Category, Confidence, Finding, Severity, SkillFile
from skillfuse.core.textutil import iter_matches
from skillfuse.rules.base import TEXT_KINDS, Rule, RuleContext, RuleDescriptor

URL_RE = re.compile(r"\b(?:https?|wss?|ftp)://[^\s<>\"'`)\]}]+", re.IGNORECASE)

SUSPICIOUS_HOSTS: tuple[str, ...] = (
    # shorteners
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "cutt.ly",
    "rb.gy",
    "shorturl.at",
    "tiny.cc",
    "ow.ly",
    # paste / anonymous hosting
    "pastebin.com",
    "paste.ee",
    "hastebin.com",
    "ghostbin.",
    "rentry.co",
    "transfer.sh",
    "file.io",
    "anonfiles.com",
    "gofile.io",
    "0x0.st",
    "temp.sh",
    "catbox.moe",
    "termbin.com",
    "dpaste.",
    # tunnels / request catchers (OAST)
    "ngrok.io",
    "ngrok-free.app",
    "ngrok.app",
    "loca.lt",
    "localtunnel.me",
    "serveo.net",
    "trycloudflare.com",
    "webhook.site",
    "requestbin.",
    "pipedream.net",
    "requestcatcher.com",
    "hookbin.com",
    "beeceptor.com",
    "burpcollaborator.net",
    "oastify.com",
    "oast.fun",
    "oast.live",
    "oast.me",
    "oast.online",
    "oast.pro",
    "oast.site",
    "interact.sh",
    "interactsh.com",
    "canarytokens.com",
    "dnslog.cn",
    "ceye.io",
    # dynamic dns
    "duckdns.org",
    "no-ip.org",
    "ddns.net",
    "hopto.org",
    "zapto.org",
    "sytes.net",
    "dynu.net",
    # discord/telegram webhooks are common exfil sinks
    "discord.com/api/webhooks",
    "discordapp.com/api/webhooks",
    "api.telegram.org/bot",
)
SUSPICIOUS_TLDS: frozenset[str] = frozenset(
    {
        "tk",
        "ml",
        "ga",
        "cf",
        "gq",
        "xyz",
        "top",
        "zip",
        "mov",
        "click",
        "link",
        "work",
        "live",
        "icu",
        "cam",
        "buzz",
        "monster",
        "rest",
        "su",
        "ru",
        "cn",
        "onion",
    }
)
_PRIVATE_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1", "host.docker.internal"}  # noqa: S104
_DOC_HOSTS = {"example.com", "example.org", "example.net", "localhost"}


def _host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def _is_private(host: str) -> bool:
    if host in _PRIVATE_HOSTS:
        return True
    if _is_ip(host):
        ip = ipaddress.ip_address(host.strip("[]"))
        return ip.is_private or ip.is_loopback or ip.is_link_local
    return host.endswith((".local", ".internal", ".localhost"))


def _domain_allowed(host: str, allowed: list[str]) -> bool:
    return any(
        fnmatch.fnmatch(host, pat.lower())
        or host == pat.lower()
        or host.endswith("." + pat.lower().lstrip("*."))
        for pat in allowed
    )


class UrlHygiene(Rule):
    """One rule class emits several URL-related rule IDs so each URL is parsed exactly once."""

    id = "SC-NET-000"
    title = "URL hygiene"
    severity = Severity.LOW
    confidence = Confidence.DETERMINISTIC
    category = Category.NETWORK
    applies_to = TEXT_KINDS
    capabilities = ("network.egress",)

    _SUBRULES: dict[str, tuple[str, Severity, str]] = {
        "SC-NET-001": (
            "Plaintext (non-TLS) URL",
            Severity.LOW,
            "Use https:// so content cannot be tampered with in transit.",
        ),
        "SC-NET-002": (
            "Raw IP address endpoint",
            Severity.MEDIUM,
            "Use a named host with TLS; raw IPs evade allowlists and TLS validation.",
        ),
        "SC-NET-003": (
            "Shortener, paste site, tunnel, or OAST endpoint",
            Severity.HIGH,
            "Link to the canonical, reviewable source instead.",
        ),
        "SC-NET-004": (
            "Suspicious top-level domain",
            Severity.LOW,
            "Verify the destination is legitimate; prefer well-known domains.",
        ),
        "SC-NET-005": (
            "Domain outside the configured allowlist",
            Severity.MEDIUM,
            "Add the domain to `network.allowed_domains` if it is expected.",
        ),
        "SC-NET-006": (
            "Internationalised (punycode) domain",
            Severity.MEDIUM,
            "Punycode domains are a common homograph phishing vector; verify intent.",
        ),
        "SC-NET-007": (
            "Credentials embedded in URL",
            Severity.HIGH,
            "Never embed credentials in URLs; pass them via headers from a secret store.",
        ),
        "SC-NET-008": ("Non-standard port", Severity.LOW, "Confirm why a non-standard port is required."),
    }

    def descriptors(self) -> tuple[RuleDescriptor, ...]:
        return tuple(
            RuleDescriptor(
                id=rid,
                title=title,
                description=title,
                severity=sev,
                confidence=Confidence.DETERMINISTIC,
                category=Category.NETWORK,
                remediation=rem,
            )
            for rid, (title, sev, rem) in self._SUBRULES.items()
        )

    def check(self, file: SkillFile, ctx: RuleContext) -> Iterator[Finding]:
        if file.kind not in self.applies_to or not file.text:
            return
        allowed = ctx.config.network.allowed_domains
        flag_unlisted = ctx.config.network.flag_unlisted
        seen: set[tuple[str, str]] = set()
        for m, line, col in iter_matches(URL_RE, file.text):
            url = m.group(0).rstrip(".,;:!?")
            parts = urlsplit(url)
            host = _host(url)
            if not host or host in _DOC_HOSTS or _is_private(host):
                continue
            for sub_id, msg in self._classify(url, parts.scheme.lower(), host, parts, allowed, flag_unlisted):
                if (sub_id, url) in seen:
                    continue
                seen.add((sub_id, url))
                title, severity, remediation = self._SUBRULES[sub_id]
                yield Finding(
                    rule_id=sub_id,
                    title=title,
                    message=msg,
                    severity=severity,
                    confidence=Confidence.DETERMINISTIC,
                    category=Category.NETWORK,
                    location=self.finding(file, line=line, column=col, snippet=url).location,
                    capabilities=("network.egress",),
                    remediation=remediation,
                    tags=("url", host),
                )

    def _classify(
        self, url: str, scheme: str, host: str, parts: object, allowed: list[str], flag_unlisted: bool
    ) -> list[tuple[str, str]]:
        out: list[tuple[str, str]] = []
        if scheme in {"http", "ws", "ftp"}:
            out.append(("SC-NET-001", f"Plaintext {scheme}:// URL to {host}"))
        if _is_ip(host):
            out.append(("SC-NET-002", f"Raw IP endpoint {host}"))
        low = url.lower()
        for bad in SUSPICIOUS_HOSTS:
            if (bad.endswith(".") and bad in host) or host == bad or host.endswith("." + bad) or bad in low:
                out.append(("SC-NET-003", f"Endpoint matches suspicious host pattern '{bad}'"))
                break
        tld = host.rsplit(".", 1)[-1] if "." in host else ""
        if tld in SUSPICIOUS_TLDS and not _is_ip(host):
            out.append(("SC-NET-004", f"TLD .{tld} is frequently abused"))
        if "xn--" in host:
            out.append(("SC-NET-006", f"Punycode label in {host}"))
        if "@" in url.split("://", 1)[-1].split("/", 1)[0]:
            out.append(("SC-NET-007", f"Userinfo present in URL to {host}"))
        port = getattr(parts, "port", None)
        if port and port not in {80, 443, 8080, 8443}:
            out.append(("SC-NET-008", f"Port {port} on {host}"))
        if flag_unlisted and allowed and not _domain_allowed(host, allowed) and not _is_ip(host):
            out.append(("SC-NET-005", f"{host} is not in the allowlist"))
        return out


def extract_hosts(text: str) -> set[str]:
    return {h for h in (_host(m.group(0)) for m in URL_RE.finditer(text)) if h and not _is_private(h)}


RULES = (UrlHygiene(),)
SUBRULE_IDS = tuple(UrlHygiene._SUBRULES)
