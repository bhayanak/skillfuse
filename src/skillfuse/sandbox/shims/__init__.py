"""PATH shims for common egress/credential tools (curl, wget, nc, ssh, scp, …).

Each shim is a small POSIX shell script that records its invocation to ``$SKILLFUSE_EVENTS`` and then
either forwards to the mock recorder (curl/wget) or refuses (nc/ssh/scp/…). Installed first on ``PATH``
so scripts that shell out are observed even when they bypass the Python/Node runtime shims.
"""

from __future__ import annotations

from pathlib import Path

_RECORD = r"""#!/bin/sh
# skillfuse sandbox shim
_sc_json_escape() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/\\t/g' | tr '\n' ' '; }
_sc_emit() {
  [ -n "$SKILLFUSE_EVENTS" ] || return 0
  printf '{"type":"%s","tool":"%s","argv":"%s","runtime":"shell","ts":%s}\n' "$1" "$2" "$(_sc_json_escape "$3")" "$(date +%s)" >> "$SKILLFUSE_EVENTS"
}
"""

_FORWARD_HTTP = (
    _RECORD
    + r"""
TOOL="{tool}"
ARGS="$*"
# Extract first URL-ish argument for the recorder.
URL=""
for a in "$@"; do case "$a" in http://*|https://*|ftp://*) URL="$a"; break;; esac; done
HOST=$(printf '%s' "$URL" | sed -E 's#^[a-z]+://([^/]+).*#\1#')
if [ -n "$SKILLFUSE_EVENTS" ]; then
  printf '{"type":"egress","tool":"%s","host":"%s","url":"%s","argv":"%s","runtime":"shell","ts":%s}\n' "$TOOL" "$(_sc_json_escape "$HOST")" "$(_sc_json_escape "$URL")" "$(_sc_json_escape "$ARGS")" "$(date +%s)" >> "$SKILLFUSE_EVENTS"
fi
if [ -z "$SKILLFUSE_MOCK_ADDR" ]; then
  echo "skillfuse sandbox: $TOOL egress blocked ($URL)" >&2
  exit 7
fi
# Rewrite to mock recorder, keep the path so the recorder can log it; pass original host as header.
PATHPART=$(printf '%s' "$URL" | sed -E 's#^[a-z]+://[^/]*##')
NEWURL="http://$SKILLFUSE_MOCK_ADDR${PATHPART:-/}"
REAL="{real}"
if [ -z "$REAL" ]; then
  echo "skillfuse sandbox: recorded $TOOL to $HOST" >&2
  exit 0
fi
NEWARGS=""
for a in "$@"; do
  case "$a" in http://*|https://*|ftp://*) a="$NEWURL";; esac
  NEWARGS="$NEWARGS \"$(printf '%s' "$a" | sed 's/"/\\"/g')\""
done
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY
eval exec "$REAL" {hosthdr} $NEWARGS
"""
)

_REFUSE = (
    _RECORD
    + r"""
_sc_emit {event} "{tool}" "$*"
echo "skillfuse sandbox: {tool} is not permitted" >&2
exit 7
"""
)

_RECORD_ONLY = (
    _RECORD
    + r"""
_sc_emit {event} "{tool}" "$*"
REAL="{real}"
[ -n "$REAL" ] && exec "$REAL" "$@"
exit 0
"""
)

HTTP_TOOLS = ("curl", "wget")
REFUSED_TOOLS: dict[str, str] = {
    "nc": "egress",
    "ncat": "egress",
    "netcat": "egress",
    "socat": "egress",
    "ssh": "egress",
    "scp": "egress",
    "sftp": "egress",
    "rsync": "egress",
    "telnet": "egress",
    "ftp": "egress",
    "openssl": "egress",
    "nslookup": "dns",
    "dig": "dns",
    "host": "dns",
    "sudo": "privesc",
    "su": "privesc",
    "doas": "privesc",
    "crontab": "persistence",
    "launchctl": "persistence",
    "systemctl": "persistence",
    "mail": "egress",
    "sendmail": "egress",
}
RECORDED_TOOLS: dict[str, str] = {
    "pip": "install",
    "pip3": "install",
    "npm": "install",
    "npx": "install",
    "yarn": "install",
    "pnpm": "install",
    "uv": "install",
    "uvx": "install",
    "brew": "install",
    "apt-get": "install",
    "gem": "install",
    "cargo": "install",
    "git": "git",
    "gh": "git",
    "docker": "spawn",
    "kubectl": "cloud",
    "aws": "cloud",
    "az": "cloud",
    "gcloud": "cloud",
    "chmod": "fs",
    "rm": "fs",
    "base64": "obfuscation",
}


def _real(name: str, exclude_dir: Path) -> str:
    import shutil  # noqa: PLC0415

    for cand in (shutil.which(name) or "",):
        if cand and Path(cand).parent != exclude_dir:
            return cand
    return ""


def install_shims(bin_dir: Path, *, forward_http: bool = True) -> Path:
    bin_dir.mkdir(parents=True, exist_ok=True)
    for tool in HTTP_TOOLS:
        real = _real(tool, bin_dir) if forward_http else ""
        hosthdr = '-H "X-Skillfuse-Host: $HOST"' if tool == "curl" else '--header="X-Skillfuse-Host: $HOST"'
        _write(
            bin_dir / tool,
            _FORWARD_HTTP.replace("{tool}", tool).replace("{real}", real).replace("{hosthdr}", hosthdr),
        )
    for tool, event in REFUSED_TOOLS.items():
        _write(bin_dir / tool, _REFUSE.replace("{tool}", tool).replace("{event}", event))
    for tool, event in RECORDED_TOOLS.items():
        # rm/chmod/git must keep working for the script to behave normally; record and forward.
        real = _real(tool, bin_dir)
        if tool in {
            "pip",
            "pip3",
            "npm",
            "npx",
            "yarn",
            "pnpm",
            "uv",
            "uvx",
            "brew",
            "apt-get",
            "gem",
            "cargo",
        }:
            real = ""  # installs are recorded but never executed
        _write(
            bin_dir / tool,
            _RECORD_ONLY.replace("{tool}", tool).replace("{event}", event).replace("{real}", real),
        )
    return bin_dir


def _write(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")
    path.chmod(0o755)
