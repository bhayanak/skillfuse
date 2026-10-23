#!/usr/bin/env python3
"""Pin every `uses:` in workflows/action.yml to a commit SHA with a `# vX.Y.Z` comment.

Usage: python scripts/pin_actions.py [--check]

Resolution: for each action, the newest semver tag within the configured major version is looked up via
`gh api` and dereferenced to its commit SHA. Reusable workflows that must stay tag-referenced (SLSA
generator) are listed in KEEP_TAG. Requires an authenticated `gh`.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FILES = [*sorted((ROOT / ".github" / "workflows").glob("*.yml")), ROOT / "action.yml"]

# action -> major version to track
TARGETS: dict[str, str] = {
    "actions/checkout": "v6",
    "actions/setup-python": "v6",
    "actions/setup-node": "v6",
    "actions/upload-artifact": "v5",
    "actions/download-artifact": "v6",
    "actions/attest-build-provenance": "v3",
    "astral-sh/setup-uv": "v7",
    "codecov/codecov-action": "v5",
    "docker/setup-buildx-action": "v3",
    "docker/build-push-action": "v6",
    "docker/login-action": "v3",
    "docker/metadata-action": "v5",
    "github/codeql-action": "v4",
    "ossf/scorecard-action": "v2",
    "sigstore/gh-action-sigstore-python": "v3",
    "softprops/action-gh-release": "v2",
    "pypa/gh-action-pypi-publish": "v1",
}
# The SLSA generator verifies its own ref and rejects commit hashes; keep a tag.
KEEP_TAG: dict[str, str] = {"slsa-framework/slsa-github-generator": "v2.1.0"}

USES_RE = re.compile(
    r"^(?P<indent>\s*(?:-\s+)?uses:\s+)(?P<repo>[\w.-]+/[\w.-]+)(?P<sub>/[^@\s]+)?@(?P<ref>\S+)(?P<rest>.*)$"
)
SEMVER = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")


def gh(path: str) -> object:
    out = subprocess.run(["gh", "api", "--paginate", path], capture_output=True, text=True, check=True).stdout
    # --paginate may concatenate arrays; normalise.
    chunks = [c for c in out.replace("][", "]\n[").split("\n") if c.strip()]
    if len(chunks) > 1 and all(c.strip().startswith("[") for c in chunks):
        merged: list[object] = []
        for c in chunks:
            merged.extend(json.loads(c))
        return merged
    return json.loads(out)


def latest_tag(repo: str, major: str) -> str:
    tags = gh(f"repos/{repo}/tags?per_page=100")
    assert isinstance(tags, list)
    best: tuple[int, int, int] | None = None
    best_name = ""
    for t in tags:
        name = str(t["name"])
        m = SEMVER.match(name)
        if not m or f"v{m.group(1)}" != major:
            continue
        key = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
        if best is None or key > best:
            best, best_name = key, name
    if not best_name:
        msg = f"no {major}.x.y tag found for {repo}"
        raise SystemExit(msg)
    return best_name


def tag_sha(repo: str, tag: str) -> str:
    ref = gh(f"repos/{repo}/git/ref/tags/{tag}")
    assert isinstance(ref, dict)
    obj = ref["object"]
    if obj["type"] == "tag":  # annotated tag -> dereference to the commit
        tag_obj = gh(f"repos/{repo}/git/tags/{obj['sha']}")
        assert isinstance(tag_obj, dict)
        return str(tag_obj["object"]["sha"])
    return str(obj["sha"])


def main(check: bool) -> int:
    cache: dict[str, tuple[str, str]] = {}
    changed = 0
    for path in FILES:
        lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
        out: list[str] = []
        for line in lines:
            m = USES_RE.match(line.rstrip("\n"))
            if not m:
                out.append(line)
                continue
            repo = m.group("repo")
            if repo in KEEP_TAG:
                new = f"{m.group('indent')}{repo}{m.group('sub') or ''}@{KEEP_TAG[repo]}\n"
            elif repo in TARGETS:
                if repo not in cache:
                    tag = latest_tag(repo, TARGETS[repo])
                    cache[repo] = (tag_sha(repo, tag), tag)
                sha, tag = cache[repo]
                new = f"{m.group('indent')}{repo}{m.group('sub') or ''}@{sha} # {tag}\n"
            else:
                print(f"warning: no target for {repo} in {path.name}", file=sys.stderr)
                out.append(line)
                continue
            if new != line:
                changed += 1
            out.append(new)
        if not check:
            path.write_text("".join(out), encoding="utf-8")
    print(f"{'would change' if check else 'changed'} {changed} uses: line(s)")
    for repo, (sha, tag) in sorted(cache.items()):
        print(f"  {repo:40} {tag:10} {sha}")
    return 1 if (check and changed) else 0


if __name__ == "__main__":
    raise SystemExit(main("--check" in sys.argv))
