"""Discovery of skill packages in a filesystem tree.

Supported layouts (host-agnostic, table driven):

* **Agent Skills** - a directory containing ``SKILL.md`` (Claude Code, Copilot, Cursor, Codex, ...).
* **VS Code customisations** - ``*.agent.md``, ``*.chatmode.md``, ``*.prompt.md``, ``*.instructions.md``.
* **Repo-level instructions** - ``AGENTS.md``, ``CLAUDE.md``, ``GEMINI.md``, ``copilot-instructions.md``.
* **Cursor** - ``.cursorrules``, ``.cursor/rules/*.mdc``.
* **MCP configurations** - ``mcp.json``, ``.mcp.json``, ``.vscode/mcp.json``, ``claude_desktop_config.json``.
* **Plugins** - directories holding ``plugin.json`` (``.claude-plugin/`` or root).
"""

from __future__ import annotations

import os
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any

import yaml

from skillfuse.core.hashing import DEFAULT_EXCLUDES, SIGNATURE_DIR
from skillfuse.core.models import FileKind, SkillKind, SkillPackage
from skillfuse.formats.base import read_skill_file, split_frontmatter
from skillfuse.formats.configs import parse_jsonc

INSTRUCTION_FILENAMES = {"agents.md", "claude.md", "gemini.md", "copilot-instructions.md", ".cursorrules"}
MCP_FILENAMES = {
    "mcp.json",
    ".mcp.json",
    "claude_desktop_config.json",
    "mcp_servers.json",
    "mcp-servers.json",
}
SINGLE_FILE_SUFFIXES: dict[str, SkillKind] = {
    ".agent.md": SkillKind.AGENT,
    ".chatmode.md": SkillKind.AGENT,
    ".prompt.md": SkillKind.PROMPT,
    ".instructions.md": SkillKind.INSTRUCTIONS,
    ".mcp.json": SkillKind.MCP_CONFIG,
    ".mdc": SkillKind.CURSOR_RULES,
}
MANIFEST_FILENAMES = ("skillfuse.yaml", "skillfuse.yml")


def _kind_for_file(path: Path) -> SkillKind | None:
    lower = path.name.lower()
    if lower == "skill.md":
        return SkillKind.SKILL
    if lower == "plugin.json":
        return SkillKind.PLUGIN
    if lower in MCP_FILENAMES:
        return SkillKind.MCP_CONFIG
    if lower in INSTRUCTION_FILENAMES:
        return SkillKind.INSTRUCTIONS
    for suffix, kind in SINGLE_FILE_SUFFIXES.items():
        if lower.endswith(suffix):
            if suffix == ".mdc" and path.parent.name != "rules":
                continue
            return kind
    return None


def _walk(root: Path, excludes: set[str]) -> Iterator[Path]:
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in excludes)
        for name in sorted(filenames):
            yield Path(dirpath) / name


def _load_declared_manifest(root: Path) -> dict[str, Any]:
    for name in MANIFEST_FILENAMES:
        p = root / name
        if p.is_file():
            try:
                data = yaml.safe_load(p.read_text(encoding="utf-8"))
            except (yaml.YAMLError, OSError):
                return {}
            return data if isinstance(data, dict) else {}
    return {}


def _package_from_dir(
    root: Path, entry: Path, kind: SkillKind, excludes: set[str], max_bytes: int
) -> SkillPackage:
    files = tuple(
        read_skill_file(root, p, max_bytes=max_bytes)
        for p in _walk(root, excludes | {SIGNATURE_DIR})
        if p.name not in excludes
    )
    rel_entry = entry.relative_to(root).as_posix()
    entry_file = next((f for f in files if f.path == rel_entry), None)
    metadata: dict[str, Any] = {}
    if entry_file is not None:
        if entry_file.kind == FileKind.CONFIG:
            parsed = parse_jsonc(entry_file.text)
            metadata = parsed if isinstance(parsed, dict) else {}
        else:
            metadata = dict(entry_file.frontmatter)
    declared = _load_declared_manifest(root)
    if declared:
        metadata["__skillfuse_manifest__"] = declared
    name = str(metadata.get("name") or declared.get("name") or root.name)
    return SkillPackage(
        name=name,
        kind=kind,
        root=str(root),
        entrypoint=rel_entry,
        files=files,
        metadata=metadata,
        publisher=_publisher(metadata, declared),
        version=_opt_str(metadata.get("version") or declared.get("version")),
    )


def _package_from_file(path: Path, kind: SkillKind, max_bytes: int) -> SkillPackage:
    root = path.parent
    sf = read_skill_file(root, path, max_bytes=max_bytes)
    metadata: dict[str, Any]
    if sf.kind == FileKind.CONFIG:
        parsed = parse_jsonc(sf.text)
        metadata = parsed if isinstance(parsed, dict) else {}
    else:
        metadata = dict(sf.frontmatter)
    declared = _load_declared_manifest(root)
    if declared and declared.get("name") in (None, metadata.get("name"), path.stem, path.name):
        metadata["__skillfuse_manifest__"] = declared
    stem = path.name
    for suffix in SINGLE_FILE_SUFFIXES:
        if stem.lower().endswith(suffix):
            stem = stem[: -len(suffix)]
            break
    else:
        stem = path.stem if path.suffix else path.name
    if kind == SkillKind.MCP_CONFIG:
        stem = f"{path.parent.name}/{path.name}" if path.parent.name else path.name
    name = str(metadata.get("name") or stem)
    return SkillPackage(
        name=name,
        kind=kind,
        root=str(root),
        entrypoint=sf.path,
        files=(sf,),
        metadata=metadata,
        publisher=_publisher(metadata, declared),
        version=_opt_str(metadata.get("version")),
    )


def _publisher(metadata: dict[str, Any], declared: dict[str, Any]) -> str | None:
    nested = metadata.get("metadata")
    sources: list[dict[str, Any]] = [declared, metadata, nested if isinstance(nested, dict) else {}]
    for source in sources:
        for key in ("publisher", "author", "owner", "maintainer"):
            value = source.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
            if isinstance(value, dict) and isinstance(value.get("name"), str):
                return str(value["name"])
    return None


def _opt_str(value: Any) -> str | None:
    return str(value) if value not in (None, "") else None


def discover_packages(
    target: Path,
    *,
    excludes: Iterable[str] = DEFAULT_EXCLUDES,
    max_bytes: int = 2_000_000,
) -> list[SkillPackage]:
    """Discover every skill package under *target* (a file or directory)."""
    target = target.resolve()
    excluded = set(excludes)
    if target.is_file():
        file_kind = _kind_for_file(target) or SkillKind.UNKNOWN
        if file_kind in (SkillKind.SKILL, SkillKind.PLUGIN):
            root = target.parent.parent if target.parent.name == ".claude-plugin" else target.parent
            return [_package_from_dir(root, target, file_kind, excluded, max_bytes)]
        return [_package_from_file(target, file_kind, max_bytes)]

    packages: list[SkillPackage] = []
    dir_roots: list[Path] = []
    # Pass 1: directory-shaped packages (SKILL.md / plugin.json)
    for path in _walk(target, excluded):
        kind = _kind_for_file(path)
        if kind == SkillKind.SKILL:
            dir_roots.append(path.parent)
            packages.append(_package_from_dir(path.parent, path, kind, excluded, max_bytes))
        elif kind == SkillKind.PLUGIN:
            plugin_root = path.parent.parent if path.parent.name == ".claude-plugin" else path.parent
            if any(plugin_root == r or plugin_root.is_relative_to(r) for r in dir_roots):
                continue
            dir_roots.append(plugin_root)
            packages.append(_package_from_dir(plugin_root, path, kind, excluded, max_bytes))
    # Pass 2: single-file packages not already covered
    for path in _walk(target, excluded):
        if any(path.is_relative_to(r) for r in dir_roots):
            continue
        single_kind = _kind_for_file(path)
        if single_kind is None or single_kind in (SkillKind.SKILL, SkillKind.PLUGIN):
            continue
        packages.append(_package_from_file(path, single_kind, max_bytes))
    if not packages:
        # Treat the whole directory as one opaque package so rules still run.
        entry = _first_markdown(target, excluded) or target
        packages.append(
            _package_from_dir(
                target, entry if entry != target else target, SkillKind.UNKNOWN, excluded, max_bytes
            )
        )
    return _dedupe(packages)


def _first_markdown(root: Path, excludes: set[str]) -> Path | None:
    for p in _walk(root, excludes):
        if p.suffix.lower() == ".md":
            return p
    return None


def _dedupe(packages: list[SkillPackage]) -> list[SkillPackage]:
    seen: dict[tuple[str, str], SkillPackage] = {}
    for pkg in packages:
        seen.setdefault((pkg.root, pkg.entrypoint), pkg)
    return list(seen.values())


def read_frontmatter(path: Path) -> dict[str, Any]:
    data, _, _ = split_frontmatter(path.read_text(encoding="utf-8", errors="replace"))
    return data
