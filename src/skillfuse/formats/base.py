"""Low-level file parsing shared by all format handlers."""

from __future__ import annotations

import re
import stat
from pathlib import Path
from typing import Any

import yaml

from skillfuse.core.models import FileKind, SkillFile

_FRONTMATTER_RE = re.compile(r"\A---[ \t]*\r?\n(.*?)\r?\n---[ \t]*(?:\r?\n|\Z)", re.DOTALL)

SCRIPT_LANGUAGES: dict[str, str] = {
    ".sh": "shell",
    ".bash": "shell",
    ".zsh": "shell",
    ".ksh": "shell",
    ".py": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".ps1": "powershell",
    ".psm1": "powershell",
    ".rb": "ruby",
    ".pl": "perl",
    ".php": "php",
    ".bat": "batch",
    ".cmd": "batch",
}
CONFIG_SUFFIXES = {".json", ".yaml", ".yml", ".toml", ".jsonc", ".json5"}
MARKDOWN_SUFFIXES = {".md", ".mdc", ".markdown", ".mdx", ".txt"}
SHEBANG_LANG = (
    (re.compile(r"^#!.*\b(ba|z|k|da)?sh\b"), "shell"),
    (re.compile(r"^#!.*\bpython"), "python"),
    (re.compile(r"^#!.*\bnode\b"), "javascript"),
    (re.compile(r"^#!.*\bpwsh\b"), "powershell"),
)


def split_frontmatter(text: str) -> tuple[dict[str, Any], str, int]:
    """Return (frontmatter, body, body_line_offset)."""
    m = _FRONTMATTER_RE.match(text)
    if not m:
        return {}, text, 0
    raw = m.group(1)
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError:
        data = {"__invalid_frontmatter__": True}
    if not isinstance(data, dict):
        data = {"__invalid_frontmatter__": True} if data is not None else {}
    body = text[m.end() :]
    offset = text.count("\n", 0, m.end())
    return data, body, offset


def is_probably_binary(data: bytes) -> bool:
    if not data:
        return False
    sample = data[:8000]
    if b"\x00" in sample:
        return True
    text_chars = bytes(range(32, 127)) + b"\n\r\t\b\f\x1b"
    nontext = sample.translate(None, text_chars)
    return len(nontext) / len(sample) > 0.30


def classify(path: Path, text: str | None) -> tuple[FileKind, str | None]:
    suffix = path.suffix.lower()
    name = path.name.lower()
    if suffix in SCRIPT_LANGUAGES:
        return FileKind.SCRIPT, SCRIPT_LANGUAGES[suffix]
    if name in {"makefile", "justfile", "dockerfile"} or name.startswith("dockerfile."):
        return FileKind.SCRIPT, "shell"
    if text is not None:
        first = text.split("\n", 1)[0]
        for pattern, lang in SHEBANG_LANG:
            if pattern.match(first):
                return FileKind.SCRIPT, lang
    if suffix in CONFIG_SUFFIXES:
        return FileKind.CONFIG, suffix.lstrip(".")
    if suffix in MARKDOWN_SUFFIXES or suffix == "":
        return FileKind.INSTRUCTIONS, "markdown"
    return FileKind.DATA, None


def read_skill_file(root: Path, path: Path, *, max_bytes: int = 2_000_000) -> SkillFile:
    rel = path.relative_to(root).as_posix()
    is_symlink = path.is_symlink()
    target: str | None = None
    executable = False
    if is_symlink:
        target = (
            str(Path(path.parent, Path(path).readlink()).resolve()) if path.exists() else str(path.readlink())
        )
    try:
        st = path.stat()
        executable = bool(st.st_mode & stat.S_IXUSR)
        size = st.st_size
    except OSError:
        size = 0
    if is_symlink and not path.exists():
        return SkillFile(path=rel, kind=FileKind.DATA, is_symlink=True, symlink_target=target, size=0)
    try:
        with path.open("rb") as fh:
            data = fh.read(max_bytes + 1)
    except OSError:
        return SkillFile(
            path=rel, kind=FileKind.DATA, size=size, is_symlink=is_symlink, symlink_target=target
        )
    truncated = len(data) > max_bytes
    data = data[:max_bytes]
    if is_probably_binary(data):
        return SkillFile(
            path=rel,
            kind=FileKind.BINARY,
            size=size,
            is_symlink=is_symlink,
            symlink_target=target,
            executable=executable,
        )
    text = data.decode("utf-8", errors="replace")
    kind, language = classify(path, text)
    frontmatter: dict[str, Any] = {}
    offset = 0
    if kind == FileKind.INSTRUCTIONS:
        frontmatter, text, offset = split_frontmatter(text)
    return SkillFile(
        path=rel,
        kind=kind,
        text=text,
        frontmatter=frontmatter,
        body_offset=offset,
        language=language,
        size=size if not truncated else max_bytes,
        is_symlink=is_symlink,
        symlink_target=target,
        executable=executable,
    )
