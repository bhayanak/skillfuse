"""Deterministic content hashing for skill packages.

The tree digest is the identity used by signing, lockfiles, and the transparency log. It must be
reproducible across operating systems, so it is computed over sorted POSIX-relative paths and raw bytes,
and never includes mtimes, uids, or permission bits (except the executable bit, which matters for behaviour).
"""

from __future__ import annotations

import hashlib
import os
import stat
from collections.abc import Iterable, Iterator
from pathlib import Path

DEFAULT_EXCLUDES: frozenset[str] = frozenset(
    {".git", ".hg", ".svn", "__pycache__", ".DS_Store", "node_modules", ".venv", ".mypy_cache", ".ruff_cache"}
)
SIGNATURE_DIR = ".skillchain"


def iter_package_files(
    root: Path, *, excludes: Iterable[str] = DEFAULT_EXCLUDES, include_signature_dir: bool = False
) -> Iterator[Path]:
    """Yield regular files (and symlinks) under *root* in a stable, sorted order."""
    excluded = set(excludes)
    if not include_signature_dir:
        excluded.add(SIGNATURE_DIR)
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in excluded)
        for name in sorted(filenames):
            if name in excluded:
                continue
            yield Path(dirpath) / name


def file_digest(path: Path) -> str:
    h = hashlib.sha256()
    if path.is_symlink():
        h.update(b"symlink\0")
        h.update(str(path.readlink()).encode("utf-8", "surrogateescape"))
        return h.hexdigest()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def _mode_tag(path: Path) -> bytes:
    if path.is_symlink():
        return b"l"
    try:
        mode = path.stat().st_mode
    except OSError:
        return b"f"
    return b"x" if mode & stat.S_IXUSR else b"f"


def tree_digest(root: Path, *, excludes: Iterable[str] = DEFAULT_EXCLUDES) -> str:
    """Return ``sha256:<hex>`` over all files in *root*.

    Each entry contributes ``<mode>\\0<relative-posix-path>\\0<sha256(content)>\\n`` to the outer hash.
    """
    root = root.resolve()
    outer = hashlib.sha256()
    for path in iter_package_files(root, excludes=excludes):
        rel = path.relative_to(root).as_posix().encode("utf-8")
        outer.update(_mode_tag(path) + b"\0" + rel + b"\0" + file_digest(path).encode("ascii") + b"\n")
    return f"sha256:{outer.hexdigest()}"


def text_digest(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()
