"""Reproducible packaging: a deterministic ``.tar.gz`` whose bytes depend only on content."""

from __future__ import annotations

import gzip
import hashlib
import io
import stat
import tarfile
from pathlib import Path

from skillfuse.core.hashing import DEFAULT_EXCLUDES, iter_package_files


def pack(root: Path, output: Path, *, include_signature: bool = True, prefix: str | None = None) -> str:
    """Write a reproducible archive of *root* to *output* and return ``sha256:<hex>`` of the archive bytes."""
    root = root.resolve()
    name = prefix if prefix is not None else root.name
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for path in iter_package_files(
            root, excludes=DEFAULT_EXCLUDES, include_signature_dir=include_signature
        ):
            rel = path.relative_to(root).as_posix()
            info = tar.gettarinfo(str(path), arcname=f"{name}/{rel}" if name else rel)
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mtime = 0
            info.pax_headers = {}
            if info.isreg():
                info.mode = 0o755 if path.stat().st_mode & stat.S_IXUSR else 0o644
                with path.open("rb") as fh:
                    tar.addfile(info, fh)
            else:
                info.mode = 0o777 if info.issym() else 0o644
                tar.addfile(info)
    raw = buf.getvalue()
    out = io.BytesIO()
    with gzip.GzipFile(fileobj=out, mode="wb", mtime=0, filename="") as gz:
        gz.write(raw)
    data = out.getvalue()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(data)
    return "sha256:" + hashlib.sha256(data).hexdigest()
