"""Scanner configuration (``.skillchain.yaml`` at the scan root or passed via ``--config``)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field

from skillchain.core.hashing import DEFAULT_EXCLUDES

CONFIG_FILENAMES = (".skillchain.yaml", ".skillchain.yml", "skillchain.config.yaml")


class NetworkConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    allowed_domains: list[str] = Field(
        default_factory=list,
        description="Glob-style domains that are expected (e.g. 'api.github.com', '*.hpe.com').",
    )
    flag_unlisted: bool = Field(
        default=False, description="Emit SC-NET-005 for domains outside the allowlist."
    )


class ScanConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    excludes: list[str] = Field(default_factory=lambda: sorted(DEFAULT_EXCLUDES))
    disabled_rules: list[str] = Field(default_factory=list)
    rules_dirs: list[str] = Field(default_factory=list, description="Directories with custom YAML rules.")
    baseline: str | None = Field(
        default=None, description="Path to a baseline JSON of accepted fingerprints."
    )
    network: NetworkConfig = Field(default_factory=NetworkConfig)
    max_file_bytes: int = Field(default=2_000_000, ge=1)
    min_severity: str = Field(default="info")
    semgrep: bool = Field(default=False, description="Run semgrep with bundled rules if available.")
    base_dir: str | None = Field(default=None, exclude=True)

    @classmethod
    def load(cls, start: Path, explicit: Path | None = None) -> ScanConfig:
        path = explicit
        if path is None:
            base = start if start.is_dir() else start.parent
            for candidate in CONFIG_FILENAMES:
                if (base / candidate).is_file():
                    path = base / candidate
                    break
        if path is None:
            return cls()
        raw: Any = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if not isinstance(raw, dict):
            msg = f"{path}: configuration must be a mapping"
            raise ValueError(msg)
        cfg = cls.model_validate(raw)
        cfg.base_dir = str(path.parent)
        return cfg

    def resolve(self, rel: str | None) -> Path | None:
        if rel is None:
            return None
        p = Path(rel)
        if not p.is_absolute() and self.base_dir:
            p = Path(self.base_dir) / p
        return p
