from __future__ import annotations

import os
from pathlib import Path

import pytest
from pydantic import ValidationError

from skillchain.core.config import ScanConfig
from skillchain.core.hashing import file_digest, iter_package_files, text_digest, tree_digest
from skillchain.core.models import (
    CapabilityManifest,
    Category,
    Confidence,
    Decision,
    Finding,
    Location,
    Severity,
)
from skillchain.core.textutil import clip, iter_matches, line_of, offset_to_line_col, redact


def _finding(**kw: object) -> Finding:
    base: dict[str, object] = {
        "rule_id": "SC-PI-001",
        "title": "t",
        "message": "m",
        "severity": Severity.HIGH,
        "confidence": Confidence.HEURISTIC,
        "category": Category.PROMPT_INJECTION,
        "location": Location(path="SKILL.md", line=3, snippet="ignore all previous instructions"),
    }
    base.update(kw)
    return Finding(**base)  # type: ignore[arg-type]


class TestSeverity:
    def test_ordering(self) -> None:
        assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW > Severity.INFO
        assert Severity.HIGH >= Severity.HIGH
        assert Severity.LOW <= Severity.MEDIUM
        assert not Severity.LOW > Severity.HIGH

    def test_sarif_level(self) -> None:
        assert Severity.CRITICAL.sarif_level == "error"
        assert Severity.MEDIUM.sarif_level == "warning"
        assert Severity.INFO.sarif_level == "note"
        assert float(Severity.CRITICAL.security_severity) > float(Severity.LOW.security_severity)

    def test_compare_with_other_type(self) -> None:
        assert Severity.HIGH.__ge__("x") is NotImplemented


class TestFinding:
    def test_fingerprint_stable_across_line_moves(self) -> None:
        a = _finding(location=Location(path="SKILL.md", line=3, snippet="x"))
        b = _finding(location=Location(path="SKILL.md", line=30, snippet="x"))
        assert a.fingerprint == b.fingerprint
        c = _finding(location=Location(path="SKILL.md", line=3, snippet="y"))
        assert a.fingerprint != c.fingerprint

    def test_rule_id_pattern(self) -> None:
        with pytest.raises(ValidationError):
            _finding(rule_id="bad")

    def test_with_skill(self) -> None:
        assert _finding().with_skill("s").skill == "s"


class TestManifest:
    def test_dedupe_and_sort(self) -> None:
        m = CapabilityManifest(capabilities=("b", "a", "a"))
        assert m.capabilities == ("a", "b")

    def test_has_prefix(self) -> None:
        m = CapabilityManifest(capabilities=("network.egress",))
        assert m.has("network")
        assert m.has("network.egress")
        assert not m.has("filesystem")

    def test_strong_excludes_weak(self) -> None:
        m = CapabilityManifest(capabilities=("a", "b"), weak=("b",))
        assert m.strong == ("a",)


class TestDecision:
    def test_rank(self) -> None:
        assert Decision.BLOCK.rank > Decision.QUARANTINE.rank > Decision.ALLOW.rank


class TestHashing:
    def test_tree_digest_is_deterministic_and_content_sensitive(self, tmp_path: Path) -> None:
        (tmp_path / "a.txt").write_text("hello")
        (tmp_path / "sub").mkdir()
        (tmp_path / "sub" / "b.txt").write_text("world")
        d1 = tree_digest(tmp_path)
        assert d1.startswith("sha256:")
        assert tree_digest(tmp_path) == d1
        os.utime(tmp_path / "a.txt", (0, 0))
        assert tree_digest(tmp_path) == d1, "mtime must not affect digest"
        (tmp_path / "a.txt").write_text("hello!")
        assert tree_digest(tmp_path) != d1

    def test_executable_bit_changes_digest(self, tmp_path: Path) -> None:
        f = tmp_path / "run.sh"
        f.write_text("echo hi")
        d1 = tree_digest(tmp_path)
        f.chmod(0o755)
        assert tree_digest(tmp_path) != d1

    def test_excludes_and_signature_dir(self, tmp_path: Path) -> None:
        (tmp_path / "a").write_text("a")
        (tmp_path / ".git").mkdir()
        (tmp_path / ".git" / "x").write_text("x")
        (tmp_path / ".skillchain").mkdir()
        (tmp_path / ".skillchain" / "sig").write_text("s")
        files = [p.name for p in iter_package_files(tmp_path)]
        assert files == ["a"]
        assert "sig" in [p.name for p in iter_package_files(tmp_path, include_signature_dir=True)]

    def test_symlink_digest(self, tmp_path: Path) -> None:
        (tmp_path / "t").write_text("t")
        (tmp_path / "l").symlink_to("t")
        assert file_digest(tmp_path / "l") != file_digest(tmp_path / "t")

    def test_text_digest(self) -> None:
        assert text_digest("a") == text_digest("a") != text_digest("b")


class TestTextUtil:
    def test_offset_to_line_col(self) -> None:
        text = "ab\ncd\nef"
        assert offset_to_line_col(text, 0) == (1, 1)
        assert offset_to_line_col(text, 3) == (2, 1)
        assert offset_to_line_col(text, 7) == (3, 2)

    def test_iter_matches_skips_leading_whitespace(self) -> None:
        import re

        text = "x\n\nenv | curl"
        (_m, line, col), *_ = list(iter_matches(re.compile(r"\s*env"), text))
        assert line == 3
        assert col == 1

    def test_clip_and_redact(self) -> None:
        assert clip("a" * 200, 10).endswith("…")
        assert len(clip("a" * 200, 10)) == 10
        assert redact("AKIAIOSFODNN7EXAMPLE") == "AKIA…MPLE"
        assert redact("short") == "*****"
        assert line_of("a\nb\nc", 2) == "b"
        assert line_of("a", 5) == ""


class TestConfig:
    def test_load_default_when_missing(self, tmp_path: Path) -> None:
        cfg = ScanConfig.load(tmp_path)
        assert cfg.min_severity == "info"
        assert cfg.resolve(None) is None

    def test_load_file_and_resolve(self, tmp_path: Path) -> None:
        (tmp_path / ".skillchain.yaml").write_text(
            "disabled_rules: [SC-NET-004]\nbaseline: base.json\nnetwork:\n  allowed_domains: [api.github.com]\n  flag_unlisted: true\n"
        )
        cfg = ScanConfig.load(tmp_path)
        assert cfg.disabled_rules == ["SC-NET-004"]
        assert cfg.resolve(cfg.baseline) == tmp_path / "base.json"
        assert cfg.network.flag_unlisted

    def test_invalid_config(self, tmp_path: Path) -> None:
        p = tmp_path / "c.yaml"
        p.write_text("- not a mapping")
        with pytest.raises(ValueError, match="mapping"):
            ScanConfig.load(tmp_path, p)
        p.write_text("unknown_key: 1")
        with pytest.raises(ValidationError):
            ScanConfig.load(tmp_path, p)
