from __future__ import annotations

import json
from pathlib import Path

from skillchain.core.config import ScanConfig
from skillchain.core.models import Severity
from skillchain.scanner import Scanner, scan_path

from .conftest import rule_ids, write_skill


class TestScanner:
    def test_scan_path_uses_config_in_tree(self, tmp_path: Path) -> None:
        root = write_skill(tmp_path / "s", "see https://evil.xyz/")
        (tmp_path / "s" / ".skillchain.yaml").write_text("disabled_rules: [SC-NET-004]")
        assert "SC-NET-004" not in rule_ids(scan_path(root))
        assert "SC-NET-004" in rule_ids(Scanner(ScanConfig()).scan(root))

    def test_min_severity(self, tmp_path: Path) -> None:
        root = write_skill(tmp_path / "s", "see https://evil.xyz/ and http://plain.example.net")
        res = Scanner(ScanConfig(min_severity="medium")).scan(root)
        assert all(f.severity >= Severity.MEDIUM for f in res.findings)

    def test_inline_suppression(self, tmp_path: Path) -> None:
        root = write_skill(
            tmp_path / "s",
            "see https://evil.xyz/ <!-- skillchain: ignore SC-NET-004 -->\nand https://bad.xyz/",
        )
        res = Scanner(ScanConfig()).scan(root)
        net4 = [f for f in res.findings if f.rule_id == "SC-NET-004"]
        assert len(net4) == 1
        assert res.suppressed >= 1
        root2 = write_skill(tmp_path / "s2", "# skillchain: ignore\nsee https://evil.xyz/")
        res2 = Scanner(ScanConfig()).scan(root2)
        assert not [f for f in res2.findings if f.rule_id == "SC-NET-004"]

    def test_baseline_fingerprints(self, tmp_path: Path) -> None:
        root = write_skill(tmp_path / "s", "see https://evil.xyz/")
        first = Scanner(ScanConfig()).scan(root)
        fps = [f.fingerprint for f in first.findings]
        base = tmp_path / "base.json"
        base.write_text(json.dumps({"fingerprints": fps}))
        second = Scanner(ScanConfig(baseline=str(base))).scan(root)
        assert second.findings == []
        assert second.suppressed == len(fps)
        # full report as baseline
        from skillchain.report import render_json

        base.write_text(render_json(first))
        third = Scanner(ScanConfig(baseline=str(base))).scan(root)
        assert third.findings == []
        base.write_text(json.dumps(fps))
        assert Scanner(ScanConfig(baseline=str(base))).scan(root).findings == []

    def test_findings_sorted_by_severity(self, corpus_result) -> None:  # type: ignore[no-untyped-def]
        for s in corpus_result.skills:
            ranks = [f.severity.rank for f in s.findings]
            assert ranks == sorted(ranks, reverse=True)

    def test_digest_for_single_and_multi_file(self, corpus_result) -> None:  # type: ignore[no-untyped-def]
        for s in corpus_result.skills:
            assert s.digest.startswith("sha256:")
            assert len(s.digest) == 7 + 64

    def test_error_isolation(self, tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        root = write_skill(tmp_path / "s", "x")
        scanner = Scanner(ScanConfig())

        def boom(*_a: object, **_k: object) -> None:
            raise RuntimeError("kaboom")

        monkeypatch.setattr(scanner, "scan_package", boom)
        res = scanner.scan(root)
        assert res.skills == ()
        assert res.errors and "kaboom" in res.errors[0]

    def test_missing_target(self, tmp_path: Path) -> None:
        res = Scanner(ScanConfig()).scan(tmp_path / "nope")
        assert res.skills == () or res.errors

    def test_result_properties(self, corpus_result) -> None:  # type: ignore[no-untyped-def]
        assert corpus_result.max_severity == Severity.CRITICAL
        skill = next(s for s in corpus_result.skills if s.package.name == "helpful-formatter")
        assert skill.max_severity == Severity.CRITICAL
        assert skill.count(Severity.CRITICAL) >= 2
        assert skill.count(Severity.CRITICAL, confidence=skill.findings[0].confidence) >= 1
