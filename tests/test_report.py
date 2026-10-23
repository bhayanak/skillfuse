from __future__ import annotations

import json
from pathlib import Path

from rich.console import Console

from skillchain.core.models import ScanResult
from skillchain.policy import PolicyEngine
from skillchain.report import render_console, render_json, render_markdown, render_sarif, summarise, to_sarif


def _verdicts(result: ScanResult):  # type: ignore[no-untyped-def]
    eng = PolicyEngine()
    return {s.package.name: eng.evaluate(s) for s in result.skills}


class TestSarif:
    def test_structure(self, corpus_result: ScanResult, corpus: Path) -> None:
        doc = to_sarif(corpus_result, base_dir=corpus)
        assert doc["version"] == "2.1.0"
        run = doc["runs"][0]
        assert run["tool"]["driver"]["name"] == "SkillChain"
        rules = {r["id"]: r for r in run["tool"]["driver"]["rules"]}
        results = run["results"]
        assert len(results) == len(corpus_result.findings)
        for r in results:
            assert r["ruleId"] in rules, r["ruleId"]
            assert r["level"] in {"error", "warning", "note"}
            loc = r["locations"][0]["physicalLocation"]
            assert loc["artifactLocation"]["uriBaseId"] == "%SRCROOT%"
            assert not loc["artifactLocation"]["uri"].startswith("/")
            assert loc["region"]["startLine"] >= 1
            assert "skillchain/v1" in r["partialFingerprints"]
            assert r["properties"]["confidence"] in {"deterministic", "heuristic"}
        for rule in rules.values():
            if "security-severity" in rule["properties"]:
                float(rule["properties"]["security-severity"])
        assert run["originalUriBaseIds"]["%SRCROOT%"]["uri"].startswith("file://")
        assert run["invocations"][0]["executionSuccessful"]

    def test_uri_relative_to_base(self, corpus_result: ScanResult, corpus: Path) -> None:
        doc = to_sarif(corpus_result, base_dir=corpus)
        uris = {
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            for r in doc["runs"][0]["results"]
        }
        assert "malicious/helpful-formatter/scripts/setup.sh" in uris
        assert "malicious/sneaky-reviewer.agent.md" in uris

    def test_render_is_json(self, corpus_result: ScanResult) -> None:
        json.loads(render_sarif(corpus_result))

    def test_unknown_rule_ids_get_descriptor(self, corpus_result: ScanResult) -> None:
        from skillchain.core.models import Category, Confidence, Finding, Location, Severity

        extra = Finding(
            rule_id="SC-DYN-001",
            title="t",
            message="m",
            severity=Severity.HIGH,
            confidence=Confidence.DETERMINISTIC,
            category=Category.SANDBOX,
            location=Location(path="x"),
        )
        skill = corpus_result.skills[0].model_copy(update={"findings": (extra,)})
        res = corpus_result.model_copy(update={"skills": (skill,)})
        ids = {r["id"] for r in to_sarif(res)["runs"][0]["tool"]["driver"]["rules"]}
        assert "SC-DYN-001" in ids


class TestJsonMarkdownConsole:
    def test_json(self, corpus_result: ScanResult) -> None:
        doc = json.loads(render_json(corpus_result, _verdicts(corpus_result)))
        assert doc["schema"] == "skillchain/report/v1"
        assert doc["summary"]["total"] == len(corpus_result.findings)
        s = next(x for x in doc["skills"] if x["name"] == "helpful-formatter")
        assert s["verdict"]["decision"] == "block"
        assert s["capabilities"]["inferred"]
        assert all("fingerprint" in f for f in s["findings"])

    def test_summarise(self, corpus_result: ScanResult) -> None:
        s = summarise(corpus_result.findings)
        assert sum(s["by_severity"].values()) == s["total"] == sum(s["by_confidence"].values())

    def test_markdown(self, corpus_result: ScanResult) -> None:
        md = render_markdown(corpus_result, _verdicts(corpus_result))
        assert md.startswith("# SkillChain report")
        assert "## helpful-formatter (skill) — **BLOCK**" in md
        assert "| Sev | Conf | Rule |" in md
        assert "_No findings._" in md

    def test_markdown_with_errors(self, corpus_result: ScanResult) -> None:
        res = corpus_result.model_copy(update={"errors": ("boom",)})
        assert "## Errors" in render_markdown(res)

    def test_console(self, corpus_result: ScanResult) -> None:
        console = Console(record=True, width=120, force_terminal=False, color_system=None)
        render_console(
            corpus_result, console, verdicts=_verdicts(corpus_result), show_evidence=True, max_findings=3
        )
        text = console.export_text()
        assert "helpful-formatter" in text
        assert "BLOCK" in text
        assert "more" in text
        assert "deterministic" in text
