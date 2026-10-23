from __future__ import annotations

import json
from pathlib import Path

import pytest

from skillfuse.capabilities import (
    capabilities_for_tool,
    covers,
    declared_manifest,
    diff_manifests,
    infer_capabilities,
    is_valid_capability,
    manifest_findings,
)
from skillfuse.core.config import ScanConfig
from skillfuse.core.models import CapabilityManifest, Confidence, Severity
from skillfuse.formats import discover_packages
from skillfuse.scanner import Scanner

from .conftest import rule_ids, write_skill


class TestTaxonomy:
    def test_tool_mapping(self) -> None:
        assert "shell.exec" in capabilities_for_tool("runCommands")
        assert "filesystem.write" in capabilities_for_tool("editFiles")
        assert "jira.write" in capabilities_for_tool("mcp_atlassian_transitionJiraIssue")
        assert "jira.read" in capabilities_for_tool("mcp_atlassian_getJiraIssue")
        assert "slack.write" in capabilities_for_tool("mcp_slack_send_message")
        assert "browser.automation" in capabilities_for_tool("mcp_playwright_browser_click")
        assert capabilities_for_tool("mcp_unknown_thing") == ("mcp.tools", "network.egress")
        assert capabilities_for_tool("") == ()
        assert capabilities_for_tool("Bash") == ("shell.exec",)

    def test_covers(self) -> None:
        assert covers("network", "network.egress")
        assert covers("network.egress", "network.egress")
        assert not covers("network.egress", "network")
        assert not covers("filesystem", "network.egress")

    def test_valid(self) -> None:
        assert is_valid_capability("network.egress")
        assert is_valid_capability("network")
        assert not is_valid_capability("Network.Egress")
        assert not is_valid_capability("magic.beans")


class TestInference:
    def test_script_evidence_is_strong(self, tmp_path: Path) -> None:
        root = write_skill(
            tmp_path / "s",
            "Does stuff.",
            scripts={
                "x.sh": "curl https://api.example.net | jq\nsudo rm -rf /tmp/x\npip install foo\ngit push origin main\n"
            },
        )
        m = infer_capabilities(discover_packages(root)[0])
        for cap in ("network.egress", "system.admin", "filesystem.delete", "package.install", "git.write"):
            assert cap in m.capabilities, cap
            assert cap not in m.weak
        assert any("x.sh:1" in e for e in m.evidence["network.egress"])

    def test_prose_only_is_weak_and_negation_ignored(self, tmp_path: Path) -> None:
        root = write_skill(
            tmp_path / "s",
            "Run the command `make test`. Never delete any files. Create a new file called out.md.",
        )
        m = infer_capabilities(discover_packages(root)[0])
        assert "shell.exec" in m.capabilities
        assert "shell.exec" in m.weak
        assert "filesystem.write" in m.capabilities
        assert "filesystem.delete" not in m.capabilities

    def test_tools_frontmatter(self, tmp_path: Path) -> None:
        root = write_skill(
            tmp_path / "s",
            "x",
            frontmatter="name: s\ndescription: d\ntools: ['runCommands', 'fetch']\nallowed-tools: Bash(git:*) Read",
        )
        m = infer_capabilities(discover_packages(root)[0])
        assert {"shell.exec", "network.egress", "filesystem.read"} <= set(m.capabilities)
        assert "shell.exec" not in m.weak

    def test_mcp_config(self, benign_dir: Path) -> None:
        pkg = next(p for p in discover_packages(benign_dir) if p.name == ".vscode/mcp.json")
        m = infer_capabilities(pkg)
        assert {
            "mcp.server",
            "process.spawn",
            "package.install",
            "network.egress",
            "env.read",
            "secrets.read",
        } <= set(m.capabilities)
        assert not m.weak

    def test_config_hooks_and_tools(self, tmp_path: Path) -> None:
        root = tmp_path / "p"
        root.mkdir()
        (root / "plugin.json").write_text(
            json.dumps({"name": "p", "hooks": {"x": [{"command": "echo"}]}, "tools": ["editFiles"]})
        )
        m = infer_capabilities(discover_packages(root)[0])
        assert {"shell.exec", "process.spawn", "filesystem.write"} <= set(m.capabilities)

    def test_markdown_shell_block(self, tmp_path: Path) -> None:
        root = write_skill(tmp_path / "s", "Do:\n\n```bash\nls -la\n```\n")
        assert "shell.exec" in infer_capabilities(discover_packages(root)[0]).capabilities


class TestManifest:
    def test_declared_from_frontmatter_list_and_string(self, tmp_path: Path) -> None:
        root = write_skill(
            tmp_path / "a", "x", frontmatter="name: a\ndescription: d\ncapabilities: network.egress, git.read"
        )
        d = declared_manifest(discover_packages(root)[0])
        assert d is not None
        assert d.capabilities == ("git.read", "network.egress")
        root = write_skill(
            tmp_path / "b",
            "x",
            frontmatter="name: b\ndescription: d\npermissions:\n  network: [egress]\n  filesystem:\n    write: true\n    delete: false",
        )
        d = declared_manifest(discover_packages(root)[0])
        assert d is not None
        assert d.capabilities == ("filesystem.write", "network.egress")

    def test_skillfuse_yaml_wins(self, tmp_path: Path) -> None:
        root = write_skill(
            tmp_path / "a", "x", frontmatter="name: a\ndescription: d\ncapabilities: [git.read]"
        )
        (root / "skillfuse.yaml").write_text("capabilities: [network.egress]")
        d = declared_manifest(discover_packages(root)[0])
        assert d is not None
        assert d.capabilities == ("network.egress",)

    def test_none_when_absent(self, tmp_path: Path) -> None:
        root = write_skill(tmp_path / "a", "x")
        assert declared_manifest(discover_packages(root)[0]) is None

    def test_diff(self) -> None:
        inferred = CapabilityManifest(capabilities=("network.egress", "shell.exec", "git.read"))
        declared = CapabilityManifest(capabilities=("network", "filesystem.write"), source="declared")
        d = diff_manifests(declared, inferred)
        assert d.undeclared == ("git.read", "shell.exec")
        assert d.matched == ("network.egress",)
        assert d.overdeclared == ("filesystem.write",)
        assert not d.clean
        assert diff_manifests(None, inferred).undeclared == inferred.capabilities

    def test_findings(self, tmp_path: Path) -> None:
        root = write_skill(
            tmp_path / "a",
            "Run the command `curl x`.",
            frontmatter="name: a\ndescription: d\ncapabilities: [bogus.cap, filesystem.write]",
            scripts={"s.sh": "curl https://a.example.net"},
        )
        pkg = discover_packages(root)[0]
        inferred = infer_capabilities(pkg)
        declared = declared_manifest(pkg)
        diff = diff_manifests(declared, inferred)
        observed = CapabilityManifest(
            capabilities=("system.persistence",),
            evidence={"system.persistence": ("crontab -",)},
            source="observed",
        )
        fs = manifest_findings(pkg, declared, inferred, diff, observed)
        ids = {f.rule_id for f in fs}
        assert {"SC-MAN-001", "SC-MAN-003", "SC-MAN-004", "SC-MAN-005"} <= ids
        undeclared = [f for f in fs if f.rule_id == "SC-MAN-001"]
        strong = next(f for f in undeclared if "network.egress" in f.message)
        assert strong.confidence == Confidence.DETERMINISTIC
        assert strong.severity == Severity.HIGH
        assert strong.location.path == "s.sh"
        weak = next(f for f in undeclared if "shell.exec" in f.message)
        assert weak.confidence == Confidence.HEURISTIC
        assert "prose only" in weak.message
        runtime = next(f for f in fs if f.rule_id == "SC-MAN-004")
        assert runtime.severity == Severity.CRITICAL

    def test_no_manifest_finding(self, tmp_path: Path) -> None:
        root = write_skill(tmp_path / "a", "x")
        res = Scanner(ScanConfig()).scan(root)
        assert "SC-MAN-002" in rule_ids(res)


@pytest.mark.parametrize("cap", ["network.egress", "filesystem", "jira.write"])
def test_manifest_has(cap: str) -> None:
    m = CapabilityManifest(capabilities=("network.egress", "filesystem.read", "jira.write"))
    assert m.has(cap)
