from __future__ import annotations

from pathlib import Path

from skillfuse.core.models import FileKind, SkillKind
from skillfuse.formats import (
    McpServer,
    classify,
    discover_packages,
    extract_mcp_servers,
    parse_jsonc,
    read_skill_file,
    split_frontmatter,
)
from skillfuse.formats.base import is_probably_binary


class TestFrontmatter:
    def test_split(self) -> None:
        fm, body, off = split_frontmatter("---\nname: x\ntools: [a, b]\n---\nbody\n")
        assert fm == {"name": "x", "tools": ["a", "b"]}
        assert body == "body\n"
        assert off == 4

    def test_no_frontmatter(self) -> None:
        assert split_frontmatter("just text") == ({}, "just text", 0)

    def test_invalid_yaml(self) -> None:
        fm, _, _ = split_frontmatter("---\n: : :\n  - [\n---\nbody")
        assert fm.get("__invalid_frontmatter__") is True

    def test_non_mapping(self) -> None:
        fm, _, _ = split_frontmatter("---\n- a\n- b\n---\nbody")
        assert fm.get("__invalid_frontmatter__") is True


class TestClassify:
    def test_by_suffix(self) -> None:
        assert classify(Path("x.sh"), None) == (FileKind.SCRIPT, "shell")
        assert classify(Path("x.py"), None) == (FileKind.SCRIPT, "python")
        assert classify(Path("x.json"), None) == (FileKind.CONFIG, "json")
        assert classify(Path("x.md"), None) == (FileKind.INSTRUCTIONS, "markdown")
        assert classify(Path("x.bin"), None) == (FileKind.DATA, None)
        assert classify(Path("Makefile"), None) == (FileKind.SCRIPT, "shell")

    def test_by_shebang(self) -> None:
        assert classify(Path("run"), "#!/usr/bin/env python3\nprint(1)") == (FileKind.SCRIPT, "python")
        assert classify(Path("run"), "#!/bin/bash\necho") == (FileKind.SCRIPT, "shell")
        assert classify(Path("run"), "#!/usr/bin/env node\n") == (FileKind.SCRIPT, "javascript")

    def test_binary_detection(self) -> None:
        assert is_probably_binary(b"\x00\x01\x02")
        assert not is_probably_binary(b"hello world\n")
        assert not is_probably_binary(b"")
        assert is_probably_binary(bytes(range(128, 256)) * 10)


class TestReadSkillFile:
    def test_reads_markdown_with_frontmatter(self, tmp_path: Path) -> None:
        p = tmp_path / "SKILL.md"
        p.write_text("---\nname: a\n---\nbody")
        sf = read_skill_file(tmp_path, p)
        assert sf.kind == FileKind.INSTRUCTIONS
        assert sf.frontmatter == {"name": "a"}
        assert sf.text == "body"
        assert sf.body_offset == 3
        assert sf.lines == ["body"]

    def test_binary(self, tmp_path: Path) -> None:
        p = tmp_path / "blob"
        p.write_bytes(b"\x00" * 100)
        assert read_skill_file(tmp_path, p).kind == FileKind.BINARY

    def test_truncation(self, tmp_path: Path) -> None:
        p = tmp_path / "big.txt"
        p.write_text("a" * 100)
        sf = read_skill_file(tmp_path, p, max_bytes=10)
        assert len(sf.text) == 10

    def test_broken_symlink(self, tmp_path: Path) -> None:
        p = tmp_path / "link"
        p.symlink_to("/nonexistent/target")
        sf = read_skill_file(tmp_path, p)
        assert sf.is_symlink
        assert sf.kind == FileKind.DATA

    def test_executable_flag(self, tmp_path: Path) -> None:
        p = tmp_path / "x.sh"
        p.write_text("echo")
        p.chmod(0o755)
        assert read_skill_file(tmp_path, p).executable


class TestConfigs:
    def test_parse_jsonc(self) -> None:
        assert parse_jsonc('{"a": 1}') == {"a": 1}
        assert parse_jsonc('{\n // c\n "a": 1, /* x */ "b": [1,2,],\n}') == {"a": 1, "b": [1, 2]}
        assert parse_jsonc("a: 1") == {"a": 1}
        assert parse_jsonc("{{{") is None or parse_jsonc("{{{") == "{{{"

    def test_extract_servers_variants(self) -> None:
        for key in ("servers", "mcpServers", "mcp_servers"):
            servers = extract_mcp_servers(
                {key: {"x": {"command": "npx", "args": ["-y", "pkg"], "env": {"A": "1"}}}}
            )
            assert len(servers) == 1
            assert servers[0].command_line == "npx -y pkg"
            assert servers[0].env == {"A": "1"}
            assert servers[0].transport == "stdio"
        bare = extract_mcp_servers({"x": {"url": "https://h/mcp", "headers": {"Authorization": "Bearer t"}}})
        assert bare[0].url == "https://h/mcp"
        assert bare[0].transport == "http"
        assert extract_mcp_servers("nope") == []
        assert extract_mcp_servers({"servers": []}) == []

    def test_mcp_server_defaults(self) -> None:
        s = McpServer("n", {"args": "notalist", "env": "x"})
        assert s.args == []
        assert s.env == {}
        assert s.command is None


class TestDiscovery:
    def test_discovers_corpus(self, corpus: Path) -> None:
        pkgs = discover_packages(corpus)
        kinds = {p.name: p.kind for p in pkgs}
        assert kinds["changelog-writer"] == SkillKind.SKILL
        assert kinds["code-reviewer"] == SkillKind.AGENT
        assert kinds["sneaky-reviewer"] == SkillKind.AGENT
        assert kinds[".vscode/mcp.json"] == SkillKind.MCP_CONFIG
        assert kinds["malicious/mcp.json"] == SkillKind.MCP_CONFIG
        assert kinds["trojan-source"] == SkillKind.SKILL
        cw = next(p for p in pkgs if p.name == "changelog-writer")
        assert {f.path for f in cw.files} == {"SKILL.md", "scripts/group_commits.py"}
        assert cw.declared_tools == ()
        assert cw.description.startswith("Summarise")

    def test_single_file_target(self, benign_dir: Path) -> None:
        pkgs = discover_packages(benign_dir / "code-reviewer.agent.md")
        assert len(pkgs) == 1
        assert pkgs[0].kind == SkillKind.AGENT
        assert pkgs[0].declared_tools == ("codebase", "search", "readFile")

    def test_skill_md_target(self, benign_dir: Path) -> None:
        pkgs = discover_packages(benign_dir / "changelog-writer" / "SKILL.md")
        assert pkgs[0].kind == SkillKind.SKILL
        assert len(pkgs[0].files) == 2

    def test_plugin_layout(self, tmp_path: Path) -> None:
        root = tmp_path / "plug"
        (root / ".claude-plugin").mkdir(parents=True)
        (root / ".claude-plugin" / "plugin.json").write_text(
            '{"name": "p", "version": "1.2.3", "author": {"name": "acme"}, "hooks": {"PreToolUse": [{"command": "echo hi"}]}}'
        )
        (root / "commands").mkdir()
        (root / "commands" / "x.md").write_text("do x")
        pkgs = discover_packages(root)
        assert pkgs[0].kind == SkillKind.PLUGIN
        assert pkgs[0].name == "p"
        assert pkgs[0].version == "1.2.3"
        assert pkgs[0].publisher == "acme"

    def test_nested_plugin_inside_skill_is_not_duplicated(self, tmp_path: Path) -> None:
        root = tmp_path / "s"
        root.mkdir()
        (root / "SKILL.md").write_text("---\nname: s\n---\nx")
        (root / "plugin.json").write_text("{}")
        assert len(discover_packages(root)) == 1

    def test_instruction_files_and_cursor(self, tmp_path: Path) -> None:
        (tmp_path / "AGENTS.md").write_text("Always run tests.")
        (tmp_path / ".cursorrules").write_text("be nice")
        (tmp_path / ".cursor" / "rules").mkdir(parents=True)
        (tmp_path / ".cursor" / "rules" / "py.mdc").write_text("---\ndescription: py\n---\nuse ruff")
        (tmp_path / "other.mdc").write_text("not a rule")
        kinds = {p.name: p.kind for p in discover_packages(tmp_path)}
        assert kinds["AGENTS"] == SkillKind.INSTRUCTIONS
        assert kinds[".cursorrules"] == SkillKind.INSTRUCTIONS
        assert kinds["py"] == SkillKind.CURSOR_RULES
        assert "other" not in kinds

    def test_unknown_directory_becomes_opaque_package(self, tmp_path: Path) -> None:
        (tmp_path / "notes.md").write_text("hello")
        (tmp_path / "a.py").write_text("print(1)")
        pkgs = discover_packages(tmp_path)
        assert len(pkgs) == 1
        assert pkgs[0].kind == SkillKind.UNKNOWN
        assert pkgs[0].entrypoint == "notes.md"

    def test_skillfuse_yaml_manifest(self, tmp_path: Path) -> None:
        root = tmp_path / "s"
        root.mkdir()
        (root / "SKILL.md").write_text("---\nname: s\n---\nx")
        (root / "skillfuse.yaml").write_text(
            "publisher: acme\nversion: '2'\ncapabilities: [network.egress]\n"
        )
        pkg = discover_packages(root)[0]
        assert pkg.publisher == "acme"
        assert pkg.version == "2"
        assert pkg.metadata["__skillfuse_manifest__"]["capabilities"] == ["network.egress"]

    def test_unreadable_manifest_ignored(self, tmp_path: Path) -> None:
        root = tmp_path / "s"
        root.mkdir()
        (root / "SKILL.md").write_text("---\nname: s\n---\nx")
        (root / "skillfuse.yaml").write_text(": : [")
        assert "__skillfuse_manifest__" not in discover_packages(root)[0].metadata
