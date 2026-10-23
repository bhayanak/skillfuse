"""Shared fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

from skillfuse.core.config import ScanConfig
from skillfuse.core.models import ScanResult
from skillfuse.scanner import Scanner

FIXTURES = Path(__file__).parent / "fixtures"
CORPUS = FIXTURES / "corpus"


@pytest.fixture(scope="session")
def corpus() -> Path:
    return CORPUS


@pytest.fixture(scope="session")
def benign_dir() -> Path:
    return CORPUS / "benign"


@pytest.fixture(scope="session")
def malicious_dir() -> Path:
    return CORPUS / "malicious"


@pytest.fixture(scope="session")
def corpus_result() -> ScanResult:
    return Scanner(ScanConfig()).scan(CORPUS)


@pytest.fixture
def skill_dir(tmp_path: Path) -> Path:
    """A minimal benign skill directory the test can mutate."""
    root = tmp_path / "my-skill"
    (root / "scripts").mkdir(parents=True)
    (root / "SKILL.md").write_text(
        "---\nname: my-skill\ndescription: Does a thing.\ncapabilities: [filesystem.read]\n---\n\n# My skill\n\nRead the README and summarise it.\n",
        encoding="utf-8",
    )
    (root / "scripts" / "run.py").write_text("print('hello')\n", encoding="utf-8")
    return root


def write_skill(
    root: Path,
    body: str,
    *,
    frontmatter: str = "name: t\ndescription: test skill",
    scripts: dict[str, str] | None = None,
) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "SKILL.md").write_text(f"---\n{frontmatter}\n---\n\n{body}\n", encoding="utf-8")
    for rel, text in (scripts or {}).items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return root


def rule_ids(result: ScanResult, skill: str | None = None) -> set[str]:
    return {f.rule_id for s in result.skills if skill is None or s.package.name == skill for f in s.findings}
