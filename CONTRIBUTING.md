# Contributing to SkillChain

Thanks for helping make agent skills safer. This guide covers setup, conventions, and how to add rules.

## Development setup

```bash
git clone https://github.com/skillchain-dev/skillchain && cd skillchain
uv sync --all-extras          # creates .venv with dev dependencies
uv run pre-commit install     # optional but recommended
make test lint typecheck      # the same gates CI runs
```

Behind a corporate TLS proxy, export `UV_NATIVE_TLS=1`.

## Project layout

See [docs/architecture.md](docs/architecture.md). In short: `core/` models → `formats/` parsers → `rules/` →
`capabilities/` → `scanner/` → `report/` · `policy/` · `sandbox/` · `signing/` · `lockfile/` · `broker/` · `ci/` · `cli/`.

## Adding a rule

1. Pick the category module in `src/skillchain/rules/` and a new stable ID (`SC-<CAT>-NNN`, never reuse).
2. Subclass `RegexRule` (one finding per match) or `Rule` (custom logic). Set `severity`, `confidence`, `category`,
   `applies_to`, `remediation`, and `capabilities`.
3. **Confidence is a contract.** Use `deterministic` only when the finding is a reproducible fact about the text.
   Anything about *intent* is `heuristic`.
4. Add it to the module's `RULES` tuple.
5. Add positive **and** negative tests in `tests/test_rules.py`. If it is a realistic attack, add a fixture under
   `tests/fixtures/corpus/malicious/` and assert on it in `TestCorpus`. If it could fire on benign content, add a
   benign fixture that must stay clean.
6. Run `make docs-rules` to regenerate `docs/rules.md`.

## Adding a capability or tool mapping

Edit `src/skillchain/capabilities/taxonomy.py` (`CAPABILITIES`, `TOOL_CAPABILITIES`) and inference patterns in
`inference.py`. Script/config evidence is *strong*; prose evidence is *weak* and must stay heuristic.

## Conventions

- Python 3.11+, `from __future__ import annotations`, fully typed (`mypy --strict`).
- `ruff` for lint and format; line length 110.
- Tests: `pytest`; mark sandbox/subprocess tests `@pytest.mark.slow`. Coverage gate is 85 %.
- Never log or print secrets — use `redact()` from `core/textutil.py`.
- Keep the core dependency-free of network services. Optional tools are shelled out to and feature-detected.
- Commit messages: Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `chore:`).

## Pull requests

- One logical change per PR; include tests and a CHANGELOG entry under *Unreleased*.
- CI must be green (lint, types, tests on Linux + macOS, self-scan).
- For rule changes, paste the before/after `skillchain scan tests/fixtures/corpus` summary line in the PR.

## Code of conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).
