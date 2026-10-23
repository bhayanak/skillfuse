.DEFAULT_GOAL := help
UV ?= uv
export UV_NATIVE_TLS ?= 1

.PHONY: help install lint format typecheck test test-fast cov scan detonate build docker clean docs-rules

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

install: ## Create venv and install all deps
	$(UV) sync --all-extras

lint: ## Ruff lint + format check
	$(UV) run ruff check src tests
	$(UV) run ruff format --check src tests

format: ## Auto-format and fix
	$(UV) run ruff check --fix src tests
	$(UV) run ruff format src tests

typecheck: ## mypy strict
	$(UV) run mypy src

test: ## Full test suite with coverage gate
	$(UV) run pytest --cov --cov-report=term-missing:skip-covered

test-fast: ## Tests without the slow sandbox cases
	$(UV) run pytest -q -m "not slow"

cov: ## HTML coverage report
	$(UV) run pytest --cov --cov-report=html && open htmlcov/index.html

scan: ## Scan the fixture corpus
	$(UV) run skillfuse scan tests/fixtures/corpus

detonate: ## Detonate the malicious fixtures in the sandbox
	$(UV) run skillfuse detonate tests/fixtures/corpus/malicious --backend subprocess

build: ## Build sdist + wheel
	$(UV) build

docker: ## Build the container image
	docker build -t skillfuse:dev .

docs-rules: ## Regenerate docs/rules.md from the registry
	$(UV) run python scripts/gen_rules_doc.py > docs/rules.md

clean: ## Remove build/test artefacts
	rm -rf dist build .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage coverage.xml junit.xml *.sarif
