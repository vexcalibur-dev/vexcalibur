.PHONY: help install install-docs test test-live lint format typecheck audit check docs build pre-commit pre-commit-install secrets-baseline clean

POETRY := poetry
PACKAGE := vexcalibur

help: ## Show available targets
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-22s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

install: ## Install project dependencies
	$(POETRY) install

install-docs: ## Install project and documentation dependencies
	$(POETRY) install --with docs

test: ## Run offline tests
	$(POETRY) run pytest -m "not live"

test-live: ## Run live compatibility tests against external services
	$(POETRY) run pytest -m live

lint: ## Run ruff checks
	$(POETRY) run ruff check src tests docs/conf.py

format: ## Format source and tests
	$(POETRY) run ruff format src tests docs/conf.py
	$(POETRY) run ruff check --fix src tests docs/conf.py

typecheck: ## Run mypy
	$(POETRY) run mypy src

audit: ## Audit installed Python dependencies
	XDG_CACHE_HOME=$${XDG_CACHE_HOME:-/tmp/vexcalibur-cache} $(POETRY) run pip-audit --cache-dir $${PIP_AUDIT_CACHE_DIR:-/tmp/vexcalibur-pip-audit-cache}

check: lint typecheck audit test ## Run local quality gate

docs: ## Build Sphinx documentation
	$(POETRY) run sphinx-build -W --keep-going -b html docs docs/_build/html

build: ## Build source and wheel distributions
	$(POETRY) build

pre-commit: ## Run pre-commit checks
	$(POETRY) run pre-commit run --all-files

pre-commit-install: ## Install pre-commit hooks
	$(POETRY) run pre-commit install

secrets-baseline: ## Refresh detect-secrets baseline
	$(POETRY) run detect-secrets scan --baseline .secrets.baseline

clean: ## Remove generated local artifacts
	rm -rf build dist *.egg-info .pytest_cache .mypy_cache .ruff_cache htmlcov coverage.xml
	rm -rf docs/_build
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
