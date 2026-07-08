.PHONY: help install install-docs test test-live installed-cli-check lint workflow-lint format typecheck audit secrets secrets-pr check docs build pre-commit pre-commit-install secrets-baseline clean

UV := uv
PACKAGE := vexcalibur
SECRETS_BASELINE_REF ?= origin/main
ACTIONLINT ?= actionlint
SHELLCHECK ?= shellcheck

help: ## Show available targets
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-22s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

install: ## Install project dependencies
	$(UV) sync

install-docs: ## Install project and documentation dependencies
	$(UV) sync --extra docs

test: ## Run offline tests
	$(UV) run --frozen pytest -m "not live"

test-live: ## Run live compatibility tests against external services
	$(UV) run --frozen pytest -m live

installed-cli-check: ## Build, install, and test console scripts from the wheel
	scripts/check-installed-cli.sh

lint: ## Run ruff checks
	$(UV) run --frozen ruff check src tests scripts/*.py docs/conf.py

workflow-lint: ## Lint GitHub Actions workflows and shell scripts
	$(SHELLCHECK) --version >/dev/null
	$(ACTIONLINT) -shellcheck "$(SHELLCHECK)" .github/workflows/*.yml
	$(SHELLCHECK) scripts/*.sh

format: ## Format source and tests
	$(UV) run --frozen ruff format src tests scripts/*.py docs/conf.py
	$(UV) run --frozen ruff check --fix src tests scripts/*.py docs/conf.py

typecheck: ## Run mypy
	$(UV) run --frozen mypy src

audit: ## Audit installed Python dependencies
	XDG_CACHE_HOME=$${XDG_CACHE_HOME:-/tmp/vexcalibur-cache} $(UV) run --frozen pip-audit --cache-dir $${PIP_AUDIT_CACHE_DIR:-/tmp/vexcalibur-pip-audit-cache}

secrets: ## Check tracked files for newly introduced secrets
	git ls-files -z | xargs -0 $(UV) run --frozen detect-secrets-hook --baseline .secrets.baseline --

secrets-pr: ## Check tracked files against the base branch secret baseline
	git show $(SECRETS_BASELINE_REF):.secrets.baseline > /tmp/vexcalibur-base.secrets.baseline
	git ls-files -z | xargs -0 $(UV) run --frozen detect-secrets-hook --baseline /tmp/vexcalibur-base.secrets.baseline --

check: lint workflow-lint typecheck audit secrets test ## Run local quality gate

docs: ## Build Sphinx documentation
	$(UV) run --frozen --extra docs sphinx-build -W --keep-going -b html docs docs/_build/html

build: ## Build source and wheel distributions
	$(UV) build --clear --no-create-gitignore --no-sources

pre-commit: ## Run pre-commit checks
	$(UV) run --frozen pre-commit run --all-files

pre-commit-install: ## Install pre-commit hooks
	$(UV) run --frozen pre-commit install

secrets-baseline: ## Refresh detect-secrets baseline
	$(UV) run --frozen detect-secrets scan --baseline .secrets.baseline

clean: ## Remove generated local artifacts
	rm -rf build dist *.egg-info src/*.egg-info .coverage .pytest_cache .mypy_cache .ruff_cache htmlcov coverage.xml
	rm -f src/$(PACKAGE)/_version.py
	rm -rf docs/_build
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
