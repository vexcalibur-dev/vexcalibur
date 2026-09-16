"""Keep automatic formatting out of documentation examples."""

from pathlib import Path

import yaml


def test_ruff_format_preserves_markdown_examples() -> None:
    root = Path(__file__).resolve().parents[1]
    configuration = yaml.safe_load((root / ".pre-commit-config.yaml").read_text())
    formatter = next(
        hook
        for repository in configuration["repos"]
        if repository["repo"] == "https://github.com/astral-sh/ruff-pre-commit"
        for hook in repository["hooks"]
        if hook["id"] == "ruff-format"
    )

    assert set(formatter["types_or"]) == {"python", "pyi", "jupyter"}
