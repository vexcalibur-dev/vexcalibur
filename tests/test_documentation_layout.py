"""Keep published documentation URLs valid across source moves."""

import ast
from pathlib import Path

import pytest

DOCS = Path(__file__).resolve().parents[1] / "docs"


def _redirects() -> dict[str, str]:
    configuration = ast.parse((DOCS / "conf.py").read_text(encoding="utf-8"))
    for node in configuration.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "MOVED_PAGES" for target in node.targets
        ):
            return dict(ast.literal_eval(node.value))
    raise AssertionError("Sphinx configuration has no redirect map")


def test_redirects_target_existing_pages_without_chains() -> None:
    redirects = _redirects()

    assert redirects
    for target in redirects.values():
        assert target not in redirects
        assert (DOCS / f"{target}.md").is_file(), target


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("explanation/architecture", "architecture/overview"),
        ("explanation/self-release-evidence", "architecture/self-release-evidence"),
        ("contributing/self-release-evidence", "architecture/self-release-evidence"),
        ("reference/release-evidence", "architecture/release-evidence"),
        ("contributing/release-evidence", "architecture/release-evidence"),
    ],
)
def test_internal_document_moves_preserve_published_urls(old: str, new: str) -> None:
    assert _redirects()[old] == new
    assert not (DOCS / f"{old}.md").exists()
