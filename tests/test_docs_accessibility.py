from __future__ import annotations

from pathlib import Path

from scripts.check_docs_accessibility import accessibility_errors


def test_accessibility_check_accepts_labelled_search_control(tmp_path: Path) -> None:
    (tmp_path / "index.html").write_text(
        """
        <main><h1>Page</h1></main>
        <div class="sphinxsidebar">
          <label for="search">Search documentation</label>
          <input id="search" type="text">
        </div>
        """,
        encoding="utf-8",
    )

    assert accessibility_errors(tmp_path) == []


def test_accessibility_check_rejects_unlabelled_control_and_sidebar_heading(
    tmp_path: Path,
) -> None:
    page = tmp_path / "index.html"
    page.write_text(
        """
        <main><h1>Page</h1></main>
        <div class="sphinxsidebar">
          <h1>Project</h1>
          <input type="text" aria-labelledby="missing">
        </div>
        """,
        encoding="utf-8",
    )

    errors = accessibility_errors(tmp_path)

    assert errors == [
        f"{page}: sidebar contains a h1 heading",
        f"{page}: text input has no valid accessible name",
    ]
