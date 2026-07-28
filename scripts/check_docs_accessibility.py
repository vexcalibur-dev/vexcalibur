"""Check rendered documentation controls and sidebar headings."""

from __future__ import annotations

import argparse
from html.parser import HTMLParser
from pathlib import Path


class DocumentationPageParser(HTMLParser):
    """Collect accessibility facts from one rendered HTML page."""

    def __init__(self) -> None:
        super().__init__()
        self.ids: set[str] = set()
        self.label_targets: set[str] = set()
        self.text_controls: list[dict[str, str]] = []
        self.sidebar_headings: list[str] = []
        self._sidebar_depth = 0

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        attributes = {key: value or "" for key, value in attrs}
        element_id = attributes.get("id")
        if element_id:
            self.ids.add(element_id)
        if tag == "label" and attributes.get("for"):
            self.label_targets.add(attributes["for"])

        classes = set(attributes.get("class", "").split())
        if tag == "div" and "sphinxsidebar" in classes:
            self._sidebar_depth = 1
        elif self._sidebar_depth and tag == "div":
            self._sidebar_depth += 1
        if self._sidebar_depth and tag in {"h1", "h2", "h3", "h4", "h5", "h6"}:
            self.sidebar_headings.append(tag)

        if tag == "input" and attributes.get("type", "text") in {"search", "text"}:
            self.text_controls.append(attributes)

    def handle_endtag(self, tag: str) -> None:
        if tag == "div" and self._sidebar_depth:
            self._sidebar_depth -= 1


def accessibility_errors(documentation_root: Path) -> list[str]:
    """Return accessibility failures from rendered HTML below one directory."""
    errors: list[str] = []
    for page in sorted(documentation_root.rglob("*.html")):
        parser = DocumentationPageParser()
        parser.feed(page.read_text(encoding="utf-8"))
        for heading in parser.sidebar_headings:
            errors.append(f"{page}: sidebar contains a {heading} heading")
        for attributes in parser.text_controls:
            control_id = attributes.get("id", "")
            labelled_by = attributes.get("aria-labelledby", "").split()
            has_label = bool(control_id and control_id in parser.label_targets)
            has_aria_label = bool(attributes.get("aria-label"))
            has_labelled_by = bool(labelled_by) and all(
                label_id in parser.ids for label_id in labelled_by
            )
            if not (has_label or has_aria_label or has_labelled_by):
                errors.append(f"{page}: text input has no valid accessible name")
    return errors


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("documentation_root", type=Path)
    args = parser.parse_args()
    errors = accessibility_errors(args.documentation_root)
    if errors:
        raise SystemExit("\n".join(errors))
    print("rendered documentation accessibility checks passed")


if __name__ == "__main__":
    main()
