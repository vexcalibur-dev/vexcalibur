"""Sphinx configuration for the Vexcalibur documentation."""

from __future__ import annotations

from importlib.metadata import version
from pathlib import Path
from shutil import copy2

from sphinx.application import Sphinx

project = "Vexcalibur"
author = "Danny Sauer"
copyright = "2026, Danny Sauer"

release = version("vexcalibur")
version = release

extensions = [
    "myst_parser",
    "sphinx.ext.autodoc",
    "sphinx.ext.intersphinx",
    "sphinx.ext.napoleon",
    "sphinx_autodoc_typehints",
]

source_suffix = {
    ".md": "markdown",
    ".rst": "restructuredtext",
}
master_doc = "index"
exclude_patterns = [
    "_build",
    "Thumbs.db",
    ".DS_Store",
    "external/google-python-style-guide.md",
]

html_theme = "alabaster"
html_title = "Vexcalibur"
html_static_path: list[str] = []

autodoc_typehints = "description"
autodoc_typehints_format = "short"
autodoc_member_order = "bysource"
napoleon_google_docstring = True
napoleon_numpy_docstring = False

intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
}


def _copy_vendored_markdown(app: Sphinx, exception: Exception | None) -> None:
    # The vendored guide uses upstream HTML anchors that MyST cannot validate.
    if exception is not None or app.builder.format != "html":
        return
    source = Path(app.srcdir) / "external" / "google-python-style-guide.md"
    target = Path(app.outdir) / "external" / "google-python-style-guide.md"
    target.parent.mkdir(parents=True, exist_ok=True)
    copy2(source, target)


def setup(app: Sphinx) -> None:
    app.connect("build-finished", _copy_vendored_markdown)
