"""Sphinx configuration for the Vexcalibur documentation."""

from __future__ import annotations

import sys
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

project = "Vexcalibur"
author = "Danny Sauer"
copyright = "2026, Danny Sauer"

try:
    release = version("vexcalibur")
except PackageNotFoundError:
    release = "0.0.0"

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
