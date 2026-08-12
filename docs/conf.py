"""Sphinx configuration for the Vexcalibur documentation."""

from __future__ import annotations

from html import escape
from importlib.metadata import version
from json import dumps
from os.path import relpath
from pathlib import Path, PurePosixPath
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
templates_path = ["_templates"]
exclude_patterns = [
    "_build",
    "Thumbs.db",
    ".DS_Store",
    "external/google-python-style-guide.md",
]

html_theme = "alabaster"
html_title = "Vexcalibur"
html_baseurl = "https://vexcalibur-dev.github.io/vexcalibur/"
html_extra_path = ["execution-report-v1.schema.json"]

autodoc_typehints = "description"
autodoc_typehints_format = "short"
autodoc_member_order = "bysource"
napoleon_google_docstring = True
napoleon_numpy_docstring = False

intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
}


def _copy_static_documents(app: Sphinx, exception: Exception | None) -> None:
    if exception is not None or app.builder.format != "html":
        return
    # The vendored guide uses upstream HTML anchors that MyST cannot validate.
    for relative_path in (Path("external/google-python-style-guide.md"),):
        source = Path(app.srcdir) / relative_path
        target = Path(app.outdir) / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        copy2(source, target)


# Pages that moved when the manual split into user and contributor sections.
# Keep these until the published links have had time to age out; dropping one
# turns an external bookmark into a 404.
MOVED_PAGES = {
    "how-to/install": "install",
    "how-to/build-release-evidence": "contributing/build-release-evidence",
    "how-to/publish-to-pypi": "contributing/publish-to-pypi",
    "reference/release-evidence": "contributing/release-evidence",
    "explanation/self-release-evidence": "contributing/self-release-evidence",
    "development/ci": "contributing/ci",
    "development/fuzzing": "contributing/fuzzing",
    "development/github-governance": "contributing/github-governance",
    "development/python-style": "contributing/python-style",
}

_REDIRECT_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Page moved</title>
    <link rel="canonical" href="{target}">
    <meta http-equiv="refresh" content="0; url={target}">
    <script>
      // A meta refresh drops the fragment, so an old deep link such as
      // development/ci.html#reproduce-important-gates would land at the top of
      // the moved page. Carry the fragment across when scripting is available;
      // the meta refresh above still covers the case where it is not.
      location.replace({target_js} + location.hash);
    </script>
  </head>
  <body>
    <p>This page moved to <a href="{target}">{target}</a>.</p>
  </body>
</html>
"""


def _write_redirects(app: Sphinx, exception: Exception | None) -> None:
    """Leave a meta-refresh stub at each old URL so published links keep working."""
    if exception is not None or app.builder.format != "html":
        return
    for old, new in MOVED_PAGES.items():
        old_path = PurePosixPath(old)
        target = relpath(f"{new}.html", start=str(old_path.parent))
        stub = Path(app.outdir) / f"{old}.html"
        stub.parent.mkdir(parents=True, exist_ok=True)
        stub.write_text(
            _REDIRECT_TEMPLATE.format(
                target=escape(target, quote=True),
                target_js=dumps(target).replace("<", "\\u003c"),
            ),
            encoding="utf-8",
        )


def setup(app: Sphinx) -> None:
    app.connect("build-finished", _copy_static_documents)
    app.connect("build-finished", _write_redirects)
