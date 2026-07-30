"""Verify generated package versions against editable source checkouts."""

from __future__ import annotations

import importlib
import os
import re
import shutil
import subprocess
from pathlib import Path

_COMMIT_ID_PATTERN = re.compile(
    r"(?:^|[+.])g([0-9a-f]{7,40})(?:[.]|$)",
    re.ASCII,
)
_FULL_COMMIT_PATTERN = re.compile(r"[0-9a-f]{40}", re.ASCII)


class SourceVersionIdentityError(ValueError):
    """Raised when editable package metadata identifies another commit."""


def verify_source_checkout_version(version: str) -> None:
    """Require an editable source checkout's version to identify its Git HEAD."""
    root = _editable_source_root()
    if root is None:
        return
    head = _git_head(root)
    commit_id = _generated_commit_id(version)
    if commit_id is None:
        raise SourceVersionIdentityError(
            "editable Vexcalibur version metadata has no source commit"
        )
    if not head.startswith(commit_id):
        raise SourceVersionIdentityError(
            "editable Vexcalibur version metadata does not match checkout HEAD"
        )


def _editable_source_root() -> Path | None:
    package_dir = Path(__file__).resolve().parent
    source_dir = package_dir.parent
    if source_dir.name != "src":
        return None
    root = source_dir.parent
    if not (root / ".git").exists() or not (root / "pyproject.toml").is_file():
        return None
    return root


def _git_head(root: Path) -> str:
    git_path = shutil.which("git")
    if git_path is None:
        raise SourceVersionIdentityError(
            "Git is required to verify editable Vexcalibur version metadata"
        )
    try:
        environment = {
            name: value for name, value in os.environ.items() if not name.startswith("GIT_")
        }
        completed = subprocess.run(  # noqa: S603 - resolved Git with a fixed read-only command
            [
                git_path,
                "--no-optional-locks",
                "-C",
                str(root),
                "rev-parse",
                "--verify",
                "HEAD",
            ],
            check=False,
            capture_output=True,
            env=environment,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SourceVersionIdentityError(
            "could not verify editable Vexcalibur checkout HEAD"
        ) from exc
    head = completed.stdout.strip()
    if completed.returncode != 0 or _FULL_COMMIT_PATTERN.fullmatch(head) is None:
        raise SourceVersionIdentityError("could not verify editable Vexcalibur checkout HEAD")
    return head


def _generated_commit_id(version: str) -> str | None:
    try:
        generated = importlib.import_module("vexcalibur._version")
    except ImportError:
        generated = None
    if generated is not None and getattr(generated, "__version__", None) == version:
        commit_id = getattr(generated, "__commit_id__", None)
        if type(commit_id) is str:
            match = _COMMIT_ID_PATTERN.fullmatch(commit_id)
            if match is not None:
                return match.group(1)
    match = _COMMIT_ID_PATTERN.search(version)
    return None if match is None else match.group(1)
