"""Append one SHA-256-pinned local distribution to exported requirements."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


def append_locked_distribution_requirement(
    distribution: Path,
    requirements: Path,
) -> None:
    """Append an exact local distribution URI and digest."""
    resolved_distribution = distribution.resolve(strict=True)
    if not resolved_distribution.is_file():
        raise ValueError(f"distribution is not a regular file: {distribution}")

    digest = hashlib.sha256()
    with resolved_distribution.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)

    with requirements.open("a", encoding="utf-8", newline="\n") as stream:
        stream.write(f"\nvexcalibur @ {resolved_distribution.as_uri()} \\\n")
        stream.write(f"    --hash=sha256:{digest.hexdigest()}\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("distribution", type=Path)
    parser.add_argument("requirements", type=Path)
    args = parser.parse_args()
    append_locked_distribution_requirement(args.distribution, args.requirements)


if __name__ == "__main__":
    main()
