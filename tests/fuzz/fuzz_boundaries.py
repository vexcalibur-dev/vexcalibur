"""Coverage-guided Atheris entrypoint for Vexcalibur input boundaries."""

from __future__ import annotations

import os
import sys

import atheris

with atheris.instrument_imports():
    from tests.fuzz.boundaries import FUZZ_TARGETS, assert_deterministic_boundary


def test_one_input(data: bytes) -> None:
    """Run the selected target; unexpected exceptions become crash artifacts."""
    target = os.environ.get("FUZZ_TARGET", "")
    if target not in FUZZ_TARGETS:
        raise RuntimeError(f"FUZZ_TARGET must be one of: {', '.join(FUZZ_TARGETS)}")
    assert_deterministic_boundary(target, data)


def main() -> None:
    """Start libFuzzer through Atheris."""
    atheris.Setup(sys.argv, test_one_input, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
