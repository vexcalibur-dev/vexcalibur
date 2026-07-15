"""Deterministic, bounded Hypothesis profile for parser fuzzing smoke tests."""

from __future__ import annotations

import os

from hypothesis import settings

settings.register_profile(
    "fuzz-smoke",
    database=None,
    deadline=1_000,
    derandomize=True,
    max_examples=50,
)
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "fuzz-smoke"))
