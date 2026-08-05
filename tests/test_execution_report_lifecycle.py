from __future__ import annotations

from itertools import product

import pytest

from vexcalibur.execution_report_lifecycle import (
    GenerationOutputState,
    PublishedRollbackState,
    require_generation_output_transition,
    require_published_rollback_transition,
)

_GENERATION_TRANSITIONS = {
    (GenerationOutputState.PREPARED, GenerationOutputState.COMMITTING),
    (GenerationOutputState.PREPARED, GenerationOutputState.ABORT_REQUIRED),
    (GenerationOutputState.PREPARED, GenerationOutputState.CLOSED),
    (GenerationOutputState.COMMITTING, GenerationOutputState.REPORT_GUARDED),
    (GenerationOutputState.COMMITTING, GenerationOutputState.ABORT_REQUIRED),
    (GenerationOutputState.REPORT_GUARDED, GenerationOutputState.COMMITTED),
    (GenerationOutputState.REPORT_GUARDED, GenerationOutputState.ABORT_REQUIRED),
    (GenerationOutputState.COMMITTED, GenerationOutputState.ABORT_REQUIRED),
    (GenerationOutputState.COMMITTED, GenerationOutputState.CLOSED),
    (GenerationOutputState.ABORT_REQUIRED, GenerationOutputState.CLOSED),
}

_ROLLBACK_TRANSITIONS = {
    (PublishedRollbackState.UNARMED, PublishedRollbackState.ARMING),
    (PublishedRollbackState.UNARMED, PublishedRollbackState.RELEASED),
    (PublishedRollbackState.ARMING, PublishedRollbackState.ARMED),
    (PublishedRollbackState.ARMING, PublishedRollbackState.RELEASED),
    (PublishedRollbackState.ARMED, PublishedRollbackState.PUBLICATION_PENDING),
    (PublishedRollbackState.ARMED, PublishedRollbackState.REMOVAL_PENDING),
    (PublishedRollbackState.ARMED, PublishedRollbackState.DISCARDED),
    (PublishedRollbackState.ARMED, PublishedRollbackState.RELEASED),
    (PublishedRollbackState.PUBLICATION_PENDING, PublishedRollbackState.PUBLISHED),
    (PublishedRollbackState.PUBLICATION_PENDING, PublishedRollbackState.REMOVAL_PENDING),
    (PublishedRollbackState.PUBLICATION_PENDING, PublishedRollbackState.RELEASED),
    (PublishedRollbackState.PUBLISHED, PublishedRollbackState.REMOVAL_PENDING),
    (PublishedRollbackState.PUBLISHED, PublishedRollbackState.DISCARDED),
    (PublishedRollbackState.PUBLISHED, PublishedRollbackState.RELEASED),
    (PublishedRollbackState.REMOVAL_PENDING, PublishedRollbackState.DISCARDED),
    (PublishedRollbackState.REMOVAL_PENDING, PublishedRollbackState.RELEASED),
    (PublishedRollbackState.DISCARDED, PublishedRollbackState.RELEASED),
}


@pytest.mark.parametrize(
    ("current", "target"),
    tuple(product(GenerationOutputState, repeat=2)),
)
def test_generation_output_transition_table(
    current: GenerationOutputState,
    target: GenerationOutputState,
) -> None:
    if (current, target) in _GENERATION_TRANSITIONS:
        assert require_generation_output_transition(current, target) is target
        return
    with pytest.raises(RuntimeError, match="invalid generation output lifecycle transition"):
        require_generation_output_transition(current, target)


@pytest.mark.parametrize(
    ("current", "target"),
    tuple(product(PublishedRollbackState, repeat=2)),
)
def test_published_rollback_transition_table(
    current: PublishedRollbackState,
    target: PublishedRollbackState,
) -> None:
    if (current, target) in _ROLLBACK_TRANSITIONS:
        assert require_published_rollback_transition(current, target) is target
        return
    with pytest.raises(RuntimeError, match="invalid published rollback lifecycle transition"):
        require_published_rollback_transition(current, target)
