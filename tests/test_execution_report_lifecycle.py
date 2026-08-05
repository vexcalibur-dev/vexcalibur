from __future__ import annotations

from itertools import product

import pytest

from vexcalibur.execution_report_lifecycle import (
    DescriptorOwnership,
    DescriptorState,
    GenerationOutputState,
    PublishedRollbackState,
    StagedFileState,
    require_generation_output_transition,
    require_published_rollback_transition,
    require_staged_file_transition,
)

_GENERATION_TRANSITIONS = {
    (GenerationOutputState.PREPARED, GenerationOutputState.COMMITTING),
    (GenerationOutputState.PREPARED, GenerationOutputState.ABORT_REQUIRED),
    (GenerationOutputState.PREPARED, GenerationOutputState.CLOSED),
    (GenerationOutputState.COMMITTING, GenerationOutputState.REPORT_GUARD_ARMING),
    (GenerationOutputState.COMMITTING, GenerationOutputState.ABORT_REQUIRED),
    (GenerationOutputState.REPORT_GUARD_ARMING, GenerationOutputState.REPORT_GUARDED),
    (GenerationOutputState.REPORT_GUARD_ARMING, GenerationOutputState.ABORT_REQUIRED),
    (GenerationOutputState.REPORT_GUARDED, GenerationOutputState.COMMITTED),
    (GenerationOutputState.REPORT_GUARDED, GenerationOutputState.ABORT_REQUIRED),
    (GenerationOutputState.COMMITTED, GenerationOutputState.ABORT_REQUIRED),
    (GenerationOutputState.COMMITTED, GenerationOutputState.CLOSED),
    (GenerationOutputState.ABORT_REQUIRED, GenerationOutputState.CLOSED),
}

_STAGED_FILE_TRANSITIONS = {
    (StagedFileState.STAGED, StagedFileState.PUBLISHING),
    (StagedFileState.STAGED, StagedFileState.ROLLED_BACK),
    (StagedFileState.PUBLISHING, StagedFileState.PUBLISHED),
    (StagedFileState.PUBLISHING, StagedFileState.ROLLBACK_REQUIRED),
    (StagedFileState.PUBLISHED, StagedFileState.ROLLBACK_REQUIRED),
    (StagedFileState.PUBLISHED, StagedFileState.RELEASED),
    (StagedFileState.ROLLBACK_REQUIRED, StagedFileState.ROLLED_BACK),
    (StagedFileState.ROLLED_BACK, StagedFileState.RELEASED),
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
    ("descriptor", "ownership"),
    (
        (-1, DescriptorOwnership.OWNED),
        (3, DescriptorOwnership.RELEASED),
        (3, DescriptorOwnership.AMBIGUOUS),
    ),
)
def test_descriptor_state_rejects_inconsistent_ownership(
    descriptor: int,
    ownership: DescriptorOwnership,
) -> None:
    with pytest.raises(ValueError, match="descriptor"):
        DescriptorState(descriptor, ownership)


def test_descriptor_state_factories_preserve_atomic_invariants() -> None:
    assert DescriptorState.owned(3) == DescriptorState(3, DescriptorOwnership.OWNED)
    assert DescriptorState.released() == DescriptorState(-1, DescriptorOwnership.RELEASED)
    assert DescriptorState.ambiguous() == DescriptorState(-1, DescriptorOwnership.AMBIGUOUS)


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


@pytest.mark.parametrize(
    ("current", "target"),
    tuple(product(StagedFileState, repeat=2)),
)
def test_staged_file_transition_table(
    current: StagedFileState,
    target: StagedFileState,
) -> None:
    if (current, target) in _STAGED_FILE_TRANSITIONS:
        assert require_staged_file_transition(current, target) is target
        return
    with pytest.raises(RuntimeError, match="invalid staged file lifecycle transition"):
        require_staged_file_transition(current, target)
