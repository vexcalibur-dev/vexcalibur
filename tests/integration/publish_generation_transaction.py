#!/usr/bin/env python3
"""Publish one test generation transaction with optional synchronization."""

from __future__ import annotations

import fcntl
import sys
import time
from pathlib import Path

from vexcalibur import execution_report_destination as destination_module
from vexcalibur.generation_output import GenerationOutputTransaction
from vexcalibur.generation_result import (
    ExecutionReportOutputFormat,
    FindingSourceCategory,
    GenerationExecutionContext,
    GenerationResult,
    InventorySourceCategory,
)


def main() -> None:
    output_path = Path(sys.argv[1])
    report_path = Path(sys.argv[2])
    message = sys.argv[3]
    pause_marker = _optional_path(sys.argv[4])
    release_marker = _optional_path(sys.argv[5])
    lock_observation = _optional_path(sys.argv[6])

    if lock_observation is not None:
        _observe_first_lock_attempt(lock_observation)

    with GenerationOutputTransaction.prepare(
        output_path=output_path,
        report_path=report_path,
        protected_paths=(),
    ) as transaction:
        if pause_marker is not None and release_marker is not None:
            _pause_after_output_commit(
                output_path=output_path,
                pause_marker=pause_marker,
                release_marker=release_marker,
            )

        transaction.commit(
            GenerationResult(
                rendered_document=f'{{"message":"{message}"}}\n',
                components=(),
                findings=(),
                execution_context=GenerationExecutionContext(
                    InventorySourceCategory.SBOM_FILE,
                    FindingSourceCategory.LOCAL_FILE,
                    ExecutionReportOutputFormat.CYCLONEDX,
                ),
            ),
            binary_stdout=None,
        )


def _optional_path(value: str) -> Path | None:
    return None if value == "-" else Path(value)


def _observe_first_lock_attempt(observation: Path) -> None:
    real_flock = fcntl.flock
    observed = False

    def observe(descriptor: int, operation: int) -> None:
        nonlocal observed
        if observed or not operation & fcntl.LOCK_EX:
            real_flock(descriptor, operation)
            return
        observed = True
        try:
            real_flock(descriptor, operation)
        except BlockingIOError:
            observation.write_text("blocked", encoding="utf-8")
            raise
        observation.write_text("acquired", encoding="utf-8")

    fcntl.flock = observe


def _pause_after_output_commit(
    *,
    output_path: Path,
    pause_marker: Path,
    release_marker: Path,
) -> None:
    real_commit = destination_module.StagedFileWrite.commit

    def commit_then_pause(
        staged: destination_module.StagedFileWrite,
        *,
        destination_lock_held: bool = False,
    ) -> None:
        real_commit(staged, destination_lock_held=destination_lock_held)
        if staged.destination.requested_path != output_path:
            return
        pause_marker.write_text("paused", encoding="utf-8")
        deadline = time.monotonic() + 10
        while not release_marker.exists():
            if time.monotonic() >= deadline:
                raise TimeoutError("transaction release marker was not created")
            time.sleep(0.01)

    destination_module.StagedFileWrite.commit = commit_then_pause


if __name__ == "__main__":
    main()
