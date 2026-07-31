from __future__ import annotations

import hashlib
import json
import os
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

import vexcalibur
import vexcalibur.execution_report_destination as destination_module
import vexcalibur.execution_report_locks as lock_module
from vexcalibur.generation_output import GenerationOutputTransaction
from vexcalibur.generation_result import (
    ExecutionReportOutputFormat,
    FindingSourceCategory,
    GenerationExecutionContext,
    GenerationResult,
    InventorySourceCategory,
)


def _generation_result(monkeypatch: pytest.MonkeyPatch) -> GenerationResult:
    monkeypatch.setattr(vexcalibur, "__version__", "0.4.2")
    monkeypatch.setattr(
        "vexcalibur.generation_result.verify_source_checkout_version",
        lambda version: None,
    )
    monkeypatch.setattr(
        "vexcalibur.generation_result.importlib.metadata.version",
        lambda name: "0.4.2",
    )
    return GenerationResult(
        '{"message":"caf\N{LATIN SMALL LETTER E WITH ACUTE}"}\n',
        (),
        (),
        GenerationExecutionContext(
            InventorySourceCategory.SBOM_FILE,
            FindingSourceCategory.LOCAL_FILE,
            ExecutionReportOutputFormat.CYCLONEDX,
        ),
    )


def _distinct_generation_result(
    monkeypatch: pytest.MonkeyPatch,
    message: str,
) -> GenerationResult:
    result = _generation_result(monkeypatch)
    return GenerationResult(
        f'{{"message":"{message}"}}\n',
        result.components,
        result.findings,
        result.execution_context,
    )


@pytest.mark.skipif(os.name == "nt", reason="POSIX report transaction")
def test_concurrent_transactions_cannot_interleave_output_and_report(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import fcntl

    output_directory = tmp_path / "output"
    report_directory = tmp_path / "report"
    output_directory.mkdir()
    report_directory.mkdir()
    output_path = output_directory / "vex.json"
    report_path = report_directory / "execution-report.json"
    first = GenerationOutputTransaction.prepare(
        output_path=output_path,
        report_path=report_path,
        protected_paths=(),
    )
    second = GenerationOutputTransaction.prepare(
        output_path=output_path,
        report_path=report_path,
        protected_paths=(),
    )
    first_output_committed = threading.Event()
    release_first = threading.Event()
    second_output_committed = threading.Event()
    second_lock_attempted = threading.Event()
    errors: list[BaseException] = []
    real_commit = destination_module.StagedFileWrite.commit
    real_flock = fcntl.flock

    def observe_commit(
        staged: destination_module.StagedFileWrite,
        *,
        destination_lock_held: bool = False,
    ) -> None:
        real_commit(staged, destination_lock_held=destination_lock_held)
        if staged.destination.requested_path != output_path:
            return
        if threading.current_thread().name == "first-writer":
            first_output_committed.set()
            if not release_first.wait(timeout=5):
                raise AssertionError("test did not release the first transaction")
        else:
            second_output_committed.set()

    monkeypatch.setattr(
        destination_module.StagedFileWrite,
        "commit",
        observe_commit,
    )

    def observe_lock_attempt(descriptor: int, operation: int) -> None:
        if threading.current_thread().name == "second-writer" and operation & fcntl.LOCK_EX:
            second_lock_attempted.set()
        real_flock(descriptor, operation)

    monkeypatch.setattr(fcntl, "flock", observe_lock_attempt)

    def publish(
        transaction: GenerationOutputTransaction,
        result: GenerationResult,
    ) -> None:
        try:
            transaction.commit(
                result,
                binary_stdout=None,
            )
        except BaseException as exc:
            errors.append(exc)

    first_thread = threading.Thread(
        target=publish,
        args=(first, _distinct_generation_result(monkeypatch, "first")),
        name="first-writer",
    )
    second_thread = threading.Thread(
        target=publish,
        args=(second, _distinct_generation_result(monkeypatch, "second")),
        name="second-writer",
    )

    first_thread.start()
    assert first_output_committed.wait(timeout=5)
    second_thread.start()
    assert second_lock_attempted.wait(timeout=5)
    assert not second_output_committed.wait(timeout=0.1)
    release_first.set()
    first_thread.join(timeout=5)
    second_thread.join(timeout=5)

    assert not first_thread.is_alive()
    assert not second_thread.is_alive()
    assert errors == []
    output = output_path.read_bytes()
    report = json.loads(report_path.read_bytes())
    assert output == b'{"message":"second"}\n'
    assert report["document"] == {
        "bytes": len(output),
        "sha256": hashlib.sha256(output).hexdigest(),
    }


@pytest.mark.skipif(os.name == "nt", reason="POSIX report transaction")
def test_concurrent_stdout_transactions_bind_the_final_report(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "execution-report.json"
    first = GenerationOutputTransaction.prepare(
        output_path=None,
        report_path=report_path,
        protected_paths=(),
    )
    second = GenerationOutputTransaction.prepare(
        output_path=None,
        report_path=report_path,
        protected_paths=(),
    )
    first_written = threading.Event()
    release_first = threading.Event()
    second_written = threading.Event()
    content = bytearray()
    content_lock = threading.Lock()
    errors: list[BaseException] = []

    class SharedStdout:
        def write(self, value: bytes) -> int:
            with content_lock:
                content[:] = value
            if threading.current_thread().name == "first-stdout":
                first_written.set()
            else:
                second_written.set()
            return len(value)

        def flush(self) -> None:
            if threading.current_thread().name == "first-stdout" and not release_first.wait(
                timeout=5
            ):
                raise AssertionError("test did not release the first writer")

    stdout = SharedStdout()

    def publish(
        transaction: GenerationOutputTransaction,
        result: GenerationResult,
    ) -> None:
        try:
            transaction.commit(
                result,
                binary_stdout=stdout,  # type: ignore[arg-type]
            )
        except BaseException as exc:
            errors.append(exc)

    first_result = _distinct_generation_result(monkeypatch, "first")
    second_result = _distinct_generation_result(monkeypatch, "second")
    first_thread = threading.Thread(
        target=publish,
        args=(first, first_result),
        name="first-stdout",
    )
    second_thread = threading.Thread(
        target=publish,
        args=(second, second_result),
        name="second-stdout",
    )

    first_thread.start()
    assert first_written.wait(timeout=5)
    second_thread.start()
    assert not second_written.wait(timeout=0.1)
    release_first.set()
    first_thread.join(timeout=5)
    second_thread.join(timeout=5)

    assert not first_thread.is_alive()
    assert not second_thread.is_alive()
    assert errors == []
    assert bytes(content) == second_result.rendered_bytes
    report = json.loads(report_path.read_bytes())
    assert report["document"] == {
        "bytes": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
    }


@pytest.mark.skipif(os.name == "nt", reason="POSIX report transaction")
def test_opposite_role_directories_are_locked_without_deadlock(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    first_directory = tmp_path / "first"
    second_directory = tmp_path / "second"
    first_directory.mkdir()
    second_directory.mkdir()
    first_output = first_directory / "vex.json"
    first_report = second_directory / "execution-report.json"
    second_output = second_directory / "vex.json"
    second_report = first_directory / "execution-report.json"
    first = GenerationOutputTransaction.prepare(
        output_path=first_output,
        report_path=first_report,
        protected_paths=(),
    )
    second = GenerationOutputTransaction.prepare(
        output_path=second_output,
        report_path=second_report,
        protected_paths=(),
    )
    first_attempts = threading.Barrier(2)
    lock_count = threading.local()
    errors: list[BaseException] = []
    real_lock = lock_module._exclusive_destination_lock

    @contextmanager
    def synchronize_first_lock(
        descriptor: int,
    ) -> Iterator[None]:
        count = getattr(lock_count, "value", 0)
        lock_count.value = count + 1
        if count == 0:
            first_attempts.wait(timeout=5)
        with real_lock(descriptor):
            yield

    monkeypatch.setattr(
        lock_module,
        "_exclusive_destination_lock",
        synchronize_first_lock,
    )
    monkeypatch.setattr(lock_module, "DESTINATION_LOCK_TIMEOUT_SECONDS", 0.5)

    def publish(
        transaction: GenerationOutputTransaction,
        result: GenerationResult,
    ) -> None:
        try:
            transaction.commit(
                result,
                binary_stdout=None,
            )
        except BaseException as exc:
            errors.append(exc)

    first_result = _distinct_generation_result(monkeypatch, "first")
    second_result = _distinct_generation_result(monkeypatch, "second")
    threads = [
        threading.Thread(target=publish, args=(first, first_result)),
        threading.Thread(target=publish, args=(second, second_result)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)

    assert all(not thread.is_alive() for thread in threads)
    assert errors == []
    for output_path, report_path in (
        (first_output, first_report),
        (second_output, second_report),
    ):
        output = output_path.read_bytes()
        report = json.loads(report_path.read_bytes())
        assert report["document"] == {
            "bytes": len(output),
            "sha256": hashlib.sha256(output).hexdigest(),
        }


@pytest.mark.skipif(os.name == "nt", reason="POSIX report transaction")
def test_subprocess_transactions_share_the_publication_lock(tmp_path: Path) -> None:
    result_directory = tmp_path / "result"
    result_directory.mkdir()
    output_path = result_directory / "vex.json"
    report_path = result_directory / "execution-report.json"
    pause_marker = tmp_path / "first-paused"
    release_marker = tmp_path / "release-first"
    lock_observation = tmp_path / "second-lock-observation"
    helper = Path(__file__).parent / "integration" / "publish_generation_transaction.py"

    def command(
        message: str,
        pause: Path | None,
        release: Path | None,
        observation: Path | None,
    ) -> list[str]:
        return [
            sys.executable,
            str(helper),
            str(output_path),
            str(report_path),
            message,
            str(pause) if pause is not None else "-",
            str(release) if release is not None else "-",
            str(observation) if observation is not None else "-",
        ]

    first = subprocess.Popen(  # noqa: S603
        command("first", pause_marker, release_marker, None),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    second: subprocess.Popen[str] | None = None
    first_stdout = ""
    first_stderr = ""
    second_stdout = ""
    second_stderr = ""
    try:
        _wait_for_path(pause_marker)
        second = subprocess.Popen(  # noqa: S603
            command("second", None, None, lock_observation),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        _wait_for_path(lock_observation)
        assert lock_observation.read_text(encoding="utf-8") == "blocked"
        assert second.poll() is None
        assert not report_path.exists()
        release_marker.touch()
        first_stdout, first_stderr = first.communicate(timeout=5)
        second_stdout, second_stderr = second.communicate(timeout=5)
    finally:
        release_marker.touch()
        for process in (first, second):
            if process is not None and process.poll() is None:
                process.terminate()
                process.wait(timeout=5)

    assert first.returncode == 0, (first_stdout, first_stderr)
    assert second.returncode == 0, (second_stdout, second_stderr)
    output = output_path.read_bytes()
    report = json.loads(report_path.read_bytes())
    assert output == b'{"message":"second"}\n'
    assert report["document"] == {
        "bytes": len(output),
        "sha256": hashlib.sha256(output).hexdigest(),
    }


@pytest.mark.skipif(os.name == "nt", reason="POSIX report transaction")
@pytest.mark.parametrize("shared_directory", (False, True))
def test_killed_transaction_releases_locks_without_publishing_report(
    tmp_path: Path,
    shared_directory: bool,
) -> None:
    output_directory = tmp_path / "result"
    report_directory = output_directory if shared_directory else tmp_path / "report"
    output_directory.mkdir()
    if not shared_directory:
        report_directory.mkdir()
    output_path = output_directory / "vex.json"
    report_path = report_directory / "execution-report.json"
    pause_marker = tmp_path / "first-paused"
    release_marker = tmp_path / "never-release"
    helper = Path(__file__).parent / "integration" / "publish_generation_transaction.py"

    def command(message: str, pause: Path | None, release: Path | None) -> list[str]:
        return [
            sys.executable,
            str(helper),
            str(output_path),
            str(report_path),
            message,
            str(pause) if pause is not None else "-",
            str(release) if release is not None else "-",
            "-",
        ]

    first = subprocess.Popen(  # noqa: S603
        command("first", pause_marker, release_marker),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        _wait_for_path(pause_marker)
        first.terminate()
        first_stdout, first_stderr = first.communicate(timeout=5)
    finally:
        if first.poll() is None:
            first.kill()
            first.wait(timeout=5)

    assert first.returncode != 0, (first_stdout, first_stderr)
    assert output_path.read_bytes() == b'{"message":"first"}\n'
    assert not report_path.exists()

    second = subprocess.run(  # noqa: S603
        command("second", None, None),
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert second.returncode == 0, (second.stdout, second.stderr)
    output = output_path.read_bytes()
    report = json.loads(report_path.read_bytes())
    assert output == b'{"message":"second"}\n'
    assert report["document"] == {
        "bytes": len(output),
        "sha256": hashlib.sha256(output).hexdigest(),
    }


@pytest.mark.skipif(os.name == "nt", reason="POSIX report transaction")
def test_sigint_after_report_publication_removes_report_and_releases_locks(
    tmp_path: Path,
) -> None:
    result_directory = tmp_path / "result"
    result_directory.mkdir()
    output_path = result_directory / "vex.json"
    report_path = result_directory / "execution-report.json"
    pause_marker = tmp_path / "report-published"
    release_marker = tmp_path / "never-release"
    helper = Path(__file__).parent / "integration" / "publish_generation_transaction.py"

    def command(message: str, *, pause_after_report: bool = False) -> list[str]:
        return [
            sys.executable,
            str(helper),
            str(output_path),
            str(report_path),
            message,
            str(pause_marker) if pause_after_report else "-",
            str(release_marker) if pause_after_report else "-",
            "-",
            "report" if pause_after_report else "output",
        ]

    interrupted = subprocess.Popen(  # noqa: S603
        command("interrupted", pause_after_report=True),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        _wait_for_path(pause_marker)
        assert report_path.exists()
        interrupted.send_signal(signal.SIGINT)
        interrupted_stdout, interrupted_stderr = interrupted.communicate(timeout=5)
    finally:
        if interrupted.poll() is None:
            interrupted.kill()
            interrupted.wait(timeout=5)

    assert interrupted.returncode != 0, (interrupted_stdout, interrupted_stderr)
    assert output_path.read_bytes() == b'{"message":"interrupted"}\n'
    assert not report_path.exists()

    subsequent = subprocess.run(  # noqa: S603
        command("subsequent"),
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert subsequent.returncode == 0, (subsequent.stdout, subsequent.stderr)
    output = output_path.read_bytes()
    report = json.loads(report_path.read_bytes())
    assert output == b'{"message":"subsequent"}\n'
    assert report["document"] == {
        "bytes": len(output),
        "sha256": hashlib.sha256(output).hexdigest(),
    }


def _wait_for_path(path: Path) -> None:
    deadline = time.monotonic() + 5
    while not path.exists():
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out waiting for {path.name}")
        time.sleep(0.01)
