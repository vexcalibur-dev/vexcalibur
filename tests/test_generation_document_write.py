from __future__ import annotations

from pathlib import Path

import pytest

from vexcalibur.generation_output import (
    GenerationDocumentWriteError,
    write_generation_document,
)
from vexcalibur.generation_result import GenerationResult


def _result() -> GenerationResult:
    return GenerationResult(
        rendered_document='{"message":"complete"}\n',
        components=(),
        findings=(),
    )


def test_generation_document_write_uses_text_stdout_without_a_path() -> None:
    written: list[str] = []

    write_generation_document(
        _result(),
        output_path=None,
        write_text_stdout=written.append,
    )

    assert written == ['{"message":"complete"}\n']


def test_generation_document_write_writes_utf8_file(tmp_path: Path) -> None:
    output_path = tmp_path / "vex.json"

    write_generation_document(
        _result(),
        output_path=output_path,
        write_text_stdout=lambda value: None,
    )

    assert output_path.read_bytes() == b'{"message":"complete"}\n'


def test_generation_document_write_classifies_stdout_failure() -> None:
    failure = OSError("stdout failed")

    def fail_stdout(value: str) -> None:
        raise failure

    with pytest.raises(GenerationDocumentWriteError, match="stdout failed") as captured:
        write_generation_document(
            _result(),
            output_path=None,
            write_text_stdout=fail_stdout,
        )

    assert captured.value.destination is None
    assert captured.value.__cause__ is failure


def test_generation_document_write_classifies_file_failure(tmp_path: Path) -> None:
    output_path = tmp_path / "missing" / "vex.json"

    with pytest.raises(GenerationDocumentWriteError) as captured:
        write_generation_document(
            _result(),
            output_path=output_path,
            write_text_stdout=lambda value: None,
        )

    assert captured.value.destination == output_path
    assert isinstance(captured.value.__cause__, OSError)
