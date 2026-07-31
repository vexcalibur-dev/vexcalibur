import os
from pathlib import Path

import pytest

import vexcalibur.input_file as input_file_module
from vexcalibur.input_file import BoundedFileReadError, read_bounded_regular_file


def _read(path: Path, *, limit: int = 5) -> bytes:
    return read_bounded_regular_file(path, max_bytes=limit, description=f"test input {path}")


def test_bounded_reader_accepts_exact_limit_and_regular_file_symlink(tmp_path: Path) -> None:
    target = tmp_path / "target.json"
    target.write_bytes(b"12345")
    symlink = tmp_path / "input.json"
    symlink.symlink_to(target)

    assert _read(target) == b"12345"
    assert _read(symlink) == b"12345"


def test_bounded_reader_opens_inputs_in_binary_mode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "binary-input.json"
    payload = b"a\r\nb\x1a"
    path.write_bytes(payload)
    real_open = input_file_module.os.open
    native_binary_flag = hasattr(input_file_module.os, "O_BINARY")
    binary_flag = getattr(input_file_module.os, "O_BINARY", 1 << 29)
    observed_flags = 0

    def track_binary_flag(selected_path: Path, flags: int) -> int:
        nonlocal observed_flags
        observed_flags = flags
        native_flags = flags if native_binary_flag else flags & ~binary_flag
        return real_open(selected_path, native_flags)

    monkeypatch.setattr(input_file_module.os, "O_BINARY", binary_flag, raising=False)
    monkeypatch.setattr(input_file_module.os, "open", track_binary_flag)

    result = read_bounded_regular_file(
        path,
        max_bytes=len(payload),
        description="test input",
    )

    assert observed_flags & binary_flag
    assert result == payload


def test_bounded_reader_rejects_limit_plus_one(tmp_path: Path) -> None:
    path = tmp_path / "input.json"
    path.write_bytes(b"123456")

    with pytest.raises(BoundedFileReadError, match="exceeds the 5 byte limit"):
        _read(path)


def test_bounded_reader_catches_growth_after_descriptor_inspection(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    path = tmp_path / "growing.json"
    path.write_bytes(b"12345")
    real_fstat = os.fstat

    def fstat_then_grow(descriptor: int) -> os.stat_result:
        result = real_fstat(descriptor)
        path.write_bytes(b"123456")
        return result

    monkeypatch.setattr("vexcalibur.input_file.os.fstat", fstat_then_grow)

    with pytest.raises(BoundedFileReadError, match="exceeds the 5 byte limit"):
        _read(path)


def test_bounded_reader_rejects_fifo_without_waiting_for_a_writer(tmp_path: Path) -> None:
    fifo = tmp_path / "oversized-stream.json"
    os.mkfifo(fifo)

    with pytest.raises(BoundedFileReadError, match="must resolve to a regular file"):
        _read(fifo)


def test_bounded_reader_rejects_symlink_to_fifo(tmp_path: Path) -> None:
    fifo = tmp_path / "stream"
    os.mkfifo(fifo)
    symlink = tmp_path / "input.json"
    symlink.symlink_to(fifo)

    with pytest.raises(BoundedFileReadError, match="must resolve to a regular file"):
        _read(symlink)


def test_bounded_reader_rejects_symlink_to_device(tmp_path: Path) -> None:
    device = Path("/dev/null")
    if not device.exists():
        pytest.skip("this platform does not expose /dev/null")
    symlink = tmp_path / "input.json"
    symlink.symlink_to(device)

    with pytest.raises(BoundedFileReadError, match="must resolve to a regular file"):
        _read(symlink)
