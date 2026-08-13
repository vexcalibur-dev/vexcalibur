"""Contract tests for the scheduled Atheris campaign wrapper."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from tests.fuzz.boundaries import FUZZ_TARGETS
from tests.fuzz.corpus_staging import stage_corpus

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.skipif(os.name == "nt", reason="Atheris runner requires Bash")
def test_atheris_runner_allows_targets_without_a_checked_in_corpus(
    tmp_path: Path,
) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    invocation_log = tmp_path / "uv-invocations.txt"
    fake_uv = fake_bin / "uv"
    fake_uv.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        'if [[ "$*" == *"tests.fuzz.corpus_staging list-targets"* ]]; then\n'
        '  printf "%s\\n" "${FAKE_FUZZ_TARGETS:?}"\n'
        "  exit 0\n"
        "fi\n"
        'if [[ "$*" == *"tests.fuzz.corpus_staging stage"* ]]; then\n'
        '  [[ ! -e "${FUZZ_CORPUS_ROOT:?}" ]]\n'
        "  exit 0\n"
        "fi\n"
        'printf "%s\\n" "${FUZZ_TARGET:?}" >>"${FAKE_UV_LOG:?}"\n',
        encoding="utf-8",
    )
    fake_uv.chmod(0o755)
    environment = {
        **os.environ,
        "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}",
        "FAKE_UV_LOG": str(invocation_log),
        "FAKE_FUZZ_TARGETS": "\n".join(FUZZ_TARGETS),
        "FUZZ_CORPUS_ROOT": str(tmp_path / "generated-corpus"),
        "FUZZ_ARTIFACT_ROOT": str(tmp_path / "artifacts"),
        "FUZZ_MAX_TOTAL_TIME": "1",
    }
    bash = shutil.which("bash")
    assert bash is not None

    result = subprocess.run(  # noqa: S603
        [bash, "scripts/run-atheris.sh"],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0, result.stderr
    assert invocation_log.read_text(encoding="utf-8").splitlines() == list(FUZZ_TARGETS)
    assert (tmp_path / "generated-corpus" / "consumer").is_dir()


def test_corpus_staging_materializes_binary_seeds_for_every_target(tmp_path: Path) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    report = source / "report"
    report.mkdir(parents=True)
    (report / "malformed.hex").write_text("00 ff\n", encoding="ascii")
    (report / "valid.txt").write_text("report\n", encoding="ascii")

    stage_corpus(source, destination)

    assert (destination / "report" / "malformed.bin").read_bytes() == b"\x00\xff"
    assert not (destination / "report" / "malformed.hex").exists()
    assert (destination / "report" / "valid.txt").read_text(encoding="ascii") == "report\n"
    assert all((destination / target).is_dir() for target in FUZZ_TARGETS)


def test_corpus_staging_rejects_colliding_seed_names(tmp_path: Path) -> None:
    source = tmp_path / "source"
    json_corpus = source / "json"
    json_corpus.mkdir(parents=True)
    (json_corpus / "valid.json").write_text("{}\n", encoding="ascii")
    report = source / "report"
    report.mkdir(parents=True)
    (report / "same.hex").write_text("ff\n", encoding="ascii")
    (report / "same.bin").write_bytes(b"different")

    with pytest.raises(ValueError, match="same staged name"):
        stage_corpus(source, tmp_path / "destination")

    assert not (tmp_path / "destination").exists()


def test_corpus_staging_rejects_malformed_hex_before_writing(tmp_path: Path) -> None:
    source = tmp_path / "source"
    json_corpus = source / "json"
    json_corpus.mkdir(parents=True)
    (json_corpus / "valid.json").write_text("{}\n", encoding="ascii")
    report = source / "report"
    report.mkdir()
    (report / "malformed.hex").write_text("not hexadecimal\n", encoding="ascii")
    destination = tmp_path / "destination"

    with pytest.raises(ValueError, match="non-hexadecimal number"):
        stage_corpus(source, destination)

    assert not destination.exists()


@pytest.mark.skipif(os.name == "nt", reason="symlink creation requires privileges")
@pytest.mark.parametrize("symlink_kind", ("target", "output"))
def test_corpus_staging_rejects_destination_symlinks_without_removing_source(
    tmp_path: Path,
    symlink_kind: str,
) -> None:
    source = tmp_path / "source"
    report = source / "report"
    report.mkdir(parents=True)
    seed = report / "malformed.hex"
    seed.write_text("ff\n", encoding="ascii")
    destination = tmp_path / "destination"
    destination.mkdir()
    if symlink_kind == "target":
        (destination / "report").symlink_to(report, target_is_directory=True)
    else:
        staged_report = destination / "report"
        staged_report.mkdir()
        (staged_report / "malformed.bin").symlink_to(seed)

    with pytest.raises(ValueError, match="must not be a symlink"):
        stage_corpus(source, destination)

    assert seed.read_text(encoding="ascii") == "ff\n"


@pytest.mark.skipif(os.name == "nt", reason="symlink creation requires privileges")
def test_corpus_staging_rejects_source_target_symlink(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    external = tmp_path / "external"
    external.mkdir()
    seed = external / "valid.json"
    seed.write_text("{}\n", encoding="ascii")
    (source / "json").symlink_to(external, target_is_directory=True)
    destination = tmp_path / "destination"

    with pytest.raises(ValueError, match="target must not be a symlink"):
        stage_corpus(source, destination)

    assert not destination.exists()


@pytest.mark.skipif(os.name == "nt", reason="hard-link behavior differs on Windows")
def test_corpus_staging_replaces_hard_link_without_modifying_source(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    report = source / "report"
    report.mkdir(parents=True)
    seed = report / "malformed.hex"
    seed.write_text("ff\n", encoding="ascii")
    destination = tmp_path / "destination"
    staged_report = destination / "report"
    staged_report.mkdir(parents=True)
    staged_seed = staged_report / "malformed.bin"
    os.link(seed, staged_seed)

    stage_corpus(source, destination)

    assert seed.read_text(encoding="ascii") == "ff\n"
    assert staged_seed.read_bytes() == b"\xff"
    assert seed.stat().st_ino != staged_seed.stat().st_ino


@pytest.mark.parametrize("destination_kind", ("same", "descendant", "ancestor"))
def test_corpus_staging_rejects_overlapping_roots_without_removing_source(
    tmp_path: Path,
    destination_kind: str,
) -> None:
    source = tmp_path / "source"
    report = source / "report"
    report.mkdir(parents=True)
    seed = report / "malformed.hex"
    seed.write_text("ff\n", encoding="ascii")
    destinations = {
        "same": source,
        "descendant": source / "generated",
        "ancestor": tmp_path,
    }

    with pytest.raises(ValueError, match="must not overlap"):
        stage_corpus(source, destinations[destination_kind])

    assert seed.read_text(encoding="ascii") == "ff\n"
