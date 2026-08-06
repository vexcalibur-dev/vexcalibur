"""Contract tests for the scheduled Atheris campaign wrapper."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from tests.fuzz.boundaries import FUZZ_TARGETS

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
        'printf "%s\\n" "${FUZZ_TARGET:?}" >>"${FAKE_UV_LOG:?}"\n',
        encoding="utf-8",
    )
    fake_uv.chmod(0o755)
    environment = {
        **os.environ,
        "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}",
        "FAKE_UV_LOG": str(invocation_log),
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
