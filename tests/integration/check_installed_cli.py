"""Check Vexcalibur console scripts from an installed wheel."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from hashlib import sha256
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.metadata import version as distribution_version
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[2]
FIXTURE_ROOT = ROOT / "tests" / "fixtures"
PYTHON_API_REPORT_EXAMPLE = ROOT / "docs" / "examples" / "generate_execution_report.py"
COMMAND_TIMEOUT_SECONDS = 30
EXPECTED_ANALYSIS_STATES = [
    "resolved",
    "exploitable",
    "in_triage",
    "false_positive",
    "not_affected",
]
EXPECTED_OPENVEX_STATUSES = [
    "fixed",
    "affected",
    "under_investigation",
    "not_affected",
    "not_affected",
]


def main() -> None:
    """Run installed console-script smoke and negative checks."""
    bin_dir = _required_bin_dir()
    vexcalibur = _console_script(bin_dir, "vexcalibur")
    vexy = _console_script(bin_dir, "vexy")
    _assert_installed_version()
    with TemporaryDirectory(prefix="vexcalibur-installed-python-api-") as directory:
        output_directory = Path(directory) / "generated"
        output_path = output_directory / "vex.json"
        report_path = output_directory / "execution-report.json"
        _expect(
            [
                sys.executable,
                str(PYTHON_API_REPORT_EXAMPLE),
                str(output_directory),
            ],
            returncode=0,
            stdout_contains=[str(output_path), str(report_path)],
            stderr_equals="",
        )
        _assert_execution_report_bytes(
            output_bytes=output_path.read_bytes(),
            report_path=report_path,
        )

    _expect(
        [str(vexcalibur), "--help"],
        returncode=0,
        stdout_contains=["Generate VEX documents"],
        stderr_equals="",
    )
    _expect(
        [str(vexy), "--help"],
        returncode=0,
        stdout_contains=["legacy vexy workflows"],
        stderr_equals="",
    )
    _expect(
        [str(vexcalibur), "query-osv"],
        returncode=2,
        stdout_equals="",
        stderr_contains=["Missing argument"],
    )
    _expect(
        [str(vexcalibur), "query-osv", "   "],
        returncode=2,
        stdout_equals="",
        stderr_contains=["not a valid package URL"],
    )
    _expect(
        [str(vexcalibur), "query-osv", "not a purl"],
        returncode=2,
        stdout_equals="",
        stderr_contains=["not a valid package URL"],
    )
    _expect(
        [str(vexcalibur), "query-osv", "pkg:pypi/example@1.0.0"],
        returncode=1,
        stdout_equals="",
        stderr_contains=["--allow-public-osv"],
    )
    _expect(
        [str(vexcalibur), "generate", str(FIXTURE_ROOT / "sbom" / "cyclonedx-json-simple.json")],
        returncode=1,
        stdout_equals="",
        stderr_contains=["--allow-public-osv"],
    )

    with _local_osv_failure_server() as osv_url:
        _expect(
            [
                str(vexcalibur),
                "query-osv",
                "pkg:pypi/example@1.0.0",
                "--osv-url",
                osv_url,
            ],
            returncode=1,
            stdout_equals="",
            stderr_contains=["OSV API POST /v1/querybatch failed with HTTP 503"],
        )

    generated = _expect(
        [
            str(vexcalibur),
            "generate",
            str(FIXTURE_ROOT / "sbom" / "cyclonedx-xml-1.5-simple.xml"),
            "--findings-file",
            str(FIXTURE_ROOT / "findings" / "all-analysis-states.json"),
            "--offline",
            "--timestamp",
            "2026-06-23T00:00:00Z",
        ],
        returncode=0,
        stdout_contains=['"bomFormat": "CycloneDX"'],
        stderr_equals="",
    )
    _assert_generated_vex_shape(generated.stdout)

    with TemporaryDirectory(prefix="vexcalibur-installed-report-") as temporary_directory:
        output_path = Path(temporary_directory) / "vex.json"
        report_path = Path(temporary_directory) / "execution-report.json"
        _expect(
            [
                str(vexcalibur),
                "generate",
                str(FIXTURE_ROOT / "sbom" / "cyclonedx-xml-1.5-simple.xml"),
                "--findings-file",
                str(FIXTURE_ROOT / "findings" / "all-analysis-states.json"),
                "--offline",
                "--timestamp",
                "2026-06-23T00:00:00Z",
                "--output",
                str(output_path),
                "--execution-report",
                str(report_path),
            ],
            returncode=0,
            stdout_equals="",
            stderr_equals="",
        )
        _assert_execution_report(output_path=output_path, report_path=report_path)

    with TemporaryDirectory(prefix="vexcalibur-installed-stdout-report-") as temporary_directory:
        report_path = Path(temporary_directory) / "execution-report.json"
        generated_with_report = _expect(
            [
                str(vexcalibur),
                "generate",
                str(FIXTURE_ROOT / "sbom" / "cyclonedx-xml-1.5-simple.xml"),
                "--findings-file",
                str(FIXTURE_ROOT / "findings" / "all-analysis-states.json"),
                "--offline",
                "--timestamp",
                "2026-06-23T00:00:00Z",
                "--execution-report",
                str(report_path),
            ],
            returncode=0,
            stdout_contains=['"bomFormat": "CycloneDX"'],
            stderr_equals="",
        )
        _assert_execution_report_bytes(
            output_bytes=generated_with_report.stdout.encode("utf-8"),
            report_path=report_path,
        )

    with TemporaryDirectory(prefix="vexcalibur-installed-openvex-report-") as directory:
        output_path = Path(directory) / "openvex.json"
        report_path = Path(directory) / "execution-report.json"
        _expect(
            [
                str(vexcalibur),
                "generate",
                str(FIXTURE_ROOT / "sbom" / "cyclonedx-xml-1.5-simple.xml"),
                "--findings-file",
                str(FIXTURE_ROOT / "findings" / "all-analysis-states.json"),
                "--offline",
                "--format",
                "openvex",
                "--author",
                "Vexcalibur installed CLI test",
                "--author-role",
                "Test producer",
                "--timestamp",
                "2026-06-23T00:00:00Z",
                "--output",
                str(output_path),
                "--execution-report",
                str(report_path),
            ],
            returncode=0,
            stdout_equals="",
            stderr_equals="",
        )
        _assert_generated_openvex_shape(output_path.read_text(encoding="utf-8"))
        _assert_execution_report(
            output_path=output_path,
            report_path=report_path,
            output_format="openvex",
        )

    _expect(
        [
            str(vexcalibur),
            "generate",
            str(FIXTURE_ROOT / "sbom" / "cyclonedx-json-simple.json"),
            "--findings-file",
            str(FIXTURE_ROOT / "findings" / "all-analysis-states.json"),
            "--offline",
            "--format",
            "openvex",
        ],
        returncode=1,
        stdout_equals="",
        stderr_contains=["--author is required with --format openvex"],
    )

    vexy_generated = _expect(
        [
            str(vexy),
            "-c",
            str(FIXTURE_ROOT / "vexy" / "legacy-config.yml"),
            "-i",
            str(FIXTURE_ROOT / "sbom" / "cyclonedx-xml-1.5-simple.xml"),
            "--format",
            "json",
            "--schema-version",
            "1.6",
            "--output",
            "-",
            "--findings-file",
            str(FIXTURE_ROOT / "findings" / "all-analysis-states.json"),
            "--offline",
            "--timestamp",
            "2026-06-23T00:00:00Z",
        ],
        returncode=0,
        stdout_contains=['"bomFormat": "CycloneDX"'],
        stderr_equals="",
    )
    _assert_generated_vex_shape(vexy_generated.stdout)


def _required_bin_dir() -> Path:
    try:
        bin_dir = Path(os.environ["VEXCALIBUR_BIN_DIR"])
    except KeyError:
        print(
            "VEXCALIBUR_BIN_DIR must point to the installed environment bin directory",
            file=sys.stderr,
        )
        raise SystemExit(2) from None

    if not bin_dir.is_dir():
        print(f"VEXCALIBUR_BIN_DIR is not a directory: {bin_dir}", file=sys.stderr)
        raise SystemExit(2)
    return bin_dir


def _console_script(bin_dir: Path, name: str) -> Path:
    suffix = ".exe" if os.name == "nt" else ""
    script = bin_dir / f"{name}{suffix}"
    if not script.is_file():
        print(f"Installed console script was not found: {script}", file=sys.stderr)
        raise SystemExit(2)
    return script


def _assert_installed_version() -> None:
    import vexcalibur

    expected_python = os.environ.get("VEXCALIBUR_EXPECTED_PYTHON")
    if expected_python is not None:
        try:
            expected_python_info = tuple(int(value) for value in expected_python.split("."))
        except ValueError:
            print(f"Invalid expected Python version: {expected_python!r}", file=sys.stderr)
            raise SystemExit(2) from None
        if len(expected_python_info) != 2:
            print(f"Invalid expected Python version: {expected_python!r}", file=sys.stderr)
            raise SystemExit(2)
        if sys.version_info[:2] != expected_python_info:
            actual = f"{sys.version_info.major}.{sys.version_info.minor}"
            print(
                f"Installed checks used Python {actual} instead of {expected_python}.",
                file=sys.stderr,
            )
            raise SystemExit(1)

    installed_package = Path(vexcalibur.__file__).resolve()
    installed_prefix = Path(sys.prefix).resolve()
    if not installed_package.is_relative_to(installed_prefix):
        print(
            f"Imported Vexcalibur from outside the installed environment: {installed_package}",
            file=sys.stderr,
        )
        raise SystemExit(1)

    expected_version = os.environ.get("VEXCALIBUR_EXPECTED_VERSION")
    if expected_version is None:
        return

    actual_distribution_version = distribution_version("vexcalibur")
    if actual_distribution_version != expected_version:
        print(
            "Installed distribution version "
            f"{actual_distribution_version!r} did not match {expected_version!r}.",
            file=sys.stderr,
        )
        raise SystemExit(1)

    if vexcalibur.__version__ != expected_version:
        print(
            f"vexcalibur.__version__ {vexcalibur.__version__!r} "
            f"did not match {expected_version!r}.",
            file=sys.stderr,
        )
        raise SystemExit(1)


def _expect(
    command: list[str],
    *,
    returncode: int,
    stdout_contains: list[str] | None = None,
    stderr_contains: list[str] | None = None,
    stdout_equals: str | None = None,
    stderr_equals: str | None = None,
) -> subprocess.CompletedProcess[str]:
    result = _run(command)
    if result.returncode != returncode:
        _print_failure(command, result)
        print(f"Expected exit code {returncode}.", file=sys.stderr)
        raise SystemExit(1)

    if stdout_equals is not None:
        _assert_equal_stream(command, result, "stdout", result.stdout, stdout_equals)
    if stderr_equals is not None:
        _assert_equal_stream(command, result, "stderr", result.stderr, stderr_equals)
    for expected_output in stdout_contains or []:
        _assert_output_contains(command, result, "stdout", result.stdout, expected_output)
    for expected_output in stderr_contains or []:
        _assert_output_contains(command, result, "stderr", result.stderr, expected_output)

    _assert_no_traceback(command, result)
    return result


def _run(command: list[str]) -> subprocess.CompletedProcess[str]:
    env = {
        **os.environ,
        "COLUMNS": "120",
        "NO_COLOR": "1",
        "TERM": "dumb",
    }
    return subprocess.run(  # noqa: S603 - commands are built by this test harness.
        command,
        cwd=ROOT,
        text=True,
        capture_output=True,
        timeout=COMMAND_TIMEOUT_SECONDS,
        check=False,
        env=env,
    )


def _assert_equal_stream(
    command: list[str],
    result: subprocess.CompletedProcess[str],
    stream_name: str,
    actual: str,
    expected: str,
) -> None:
    if actual == expected:
        return
    _print_failure(command, result)
    print(f"Expected {stream_name} to equal {expected!r}.", file=sys.stderr)
    raise SystemExit(1)


def _assert_output_contains(
    command: list[str],
    result: subprocess.CompletedProcess[str],
    stream_name: str,
    actual: str,
    expected_output: str,
) -> None:
    if _normalize_output(expected_output) in _normalize_output(actual):
        return
    _print_failure(command, result)
    print(f"Expected {stream_name} to contain: {expected_output}", file=sys.stderr)
    raise SystemExit(1)


def _normalize_output(value: str) -> str:
    return " ".join(value.split())


def _assert_no_traceback(command: list[str], result: subprocess.CompletedProcess[str]) -> None:
    combined = f"{result.stdout}\n{result.stderr}"
    if "Traceback" in combined:
        _print_failure(command, result)
        print("Installed CLI command emitted a traceback.", file=sys.stderr)
        raise SystemExit(1)


def _assert_generated_vex_shape(generated: str) -> None:
    document = json.loads(generated)
    vulnerabilities = document["vulnerabilities"]
    if document["bomFormat"] != "CycloneDX":
        print("Generated document did not use CycloneDX output.", file=sys.stderr)
        raise SystemExit(1)
    if [vulnerability["analysis"]["state"] for vulnerability in vulnerabilities] != (
        EXPECTED_ANALYSIS_STATES
    ):
        print(
            "Generated VEX did not preserve expected local finding analysis states.",
            file=sys.stderr,
        )
        raise SystemExit(1)


def _assert_generated_openvex_shape(generated: str) -> None:
    document = json.loads(generated)
    statements = document["statements"]
    if document["@context"] != "https://openvex.dev/ns/v0.2.0":
        print("Generated document did not use OpenVEX 0.2.0 output.", file=sys.stderr)
        raise SystemExit(1)
    if [statement["status"] for statement in statements] != EXPECTED_OPENVEX_STATUSES:
        print("Generated OpenVEX did not map expected analysis states.", file=sys.stderr)
        raise SystemExit(1)
    if not all(statement["products"] for statement in statements):
        print("Generated OpenVEX statement did not identify a product.", file=sys.stderr)
        raise SystemExit(1)
    if "action_statement" not in statements[1]:
        print("Generated affected OpenVEX statement did not include an action.", file=sys.stderr)
        raise SystemExit(1)
    if "Confirmed fixed product version: 1.2" not in statements[0]["status_notes"]:
        print(
            "Generated fixed OpenVEX statement did not confirm its version.",
            file=sys.stderr,
        )
        raise SystemExit(1)
    if not all("impact_statement" in statements[index] for index in (3, 4)):
        print(
            "Generated not-affected OpenVEX statement did not explain its impact.", file=sys.stderr
        )
        raise SystemExit(1)


def _assert_execution_report(
    *,
    output_path: Path,
    report_path: Path,
    output_format: str = "cyclonedx",
) -> None:
    _assert_execution_report_bytes(
        output_bytes=output_path.read_bytes(),
        report_path=report_path,
        output_format=output_format,
    )
    if os.name != "nt":
        for path in (output_path, report_path):
            if path.stat().st_mode & 0o777 != 0o600:
                print(f"Installed CLI output mode was not 0600: {path}", file=sys.stderr)
                raise SystemExit(1)


def _assert_execution_report_bytes(
    *,
    output_bytes: bytes,
    report_path: Path,
    output_format: str = "cyclonedx",
) -> None:
    report_bytes = report_path.read_bytes()
    report = json.loads(report_bytes)
    expected = {
        "schema_version": 1,
        "command": "generate",
        "vexcalibur_version": distribution_version("vexcalibur"),
        "inventory_source": "sbom_file",
        "finding_source": "local_file",
        "output_format": output_format,
        "component_count": 2,
        "finding_count": 5,
        "analysis_state_counts": {
            "resolved": 1,
            "exploitable": 1,
            "in_triage": 1,
            "false_positive": 1,
            "not_affected": 1,
        },
        "document": {
            "sha256": sha256(output_bytes).hexdigest(),
            "bytes": len(output_bytes),
        },
    }
    if report != expected:
        print("Installed CLI execution report did not match generated VEX.", file=sys.stderr)
        print(json.dumps(report, indent=2, sort_keys=True), file=sys.stderr)
        raise SystemExit(1)
    canonical = (
        json.dumps(
            expected,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("ascii")
    if report_bytes != canonical:
        print("Installed CLI execution report bytes were not canonical.", file=sys.stderr)
        raise SystemExit(1)


@contextmanager
def _local_osv_failure_server() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _OsvFailureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=COMMAND_TIMEOUT_SECONDS)
        server.server_close()


class _OsvFailureHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        self.send_response(503)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"error":"service unavailable"}')

    def log_message(self, format: str, *args: object) -> None:
        return


def _print_failure(command: list[str], result: subprocess.CompletedProcess[str]) -> None:
    print(f"Command failed expectation: {' '.join(command)}", file=sys.stderr)
    print(f"Exit code: {result.returncode}", file=sys.stderr)
    print("stdout:", file=sys.stderr)
    print(result.stdout, file=sys.stderr)
    print("stderr:", file=sys.stderr)
    print(result.stderr, file=sys.stderr)


if __name__ == "__main__":
    main()
