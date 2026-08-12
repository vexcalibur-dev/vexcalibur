#!/usr/bin/env python3
"""Enforce aggregate, critical-file, and changed-line coverage policy."""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import shutil
import subprocess
import sys
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

AGGREGATE_FLOOR = 75.0
CHANGED_LINE_FLOOR = 90.0
SOURCE_ROOT = PurePosixPath("src/vexcalibur")
CRITICAL_FLOORS: Mapping[PurePosixPath, float] = {
    PurePosixPath("src/vexcalibur/generation_result.py"): 88.0,
    PurePosixPath("src/vexcalibur/execution_report_validation.py"): 75.0,
    PurePosixPath("src/vexcalibur/generation_output.py"): 90.0,
    PurePosixPath("src/vexcalibur/execution_report_destination.py"): 88.0,
    PurePosixPath("src/vexcalibur/execution_report_filesystem.py"): 80.0,
    PurePosixPath("src/vexcalibur/execution_report_lifecycle.py"): 95.0,
    PurePosixPath("src/vexcalibur/execution_report_locks.py"): 85.0,
    PurePosixPath("src/vexcalibur/execution_report_staging.py"): 82.0,
    PurePosixPath("src/vexcalibur/github_sbom.py"): 75.0,
    PurePosixPath("scripts/archive_limits.py"): 85.0,
    PurePosixPath("scripts/check_coverage_policy.py"): 90.0,
    PurePosixPath("scripts/execution_report_oracle.py"): 74.0,
    PurePosixPath("scripts/release_evidence.py"): 65.0,
}
HUNK_PATTERN = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


class CoveragePolicyError(RuntimeError):
    """Raised when coverage evidence or its Git comparison is invalid."""


@dataclass(frozen=True)
class FileCoverage:
    """Branch-aware coverage for one source file."""

    executed_lines: frozenset[int]
    missing_lines: frozenset[int]
    excluded_lines: frozenset[int]
    missing_branch_origins: frozenset[int]
    percentage: float

    def covers(self, line_number: int) -> bool | None:
        """Return coverage for an executable line, or None for a non-executable line."""
        if line_number in self.missing_lines:
            return False
        if line_number in self.excluded_lines or line_number not in self.executed_lines:
            return None
        return line_number not in self.missing_branch_origins


@dataclass(frozen=True)
class CoverageReport:
    """Validated coverage.py JSON evidence."""

    files: Mapping[PurePosixPath, FileCoverage]
    aggregate_percentage: float


@dataclass(frozen=True)
class ChangedCoverageResult:
    """Coverage result for changed executable lines."""

    covered: int
    measured: int
    uncovered: tuple[tuple[PurePosixPath, int], ...]
    missing_files: tuple[PurePosixPath, ...]

    @property
    def percentage(self) -> float:
        """Return the covered percentage, treating no measured lines as complete."""
        if self.measured == 0:
            return 100.0
        return self.covered * 100.0 / self.measured


@dataclass(frozen=True)
class ChangedPath:
    """A changed destination path and its optional pre-rename source path."""

    path: PurePosixPath
    source_path: PurePosixPath | None = None


def _require_mapping(value: object, *, field: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise CoveragePolicyError(f"{field} must be an object")
    return value


def _require_percentage(value: object, *, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise CoveragePolicyError(f"{field} must be a percentage")
    percentage = float(value)
    if not math.isfinite(percentage) or not 0.0 <= percentage <= 100.0:
        raise CoveragePolicyError(f"{field} must be between 0 and 100")
    return percentage


def _require_lines(value: object, *, field: str) -> frozenset[int]:
    if not isinstance(value, list) or any(type(line) is not int or line < 1 for line in value):
        raise CoveragePolicyError(f"{field} must contain positive line numbers")
    lines = frozenset(value)
    if len(lines) != len(value):
        raise CoveragePolicyError(f"{field} must not repeat line numbers")
    return lines


def _require_branch_origins(value: object, *, field: str) -> frozenset[int]:
    if not isinstance(value, list):
        raise CoveragePolicyError(f"{field} must be a list")
    origins: set[int] = set()
    for branch in value:
        if (
            not isinstance(branch, list)
            or len(branch) != 2
            or type(branch[0]) is not int
            or branch[0] < 1
            or type(branch[1]) is not int
        ):
            raise CoveragePolicyError(f"{field} must contain branch line pairs")
        origins.add(branch[0])
    return frozenset(origins)


def _normalized_path(value: str, *, windows_separators: bool = False) -> PurePosixPath:
    normalized = value.removeprefix("./")
    if windows_separators:
        normalized = normalized.replace("\\", "/")
    path = PurePosixPath(normalized)
    if not normalized or path == PurePosixPath(".") or path.is_absolute() or ".." in path.parts:
        raise CoveragePolicyError(f"coverage report contains an unsafe path: {value!r}")
    return path


def load_coverage_report(report_path: Path) -> CoverageReport:
    """Load branch-aware coverage.py JSON evidence."""
    try:
        document = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CoveragePolicyError(f"could not read coverage report {report_path}: {exc}") from exc
    root = _require_mapping(document, field="coverage report")
    meta = _require_mapping(root.get("meta"), field="coverage report meta")
    if meta.get("branch_coverage") is not True:
        raise CoveragePolicyError("coverage report does not contain branch coverage")
    raw_files = _require_mapping(root.get("files"), field="coverage report files")

    files: dict[PurePosixPath, FileCoverage] = {}
    for raw_path, raw_file in raw_files.items():
        if not isinstance(raw_path, str):
            raise CoveragePolicyError("coverage report file names must be strings")
        path = _normalized_path(raw_path, windows_separators=os.name == "nt")
        if path in files:
            raise CoveragePolicyError(f"coverage report repeats {path}")
        file_data = _require_mapping(raw_file, field=f"coverage for {path}")
        summary = _require_mapping(file_data.get("summary"), field=f"coverage summary for {path}")
        executed_lines = _require_lines(
            file_data.get("executed_lines"), field=f"executed lines for {path}"
        )
        missing_lines = _require_lines(
            file_data.get("missing_lines"), field=f"missing lines for {path}"
        )
        if executed_lines & missing_lines:
            raise CoveragePolicyError(f"coverage report contradicts itself for {path}")
        files[path] = FileCoverage(
            executed_lines=executed_lines,
            missing_lines=missing_lines,
            excluded_lines=_require_lines(
                file_data.get("excluded_lines"), field=f"excluded lines for {path}"
            ),
            missing_branch_origins=_require_branch_origins(
                file_data.get("missing_branches"), field=f"missing branches for {path}"
            ),
            percentage=_require_percentage(
                summary.get("percent_covered"), field=f"coverage percentage for {path}"
            ),
        )

    totals = _require_mapping(root.get("totals"), field="coverage report totals")
    return CoverageReport(
        files=files,
        aggregate_percentage=_require_percentage(
            totals.get("percent_covered"), field="aggregate coverage percentage"
        ),
    )


def parse_changed_lines(patch: str) -> frozenset[int]:
    """Return destination line numbers from a zero-context Git patch."""
    changed: set[int] = set()
    for line in patch.splitlines():
        if (match := HUNK_PATTERN.match(line)) is None:
            continue
        start = int(match.group(1))
        count = int(match.group(2) or "1")
        changed.update(range(start, start + count))
    return frozenset(changed)


def _monitored_paths() -> tuple[PurePosixPath, ...]:
    scripts = tuple(path for path in CRITICAL_FLOORS if SOURCE_ROOT not in path.parents)
    return (SOURCE_ROOT, *scripts)


def _is_monitored(path: PurePosixPath) -> bool:
    return path.suffix == ".py" and (SOURCE_ROOT in path.parents or path in CRITICAL_FLOORS)


def _run_git(git: str, arguments: Sequence[str], *, repository: Path | None = None) -> bytes:
    try:
        completed = subprocess.run(  # noqa: S603 - no shell; arguments remain discrete.
            [git, *arguments],
            cwd=repository,
            check=True,
            capture_output=True,
        )
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.decode("utf-8", errors="replace").strip()
        raise CoveragePolicyError(f"Git comparison failed: {detail or exc}") from exc
    return completed.stdout


def repository_root(git: str) -> Path:
    """Return the absolute root of the current Git worktree."""
    try:
        root = _run_git(git, ("rev-parse", "--show-toplevel")).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CoveragePolicyError("Git reported a non-UTF-8 repository path") from exc
    return Path(root.rstrip("\r\n")).resolve()


def _decode_git_path(value: bytes) -> PurePosixPath:
    try:
        return _normalized_path(value.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise CoveragePolicyError("Git reported a non-UTF-8 source path") from exc


def changed_files(
    git: str,
    repository: Path,
    compare_ref: str,
    target_ref: str | None = None,
) -> tuple[ChangedPath, ...]:
    """Return changed monitored paths, including local untracked source files."""
    roots = tuple(str(path) for path in _monitored_paths())
    tracked = _run_git(
        git,
        (
            "diff",
            "--name-status",
            "-z",
            "--no-ext-diff",
            "--find-renames",
            "--diff-filter=ACMRTUXB",
            compare_ref,
            *((target_ref,) if target_ref is not None else ()),
            "--",
            *roots,
        ),
        repository=repository,
    )
    fields = tracked.rstrip(b"\0").split(b"\0") if tracked else []
    changes: list[ChangedPath] = []
    index = 0
    while index < len(fields):
        status = fields[index]
        index += 1
        if not status:
            raise CoveragePolicyError("Git reported an empty change status")
        if status.startswith((b"R", b"C")):
            if index + 1 >= len(fields):
                raise CoveragePolicyError("Git reported an incomplete rename")
            source = _decode_git_path(fields[index])
            path = _decode_git_path(fields[index + 1])
            index += 2
            if _is_monitored(path):
                changes.append(ChangedPath(path=path, source_path=source))
            continue
        if index >= len(fields):
            raise CoveragePolicyError("Git reported an incomplete changed path")
        path = _decode_git_path(fields[index])
        index += 1
        if _is_monitored(path):
            changes.append(ChangedPath(path=path))

    if target_ref is None:
        untracked = _run_git(
            git,
            ("ls-files", "--others", "--exclude-standard", "-z", "--", *roots),
            repository=repository,
        )
        changes.extend(
            ChangedPath(path=path)
            for raw in untracked.split(b"\0")
            if raw and _is_monitored(path := _decode_git_path(raw))
        )
    return tuple(sorted(set(changes), key=lambda change: change.path))


def changed_lines_for_file(
    git: str,
    repository: Path,
    compare_ref: str,
    change: ChangedPath,
    target_ref: str | None = None,
) -> frozenset[int]:
    """Return changed destination lines for one tracked or untracked file."""
    path = change.path
    if target_ref is None:
        tracked = _run_git(
            git,
            ("ls-files", "-z", "--", str(path)),
            repository=repository,
        )
    else:
        _run_git(git, ("cat-file", "-e", f"{target_ref}:{path}"), repository=repository)
        tracked = b"tracked"
    if not tracked:
        if target_ref is not None:
            raise CoveragePolicyError(f"target revision does not contain source path: {path}")
        local_path = repository / path
        if local_path.is_symlink() or not local_path.is_file():
            raise CoveragePolicyError(f"untracked source path is not a regular file: {path}")
        try:
            contents = local_path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise CoveragePolicyError(
                f"could not read untracked source file {path}: {exc}"
            ) from exc
        return frozenset(range(1, len(contents.splitlines()) + 1))
    patch = _run_git(
        git,
        (
            "diff",
            "--unified=0",
            "--no-color",
            "--no-ext-diff",
            "--text",
            "--find-renames",
            compare_ref,
            *((target_ref,) if target_ref is not None else ()),
            "--",
            *((str(change.source_path),) if change.source_path is not None else ()),
            str(path),
        ),
        repository=repository,
    )
    return parse_changed_lines(patch.decode("utf-8", errors="replace"))


def evaluate_changed_coverage(
    report: CoverageReport,
    changes: Iterable[tuple[PurePosixPath, frozenset[int]]],
) -> ChangedCoverageResult:
    """Compare changed lines with executable coverage records."""
    covered = 0
    measured = 0
    uncovered: list[tuple[PurePosixPath, int]] = []
    missing_files: list[PurePosixPath] = []
    for path, changed_lines in changes:
        file_coverage = report.files.get(path)
        if file_coverage is None:
            missing_files.append(path)
            continue
        for line_number in sorted(changed_lines):
            line_covered = file_coverage.covers(line_number)
            if line_covered is None:
                continue
            measured += 1
            if line_covered:
                covered += 1
            else:
                uncovered.append((path, line_number))
    return ChangedCoverageResult(
        covered=covered,
        measured=measured,
        uncovered=tuple(uncovered),
        missing_files=tuple(missing_files),
    )


def _line_ranges(lines: Iterable[int]) -> str:
    numbers = sorted(set(lines))
    ranges: list[str] = []
    index = 0
    while index < len(numbers):
        start = numbers[index]
        end = start
        while index + 1 < len(numbers) and numbers[index + 1] == end + 1:
            index += 1
            end = numbers[index]
        ranges.append(str(start) if start == end else f"{start}-{end}")
        index += 1
    return ", ".join(ranges)


def _valid_compare_ref(value: str) -> bool:
    return (
        bool(value)
        and not value.startswith("-")
        and not any(character.isspace() for character in value)
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("coverage_report", type=Path)
    parser.add_argument("--compare-ref", default=os.environ.get("COVERAGE_COMPARE_REF") or None)
    parser.add_argument("--target-ref", default=os.environ.get("COVERAGE_TARGET_REF") or None)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the complete coverage policy."""
    args = _parser().parse_args(argv)
    for option, value in (("--compare-ref", args.compare_ref), ("--target-ref", args.target_ref)):
        if value is not None and not _valid_compare_ref(value):
            print(f"{option} must be one non-empty Git revision", file=sys.stderr)
            return 2
    if args.target_ref is not None and args.compare_ref is None:
        print("--target-ref requires --compare-ref", file=sys.stderr)
        return 2
    try:
        report = load_coverage_report(args.coverage_report)
    except CoveragePolicyError as exc:
        print(f"Coverage policy failed: {exc}", file=sys.stderr)
        return 2

    failed = report.aggregate_percentage < AGGREGATE_FLOOR
    print(
        f"Aggregate branch coverage: {report.aggregate_percentage:.2f}% "
        f"(required {AGGREGATE_FLOOR:.2f}%)"
    )
    print("Critical-file branch coverage:")
    for path, floor in CRITICAL_FLOORS.items():
        file_coverage = report.files.get(path)
        if file_coverage is None:
            print(f"  {path}: missing coverage entry (required {floor:.2f}%)")
            failed = True
            continue
        print(f"  {path}: {file_coverage.percentage:.2f}% (required {floor:.2f}%)")
        failed |= file_coverage.percentage < floor

    if args.compare_ref is not None:
        git = shutil.which("git")
        if git is None:
            print("Coverage policy failed: git is required", file=sys.stderr)
            return 2
        try:
            repository = repository_root(git)
            _run_git(
                git,
                ("rev-parse", "--verify", "--end-of-options", f"{args.compare_ref}^{{commit}}"),
                repository=repository,
            )
            if args.target_ref is not None:
                _run_git(
                    git,
                    (
                        "rev-parse",
                        "--verify",
                        "--end-of-options",
                        f"{args.target_ref}^{{commit}}",
                    ),
                    repository=repository,
                )
            paths = changed_files(git, repository, args.compare_ref, args.target_ref)
            changes = tuple(
                (
                    change.path,
                    changed_lines_for_file(
                        git,
                        repository,
                        args.compare_ref,
                        change,
                        args.target_ref,
                    ),
                )
                for change in paths
            )
            changed = evaluate_changed_coverage(report, changes)
        except CoveragePolicyError as exc:
            print(f"Coverage policy failed: {exc}", file=sys.stderr)
            return 2
        for path in changed.missing_files:
            print(f"Missing coverage entry: {path}")
        uncovered_by_path: dict[PurePosixPath, list[int]] = {}
        for path, line_number in changed.uncovered:
            uncovered_by_path.setdefault(path, []).append(line_number)
        for path, lines in uncovered_by_path.items():
            print(f"Uncovered changed lines: {path}:{_line_ranges(lines)}")
        print(
            f"Changed-line branch coverage: {changed.percentage:.2f}% "
            f"({changed.covered}/{changed.measured}); required {CHANGED_LINE_FLOOR:.2f}%"
        )
        failed |= bool(changed.missing_files) or changed.percentage < CHANGED_LINE_FLOOR
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
