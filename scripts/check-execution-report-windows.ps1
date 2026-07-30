[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$DistributionDirectory,
  [string]$ExpectedPython = "",
  [string]$ExpectedVersion = "",
  [string]$ExpectedWheelSha256 = "",
  [string]$ExpectedSdistSha256 = ""
)

$ErrorActionPreference = "Stop"
if ($PSVersionTable.PSVersion -lt [Version]"7.3") {
  throw "PowerShell 7.3 or newer is required"
}
$PSNativeCommandUseErrorActionPreference = $true

$resolvedDistributionDirectory = (
  Resolve-Path -LiteralPath $DistributionDirectory
).Path
$temporaryRoot = if ([string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) {
  [System.IO.Path]::GetTempPath()
} else {
  $env:RUNNER_TEMP
}
$work = Join-Path `
  $temporaryRoot `
  "vexcalibur-windows-contract-$([Guid]::NewGuid().ToString())"
$previousExpectedPython = $env:VEXCALIBUR_EXPECTED_PYTHON
$previousExpectedVersion = $env:VEXCALIBUR_EXPECTED_VERSION

function Assert-DistributionDigest {
  param(
    [Parameter(Mandatory = $true)]
    [System.IO.FileInfo]$File,
    [Parameter(Mandatory = $true)]
    [string]$Expected,
    [Parameter(Mandatory = $true)]
    [string]$Role
  )

  if ([string]::IsNullOrWhiteSpace($Expected)) {
    return
  }
  if ($Expected -cnotmatch "^[0-9a-f]{64}$") {
    throw "Expected $Role digest is not a lowercase SHA-256"
  }
  $actual = (
    Get-FileHash -Algorithm SHA256 -LiteralPath $File.FullName
  ).Hash.ToLowerInvariant()
  if ($actual -cne $Expected) {
    throw "$Role digest did not match the canonical build"
  }
}

try {
  New-Item -ItemType Directory -Path $work | Out-Null
  uv run --frozen pytest -q `
    tests/test_execution_report_destination.py::test_native_windows_report_request_fails_closed `
    tests/test_cli_execution_report.py::test_native_windows_cli_fails_closed_for_report_and_keeps_normal_output `
    tests/test_documented_ci.py::test_execution_report_schema_checkout_bytes_are_pinned_to_lf `
    tests/test_execution_report_consumer_example.py::test_consumer_example_accepts_a_matching_report `
    tests/test_execution_report_consumer_example.py::test_consumer_example_reports_validation_failure_without_a_traceback

  $wheels = @(
    Get-ChildItem -LiteralPath $resolvedDistributionDirectory -Filter *.whl
  )
  $sdists = @(
    Get-ChildItem -LiteralPath $resolvedDistributionDirectory -Filter *.tar.gz
  )
  if ($wheels.Count -ne 1) {
    throw "Expected exactly one wheel, found $($wheels.Count)"
  }
  if ($sdists.Count -ne 1) {
    throw "Expected exactly one sdist, found $($sdists.Count)"
  }
  Assert-DistributionDigest `
    -File $wheels[0] `
    -Expected $ExpectedWheelSha256 `
    -Role "wheel"
  Assert-DistributionDigest `
    -File $sdists[0] `
    -Expected $ExpectedSdistSha256 `
    -Role "sdist"

  if ([string]::IsNullOrWhiteSpace($ExpectedVersion)) {
    $ExpectedVersion = (
      uv run --frozen python -I -c `
        "import importlib.metadata; print(importlib.metadata.version('vexcalibur'))"
    )
  }
  if ([string]::IsNullOrWhiteSpace($ExpectedPython)) {
    $ExpectedPython = (
      python -I -c `
        "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
    )
  }

  $buildRequirements = Join-Path $work "sdist-build-requirements.txt"
  $buildVenv = Join-Path $work "sdist-build-venv"
  uv export `
    --quiet `
    --frozen `
    --only-group sdist-build `
    --no-emit-project `
    --no-annotate `
    --output-file $buildRequirements
  uv venv $buildVenv
  $buildPython = Join-Path $buildVenv "Scripts/python.exe"
  uv pip sync `
    --require-hashes `
    --only-binary :all: `
    --python $buildPython `
    $buildRequirements

  $distributions = @(
    @{ Name = "wheel"; Path = $wheels[0].FullName },
    @{ Name = "sdist"; Path = $sdists[0].FullName }
  )
  foreach ($distribution in $distributions) {
    $installDistribution = $distribution.Path
    if ($distribution.Name -eq "sdist") {
      $wheelDir = Join-Path $work "sdist-wheel"
      New-Item -ItemType Directory -Path $wheelDir | Out-Null
      $previousVirtualEnv = $env:VIRTUAL_ENV
      try {
        $env:VIRTUAL_ENV = $buildVenv
        uv build `
          --wheel `
          --no-build-isolation `
          --offline `
          --python $buildPython `
          --out-dir $wheelDir `
          $distribution.Path
      } finally {
        if ($null -eq $previousVirtualEnv) {
          Remove-Item Env:VIRTUAL_ENV -ErrorAction SilentlyContinue
        } else {
          $env:VIRTUAL_ENV = $previousVirtualEnv
        }
      }
      $builtWheels = @(Get-ChildItem -LiteralPath $wheelDir -Filter *.whl)
      if ($builtWheels.Count -ne 1) {
        throw "Expected one wheel built from the sdist, found $($builtWheels.Count)"
      }
      $installDistribution = $builtWheels[0].FullName
    }

    $venv = Join-Path $work "installed-$($distribution.Name)"
    $requirements = Join-Path $work "runtime-$($distribution.Name).txt"
    $constraints = Join-Path $work "runtime-$($distribution.Name).constraints.txt"
    uv export `
      --quiet `
      --frozen `
      --no-dev `
      --no-emit-project `
      --no-annotate `
      --output-file $constraints
    [System.IO.File]::WriteAllText(
      $requirements,
      "",
      [System.Text.UTF8Encoding]::new($false)
    )
    uv run --frozen python scripts/append_locked_distribution_requirement.py `
      $installDistribution `
      $requirements
    uv venv $venv
    $python = Join-Path $venv "Scripts/python.exe"
    uv pip install `
      --require-hashes `
      --only-binary :all: `
      --constraint $constraints `
      --python $python `
      --requirements $requirements
    $env:VEXCALIBUR_EXPECTED_PYTHON = $ExpectedPython
    $env:VEXCALIBUR_EXPECTED_VERSION = $ExpectedVersion
    & $python tests/integration/check_installed_windows.py
  }
} finally {
  if ($null -eq $previousExpectedPython) {
    Remove-Item Env:VEXCALIBUR_EXPECTED_PYTHON -ErrorAction SilentlyContinue
  } else {
    $env:VEXCALIBUR_EXPECTED_PYTHON = $previousExpectedPython
  }
  if ($null -eq $previousExpectedVersion) {
    Remove-Item Env:VEXCALIBUR_EXPECTED_VERSION -ErrorAction SilentlyContinue
  } else {
    $env:VEXCALIBUR_EXPECTED_VERSION = $previousExpectedVersion
  }
  Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
