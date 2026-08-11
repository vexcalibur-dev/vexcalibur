# Install Vexcalibur

Install a release when you want to run `vexcalibur` as a command. The how-to
guides assume this install and call `vexcalibur` directly.

Vexcalibur is pre-1.0. Pin an exact version, because command flags, Python
APIs, and output detail can change between releases.

## Choose a version

Open the [release page](https://github.com/vexcalibur-dev/vexcalibur/releases)
and pick an exact `MAJOR.MINOR.PATCH` version. The commands below prompt for
that version so an unresolved placeholder can't reach `pip`.

## Install into a virtual environment

Run this from a directory you control:

```bash
set -euo pipefail

read -r -p "Vexcalibur version from the release page: " VEXCALIBUR_VERSION
if [[ ! "$VEXCALIBUR_VERSION" =~ ^(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})$ ]]; then
  printf 'Enter a MAJOR.MINOR.PATCH release version\n' >&2
  exit 2
fi
VEXCALIBUR_VENV=".venv-vexcalibur-${VEXCALIBUR_VERSION}"
if [[ -e "$VEXCALIBUR_VENV" ]]; then
  printf 'Refusing to reuse %s\n' "$VEXCALIBUR_VENV" >&2
  exit 2
fi
python -m venv "$VEXCALIBUR_VENV"
"$VEXCALIBUR_VENV/bin/python" -m pip install \
  "vexcalibur==${VEXCALIBUR_VERSION}"
INSTALLED_VERSION="$("$VEXCALIBUR_VENV/bin/python" -c \
  'from importlib.metadata import version; print(version("vexcalibur"))')"
test "$INSTALLED_VERSION" = "$VEXCALIBUR_VERSION"
"$VEXCALIBUR_VENV/bin/vexcalibur" --help
```

In PowerShell 7.3 or newer, use:

```powershell
$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true
$VEXCALIBUR_VERSION = Read-Host "Vexcalibur version from the release page"
if ($VEXCALIBUR_VERSION -notmatch '^(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})$') {
    throw "Enter a MAJOR.MINOR.PATCH release version"
}
$VEXCALIBUR_VENV = ".venv-vexcalibur-$VEXCALIBUR_VERSION"
if (Test-Path -LiteralPath $VEXCALIBUR_VENV) {
    throw "Refusing to reuse $VEXCALIBUR_VENV"
}
py -m venv $VEXCALIBUR_VENV
$PYTHON = Join-Path $VEXCALIBUR_VENV "Scripts/python.exe"
$VEXCALIBUR = Join-Path $VEXCALIBUR_VENV "Scripts/vexcalibur.exe"
& $PYTHON -m pip install "vexcalibur==$VEXCALIBUR_VERSION"
$INSTALLED_VERSION = & $PYTHON -c `
    'from importlib.metadata import version; print(version("vexcalibur"))'
if ($INSTALLED_VERSION -ne $VEXCALIBUR_VERSION) {
    throw "Installed $INSTALLED_VERSION instead of $VEXCALIBUR_VERSION"
}
& $VEXCALIBUR --help
```

The final command prints the `query-osv` and `generate` help. That's the
success signal.

The install needs Python 3.10 through 3.14, the range the project tests, and
it reaches your configured package index. Package metadata alone permits any
3.x, so `pip` won't stop you on a newer interpreter; nothing verifies that
combination.

Once installed, the generation examples in the how-to guides read and write
local files only. The source path below and the guides built on it are
different — they run `uv sync --frozen`, which does reach your index.

## Put the command on your PATH

The guides write `vexcalibur` with no path prefix. Either activate the
environment for your shell session:

```bash
source .venv-vexcalibur-0.7.0/bin/activate
```

Or call the binary by its full path, which keeps the pinned version explicit:

```bash
.venv-vexcalibur-0.7.0/bin/vexcalibur --help
```

In PowerShell, the virtual environment puts both under `Scripts` instead:

```powershell
.venv-vexcalibur-0.7.0\Scripts\Activate.ps1
.venv-vexcalibur-0.7.0\Scripts\vexcalibur.exe --help
```

Substitute the version you installed for `0.7.0`. The install script prompts
for that version rather than exporting it, so it won't be set in your shell.

Activating changes only the current shell. A CI job that starts a fresh shell
per step should use the full path.

## Check that your release has the feature you need

Output formats arrived in different releases, so confirm before you write
automation against one:

```bash
vexcalibur generate --help
```

The `--format` choices list what this release can write. Formats and options
arrived in these releases:

| Feature | First release |
| --- | --- |
| CycloneDX 1.6 output | `v0.1.0` |
| OpenVEX 0.2.0 output | `v0.2.0` |
| CSAF 2.0 output | `v0.3.0` |
| `--execution-report` | `v0.6.0` |
| SPDX 3.0.1 output | `v0.7.0` |

If the format you need is missing, install a newer release rather than working
around it.

## Install from source instead

Install from a checkout in three cases: you need unreleased work, you're
changing Vexcalibur itself, or a guide's validation step reads the
repository's schemas. Run:

```bash
git clone https://github.com/vexcalibur-dev/vexcalibur.git
cd vexcalibur
uv sync --frozen
uv run --frozen vexcalibur --help
```

This path needs `uv` at the version recorded in `.tool-versions`. Commands then
run as `uv run --frozen vexcalibur` from the repository root.

Use the guide from the checkout you're running, not the hosted documentation,
because the hosted site tracks current development.

## Next

- Generate your first document with the [quickstart](../tutorials/quickstart.md).
- Write CycloneDX, OpenVEX, CSAF, or SPDX 3 with the
  [generation guides](generate-cyclonedx-vex.md).
- Read the [CLI reference](../reference/cli.md) for flags, limits, and exit
  behavior.
