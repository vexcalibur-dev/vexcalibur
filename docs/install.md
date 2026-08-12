# Install Vexcalibur

Install a release when you want to run `vexcalibur` as a command. The how-to
guides assume this install and call `vexcalibur` directly.

Vexcalibur needs Python 3.10 through 3.14, the range the project tests. Package
metadata alone permits any 3.x, so `pip` will happily build you an untested
environment on a newer interpreter. Check before you start:

```bash
python3 -V
```

On Windows, use the launcher instead. A normal Python installation puts `py` on
your PATH and may not provide `python3` at all:

```powershell
py -V
```

## Install with pip

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install vexcalibur
vexcalibur --help
```

In PowerShell, the virtual environment puts its commands under `Scripts`:

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
pip install vexcalibur
vexcalibur --help
```

The help output lists the `query-osv` and `generate` commands. That's the
success signal.

Activating changes only the current shell. A CI job that starts a fresh shell
per step should skip the activate step and call `.venv/bin/vexcalibur` by its
full path instead.

## Install with uv

`uv tool install` creates and manages the environment for you, so there is
nothing to activate:

```bash
uv tool install vexcalibur
vexcalibur --help
```

This installs two commands, `vexcalibur` and `vexy`. If your shell can't find
them afterward, run `uv tool update-shell` and open a new shell.

## Pin a version

The commands above install the latest release. Vexcalibur is pre-1.0, so
command flags, Python APIs, and output detail can change between releases. Pin
an exact version in anything you automate.

A pin is a version specifier on the install command:

```bash
pip install vexcalibur==0.1.0
```

`0.1.0` is the first release, shown here for the form rather than as a
recommendation. The [release
page](https://github.com/vexcalibur-dev/vexcalibur/releases) lists what you can
pin to, and the table below says which release first shipped each output
format.

To pin whatever is current, install it and record what you got:

```bash
pip install --upgrade vexcalibur
pip freeze | grep '^vexcalibur=='
```

In PowerShell, `grep` isn't available, so filter with `Select-String`:

```powershell
pip install --upgrade vexcalibur
pip freeze | Select-String '^vexcalibur=='
```

`--upgrade` matters here. Without it, `pip` treats any already-installed
Vexcalibur as satisfying the unbounded requirement and leaves it alone, so you
would record whatever was there rather than the current release.

Either one prints a single `vexcalibur==` line carrying the version you just
installed. Put it in your requirements file or lockfile.

A version pin selects a release, not a particular file. PyPI does not let a
published file be replaced with different content, but a release contains both
a wheel and a source distribution, and which one `pip` takes depends on the
environment and the install options. When you need the same bytes every time,
record hashes or use a lockfile that stores them.

## What a command reaches

Installing reaches your configured package index. After that, what Vexcalibur
contacts depends on the options you pass, not on how you installed it:

| Options | Network |
| --- | --- |
| `--offline` with `--findings-file` | Local files only |
| `--osv-url URL` | The mirror you name |
| `--allow-public-osv` | `https://api.osv.dev` |
| `--github-repo OWNER/REPO` | The GitHub API |

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
changing Vexcalibur itself, or a guide's validation step reads the repository's
schemas. This path needs `uv` at the version recorded in `.tool-versions`, and
`uv sync` reaches your package index.

```bash
git clone https://github.com/vexcalibur-dev/vexcalibur.git
cd vexcalibur
uv sync --frozen
uv run --frozen vexcalibur --help
```

Commands then run as `uv run --frozen vexcalibur` from the repository root. Use
the guides from the checkout you're running rather than the hosted
documentation, because the hosted site tracks current development.

## Next

- Generate your first document with the [quickstart](tutorials/quickstart.md).
- Write CycloneDX, OpenVEX, CSAF, or SPDX 3 with the
  [generation guides](how-to/generate-cyclonedx-vex.md).
- Read the [CLI reference](reference/cli.md) for flags, limits, and exit
  behavior.
