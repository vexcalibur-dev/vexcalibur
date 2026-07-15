# Command-line interface

The package installs two executables:

| Command | Purpose |
| --- | --- |
| `vexcalibur` | Primary interface |
| `vexy` | Compatibility interface for a limited set of legacy invocations |

These commands are pre-1.0. Flags, defaults, messages, and exit behavior may change between releases.

Run `vexcalibur --help` or `vexcalibur COMMAND --help` for help generated from the installed version. Expected input and source errors are printed without a Python traceback. Automation should treat every nonzero status as failure.

## `vexcalibur query-osv`

Queries an OSV-compatible service for one or more package URLs.

```text
vexcalibur query-osv [OPTIONS] PURL...
```

### Arguments

| Argument | Required | Description |
| --- | --- | --- |
| `PURL...` | Yes | One or more values accepted by `packageurl-python`. Include a version for a version-specific query. |

An invalid package URL is rejected before a request is sent.

### Options

| Option | Default | Description |
| --- | --- | --- |
| `--osv-url TEXT` | `https://api.osv.dev` | OSV API base URL. Set this for a private mirror. |
| `--allow-public-osv` | Off | Consent to send package URLs to public OSV. |
| `--help` | — | Print help and exit. |

The public default fails unless `--allow-public-osv` is present. A private endpoint does not require that flag.

An OSV URL must use HTTPS and include a hostname. HTTP is accepted only for a loopback host such as `localhost`, `127.0.0.1`, or `::1`. User information, query strings, and fragments are rejected. The endpoint must implement `/v1/querybatch`.

Success produces one line per input:

```text
pkg:pypi/django@1.2: VULN-ID-1, VULN-ID-2
pkg:pypi/example@1.0.0: no vulnerabilities found
```

Live IDs and ordering may change.

### Exit behavior

| Condition | Status | Error prefix or output |
| --- | --- | --- |
| All queries succeed | `0` | One standard-output line per PURL |
| Missing argument or invalid PURL | Nonzero Typer usage error | Typer usage or parameter message |
| Public OSV without consent | `1` | `OSV query failed:` |
| Invalid URL, HTTP failure, bad response, or pagination failure | `1` | `OSV query failed:` |

## `vexcalibur generate`

Generates CycloneDX 1.6, OpenVEX 0.2.0, or CSAF 2.0 VEX JSON.

```text
vexcalibur generate [OPTIONS] [INPUT_FILE]
```

### Inventory input

Provide exactly one inventory source:

| Input | Description |
| --- | --- |
| `INPUT_FILE` | Readable CycloneDX JSON or XML file |
| `--github-repo OWNER/REPO` | GitHub Dependency Graph SBOM |

Local input accepts CycloneDX 1.4, 1.5, and 1.6. JSON must be UTF-8. XML must have a CycloneDX `bom` root in the matching namespace. Parser-detected encodings such as UTF-16 are accepted.

XML input rejects DTD, entity, and external-reference declarations.

Local files and GitHub report downloads are limited to 10 MiB. A document may contain at most 10,000 components and 50 component nesting levels. Parsed components with package URLs must have unique references.

GitHub input requests an asynchronous SPDX 2.3 JSON report and extracts package URL references. The repository package itself and packages without package URLs are omitted.

### Finding source

Choose one source mode:

| Mode | Options | Network behavior |
| --- | --- | --- |
| Local findings | `--findings-file PATH`; normally paired with `--offline` | Does not construct an OSV client |
| Private OSV | `--osv-url URL` | Sends inventory to that endpoint |
| Public OSV | `--allow-public-osv` | Sends inventory to `https://api.osv.dev` |

`--offline` currently requires `--findings-file`. A findings file cannot be combined with `--osv-url` or `--allow-public-osv`.

OSV generation needs at least one versioned component with a package URL. A version may come from the PURL, CycloneDX `version`, or GitHub SPDX `versionInfo`. The command fails instead of treating an empty query set as authoritative.

An explicit empty local findings array is valid for CycloneDX output. OpenVEX
and CSAF reject it because their standalone VEX documents need at least one
statement or vulnerability assertion.

### Options

| Option | Default | Description |
| --- | --- | --- |
| `--output PATH`, `-o PATH` | Standard output | Write VEX JSON to a file. |
| `--timestamp TEXT` | Current UTC time | ISO-8601 document timestamp. |
| `--format cyclonedx\|openvex\|csaf` | `cyclonedx` | Select the output format. |
| `--author TEXT` | — | OpenVEX document author; required for OpenVEX. |
| `--author-role TEXT` | — | Optional OpenVEX document author role. |
| `--csaf-version TEXT` | `2.0` | CSAF version; only `2.0` is accepted. |
| `--csaf-document-id TEXT` | — | CSAF tracking ID; required for CSAF. |
| `--csaf-document-title TEXT` | — | CSAF document title; required for CSAF. |
| `--csaf-publisher-name TEXT` | — | CSAF publisher name; required for CSAF. |
| `--csaf-publisher-namespace TEXT` | — | Normalized absolute HTTP(S) publisher URL; required for CSAF. |
| `--csaf-publisher-category TEXT` | — | CSAF publisher category; required for CSAF. |
| `--csaf-document-status TEXT` | `draft` | CSAF status: `draft`, `final`, or `interim`. |
| `--findings-file PATH` | — | Local findings JSON. |
| `--offline` | Off | Disable network finding sources; requires local findings. |
| `--osv-url TEXT` | Public OSV when no local findings are selected | OSV-compatible base URL. |
| `--allow-public-osv` | Off | Consent to send the inventory to public OSV. |
| `--github-repo OWNER/REPO` | — | Fetch a GitHub Dependency Graph SBOM instead of reading `INPUT_FILE`. |
| `--github-api-url TEXT` | `https://api.github.com` | GitHub REST API base URL. |
| `--github-token-env NAME` | — | Read the GitHub token from this environment variable. |
| `--gh-auth`, `--no-gh-auth` | Enabled | Enable or disable fallback to `gh auth token`. |
| `--help` | — | Print help and exit. |

The GitHub API URL must use HTTPS and must not contain user information, a query string, or a fragment. For GitHub Enterprise, pass its API base path, such as `https://github.example.test/api/v3`.

When `--github-token-env` is absent, token lookup checks `GH_TOKEN` and `GITHUB_TOKEN` for `api.github.com`. It then tries `gh auth token --hostname HOST` if fallback is enabled.

Public repositories may work anonymously. Token-backed requests need repository `Contents: read` permission.

`--github-repo` cannot be combined with `--offline` because fetching the SBOM uses the network. Public OSV consent remains separate.

`--author` and `--author-role` are valid only with `--format openvex`.

The `--csaf-*` options are valid only with `--format csaf`. CSAF requires the
document ID, title, publisher name, publisher namespace, and publisher
category. The namespace must be an absolute normalized HTTP(S) URL controlled
by the publisher. Use ASCII RFC 3986 syntax, with IDNA for internationalized
hosts and percent encoding for non-ASCII path characters. Publisher category
accepts `coordinator`, `discoverer`, `other`, `user`, or `vendor`; `translator`
is not supported. Document IDs cannot contain line terminators.

Format metadata is checked before Vexcalibur fetches a GitHub SBOM or queries
OSV.

### Output

Without `--output`, JSON goes to standard output. With it, the command writes the file and prints no success message.

`--output` overwrites an existing file without prompting. Its parent directory
must already exist, and there is no `--force` or atomic-write option. The
`vexy` compatibility command differs: it refuses an existing file unless
`--force` is present.

CSAF file output also enforces the standard basename derived from the document
ID. Lowercase the ID, replace each run matching `[^+\-a-z0-9]+` with one
underscore, and append `.json`. For example, `ACME VEX:2026/001` requires
`acme_vex_2026_001.json`. The rule does not apply to standard output.

OSV-derived entries use analysis state `in_triage`. Local findings may set any supported domain state.

CycloneDX output preserves those state names. OpenVEX maps them to its
four-status model and requires state-specific evidence. CSAF maps them to
product-status lists and requires product-scoped remediation or impact
evidence where the VEX profile calls for it. OpenVEX rejects nonidentical
assertions for one vulnerability and product. CSAF can group same-status
provenance and evidence, but rejects contradictory effective statuses for that
pair. Read the
[CycloneDX](cyclonedx-vex-output.md), [OpenVEX](openvex-output.md), or
[CSAF](csaf-output.md) output reference for the exact contract.

### Exit behavior

| Condition | Status | Error prefix |
| --- | --- | --- |
| Generation succeeds | `0` | JSON on standard output or in `--output` |
| Bad timestamp | Nonzero Typer parameter error | Typer parameter message |
| Missing or conflicting input/source options | `1` | `Invalid generate options:` |
| Invalid local SBOM or unqueryable inventory | `1` | `SBOM ingest failed:` |
| GitHub configuration, request, or SPDX failure | `1` | `GitHub SBOM ingest failed:` |
| Invalid local findings | `1` | `Local findings ingest failed:` |
| Public OSV without consent or invalid OSV URL | `1` | `VEX generation failed:` |
| OSV request or response failure | `1` | `OSV query failed:` |
| Findings cannot form the selected VEX format | `1` | `VEX generation failed:` |
| Output write failure | `1` | `Could not write VEX output` |

### Network limits

The CLI uses these fixed client defaults:

| Service | Request timeout | Polling or pagination | Automatic retry |
| --- | --- | --- | --- |
| OSV-compatible API | 30 seconds per request | At most 100 pagination rounds | None |
| GitHub SBOM API and report download | 30 seconds per request | At most 30 report polls; one-second default delay; numeric `Retry-After` capped at 10 seconds | Report polling only; request failures are not retried |

Library callers may configure these limits through the client constructors.

## Shell completion

Both executables provide Typer's completion options:

| Option | Behavior |
| --- | --- |
| `--install-completion` | Install completion for the current shell. |
| `--show-completion` | Print the completion script for review or customization. |

Use the option on the executable itself, for example `vexcalibur --show-completion`.

## `vexy`

The compatibility executable maps selected legacy-style flags to the current generator. It writes CycloneDX 1.6 JSON only.

```text
vexy [OPTIONS]
```

It does not restore Sonatype OSS Index behavior, CycloneDX XML VEX output, or CycloneDX 1.4 VEX output.

### Compatibility options

| Option | Default | Behavior |
| --- | --- | --- |
| `-c PATH`, `--config PATH` | — | Accepted but not read. Legacy credentials and sources are ignored. |
| `-i PATH`, `--in-file PATH` | Required | CycloneDX JSON or XML path. Standard input (`-`) is rejected. |
| `--format TEXT` | `json` | Only `json` is accepted. |
| `--schema-version TEXT` | `1.6` | Only `1.6` is accepted. |
| `-o PATH`, `--o PATH`, `--output PATH` | `cyclonedx-vex.json` | Output path. Use `-` for standard output. |
| `--force` | Off | Replace an existing output file. |
| `-q` | Off | Accepted; there is no progress output to suppress. |
| `-X` | Off | Print compatibility diagnostics to standard error. |
| `--timestamp TEXT` | Current UTC time | ISO-8601 document timestamp. |

The current Vexcalibur source options are also accepted: `--findings-file`, `--offline`, `--osv-url`, and `--allow-public-osv`. The same trust boundary and option conflicts apply as for `vexcalibur generate`.

### Offline migration example

<!-- vexy-compat-offline-example:start -->
```bash
uv run --frozen vexy \
  -c tests/fixtures/vexy/legacy-config.yml \
  -i tests/fixtures/sbom/cyclonedx-xml-1.5-simple.xml \
  --format json \
  --schema-version 1.6 \
  --output - \
  --offline \
  --findings-file tests/fixtures/findings/all-analysis-states.json \
  --timestamp 2026-06-23T00:00:00Z
```
<!-- vexy-compat-offline-example:end -->

Success writes CycloneDX 1.6 JSON to standard output.

### Exit behavior

| Condition | Status | Error prefix or output |
| --- | --- | --- |
| Generation succeeds | `0` | JSON on standard output or in the selected file |
| Missing input, standard-input request, unsupported format/schema, existing output, or bad timestamp | `1` | `vexy compatibility failed:` |
| Conflicting source options | `1` | `vexy compatibility failed:` |
| Invalid SBOM | `1` | `SBOM ingest failed:` |
| Invalid local findings | `1` | `Local findings ingest failed:` |
| Public OSV without consent or invalid OSV URL | `1` | `VEX generation failed:` |
| OSV request or response failure | `1` | `OSV query failed:` |
