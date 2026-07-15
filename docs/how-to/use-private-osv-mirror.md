# Use a private OSV mirror

Use an internal OSV-compatible endpoint when package names, versions, or dependency inventory must not go to public OSV.

The `uv run --frozen` examples assume a Vexcalibur source checkout. Run them from its root after installing dependencies with `uv sync`. When using an installed release, run `vexcalibur` directly.

You need an endpoint that implements OSV `/v1/querybatch` and a runner that can reach it.

## Generate VEX through the mirror

Pass the mirror's base URL:

```bash
uv run --frozen vexcalibur generate \
  path/to/private-sbom.json \
  --osv-url https://osv.internal.example \
  --output /tmp/vexcalibur-vex.json
```

Do not add `--allow-public-osv`. That flag is consent to send inventory to `https://api.osv.dev`; it is not needed for a private endpoint.

The command should exit with status `0` and write CycloneDX 1.6 VEX JSON.

By default, generated findings identify this source as
`OSV-compatible mirror` and use the canonicalized endpoint URL. Vexcalibur does
not label mirror data as official OSV data.

## Publish a provenance alias

The default provenance exposes the mirror base URL in the VEX document. When
that URL is private, provide a public name and URL that identify the feed or
organization responsible for it:

```bash
uv run --frozen vexcalibur generate \
  path/to/private-sbom.json \
  --osv-url https://osv.internal.example/private \
  --osv-source-name "Example Security Feed" \
  --osv-source-url https://security.example.test/vulnerability-data \
  --output /tmp/vexcalibur-vex.json
```

The two alias options are a pair. The public URL must use HTTPS and cannot
contain credentials, a query, or a fragment. Choose an attributable page that
explains the feed. The alias changes only emitted provenance; requests still go
to `--osv-url`. Aliases apply only to custom endpoints. The canonical public
endpoint cannot be aliased, and a mirror cannot claim the reserved `OSV` name
or any HTTPS URL on the official `osv.dev` origin. Vexcalibur does not infer an
alias because doing so could make a private or modified feed look like a
different provider.

## Use a GitHub-hosted inventory

Keep the mirror selected when the SBOM comes from GitHub:

```bash
uv run --frozen vexcalibur generate \
  --github-repo internal/example \
  --github-api-url https://github.example.test/api/v3 \
  --github-token-env GH_ENTERPRISE_TOKEN \
  --osv-url https://osv.internal.example \
  --output /tmp/vexcalibur-vex.json
```

This command contacts GitHub for the SBOM and the private mirror for findings. It does not send the GitHub-derived inventory to public OSV.

## Query one package URL

Use the mirror with `query-osv`:

```bash
uv run --frozen vexcalibur query-osv \
  pkg:pypi/example@1.0.0 \
  --osv-url https://osv.internal.example
```

The command prints one line for the submitted package URL.

## Meet the URL rules

Use an absolute HTTPS URL with a hostname. Do not include credentials, a query string, or a fragment in the URL.

Vexcalibur accepts cleartext HTTP only for loopback hosts such as `localhost`, `127.0.0.1`, and `::1`. This exception supports local test servers; it is not for a remote mirror.

The CLI has no option for a bearer token or custom HTTP header, and credentials in `--osv-url` are rejected. A CLI-accessible mirror must accept requests through the runner's existing network or gateway authentication. Python callers that need application headers can inject a configured `httpx.Client` into `OsvClient`, then use that client through `OsvSource`; keep the source and client base URLs identical.

## Handle mirror failures

Vexcalibur disables redirects and streams raw success, error, and redirect
bodies through independent encoded and decoded byte limits. Gzip decompression
is bounded, and every transport chunk is checked against the total deadline. It
also rejects invalid JSON, non-object responses, mismatched batch results,
unsafe or oversized IDs, long and repeated pagination tokens, excessive page
counts, result amplification, and operations that exceed their total deadline.
Large inventories are sent in ordered batches of at most 1,000 queries. See the
[CLI reference](../reference/cli.md) for exact resource-limit defaults.

Treat any of these errors as a broken, hostile, or incompatible source
response. Vexcalibur fails the whole operation; it does not publish a partial
result.

Repair the mirror before publishing its result. If the service cannot be restored, use reviewed [local findings](../reference/local-findings.md) with `--offline` instead.
