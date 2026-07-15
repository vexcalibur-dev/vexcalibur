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

Vexcalibur rejects invalid JSON, non-object responses, mismatched batch results, repeated pagination tokens, and excessive page counts. Treat these errors as a broken or incompatible source response.

Repair the mirror before publishing its result. If the service cannot be restored, use reviewed [local findings](../reference/local-findings.md) with `--offline` instead.
