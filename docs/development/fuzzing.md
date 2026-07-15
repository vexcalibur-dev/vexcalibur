# Fuzz untrusted input boundaries

Vexcalibur combines deterministic Hypothesis properties with bounded Atheris
campaigns. Use the property tests while developing. Use Atheris when a parser,
source client, package-URL rule, or terminal-safety boundary changes.

Fuzzing finds counterexamples; it does not prove that a parser is safe. The
normal regression suite, input-size limits, interoperability tests, dependency
audit, and CodeQL remain separate controls.

## What the harness covers

Every target calls production parsing code. The shared oracle runs the same
input twice and compares a normalized outcome. Documented boundary exceptions
are rejections. Any other exception, assertion failure, timeout, or process
failure is a crash to investigate.

| Target | Production boundary | Additional invariant |
| --- | --- | --- |
| `json` | strict UTF-8 JSON decoder | Duplicate keys, excessive nesting, oversized integers, and non-finite numbers have typed failures. |
| `sbom` | CycloneDX JSON/XML loader | XML defenses and component-count, depth, reference, version, and package-URL rules remain fail-closed. |
| `github` | GitHub SPDX 2.3 response mapper | Malformed shapes, ambiguous package URLs, duplicate references, and conflicting versions have typed failures. |
| `local` | Local findings loader | Selectors, URLs, timestamps, enums, and component matching have typed failures. |
| `osv` | OSV response transport and query parsers | Identity, valid and malformed gzip, HTTP errors, pagination, evolving fields, and terminal-safe vulnerability IDs are covered without network access. |
| `identity` | CycloneDX component normalization | Equivalent generated JSON and XML produce the same component identity. |

Inputs are synthetic. The harness never calls GitHub, OSV, or another service.
Do not add private SBOMs, credentials, embargoed vulnerability data, or customer
identifiers to a corpus or crash artifact.

GitHub Actions logs and artifacts in a public repository are not a confidential
disclosure channel. Reproduce an embargoed or sensitive case only on a local or
approved private runner, then report it through the private route in
`SECURITY.md`.

## Run deterministic property tests

Install the normal locked development environment and run the required smoke
profile:

```bash
uv sync --frozen
make fuzz-smoke
```

The profile disables Hypothesis's example database, derives examples
deterministically, runs 50 examples for each target, caps an example at 64 KiB,
and applies a one-second deadline. Pull requests run this profile on CPython
3.14 in the `Parser fuzz smoke` job. The job has a five-minute wall-clock limit
and is part of the protected `CI result` check.

The ordinary Python 3.10–3.14 matrix excludes tests marked `fuzz`; this avoids
running the same deterministic campaign five times. `make check` includes the
smoke profile once.

## Run coverage-guided fuzzing

Atheris 3.1.0 is isolated in the non-default `fuzz` dependency group. Its
published wheels support CPython 3.12–3.14 on Linux x86-64. The scheduled job
uses CPython 3.14 on an x86-64 Ubuntu runner. Other platforms can run the
Hypothesis layer but cannot install the locked Atheris group.

Run every target locally:

```bash
make fuzz-coverage
```

Select one target while developing:

```bash
FUZZ_TARGET=osv FUZZ_MAX_TOTAL_TIME=60 make fuzz-coverage
```

Defaults are deliberately finite:

| Limit | Local default | Scheduled value |
| --- | ---: | ---: |
| Input length | 65,536 bytes | 65,536 bytes |
| One input | 5 seconds | 5 seconds |
| Resident memory | 2,048 MiB | 2,048 MiB |
| Campaign per target | 30 seconds | 120 seconds |
| Whole CI job | Not applicable | 20 minutes |

Lower the local input cap with `FUZZ_MAX_LEN`. The shared oracle always rejects
inputs above 65,536 bytes, so the runner rejects a larger value. Override the
other local integer limits with `FUZZ_TIMEOUT_SECONDS`, `FUZZ_RSS_LIMIT_MB`,
and `FUZZ_MAX_TOTAL_TIME`. The runner rejects zero, negative, or non-integer
values.

The weekly `Parser fuzzing` workflow has only `contents: read`. It installs and
audits the frozen fuzz dependency group, runs targets sequentially, and uploads
synthetic crash reproducers only after a failure. CI keeps generated corpus and
artifacts below its isolated runner-temporary directory. Local generated corpus
entries live in `.fuzz-corpus/`; local crash, timeout, leak, and out-of-memory
reproducers live below `fuzz-artifacts/`. Both local directories are ignored. Set
`FUZZ_CORPUS_ROOT` or `FUZZ_ARTIFACT_ROOT` to choose another local location.

## Maintain seeds and regressions

Repository maintainers own the initial classification of every scheduled-run
failure. Move a security-sensitive case to the private `SECURITY.md` route as
soon as that classification is plausible.

Keep a small seed for each distinct parser shape under
`tests/fuzz/corpus/<target>/`. A seed should reach useful production code, not
enumerate every invalid spelling. Keep it human-inspectable when possible and
well below the 64 KiB limit.

When a campaign finds a crash:

1. Download the artifact without opening or executing it.
2. Confirm that it contains only synthetic data.
3. Replay it against the exact failing commit and target. For example:

   ```bash
   FUZZ_TARGET=osv uv run --frozen --group fuzz python -m tests.fuzz.fuzz_boundaries \
     fuzz-artifacts/osv/crash-example -runs=1
   ```

4. Classify the result: security impact, correctness defect, resource-limit
   defect, harness defect, or expected typed rejection.
5. Minimize the input with Atheris or by hand.
6. Add the minimal case as an ordinary named regression test. Add it to the
   seed corpus only when it improves exploration.
7. Fix the production boundary without broadening the list of swallowed
   exceptions.

Report a security-sensitive crash through the private route in `SECURITY.md`.
Do not attach it to a public issue before the impact is understood.

## Know the limits

Atheris instruments Python execution. It does not provide native-code coverage
inside XML, compression, HTTP, or package-URL dependencies. The OSV target uses
an in-memory HTTP transport and deliberately covers response handling rather
than DNS, TLS, proxy, or socket behavior. The identity target generates valid,
bounded package identities; arbitrary package-URL spellings still enter through
the raw SBOM, GitHub, and local-findings targets.

The checked-in corpus is a starting point, not a coverage claim. Review target
scope whenever an input format, source provider, normalization rule, or output
presentation boundary changes.
