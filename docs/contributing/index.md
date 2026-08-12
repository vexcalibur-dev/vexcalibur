# Contributing to Vexcalibur

These pages describe how this repository is tested, released, and governed.
They're for people changing Vexcalibur itself. If you only want to generate VEX
documents, the [user guides](../index.md) cover that and you can skip all of
this.

Start with the root [contribution guide](https://github.com/vexcalibur-dev/vexcalibur/blob/main/CONTRIBUTING.md)
for branch, review, and local-gate expectations. The pages here go deeper on
one area each.

## Working on the code

- [Python style policy](python-style.md) — the enforceable rules, and where
  they diverge from the vendored Google guide
- [Fuzz untrusted input boundaries](fuzzing.md) — when a parser, source client,
  or terminal-safety boundary changes
- [Vendored external documents](../external/README.md) — what's copied in from
  upstream, and how it's kept in sync

## Releasing

Read these in order. The first explains why the release process looks the way
it does, and the rest are runbooks.

- [Why Vexcalibur publishes evidence about itself](self-release-evidence.md)
- [Build and review local release evidence](build-release-evidence.md)
- [Publish Vexcalibur to GitHub and PyPI](publish-to-pypi.md)
- [Release-evidence reference](release-evidence.md) — the evidence file
  formats, which are maintained by this repository and are not part of the
  package's Python API

## Automation and governance

- [CI, release, and recurring automation](ci.md)
- [Verify GitHub governance](github-governance.md)

```{toctree}
:hidden:
:maxdepth: 1

python-style
fuzzing
../external/README
self-release-evidence
build-release-evidence
publish-to-pypi
release-evidence
ci
github-governance
```
