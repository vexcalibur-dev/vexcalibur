# Reviewed release-evidence inputs

This directory contains the public, human-reviewed inputs for Vexcalibur's own
release evidence. `review.json` binds the review to the exact SHA-256 digest of
`uv.lock` and `findings.json`. The initial findings snapshot is empty. That
means it makes no VEX assertions; it does not claim that the locked inventory
has no vulnerabilities.

`reviewed_by` is a public claimed attribution. Its provenance comes from the
repository's commit and review history; the JSON field does not independently
authenticate a reviewer.

Only explicit `in_triage` findings are accepted by the production generator.
Do not add private reports, embargoed advisory data, credentials, or customer
identifiers here.

Maintainers should follow [Build and review local release
evidence](../docs/how-to/build-release-evidence.md) before changing either JSON
file. The [release-evidence reference](../docs/reference/release-evidence.md)
defines both local and immutable-publication bundles and their omission rules.
