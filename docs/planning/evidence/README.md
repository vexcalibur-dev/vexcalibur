# Planning evidence

Keep dated receipts here when a design depends on a measurement, experiment,
or reviewed test result. No receipts have been recorded here yet. A proposed
test matrix belongs in its design document, not in a receipt that implies
the tests have passed.

Name a receipt `YYYY-MM-DD-short-title.md`. Record the claim, tested commit
and artifact digests, environment, commands or workflow run, result, and
limits of the observation. Link the design or issue the result informs.
Evidence is append-only: add a new receipt for a changed result and retain
the earlier one.

Don't commit credentials, private inventories, or raw logs containing them.
Prefer a short sanitized result with links to retained artifacts. A CI link
alone is not durable evidence if its artifacts will expire.

Release evidence remains a separate, machine-checked publication contract.
Read the [release-evidence reference](../../architecture/release-evidence.md)
for its assets and verification rules. Planning receipts don't replace those
checks or certify the contents of a future container image.
