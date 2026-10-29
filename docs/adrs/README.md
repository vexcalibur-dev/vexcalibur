# Architecture decision records

This directory holds durable decisions that govern the Vexcalibur CLI
repository. No ADRs have been recorded here yet. The
[internal requirements](../architecture/quality-attributes.md) and
[public reference contracts](../index.md) still apply; introducing ADRs
doesn't reset those commitments.

Name a new record `YYYY-MM-DD-short-title.md`. Confirm its owner and include
the date, status, context, decision, alternatives, consequences, and links to
the relevant design and requirements. A Proposed record also needs a
`Revisit by` date or a `Revisit when` condition.

Use `Draft`, `Proposed`, `Accepted`, `Rejected`, or `Superseded` as the status.
Draft and Proposed records can be edited during review. Once Accepted,
Rejected, or Superseded, preserve the record and append dated corrections
rather than rewriting its reasoning. A changed decision needs a new ADR;
update the old record's status and `Superseded by` link.

Add each record here as a visible link and a Sphinx toctree entry. The
[planning guide](../planning/README.md) defines the reading order and the
relationship between ADRs, living pages, and issues.
