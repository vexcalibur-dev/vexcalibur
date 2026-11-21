# Planning and design records

Vexcalibur uses Trellis to separate proposed designs, durable decisions, current
contracts, and evidence. These pages are for contributors deciding what to
change. For supported installation methods, start with
[Install Vexcalibur](../install.md).

GitHub issues track work and acceptance criteria. A design document compares
options; it doesn't replace the issue tracker or announce a shipped feature.
The [container distribution proposal](../design/2026-10-28-container-distribution.md)
is open for review. It does not provide an installable image.

## Document map

Internal architecture and requirements live together in `docs/architecture/`.
The user manual keeps its Diataxis paths. This separates contributor design
material from documentation for people using the CLI or Python API.

| Kind | Home | How it changes |
| --- | --- | --- |
| Internal requirements | [Quality attributes and internal requirements](../architecture/quality-attributes.md) | Maintain internal obligations here. Plans and agent guidance link to this page rather than keeping their own policy lists. |
| Living architecture | [Architecture overview](../architecture/overview.md), [release architecture](../architecture/self-release-evidence.md), and [internal evidence formats](../architecture/release-evidence.md) | Update these with the implementation. Put dated history in a decision record, evidence receipt, or commit message. |
| User documentation | [Compatibility policy](../reference/compatibility.md), [reference pages](../index.md), and [project status](../explanation/project-status.md) | Keep supported interfaces and user guarantees in the user manual. Link to them from internal docs instead of copying their detailed contracts. |
| Open design | [Design documents](../design/README.md) | Compare options while Draft or In review. Freeze the reasoning once Decided or Abandoned. |
| Architecture decision record (ADR) | [Decision records](../adrs/README.md) | One durable decision per record. Accepted, Rejected, and Superseded records retain their history. |
| Evidence receipt | [Planning evidence](evidence/README.md) | Add a dated receipt for a claim. Add a new receipt when results change; don't overwrite the old one. |
| Execution tracking | [GitHub issues](https://github.com/vexcalibur-dev/vexcalibur/issues) | Track tasks, dependencies, acceptance checks, and completion. Link the relevant design and ADR instead of duplicating their text. |

The root `release-evidence/` directory contains machine-consumed review inputs,
not documentation. Neither those inputs nor published release assets move into
this planning tree. Contributor procedures stay in
[`docs/contributing/`](../contributing/index.md); they link to architecture
and requirements rather than defining another set of design policies.

## Reading order and authority

Before changing behavior, read the internal requirements, relevant architecture
section and public reference contract, then any Accepted ADRs in scope. Open
designs explain proposals, not current behavior.

When documents disagree, use this order:

1. Accepted ADRs
2. Internal requirements, living architecture, and public reference contracts
3. Proposed ADRs and open design documents

Issues define the scope of work but don't override an Accepted ADR. Report a
conflict and name both documents rather than silently choosing an interpretation.
An ADR that changes a public contract needs the corresponding compatibility
review and reference update; this ordering is not permission to bypass them.

## Taking a proposal through review

Start an open choice in `docs/design/YYYY-MM-DD-short-title.md`. Use the date
the discussion starts. Include a summary, a Record table, the problem, goals
and non-goals, existing requirements, constraints, options, a comparison,
recommendation, open questions, and outcome. Include keeping the current
approach as an option. Every unresolved question needs a person or a check
that can answer it.

Use the Trellis statuses `Draft`, `In review`, `Decided`, and `Abandoned`.
Draft and In review documents can change during discussion. Decided and
Abandoned documents preserve the reasoning; later work starts a linked design.
Corrections to a frozen record are dated and leave the original reasoning
readable.

Once the maintainer accepts a durable decision, record it in an ADR and link
it from the design's Outcome section. Update the affected living pages when
the behavior ships. Merging a planning-only PR does not make its proposed
behavior available or accept every option it discusses.

Add each new page to its directory index and Sphinx toctree. Use Green Thumb
for prose and Scorched Earth for documentation review when the skills are
available. Run `make docs` from the prepared source checkout; the
[contribution guide](https://github.com/vexcalibur-dev/vexcalibur/blob/main/CONTRIBUTING.md)
covers setup and the other local checks.

## Settings and migration limits

`.trellis.yaml` maps living architecture and internal requirements to one
directory, alongside the design, ADR, and evidence directories. The previous
architecture and release-design pages have moved there; generated redirects
preserve their published HTML URLs, including the older pre-contributor URLs.
Repository links use the new paths. There are no second copies of the pages
at their former Markdown paths.

No ADR has been retrospectively marked Accepted. Requirement IDs remain unset;
before assigning them, agree on a scheme and map each obligation to its checks.
Keep assigned IDs stable and never reuse them. Consolidating the policy does
not claim that test-to-requirement traceability is complete.

No shared ADR home is configured. These records govern the CLI repository, not
organization-wide governance. Confirm the owning repository before recording
a decision that governs the Action or Orb as well. A link to a related issue
doesn't make this repository the owner of that decision.

The directory layout and lifecycle rules work without installing the Trellis
plugin. When it is available, `load-project-context` can map relevant sections
before a change and `check-doc-drift` can audit the records afterward. Its
mechanical checks don't replace the Sphinx build or review of the design.

```{toctree}
:hidden:
:maxdepth: 2

../design/README
../adrs/README
evidence/README
../architecture/README
```
