# Verify GitHub governance

GitHub repository and organization settings form part of Vexcalibur's release
security boundary. They are not stored in Git, so a normal code review cannot
show when one changes. The read-only governance checker compares those live
settings with the policy documented here.

## Run the live check

Authenticate the GitHub CLI as an organization owner or a repository
administrator who can read rulesets, security settings, environments, and
organization Actions policy. Then run:

```bash
gh auth status
make governance-check
```

The checker issues fixed `GET` requests through `gh api`. It never writes a
setting, creates a token, or prints the output of a failed authentication
request. It uses the credentials already available to `gh`; do not put a token
in this repository or in a command-line argument.

The exit status distinguishes the result:

| Status | Meaning |
| --- | --- |
| `0` | Every required endpoint was readable and the live controls matched. |
| `1` | Every required endpoint was readable and policy drift was found. |
| `2` | At least one required endpoint or snapshot was inaccessible or malformed. No policy result was produced. |

An authorization failure is not a passing or partial check. Reauthenticate with
the required read access and run the complete check again.

## Committed policy

The checker requires these default-branch controls:

| Repository | Strict GitHub Actions checks |
| --- | --- |
| `vexcalibur` | `CI result`, `Analyze Python`, `dependency-review`, `pre-commit` |
| `vexcalibur-action` | `CI result`, `Analyze (actions)`, `Analyze (python)` |
| `vexcalibur-orb` | `Quality`, `Analyze (actions)`, `Analyze (python)` |
| `.github` | `Validate workflow templates`, `Smoke Python security commands`, `Analyze (actions)` |

Every repository's default branch must remain `main`. Every check is bound to
the GitHub Actions App integration, not merely to a matching status name. Each
active ruleset applies to the default branch, requires a pull request, resolves
review threads, prevents deletion and non-fast-forward updates, and uses strict
required checks. The rulesets have no branch bypass actors. They allow zero
required approvals so a solo maintainer can merge a passing pull request
without fabricating an independent reviewer. Changing that tradeoff requires an
explicit policy review.

Core, Action, and Orb each have two active `refs/tags/v*` rulesets:

- a creation rule permits only the Vexcalibur release integration for core and
  Action. Orb uses the organization administrator as its explicit publishing
  path until its CircleCI publishing identity is configured.
- a separate update-and-deletion rule has no bypass, so an existing release tag
  is immutable even for the actor allowed to create it.

Organization policy enforces immutable GitHub Releases for every repository and
requires full commit-SHA pinning for GitHub Actions. Core's `pypi` environment
accepts deployments only from tags matching `v*` through a custom deployment
policy during normal operation. GitHub currently allows an administrator to
bypass that environment policy; the checker records that exception so it cannot
change silently.

The Orb repository also requires Dependabot vulnerability alerts and automated
security updates, secret scanning, push protection, automated security fixes,
and private vulnerability reporting. CodeQL default setup must run weekly with
the extended query suite and the `remote_and_local` threat model for Action,
Orb, and `.github`. Action and Orb scan Actions and Python; `.github` scans
Actions. Core uses its checked-in advanced CodeQL workflow instead of default
setup.

Each of the four repositories commits a `CODEOWNERS` file. [Core's
file](https://github.com/vexcalibur-dev/vexcalibur/blob/main/.github/CODEOWNERS)
records `@dannysauer` as the primary owner and repeats ownership for workflows,
release controls, dependency policy, and this drift check; the other files name
their equivalent release and consumer boundaries. The zero-approval
solo-maintainer ruleset means these are explicit ownership and review-routing
controls, not a claim of independent approval.

## Controls that still need external administration

The checker records the current safe baseline; it does not claim every desired
control is complete. Core and Action still use one long-lived automation App
key. GitHub rejects the built-in Actions integration as a tag-ruleset bypass
actor, so removing that key without a separately scoped App or credential broker
would weaken restricted `v*` tag creation. The checker confirms that the App is
unsuspended and has only contents-write plus metadata-read permission. It also
records the current, undesirably broad `all`-repositories installation selection;
narrowing that scope requires an intentional checker and documentation update.
The private-key lifecycle is not API-readable and remains tracked with the App
scope as a release-governance finding.

Future releases are immutable, but release notes and assets created before that
organization policy remain legacy-mutable; their tag refs are protected. The
`pypi` environment has no independent reviewer because the organization
currently has one maintainer, and its administrator-bypass setting remains
enabled. Orb publication still depends on the external CircleCI account,
namespace, context, and token setup described in its repository issue tracker.

## When to run it

Run the live check after changing repository, organization, environment,
security, or release settings. Also run it periodically and during release or
security reviews. The normal test suite validates the checker against the
committed offline fixture, but that fixture is not proof of the live state.

There is intentionally no scheduled workflow with a stored administrator
credential. A repository `GITHUB_TOKEN` cannot read every organization and
administrative endpoint covered here. Silently skipping those endpoints would
produce a misleading result, while storing a broad token would add a new
release-adjacent secret. Periodic execution therefore uses an authenticated
maintainer's local `gh` session and fails closed when access is insufficient.

Use the offline mode only to test or investigate a captured, reviewed fixture:

```bash
uv run --frozen python scripts/check_github_governance.py \
  --snapshot tests/fixtures/governance/expected.json
```

## Respond to drift

Do not edit the fixture merely to make a failure disappear.

1. Read every reported difference and confirm the live setting independently.
2. Restore an accidentally weakened setting before the next release.
3. For an intentional policy change, review the threat-model impact and update
   the checker, fixture, and this page together in a pull request.
4. Run the live checker again with sufficient access and retain the successful
   command result in the associated issue or pull request.

The checker is deliberately diagnostic. It has no repair mode and cannot
mutate GitHub configuration.
