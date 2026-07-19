# Issue Tracker: GitHub

Mizan uses GitHub Issues natively.

## Repository

- Owner/name: `AmaraNecib/mizan`
- Default integration branch: `develop`

## Issue relationships

Wayfinder produces map tickets (`wayfinder:map` label) broken down into
grilling tickets (`wayfinder:grilling` label). These are tracked as:

- **Map → child tickets**: child tickets list the parent map ticket in their
  body with `Parent: #<num>`. GitHub does not natively support issue
  dependencies on the free plan; this body-link convention is the fallback.
- **Blocking relationships**: child tickets list genuine blocking tickets
  explicitly with `Blocked by #<num>` in the body. This is convention-only;
  no native GitHub dependency graph is enforced.
- **PR → issue**: PRs reference issues with `Refs #<num>` (targeting `develop`)
  or `Closes #<num>` (targeting `main` on release).

## Review evidence

Review outputs from debate, test-audit, and code-review are saved locally at:

```text
.scratch/reviews/<issue-id>/<head-sha>-{debate,test-audit,code-review}.md
```

After the PR is opened, a concise summary is posted as a PR comment. The
local files are provenance, not remote links.

## Labels

See `docs/agents/triage-labels.md` for the full vocabulary.

## Required status checks

Branch protection currently has no required checks configured. The CI job is
named `Verify (typecheck + test + build)`. If required checks are added later,
they must use the exact GitHub status context name matching this job.
