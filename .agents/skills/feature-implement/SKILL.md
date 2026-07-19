---
name: feature-implement
description: "Orchestrate implementation from issue to merge-ready PR using @docs/engineering-workflow.md. Delegates each step to the right skill (implement, debate, guard, code-review, capture-wisdom). Use when the user says 'work on issue #N', 'implement this feature', or any implementation task."
---

# Feature Implementation Orchestration

This skill walks through the engineering workflow (`@docs/engineering-workflow.md`)
step by step, running only what hasn't been done yet.

## Start here

Read `@docs/engineering-workflow.md` for the full process, then read
`.agents/wisdom/*.md` for past lessons.

## Resolve the base commit

At the start, resolve the target branch and merge-base SHA once, then reuse
the SHA in every review step:

1. Determine the target branch: default is `origin/develop`. If the PR has a
   different base, use that instead.
2. Fetch the target branch: `git fetch origin <target-branch>`
3. Compute the merge-base: `git merge-base <remote-ref> HEAD`
4. Record both the target branch name and the SHA for later steps.

## Select review tier

Determine the tier based on what the change touches:

| Tier | When |
|------|------|
| **Lightweight** | Docs-only (.md, .gitignore, comments) |
| **Standard** | Code, CI, workflow, config, CodeRabbit config, release |
| **High-assurance** | Authz core, permissions, denial, revocation, security |

Record the chosen tier. Pass it to `guard` so it knows which checks to run.

## Steps

### Step 3 — Design (if no design doc)

Create `.scratch/implementation/<issue-id>-design.md`. Show the user.

### Step 4 — Implement

Load `implement` skill for TDD + tests + commit. Code-review happens later.

### Step 4.5 — Quality check

Load relevant skills from the workflow's quality check table (`codebase-design`,
`diagnosing-bugs`, `domain-modeling`, `research`) based on what you're touching.

### Step 4.75 — Debate (High-assurance only)

Load `debate` skill with the resolved base SHA. It saves evidence to
`.scratch/reviews/<issue-id>/<head-sha>-debate.md`.

### Step 4.9 — Test audit (High-assurance only)

Load `test-audit` skill with the resolved base SHA. It saves evidence to
`.scratch/reviews/<issue-id>/<head-sha>-test-audit.md`.

### Step 5 — Local verify

```
bun run typecheck && bun run lint && bun run test && bun run build
```

### Step 5.5 — Code-review (Standard and High-assurance)

Run `code-review` skill against `git diff <base-sha>...HEAD`. Save its output
to `.scratch/reviews/<issue-id>/<head-sha>-code-review.md`.

### Step 6 — Push + PR

Run `guard` before-push checks first (tier-aware), then:
```
git push origin feature/<issue-id>-<description>
gh pr create ...
```
After opening the PR, publish a concise review-evidence summary as a PR
comment referencing the local evidence files.

### Step 8 — CI + CodeRabbit

Wait for CI green. If tier is High-assurance and CodeRabbit is needed, trigger
`@coderabbitai review`. Read inline comments — don't rely on status alone.

### Step 10 — Guard + capture wisdom + report

Run `guard` before-report checks (tier-aware, evidence-based CodeRabbit check).
Then run `capture-wisdom` to save lessons.
Then report to the user.

## Evidence staleness

- If the latest commit changed only non-reviewable files (.md, .gitignore,
  .gitattributes, README, scratch files), existing evidence is still valid.
- If any reviewable code changed, evidence is stale. The relevant reviews
  must run again against the new HEAD.

## Merge rules

- **Never merge autonomously.** The agent only merges when the user explicitly
  says to (e.g., "merge it", "go ahead and merge").
- **Before merging**, verify all conditions are met:
  1. CI green
  2. CodeRabbit has no unresolved actionable comments (verified by inspecting
     inline comments, not status alone)
  3. Agent judgment — no blockers
- If conditions aren't met, report to the user — do not merge unsafely.

## Decision tree — where to start

| State | Start at |
|-------|----------|
| Nothing exists | Read workflow + wisdom |
| No design doc | Step 3 — design |
| No quality check | Step 4.5 — quality check |
| No adversarial review | Step 4.75 — debate |
| No test audit | Step 4.9 — test audit |
| Locally unverified | Step 5 — local verify |
| No code-review | Step 5.5 — code-review |
| Not pushed | Step 6 — push + PR |
| CI not green | Step 8 — CI + CodeRabbit |
| All done | Step 10 — capture wisdom + report |
