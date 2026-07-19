---
name: feature-implement
description: "Mandatory lifecycle orchestrator for code-changing issues. Delegates to implement, debate, guard, code-review, capture-wisdom. Read this first when the user says 'work on issue #N' or 'implement this feature'."
---

# Feature Implementation Orchestration

**Start here.** This is the mandatory entry point for all feature work.
Read `@docs/engineering-workflow.md` and `.agents/wisdom/*.md` first.

## Enforced order

Do not skip or reorder these steps.

### 1. Tier and base SHA

**Select review tier:**

| Tier | When |
|------|------|
| **Lightweight** | Truly non-reviewable files only (.gitignore, LICENSE, scratch) |
| **Standard** | Code, CI, workflow, config, skills |
| **High-assurance** | Authz core, permissions, denial, security |

Record the tier. Pass it to `guard`.

**Resolve base commit once:**

1. Determine target branch: default `develop`. If the PR specifies a different
   base, use that.
2. Fetch: `git fetch origin <target-remote-ref>` (e.g. `origin/develop`).
   Never produce bare `git fetch origin origin/develop` — use
   `git fetch origin develop` then reference `origin/develop`.
3. Compute merge-base: `git merge-base FETCH_HEAD HEAD`
4. Record target branch name and SHA for all subsequent steps.

### 2. Implement (Step 4)

Load `implement` skill. It handles TDD, tests, commits.

### 3. Guard pre-review (Step 4.5)

Run `guard` Phase 1 (pre-commit) to confirm everything compiles before
proceeding to reviews.

### 4. Quality check (Step 4.5)

Load relevant skills from the workflow's quality check table (`codebase-design`,
`diagnosing-bugs`, `domain-modeling`, `research`).

### 5. Debate — High-assurance only (Step 4.75)

Load `debate` with resolved base SHA. Saves evidence to
`.scratch/reviews/<issue-id>/<head-sha>-debate.md`.

### 6. Test audit — High-assurance only (Step 4.9)

Load `test-audit` with resolved base SHA. Saves evidence to
`.scratch/reviews/<issue-id>/<head-sha>-test-audit.md`.

### 7. Code-review (Step 5.5 — Standard and High-assurance)

Run `code-review` skill against `git diff <base-sha>...HEAD`. Save output to
`.scratch/reviews/<issue-id>/<head-sha>-code-review.md`.

### 8. Guard pre-push

Run `guard` Phase 2 (pre-push). Must pass before pushing.
Evidence must be for the current HEAD — otherwise stale.

### 9. Push + PR (Step 6)

```bash
git push origin feature/<issue-id>-<description>
gh pr create ...
```

After opening the PR, publish a concise review-evidence summary as a PR
comment referencing the local evidence files.

### 10. CI + CodeRabbit (Step 8)

Wait for CI green. High-assurance only: trigger `@coderabbitai review`.
Read inline comments with `--paginate` — do not truncate. Do not rely on
status alone.

### 11. Guard pre-report

Run `guard` Phase 3 (pre-report). Must pass before reporting.

### 12. Report

Run `capture-wisdom` to save lessons.
Report to the user: PR link, CI status, CodeRabbit evidence summary,
any deferred items.

## Merge rules

- The agent may merge **only when ALL** of these are true:
  1. The user explicitly says to merge
  2. CI is green
  3. No unresolved actionable review comments exist (verified by inspecting
     inline comments with `--paginate`, not status alone)
  4. The agent finds no blocker
- If any condition is not met, report to the user — do not merge.

## Evidence staleness

- Markdown files under `docs/`, `.agents/`, and `.github/` are reviewable.
- Only `.gitignore`, `.gitattributes`, `LICENSE`, and `.scratch/` files
  are non-reviewable.
- If any reviewable file changed since evidence was saved, evidence is stale.

## Where to start

| State | Start at |
|-------|----------|
| Nothing exists | Read workflow + wisdom |
| No design doc | Step 1 → design |
| Code not written | Step 2 — implement |
| No reviews done | Step 3 — guard pre-review |
| No quality check | Step 4 — quality check |
| No debate | Step 5 — debate |
| No test audit | Step 6 — test audit |
| No code-review | Step 7 — code-review |
| Locally unverified | Step 8 — guard pre-push |
| Not pushed | Step 9 — push + PR |
| CI not green | Step 10 — CI + CodeRabbit |
| All done | Step 11 — guard pre-report → Step 12 — report |
