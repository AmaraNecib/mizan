---
name: guard
description: "Single source of truth for pre-flight checks: pre-commit, pre-push, pre-report. Tier-aware. Evidence-SHA-aware. Called by feature-implement. Do not bypass."
---

# Guard — Pre-flight Checks

Three phases. Each has explicit, checkable completion criteria.
If any check fails, stop and report. Do not proceed.

## Derive repository

```bash
gh repo view --json nameWithOwner --jq .nameWithOwner
```

## Phase 1 — Pre-commit

Run before every commit.

```
[ ] git status — working tree clean?
[ ] bun run typecheck — passes?
[ ] bun run test — all tests pass?
```

## Phase 2 — Pre-push

Run before pushing and opening a PR.

```
[ ] bun run typecheck — passes?
[ ] bun run test — all tests pass?
[ ] bun run build — compiles?
[ ] git status — working tree clean?
```

### Review evidence checks

For each evidence file `.scratch/reviews/<issue-id>/<sha>-*.md`:
- Extract the SHA from the filename
- Compare to current HEAD (`git rev-parse HEAD`)
- If they match → evidence is valid for the current code
- If they differ → inspect `git diff --name-only <evidence-sha> HEAD`:
  - If any reviewable file changed (any file in packages/, .github/workflows/,
    .agents/skills/, docs/engineering-workflow.md, etc.) → evidence is STALE,
    must regenerate
  - If only trivially non-reviewable files changed (.gitignore, .gitattributes,
    .scratch/, LICENSE) → evidence remains valid

**All Markdown files under `docs/`, `.agents/`, and `.github/` are reviewable.**
Only truly non-reviewable files (.gitignore, .gitattributes, LICENSE, scratch)
get the docs-only exemption.

### Tier-specific requirements

**Lightweight** (genuinely non-reviewable files only):
→ Skip debate, test-audit, and code-review checks.

**Standard** (code, CI, workflow, config):
```
[ ] Code-review evidence exists and is not stale
```

**High-assurance** (authz core, security):
```
[ ] Debate evidence exists and is not stale
[ ] Test-audit evidence exists and is not stale
[ ] Code-review evidence exists and is not stale
```

## Phase 3 — Pre-report

Run before reporting "ready for merge".

```
[ ] CI — all checks green on GitHub?
[ ] Inline comments — fetched with --paginate, none truncated:
    gh api --paginate repos/<owner>/<repo>/pulls/<num>/comments
    — are there unresolved actionable findings?
    — was the review rate-limited or unavailable?
    If rate-limited/unavailable: report clearly, require human decision.
    SUCCESS status alone is insufficient.
[ ] PR description — accurate and complete?
[ ] Any deferred items — documented in the PR with issues?
[ ] Wisdom — any lessons to capture?
```

## When a check fails

1. Report to the user what failed and why
2. Do not proceed past the failing check
3. If the user explicitly says "skip it" after being informed of the risk,
   note the waiver and continue.
4. If the user says "fix it", fix it and re-run the check.

**Mandatory gates (never skip):** typecheck, test, build, CI green,
CodeRabbit inline-comment inspection. These must pass.
