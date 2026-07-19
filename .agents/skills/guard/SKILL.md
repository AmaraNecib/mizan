---
name: guard
description: "Run pre-flight checks before committing, pushing, or reporting done. Tier-aware: lightweight checks skip debate/code-review requirements. Evidence-SHA-aware: verifies review evidence matches current HEAD. Use automatically via feature-implement before each key action."
---

# Guard — Pre-flight Checks

Run these checks before key actions. The checks depend on the review tier
chosen for this change. If any check fails, stop and report.

## Derive repository

Use `gh repo view --json nameWithOwner --jq .nameWithOwner` to get the
current repository. Do not hard-code the repo path.

## Before commit

```
[ ] git status — are there unstaged changes?
[ ] bun run typecheck — does it pass?
[ ] bun run test — do all tests pass?
```

## Before push

### Common checks (all tiers)
```
[ ] git status — working tree clean?
[ ] bun run typecheck — passes?
[ ] bun run test — all tests pass?
[ ] bun run build — compiles?
```

### Evidence staleness check

For each evidence file `.scratch/reviews/<issue-id>/<sha>-*.md`:
- Extract the SHA from the filename
- Compare to current HEAD (`git rev-parse HEAD`)
- If they match → evidence is valid for the current code
- If they differ → inspect what changed:
  - `git diff --name-only <evidence-sha> HEAD` — list changed files
  - If only non-reviewable files (.md, .gitignore, .gitattributes, README,
    .scratch/) → evidence remains valid (docs-only exception)
  - If any reviewable file changed → evidence is STALE, must regenerate

### Tier-specific checks

**Lightweight** (docs-only):
```
[ ] No reviewable code changed — confirm with git diff --name-only
```
→ Skip debate, test-audit, and code-review checks.

**Standard** (code, CI, config):
```
[ ] Code-review evidence exists and is not stale
```

**High-assurance** (authz core, security):
```
[ ] Debate evidence exists and is not stale
[ ] Test-audit evidence exists and is not stale
[ ] Code-review evidence exists and is not stale
```

## Before reporting "ready for merge"

```
[ ] CI — all checks green on GitHub?
[ ] CodeRabbit evidence check (High-assurance only):
    1. Fetch review summary — does it cover the latest reviewable commit?
    2. Fetch inline comments — any unresolved actionable findings?
    3. Was the review rate-limited or unavailable?
    If rate-limited/unavailable: report clearly, require human decision.
    SUCCESS status alone is insufficient.
[ ] PR description — accurate and complete?
[ ] Any deferred items — documented in the PR with issues?
[ ] Wisdom — any lessons to capture?
```

## When a check fails

1. Report to the user what failed and why
2. Do not proceed past the failing check
3. If the user says "skip it", note it and continue
4. If the user says "fix it", fix it and re-run the check
