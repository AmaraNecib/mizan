---
name: implement
description: "Implementation worker: TDD, tests, and commits. Loaded by feature-implement. Does not push, report ready, or merge. Hands control back to feature-implement for review gates."
disable-model-invocation: true
---

# Implement — TDD Worker

This skill is called by `feature-implement` (Step 4). It handles the coding
phase only. It does not push, open PRs, run code-review, or merge.

## What to do

1. Use TDD at pre-agreed seams (red → green per slice).
2. Run typechecking after each slice.
3. Run the single test file after each slice.
4. Run the full test suite periodically.
5. Commit intermediate work as you go.

## What NOT to do

- Do NOT run code-review. Code-review is step 5.5, owned by feature-implement,
  and runs after debate and test-audit (not inside implement).
- Do NOT push. Push is step 6 (orchestrated by feature-implement).
- Do NOT report ready or merge.

## When done

Stop and let `feature-implement` proceed to the next step (quality check →
debate → test-audit → code-review → guard → push).
