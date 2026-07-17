# Engineering Workflow

This document defines the permanent engineering workflow for the Mizan project. Every feature, from inception to merge, follows this lifecycle.

---

## Planning Skills

Use the current planning skill names consistently:

1. `wayfinder` resolves a large design space and keeps the architectural map coherent.
2. `to-spec` synthesizes the resolved design into one implementation-ready specification issue.
3. `to-tickets` breaks that specification into tracer-bullet implementation tickets with explicit blockers.
4. `implement` works one ready-for-agent ticket at a time using the ticket's acceptance criteria.

The specification is the source of architectural truth. The tickets are the executable work queue. Use this specification-and-ticket terminology consistently throughout the workflow.

---

## Branch and Release Model

Mizan uses a small two-branch integration model:

| Branch | Purpose | Stability |
|---|---|---|
| `main` | Released, user-facing code | Stable |
| `develop` | Integration branch for accepted feature work | Pre-release |

Feature branches are created from `develop` and merged back through pull requests. Direct pushes to `main` and `develop` are not part of the normal workflow.

`main` is the stable branch; a separate permanent `stable` branch is not needed. Temporary `release/*` branches may be created when a release needs a short stabilization period, then deleted after the release is merged.

### Versioning and package distribution

- `@mizan/core` and `@mizan/memory` use fixed versioning and are released together.
- A stable release is represented in Git by a tag such as `v0.1.0` on `main` and in npm by the `latest` dist-tag.
- `npm install @mizan/core` means “install the version currently assigned to npm `latest`”; it does not install from the `main` branch directly.
- Work merged into `develop` does not move npm `latest`.
- Optional preview releases from `develop` use a prerelease version and a separate dist-tag such as `next`; users must explicitly request that channel.
- A bug fix from `main` creates the next patch release and is merged back into `develop`.

Example release flow:

```text
feature/23-foundation → develop → release/0.1.0 (optional) → main
                                                        ↓
                                             tag v0.1.0 + npm latest
```

When a pull request targets `develop`, reference its issue with `Refs #23`. Closing keywords are reserved for a release pull request targeting the default branch, or the issue can be closed manually after the work is merged and verified.

---

## Feature Lifecycle

```text
Wayfinder map / design
    ↓
to-spec
    ↓
Implementation-ready specification
    ↓
to-tickets
    ↓
Ready-for-agent ticket (GitHub)
    ↓
Architecture / ADR (if required)
    ↓
Design (.scratch/implementation/)
    ↓
Implementation (implement skill: TDD + code-review)
    ↓
Quality Check (skill-guided: codebase-design, diagnosing-bugs, domain-modeling, ...)
    ↓
Local Verification
    ↓
Pre-Push Self-Review (code-review skill)
    ↓
Push Feature Branch
    ↓
Open Pull Request (draft until CI passes)
    ↓
GitHub Actions Verification
    ↓
Fix CI (if necessary)
    ↓
CodeRabbit Review (manual @coderabbitai review trigger; auto-review disabled in config)
    ↓
Address Review Feedback
    ↓
Final CI Verification (if new commits were pushed)
    ↓
Merge into develop
    ↓
Verify the merged work
    ↓
Close Issue (manually, or through the release PR into main)
```

---

## Step Details

### 1. Issue

Every implementation starts from one ready-for-agent GitHub ticket. For a large design, the ticket must reference:
- The implementation-ready specification produced by `to-spec`
- The architecture document it conforms to
- The ADRs that constrain it

The ticket is created by `to-tickets` and must contain the end-to-end behavior, acceptance criteria, and genuine blocking tickets. Do not begin implementation from a broad specification when a tracer-bullet ticket exists.

See `.github/ISSUE_TEMPLATE/feature.md` for the template.

### 2. Architecture / ADR

Architecture is frozen during a milestone. If implementation reveals a genuine architectural problem:
- Stop implementation.
- Open an ADR.
- Resolve the architecture first.
- Then continue implementation.

Do not silently diverge from the approved architecture.

### 3. Design

Before writing production code, create a design document:

```text
.scratch/implementation/<issue-id>-design.md
```

The design document must specify:
- Public API (structs, enums, traits, functions)
- Internal dependencies
- Planned tests
- Implementation risks
- Any deviations from the architecture

### 4. Implementation (implement skill)

Load the `implement` skill. It reads the issue, implements using TDD at pre-agreed seams, runs typechecking and tests regularly, then runs `code-review` and commits to the current branch.

See `.agents/skills/implement/SKILL.md` for details.

### 4.5 — Quality Check (Skill-Guided Review)

After implementation but before running tests, load relevant skills to catch issues early.

The agent selects skills based on what the change touches:

| If the change touches... | Load these skills |
|---|---|
| New module, interface, or architecture | `codebase-design` — check depth, seam placement, deletion test |
| Complex logic, state, or edge cases | `diagnosing-bugs` — catch logic errors early |
| Domain entities, terms, or data models | `domain-modeling` — check ubiquitous language alignment |
| Any production code | `code-review` — review against coding standards |
| Large feature from a spec | `implement` — already loaded in step 4 |
| Unclear requirements or unknowns | `research` — investigate against primary sources |
| Planning a large chunk of work | `wayfinder` — break into investigation tickets |

These skills supplement the `code-review` already run by `implement`. The agent does **not** load all blindly — it picks the ones relevant to the issue.

**Why this exists:**
- Catches design and logic problems before tests are written
- Catches things `code-review` might miss (domain alignment, architecture depth, bug patterns)
- Uses the `.diwan/` model registry to route each skill to the best model

### 5. Local Verification

Before pushing any commit intended for review, run the complete local verification pipeline:

```bash
# TypeScript packages
bun run typecheck
bun run lint
bun run test

# Build packages
bun run build
```

GitHub Actions **must not** be the first place failures are discovered. The objective is:

> GitHub Actions should verify the work, not discover predictable failures.

### 5.5 Pre-Push Self-Review (code-review skill)

After local verification passes but **before pushing**, the agent runs the
`code-review` skill against the current branch to catch issues locally.

**How it works:**

1. The parent agent selects a review-capable model (e.g., `opencode-go/mimo-2.5` for review tasks).
2. The parent agent invokes the built-in `code-review` skill with the fixed point being
   `develop` (or the merge-base of the feature branch):
   ```text
   git diff develop...HEAD
   ```
3. The code-review skill spawns **two parallel sub-agents**:
   - **Standards** — checks code against documented coding standards +
     Fowler smell baseline
   - **Spec** — checks if the implementation matches the originating
     ticket and implementation-ready specification
4. The skill aggregates findings into a single report.

**Pass/Fail:**

- **No actionable findings** from either axis → ✅ safe to push. Proceed to step 6.
- **Actionable findings** → 🔧 fix them locally, re-run local verification
  (step 5), then re-run the self-review.
- **Only advisory warnings** (non-blocking) → agent uses judgment: push
  with `status:needs-investigation` label or fix before pushing.

**Why this exists:**

- Catches issues before they reach CodeRabbit or CI, reducing feedback loops.
- Runs on Windows natively (no WSL required for the review itself).
- Uses the `.diwan/` model registry to enable model diversity — the reviewer
  can use a different model than the parent.
- The `code-review` skill's Standards + Spec axes catch problems CodeRabbit might
  miss (spec drift, smell violations, missing tests).

### 6. Push Feature Branch

```bash
git checkout develop
git pull origin develop
git checkout -b feature/<issue-id>-<short-description>
# ... implement ...
git push origin feature/<issue-id>-<short-description>
```

Branch naming: `feature/<issue-id>-<short-description>` (e.g., `feature/23-foundation-core-memory-packages`).

On push, the **pre-push hook** automatically runs `bun run typecheck && bun run test && bun run build`. If it fails, fix the issue locally before pushing again.

### 7. Open Pull Request

Create a PR into `develop`. The PR must:
- Reference the issue: `Refs #23`
- Populate the PR template completely
- Apply the correct labels (`area:*`, `priority:*`, `type:*`, `release:*`)
- Be in draft state initially if CI has not yet passed

Do not rely on `Closes #23` for a PR targeting `develop`; the issue-closing keyword is intended for the stable release PR into `main`. Close the issue after the merged work has been verified if it is complete before the next release.

### 8. GitHub Actions Verification

Wait for all required CI checks to pass. If any check fails:
- Investigate the failure
- Fix locally
- Rerun local verification
- Push the fix
- Wait for CI again

### 9. CodeRabbit Review

CodeRabbit auto-review is fully disabled in config. Trigger it manually on every review cycle.

Only after CI is fully green:
- Comment `@coderabbitai review` in the PR
- Wait for CodeRabbit to complete (typically 1-5 min depending on size)
- Check the review summary for actionable findings (aim for clean with no actionable items)
- If CodeRabbit finds problems:
  1. Load the `implement` skill with CodeRabbit's findings as the input spec — it will fix, test, code-review, and commit
  2. Push the fixes
  3. Wait for CI to complete
  4. Trigger `@coderabbitai review` again
  5. Wait for CodeRabbit to re-review
- Repeat until CodeRabbit has no actionable findings

### 10. Address Review Feedback

- Address every comment (either fix or explain why not)
- If changes were made: rerun local verification, push, wait for CI

### 11. Final CI Verification

After all review feedback is addressed and CI is green again, the PR is ready to merge.

### 12. Merge

Merge into `develop` using squash merge. The commit message should reference the issue:

```text
23: foundation: fixed-version core and memory packages (closes #23)
```

Feature PRs are squash-merged into `develop`. A release PR promotes the verified `develop` state into `main`, creates the release tag, publishes the fixed-version packages, and may use the closing keyword for all issues included in that release.

### 13. Close Issue

After the merge is complete and the acceptance criteria are verified, close the GitHub Issue. If the issue is closed after merging into `develop`, the later release PR should reference the already-closed issue rather than reopening it.

### 14. Stable Release

When `develop` contains the intended release scope:

1. Create a temporary `release/<version>` branch only if stabilization work is needed.
2. Run the complete verification pipeline and review the release diff.
3. Open a release PR from `develop` (or the temporary release branch) into `main`.
4. Merge the release PR only after the required checks and human release decision pass.
5. Create the matching Git tag, for example `v0.1.0`.
6. Publish `@mizan/core` and `@mizan/memory` together with the npm `latest` dist-tag.
7. Merge any release-only fixes back into `develop` and delete the temporary release branch.

---

## Local Verification Policy

Before pushing any commit intended for review, reproduce locally everything that GitHub Actions will execute, whenever practical.

The CI workflow (`.github/workflows/ci.yml`) executes the following. Each must pass locally before pushing:

| Check | Command |
|-------|---------|
| TypeScript type check | `bun run typecheck` |
| Lint | `bun run lint` |
| Tests | `bun run test` |
| Build | `bun run build` |

**If a CI job cannot reasonably be executed locally**, (e.g., platform-specific builds, hosted services, protected secrets), document that limitation in the PR description.

---

## Commit Policy

- Small intermediate commits during implementation are acceptable on the feature branch.
- Do **not** push code that knowingly fails local verification.
- Before opening a Pull Request, the branch must pass the complete local verification pipeline.

### Husky Git Hooks

Husky enforces two automated gates:

**pre-commit** — runs on every `git commit`:
```bash
bun run typecheck  # TypeScript type checking
bun run test       # All package tests
```

**pre-push** — runs on every `git push`:
```bash
bun run typecheck  # TypeScript type checking
bun run test       # All package tests
bun run build      # Compile all packages to dist/
```

If a hook fails, the commit or push is blocked. Fix the issue locally, then retry. To bypass hooks temporarily (e.g., WIP save), use `git commit --no-verify` or `git push --no-verify`.

---

## Review Policy

```text
Local Verification (step 5)
    ↓
Pre-Push Self-Review (step 5.5) — code-review skill, local agent review
    ↓
Push Feature Branch (step 6)
    ↓
Open Pull Request (step 7)
    ↓
GitHub Actions (all required checks green)
    ↓
Request CodeRabbit Review (step 9)
    ↓
Address comments (step 10)
    ↓
GitHub Actions green again (if new commits)
    ↓
Ready for merge
```

### Two-Layer Review

The project uses a **two-layer review system**:

**Layer 1: Pre-Push Self-Review** (`code-review` skill, step 5.5)
- Runs locally before pushing
- Uses the `code-review` skill with parallel Standards + Spec sub-agents
- Can use a different model (e.g., `opencode-go/mimo-2.5`)
- Catches spec drift, smell violations, missing tests, standard breaches
- Runs on Windows, no WSL required

**Layer 2: CodeRabbit Review** (step 9)
- Runs via GitHub after all checks pass
- Provides automated AI code review
- Catches pattern-level issues the local review might miss

CodeRabbit should be triggered only after the Pull Request CI is passing. This avoids wasting review time on failures that would have been caught by CI. The local self-review avoids wasting CI and CodeRabbit on issues that could have been caught locally.

---

## Solo-Developer Agent Workflow

This section defines the protocol for a **single human developer** working with an **AI agent** (e.g., a coding assistant) and **CodeRabbit** as the automated reviewer.

In this workflow, the **agent is the de facto reviewer**. The human sets policy, the agent executes, and CodeRabbit provides the automated code review. The agent MUST NOT merge a PR until all three gates below pass.

### Branch Protection Policy

| Branch | Approval required | Status checks required | Notes |
|---|---|---|---|
| `develop` | **No for now** | **Yes (`CI / Foundation verification`)** | PR required; agent can merge after CI and review gates pass |
| `main` | **No for now** | **Yes (`CI / Foundation verification`)** | PR required; human release decision is still required; enable one approval when a second reviewer is available |

Both branches reject direct pushes, force pushes, and deletion. `main` is intentionally the stable branch; its extra safety comes from release PRs, tags, and the human release decision even while this solo workflow does not require a second GitHub approval.

### Pre-Merge Gate (Three-Step)

Before merging any PR into `develop`, the agent MUST verify **all three steps** pass. If any step fails, the agent MUST NOT merge; it must surface the issue to the human.

#### Step 1 — CI Status

All CI jobs must be `pass`:
1. Type Check
2. Lint
3. Test
4. Build

If any job is `fail` or `pending` → **fix and re-run, do not merge**.

If any job is `pending` for an extended period (e.g., >10 minutes), investigate via `gh run watch`.

#### Step 2 — CodeRabbit Two-Condition Check

A CodeRabbit review is considered **"done and clean"** when **BOTH** conditions are true:

**Condition 1 — Verbal check**: CodeRabbit's most recent review summary says **"No actionable comments were generated"** OR only contains `⚠️ Warning` items (advisory only, not blockers).

**Condition 2 — Temporal check**: Does the latest commit change **reviewable code**?

Reviewable code means: TypeScript, tests, CI config, or any file that *could* produce a new CodeRabbit finding.

Non-reviewable code means: docs (.md), .gitignore, .gitattributes, .coderabbit.yaml, README, scratch files (.scratch/), or any config that doesn't affect the code being reviewed.

- If the latest commit changes **reviewable code** → review IS stale, needs re-trigger
- If the latest commit changes **only non-reviewable code** → old review is still valid, no re-trigger needed

This avoids unnecessary re-triggers for docs-only or config-only commits.

Use the `gh` CLI to check review status and fetch comments:

```bash
# Check review status via CodeRabbit check
gh pr view <num> --json statusCheckRollup

# Check latest review comment / summary
gh pr view <num> --comments --json comments

# Compare to latest commit
gh pr view <num> --json headRefOid
```

For **inline review comments marked "Outdated"** (file-level, line-level Nits), the agent MUST:
1. Note the file and the original concern
2. Read the current state of that file
3. Determine: was the concern addressed in a later commit?
4. If yes → concern is resolved, no action
5. If no → concern still stands, treat as open finding

**Decision tree for Step 2:**

| Situation | Action |
|---|---|
| CodeRabbit check is `pending` / `in_progress` | ⏳ **Wait** — do not trigger anything |
| CodeRabbit check is `fail` (actionable findings) | 🔧 **Fix findings locally, push, re-trigger CodeRabbit** |
| CodeRabbit check is `pass` AND Condition 1 + 2 both pass | ✅ **Proceed to Step 3** |
| CodeRabbit check is `pass` BUT Condition 2 fails (stale review) | 🔧 **Apply narrow workaround** (see below) |
| CodeRabbit check is `pass` BUT inline concerns remain unresolved | 🔧 **Fix the concerns, push, re-trigger** |

#### Step 3 — Agent's Own Judgment (Soft Check)

Even with green CI and clean CodeRabbit review, the agent MUST also consider:

- Is the architecture impact captured in the PR description?
- Are there security implications not addressed?
- Do tests cover the change adequately?
- Is the diff suspicious (unrelated file changes, large generated files, secrets, etc.)?
- Does the PR description accurately reflect the changes?

If **all of the above are clean** → ✅ **Merge** (proceed to merge command).

If **any of the above raises a real concern** but Steps 1 + 2 pass → ⚠️ **Merge with flag** (see uncertainty fallback).

### Narrow Workaround (Stale Review Only)

The workaround is a **narrow tool** for one specific situation: CodeRabbit check is `pass` but its review doesn't reflect the latest commit.

**When to apply:**
- We are confident the code is correct
- CodeRabbit check shows as passed but no fresh review exists (Condition 2 fails)
- Goal: get a fresh review, NOT bypass a real concern

**Steps:**

1. Remove CodeRabbit's old review summary comments if they persist
2. Make a small cosmetic commit (e.g., a comment, formatting, whitespace — no behavior change)
3. Push and wait for CI to pass
4. Re-trigger CodeRabbit with `gh pr comment <num> --body "@coderabbitai review"`
5. Wait for the new review
6. Re-apply the two-condition check

**When NOT to apply:**
- CodeRabbit has unresolved findings → fix them, don't workaround
- The agent has its own concerns (Step 3) → surface to human
- The PR is in any other uncertain state → don't bypass, leave for human

### Uncertainty Fallback — Merge with Flag

When the agent is **uncertain** about merging (e.g., a finding is ambiguous, edge case not covered, but not a hard blocker):

**Do NOT refuse to merge** if dependent PRs may be blocked. Instead:

1. Add the `status:needs-investigation` label to the PR
2. Merge anyway (the work is done, and downstream PRs may be waiting)
3. Report clearly to the human:
   > "I merged PR #X with `status:needs-investigation` because [reason]. Dependent PRs #Y, #Z continue to work. Please review the merged PR when convenient."

The label persists on the merged PR and is searchable via `gh pr list --label status:needs-investigation`.

### Merge Command

When all three steps pass, the agent executes:

```bash
gh pr merge <num> --squash --subject "<issue-id>: <title> (closes #<issue>)"
```

**No `--delete-branch` flag** — feature branches are kept for reference.

**Merge commit format:** `<issue-id>: <short description> (closes #<issue>)`

Example: `23: foundation: fixed-version core and memory packages (closes #23)`

### Why This Workflow Exists

A solo developer cannot approve their own PR. Traditional branch protection (require 1 approval) blocks all merges. This workflow replaces the human-approval gate with an **automated, deterministic agent gate** that:

1. **CI** = "did the build pass?"
2. **CodeRabbit two-condition check** = "is the review complete and clean?"
3. **Agent judgment** = "is anything obviously wrong that the tools missed?"

The agent is accountable for following this gate. The human is accountable for the policy and for reviewing any `status:needs-investigation` PRs after the fact.

---

## Definition of Done

A feature is complete when:

- [ ] Local verification passes
- [ ] Pre-Push Self-Review (code-review skill) passes with no actionable findings
- [ ] Pre-commit hooks (husky) pass on every commit
- [ ] Feature branch is pushed
- [ ] Pull Request exists in GitHub
- [ ] GitHub Actions are green
- [ ] CodeRabbit review has been triggered and completed (unless prevented by permissions)
- [ ] CodeRabbit feedback has been addressed (if any)
- [ ] PR has been merged into `develop`
- [ ] Issue has been closed
