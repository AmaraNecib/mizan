# Process Wisdom

## CodeRabbit review gate

- **Auto-review is disabled** in `.coderabbit.yaml` (`auto_review.enabled: false`) — must trigger manually with `@coderabbitai review`.
- After pushing new commits with reviewable code (TypeScript, tests, CI config), the review is stale — must re-trigger.
- Free tier has rate limits (35 min cooldown). After hitting the limit, sleep and retry.
- CodeRabbit finds things the pre-push self-review misses (security lens, async assertion gaps). Do not skip it.

## CodeRabbit SUCCESS with no review = rate-limited

When the CodeRabbit status check shows SUCCESS but no review summary or inline
comments are posted (even minutes after triggering), and the trigger comment
has no reply, CodeRabbit was rate-limited on the free tier (35-min cooldown).
The status check lies — it shows SUCCESS even when no review ran.

**Always**: After triggering `@coderabbitai review`, wait 2-3 minutes, then:
1. Check PR comments for a review summary
2. Fetch inline comments: `gh api --paginate repos/<owner>/<repo>/pulls/<num>/comments`
3. If both are empty, the review was rate-limited — document and move on

## Pre-merge three-step gate

From `docs/engineering-workflow.md`:

1. **CI Status** — all checks green
2. **CodeRabbit** — SUCCESS + no actionable comments + review covers latest commit
3. **Agent judgment** — architecture, security, test coverage

Do not merge until all three pass. Do not assume CodeRabbit auto-triggered — it didn't.

## Reverting a merge on a protected branch

- `develop` is protected — direct pushes are rejected.
- To undo a merge: create a revert branch, push, open a PR, merge that PR.
- Faster: just create a new PR with the fix rather than reverting and re-applying.

## Bun workspace dependencies and bun build

- `bun build` (the bundler) does not resolve `workspace:*` protocol deps when run
  from a workspace member's directory. The bundled entry points import from
  package names that aren't resolved.
- **Fix**: either (a) run `bun build` from the repo root with relative entry
  paths, or (b) use the `--cwd` trick: `cd <relative-to-root> && bun build ...`
  from the workspace member's build script. The latter keeps the build script
  self-documenting in the member's `package.json`.
- Also ensure `bun.lock` uses `workspace:*` (not `file:`) references for
  workspace members — `file:` creates nested lockfile entries that break
  frozen-lockfile CI.

## Commit message format

```text
<issue-id>: <short description> (closes #<issue>)
```

Example: `24: first decision: trusted principal, memory facts, can, and decide (closes #24)`

For non-closing commits: `Refs #<issue>`
