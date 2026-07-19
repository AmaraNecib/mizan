# Adversarial Review Wisdom

## CodeRabbit inline comments are where real findings live (🔴 Critical)

The status check (`SUCCESS`/`FAIL`) and the summary comment only show the
surface. The per-line inline comments often contain real bugs that the
summary doesn't repeat.

**Always**: Fetch inline comments with `--paginate` to get all pages:
```bash
gh api --paginate repos/<owner>/<repo>/pulls/<num>/comments
```

Do not truncate bodies with `body[:100]` or similar filters — you need the
full text to understand the finding.

## CodeRabbit status can lie — SUCCESS doesn't mean reviewed (🔴 Critical)

The status check can show `SUCCESS` even when:
- **Rate-limited**: The review couldn't run, but the check still passes.
- **Incremental skip**: "Does not re-review already reviewed commits" —
  the check passes but no new review was produced.

**Always**:
1. Read the latest review comment — is it real findings or "rate limited"?
2. Fetch inline comments with `--paginate` — these are the actual review
3. Check each one against current code
4. Never trust SUCCESS alone

## Critic + Defender pattern catches real bugs (🟠 Major)

Running a critic and defender in parallel sub-agents catches things a single
reviewer misses. In practice this found: overnight window over-match,
schedule mismatch conflated with "expired", and empty schedule foot-gun.

**Always**: Run adversarial review before code-review for high-assurance
changes. Fix the easy findings and document deferred ones.
