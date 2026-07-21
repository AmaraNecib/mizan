---
name: Feature
about: Implementation-ready specification or ticket
labels: ready-for-agent
---

## Parent

<!-- Link to the parent spec, wayfinder map, or epic issue. -->

## Acceptance criteria

<!--
List the end-to-end behaviors that must be true for this issue to be complete.
Each criterion should be testable.
-->

- [ ] ...

## Blocked by

<!--
List genuine blocking tickets. Use `#<num>` syntax.
-->

- ...

## Review tier

<!-- Select one: Lightweight, Standard, High-assurance -->

Tier: <!-- Lightweight | Standard | High-assurance -->

## Verification

```bash
bun run typecheck
bun run lint
bun run test
bun run build
```

## Review evidence

After the PR is opened, review outputs are saved locally at:
`.scratch/reviews/<issue-id>/<head-sha>-{debate,test-audit,code-review}.md`
A summary of findings is posted as a PR comment (these local paths are
provenance, not remote links).
