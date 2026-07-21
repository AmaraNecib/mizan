# Triage Labels

Labels found on the repository during workflow-hardening inspection.
Labels marked absent were referenced by the workflow but do not exist yet.

## Existing labels

| Label | Description | Purpose |
|-------|-------------|---------|
| `bug` | Something isn't working | Standard GitHub |
| `documentation` | Improvements or additions to documentation | Standard GitHub |
| `duplicate` | This issue or PR already exists | Standard GitHub |
| `enhancement` | New feature or request | Standard GitHub |
| `good first issue` | Good for newcomers | Standard GitHub |
| `help wanted` | Extra attention is needed | Standard GitHub |
| `invalid` | This doesn't seem right | Standard GitHub |
| `question` | Further information is requested | Standard GitHub |
| `wontfix` | This will not be worked on | Standard GitHub |
| `wayfinder:map` | Wayfinder destination map | Produced by wayfinder |
| `wayfinder:grilling` | Wayfinder grilling ticket | Produced by wayfinder |
| `ready-for-agent` | Implementation-ready specification or ticket | Applied by to-spec / to-tickets |

## Labels referenced by workflow but absent

The engineering workflow references `area:*`, `priority:*`, `type:*`, and
`release:*` labels for PRs. These do not exist yet. Create them if PR
tagging becomes a bottleneck. Do not create without explicit approval.

## Label creation policy

New labels are created only when a concrete workflow step requires them.
Do not pre-create labels speculatively.
