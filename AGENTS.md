# Agent Setup

This project uses a skills-and-workflow system for AI coding agents.

## Entry points

- `.agents/skills/` — task-specific skills (feature-implement, implement, debate, guard, etc.)
- `docs/engineering-workflow.md` — the full development lifecycle
- `docs/agents/issue-tracker.md` — issue tracker configuration
- `docs/agents/triage-labels.md` — label vocabulary
- `docs/agents/domain.md` — domain glossary layout
- `CONTEXT.md` — domain glossary and ubiquitous language

## For agents

Read the engineering workflow first. It defines the lifecycle from issue to merge.
Skills are loaded as needed at each step. Configuration files under `docs/agents/`
are written by `setup-matt-pocock-skills` and consumed by workflow skills.
