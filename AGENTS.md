# Agent Setup

This project uses a skills-and-workflow system for AI coding agents.

## Entry point

All feature implementation work starts at **`feature-implement`** (`.agents/skills/feature-implement/SKILL.md`). It orchestrates the full lifecycle: design → implement → review → PR → report.

Do not bypass `feature-implement` for code-changing work. Read it first.

## Supporting skills

- `.agents/skills/` — task-specific skills (implement, debate, guard, code-review, etc.)
- `docs/engineering-workflow.md` — the full development lifecycle
- `docs/agents/issue-tracker.md` — issue tracker configuration
- `docs/agents/triage-labels.md` — label vocabulary
- `docs/agents/domain.md` — domain glossary layout
- `CONTEXT.md` — domain glossary and ubiquitous language

## For agents

Start by reading `feature-implement`. It will load the engineering workflow
and delegate each step to the right skill.
