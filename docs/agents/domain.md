# Domain Layout

Mizan is a single-context project.

## Structure

- `CONTEXT.md` at repository root — domain glossary and ubiquitous language
- `docs/adr/` — architecture decision records
- No `CONTEXT-MAP.md` exists; the project has one bounded context

## Glossary

See `CONTEXT.md` for the canonical vocabulary. Key terms:

- **Authorization decision** — allow or deny outcome
- **Authorization fact** — a normalized permission record from an adapter
- **Authorization adapter** — an integration that supplies facts
- **Source resolver** — the interface an adapter implements
- **Plan** — a composition strategy for multiple sources
