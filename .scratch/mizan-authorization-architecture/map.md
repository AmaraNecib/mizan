# Mizan Authorization Architecture

## Destination

Produce a decision-complete architecture and delivery map for Mizan: an open-source TypeScript authorization decision layer that can work with database, JWT, cookie/session, JSON, API, cached, stateful, stateless, hybrid, and user-defined data sources without enforcing authentication or a database schema.

## Notes

- This is a planning map, not an implementation plan to execute immediately.
- Mizan owns authorization evaluation; the host owns authentication, persistence, cache storage, and source-specific freshness or revocation policy.
- Adapters should remain replaceable and composable. The core should not become a pass-through layer or a second authorization engine inside every adapter.
- The core must remain runtime-neutral and usable from the eventual Diwan ecosystem and projects such as 7awesli and Tuari.
- Consult `wayfinder`, `domain-modeling`, `codebase-design`, and `tdd` when resolving tickets.

## Decisions so far

<!-- No Wayfinder tickets have been resolved yet. -->

## Not yet specified

- The exact cache invalidation and revocation model after the source and snapshot contracts are settled.
- Whether policy conditions and resource-level authorization belong in the first stable contract or a later extension.
- The eventual management/write API for creating roles, assigning access, importing/exporting data, and supporting unusual relationships.
- The release, package, and integration strategy after the core contract stabilizes.

## Out of scope

- A hosted authorization service or central Mizan server.
- Authentication, JWT verification, cookie parsing, or session management in the core.
- A mandatory database schema, migration system, or ORM dependency.
- A Mizan-owned Redis, memory, browser, or other cache service.
- A core admin dashboard or framework-specific UI package as part of the decision-layer contract.

