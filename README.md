# Mizan

> Flexible, TypeScript-first authorization: adapters provide facts, Mizan makes the decision.

Mizan is an open-source, runtime-neutral TypeScript authorization decision layer. It helps applications evaluate roles, permissions, grants, denials, scopes, and time-based rules without forcing a database schema, ORM, authentication provider, or cache.

This repository is the Mizan monorepo and the OpenAI Build Week project submission.

## The problem

Authorization logic is repeatedly rebuilt inside application projects:

- roles and direct grants are mixed with application code;
- a direct denial needs to override a role grant;
- temporary or scheduled access is easy to implement inconsistently;
- every database or authentication setup requires a different integration;
- UI checks are mistaken for actual security checks.

Mizan separates the decision from the data source:

~~~
Application / adapter facts
          |
          v
       Mizan
          |
          v
  explainable allow or deny
~~~

Adapters and sources provide normalized authorization facts. Mizan evaluates those facts and returns the final decision with a stable reason code. The host application remains responsible for authentication, persistence, JWT/cookie/session handling, revocation, caching, and enforcing the result at its server or API boundary.

## What is implemented

The current v0.1 foundation includes:

- role-derived permission grants;
- direct grants and direct denial overrides;
- exact permissions plus namespace/global patterns such as "files.read", "files.*", and "*";
- optional scopes, where an omitted scope represents global applicability;
- absolute validity windows with startsAt and expiresAt;
- recurring weekly and date-specific schedules;
- named sources and source plans;
- a runtime-neutral source contract for custom adapters;
- structured decisions with stable denial reasons;
- an in-memory adapter for tests, examples, and reference implementations.

The API is intentionally conservative: no matching grant means deny, and an active matching denial wins over a grant.

## Packages

| Package | Purpose |
| --- | --- |
| @mizan/core | Runtime-neutral authorization evaluation and source/plan contracts |
| @mizan/memory | In-memory reference adapter for development and testing |

The monorepo uses fixed package versions. The current packages are versioned 0.1.0 in the development branch. Additional database, cache, framework, and authentication integrations can be added as separate packages when they are useful and tested.

## Quick start

### Requirements

- Bun installed for repository development and the demo;
- a modern browser;
- Node.js 18 or newer when consuming the package in a Node application.

Install and verify the repository from the root:

~~~bash
bun install
bun run typecheck
bun run test
bun run build
~~~

### Run the interactive demo

The demo is in examples/interactive-decision-demo:

~~~bash
cd examples/interactive-decision-demo
bun run dev
~~~

Open the URL printed by the server, normally:

~~~text
http://localhost:3000
~~~

Serve the demo over HTTP. Do not open index.html directly with file://; the bundled ES modules require an HTTP origin.

If you prefer to build and serve manually:

~~~bash
bun run build
bunx --bun serve .
~~~

## Interactive demo

The demo is an authorization decision gallery, not an authentication or administration product. It uses the real Mizan packages and an in-memory source.

It lets you switch between:

- **Super Admin** — can manage the demo policy and inspect the schedule controls;
- **Admin** — can read, create, and update cars; scheduled delete access is restricted to the configured work window only when scheduling is enabled (when disabled, car deletion is unrestricted), and policy management remains locked;
- **Support** — can read and create, has a direct denial for delete, and can receive a live direct grant for update from the Super Admin policy editor.

The demo shows:

- protected read, create, update, and delete actions;
- a direct denial overriding a role-derived grant;
- a policy-management permission checked by Mizan before policy mutation;
- an explainable decision banner and running decision trace;
- a configurable recurring schedule with a controllable evaluation clock;
- presentation mode that either shows denied actions disabled with their reason or hides them;
- the production boundary: hiding a browser button is not authorization, so protected actions are checked again before state changes.

## Minimal integration shape

Mizan does not decide how your application stores roles or permissions. A source adapter translates your own data into Mizan facts.

A minimal in-memory example looks like this:

~~~ts
import { createMizan } from "@mizan/core";
import { MemoryAdapter, useMemoryAdapter } from "@mizan/memory";

const mizan = createMizan();

const adapter = new MemoryAdapter({
  roles: [
    {
      name: "support",
      permissions: [
        { permission: "files.read", effect: "grant" },
      ],
    },
  ],
  assignments: [
    { principalId: "user_123", roleName: "support" },
  ],
});

useMemoryAdapter(mizan, adapter);

const authorization = mizan.forPrincipal("user_123");

const result = await authorization.decide("files.read");

console.log(result.decision); // "allow"
console.log(result.reason);   // null
~~~

A denial is structured and explainable:

~~~ts
const result = await authorization.decide("files.delete");

if (result.decision === "deny") {
  console.log(result.reason); // for example: "no-grant" or "matching-denial"
}
~~~

For a real application, replace the memory source with an adapter that reads the application's database, cache, API, or another source. Mizan does not require the adapter to use a particular schema.

## Adapter boundary

The adapter/source boundary is the main extensibility point:

- the application owns its data model;
- an adapter reads and normalizes that model;
- Mizan evaluates the resulting facts;
- the application enforces the decision where the protected operation occurs.

This means a project can keep its existing Prisma/PostgreSQL, Drizzle/SQLite, REST, cache, or custom storage design. A future integration can compose multiple sources or plans without moving persistence or authentication concerns into the core decision layer.

The memory adapter is deliberately small and serves as a reference for writing custom adapters.

## Testing

From the repository root:

~~~bash
bun run typecheck
bun run test
bun run build
~~~

To test the browser demo, run bun run dev, then exercise the three principals and verify:

1. Admin can read, create, and update cars; when scheduling is enabled, delete access is restricted to the configured work window and denied outside it; when scheduling is disabled, car deletion is unrestricted. Policy controls remain locked regardless.
2. Support can read and create, but delete is denied with matching-denial.
3. Super Admin can grant Support cars.update and the decision changes without a page reload.
4. The schedule allows access inside its window and returns outside-schedule outside it.
5. Every protected demo action is checked through the real Mizan evaluator before the demo state changes.

## Production boundary

Mizan is authorization, not authentication.

It does not currently:

- create or verify JWTs;
- parse cookies or sessions;
- revoke refresh tokens;
- provide a database or ORM;
- provide a cache;
- replace server-side enforcement;
- ship a policy-management dashboard.

Those responsibilities stay with the host application or optional integrations. A production application should obtain a trusted principal from its authentication layer, resolve the required authorization facts through its adapters, call Mizan, and enforce the result on the server or API boundary.

## Inspiration

Authorization is rebuilt inside almost every application, even though the
underlying questions are often the same: does this principal have this
permission, does a denial override a grant, is the access scoped or temporary,
and what should happen when the application's data model is different?

We wanted a small open-source decision layer that could be reused across
projects without forcing a database schema, ORM, authentication provider, or
cache. The central idea became simple: adapters provide facts; Mizan makes the
final authorization decision.

## What it does

Mizan is a runtime-neutral, TypeScript-first authorization library. It
evaluates:

- role-derived and direct grants;
- direct denial overrides, with denial taking precedence;
- exact permissions and patterns such as `files.*` and `*`;
- global and scoped facts;
- absolute validity windows with `startsAt` and `expiresAt`;
- recurring weekly and date-specific schedules;
- facts from named sources and source plans;
- explainable `allow` or `deny` decisions with stable reason codes.

The interactive demo makes these decisions visible with Super Admin, Admin,
and Support principals. It demonstrates policy management, a scheduled Admin
delete permission, a Support denial override, a controllable evaluation clock,
and protected actions that call the real Mizan evaluator before changing demo
state.

Mizan is authorization, not authentication. The host application remains
responsible for users, sessions, JWTs, cookies, persistence, revocation,
caching, and server-side enforcement.

## How we built it

Mizan is a fixed-version TypeScript monorepo. The core package owns the
decision algorithm and source contracts, while the memory package provides a
small reference adapter for tests and examples. This keeps the core
independent from Prisma, Drizzle, PostgreSQL, SQLite, Redis, or any other
storage choice.

### Codex and GPT-5.6 collaboration

Mizan was developed for OpenAI Build Week using Codex and GPT-5.6 as the
planning, architecture, and review layer. The human builder owned the product
direction, architectural decisions, acceptance criteria, trade-offs, and final
review.

ChatGPT/GPT-5.6 and Codex were used to:

- turn the authorization concept into a small, testable v0.1 architecture;
- design the source/adapter boundary and decision model;
- break the work into milestones and focused implementation tasks;
- define acceptance criteria and test scenarios;
- inspect changes, find edge cases, and review the resulting behavior;
- guide the documentation and interactive demo story.

Coding-capable worker agents/models carried out the implementation tasks under
those decisions. This was a deliberate separation: stronger reasoning models
focused on architecture and review, while specialized coding agents handled
the repository changes. Codex was the shared engineering workspace and
workflow used to coordinate that collaboration; it is not presented as the
sole author of the implementation.

The important boundary is that AI-assisted implementation does not move
application data ownership into Mizan: adapters provide facts, while Mizan
remains the decision layer.

The required Codex session information is provided in the Devpost submission
rather than committed to this repository.

## Challenges we ran into

The main challenge was balancing useful defaults with freedom for existing
applications. A library that owns the schema is easy to start with but quickly
becomes difficult to reuse, so we kept storage and authentication outside the
core and made the adapter boundary explicit.

We also had to make precedence and time behavior visible rather than hiding it
inside a boolean helper. A direct denial must remain stronger than a role grant,
and a scheduled grant must be evaluated against one consistent clock across the
sidebar, table actions, and actual mutation path. Finally, the multi-agent
workflow required tests, review gates, and human decisions so that speed did not
replace correctness.

## Accomplishments that we're proud of

- A small reusable authorization core with no ORM or authentication coupling.
- A memory adapter that acts as a reference for custom adapters.
- A fixed-version monorepo structure ready for future integrations.
- Explainable decisions with stable denial reasons instead of opaque booleans.
- Coverage for role grants, direct grants, denial precedence, scopes, temporal
  windows, schedules, and source behavior.
- An interactive browser demo that shows the decision layer working end to end.
- A documented AI-assisted development process using Codex and GPT-5.6.

## What we learned

We learned that the most reusable abstraction is not a database model but a
clear capability boundary: the adapter translates application data into facts,
and the authorization engine decides. We also reinforced that UI visibility is
only a user-experience concern; every protected operation must be checked again
at the server or API boundary.

Working with AI agents also made the engineering process itself important.
Small milestones, explicit acceptance criteria, automated tests, adversarial
review, and a final human decision made the collaboration much more reliable
than asking one model to generate an entire system without checkpoints.

## What's next for Mizan

The next steps are driven by real applications rather than by trying to solve
every authorization problem at once:

- keep the v0.1 core stable while improving adapter ergonomics and examples;
- add useful, tested integrations for common database and framework setups;
- support composed sources for database facts, cache lookups, and revocation
  workflows without moving those responsibilities into the core;
- explore resource-aware rules and a small ABAC extension for ownership and
  tenant-aware decisions;
- add optional tooling for policy import, synchronization, audit events, and
  administration;
- publish stable fixed-version releases as the API matures toward v1.

## Hackathon testing path

Judges can test the project locally without setting up a database, ORM, authentication provider, or external service:

~~~bash
git clone https://github.com/AmaraNecib/mizan.git
cd mizan
bun install
bun run typecheck
bun run test
bun run build
cd examples/interactive-decision-demo
bun run dev
~~~

Then open the local demo URL and follow the interactive scenarios above.

## Status

Mizan is an early open-source release focused on a dependable decision core and a clear adapter boundary. The API will evolve as integrations and real-world usage reveal the next needs. The goal is to grow capability without forcing every application to change its existing data model.

## License

Mizan is released under the MIT License. See LICENSE.
