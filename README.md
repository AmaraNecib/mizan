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
- **Admin** — has full car actions but cannot manage policy;
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

1. Admin can perform the car actions but cannot open policy controls.
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

## Built with Codex

Mizan was developed for OpenAI Build Week using Codex and GPT-5.6.

The human builder owned the product direction, architectural decisions, acceptance criteria, trade-offs, and final review. Codex and supporting AI agents were used to:

- turn the authorization concept into a small, testable v0.1 architecture;
- design the source/adapter boundary and decision model;
- implement the core evaluator and memory adapter;
- create tests for grants, denials, scopes, temporal windows, schedules, and source behavior;
- review changes, find edge cases, and improve documentation;
- build the interactive decision demo used for evaluation.

The important design decision is that AI-assisted implementation does not move application data ownership into Mizan: adapters provide facts, while Mizan remains the decision layer.

The required Codex session information is provided in the Devpost submission rather than committed to this repository.

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