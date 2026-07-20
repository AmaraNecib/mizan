# Interactive Authorization Decision Gallery

This example demonstrates how Mizan's authorization decision layer works in a
browser environment. It compares two principals (Admin and Support) side by
side using the real `@mizan/core` and `@mizan/memory` packages.

## Run

```bash
# From the repository root
bun install
cd examples/interactive-decision-demo
bun run build
```

Then open `index.html` in your browser (or serve it):

```bash
# e.g. with Python
python -m http.server 8080
# or with Bun
bunx serve .
```

## What it shows

| Principal | Permission       | Result | Reason              | Source                       |
|-----------|-----------------|--------|---------------------|-----------------------------|
| Admin     | `cars.read`     | allow  | —                   | Admin role (`memory`)       |
| Admin     | `cars.delete`   | allow  | —                   | Admin role (`memory`)       |
| Support   | `cars.read`     | allow  | —                   | Support role (`memory`)     |
| Support   | `cars.delete`   | deny   | `matching-denial`   | Denials source (custom)     |
| Admin     | `schedules.read`| allow  | — (Monday 10:00)    | Role with schedule          |
| Admin     | `schedules.read`| deny   | `outside-schedule`  | Role with schedule (Sunday) |

## How it maps to a real application

In a real app, the memory adapter would be replaced by a database-backed
adapter that stores roles, assignments, and per-user overrides. The "denials"
source might be a separate table for exceptions. The core evaluation logic
remains the same — adapters provide facts, Mizan makes the final decision.

## Architecture

```
┌─────────────┐     facts      ┌──────────────────┐
│ MemoryAdapter│ ─────────────→ │                  │
│ (roles,     │               │  @mizan/core      │ ←── decide("cars.read")
│ assignments)│               │  (evaluate)       │
└─────────────┘               │                  │ → AuthorizationResult
                              │                  │
┌─────────────┐               │                  │
│ Denials src │ ─────────────→ │                  │
│ (override)  │    facts      └──────────────────┘
└─────────────┘
```

## Constraints met

- ✅ Plain TypeScript, semantic HTML, CSS — no React, TanStack, Vite
- ✅ Uses `bun build` for compilation
- ✅ Calls real `@mizan/core` + `@mizan/memory` packages
- ✅ Admin and Support side by side with same permissions checked
- ✅ `cars.read` allows for both
- ✅ `cars.delete` allows Admin, denies Support with `matching-denial`
- ✅ Schedule scenario showing `outside-schedule`
- ✅ No SQLite, ORM, auth, JWT, caching, guards, network calls, or fallback
- ✅ No duplicated authorization logic in UI code
