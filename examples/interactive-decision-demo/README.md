# Interactive Authorization Decision Gallery

This example demonstrates how Mizan's authorization decision layer works
through an interactive cars table. Switch the active principal between
Admin and Support, toggle demo-only policy controls for Support, and
watch how the same protected actions resolve differently — all through
real `@mizan/core` + `@mizan/memory` evaluations.

## Run

```bash
# From the repository root
bun install
cd examples/interactive-decision-demo
bun run build
```

Then open `index.html` in your browser (or serve with any HTTP server).

## What it shows

| Feature | Description |
|---------|-------------|
| **Principal switcher** | Toggle between Admin and Support — table action buttons update from real Mizan decisions. |
| **Cars table** | Read, Create (via button), Update, and Delete actions on an in-memory car list. |
| **Protected action path** | Every click performs `decide()` through Mizan before mutating the table. |
| **Presentation mode** | Denied actions can be shown disabled (with reason badge) or hidden entirely. |
| **Policy controls (Support)** | Toggle a `cars.update` grant and a `cars.delete` deny override in real time — the table re-evaluates without a page reload. |
| **Schedule demo** | A permission restricted to Mon–Fri business hours, evaluated at two different times. |

## Permission matrix

| Permission | Admin | Support (initial) | Support (+grant) | Support (-deny) |
|------------|-------|-------------------|------------------|-----------------|
| `cars.read` | ✅ allow | ✅ allow | ✅ allow | ✅ allow |
| `cars.create` | ✅ allow | ✅ allow | ✅ allow | ✅ allow |
| `cars.update` | ✅ allow | ❌ no-grant | ✅ allow | ❌ no-grant |
| `cars.delete` | ✅ allow | ❌ matching-denial | ❌ matching-denial | ✅ allow |

## How it maps to a real application

In a production system:

- The **MemoryAdapter** would be replaced by a database adapter storing
  role definitions and assignments.
- The **policy source** would be an exceptions table or a policy-as-code
  engine.
- The **UI toggles** would be an admin interface backed by a real database,
  not in-memory state.
- Most importantly: every protected API endpoint or server action would
  **repeat the Mizan check** before performing the operation. UI toggles
  are for UX only — the server is the enforcement boundary.

## Stack

- Plain TypeScript + semantic HTML + CSS (no React, Vite, TanStack)
- `bun build` for compilation
- `@mizan/core` for authorization evaluation
- `@mizan/memory` MemoryAdapter for role-based grants
- Custom `MutablePolicySource` for runtime policy controls
