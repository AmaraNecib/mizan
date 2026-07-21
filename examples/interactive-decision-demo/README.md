# Authorization Decision Ledger

An interactive authorization playground demonstrating Mizan's decision layer.
Switch between three principals, observe how protected actions resolve, and
explain **why** — all through real `@mizan/core` + `@mizan/memory` evaluations.

## Quick start

```bash
# 1. Install dependencies (from repository root)
bun install

# 2. Build the demo
cd examples/interactive-decision-demo
bun run build

# 3. Serve over HTTP — opening index.html via file:// will NOT work
#    because the browser enforces CORS on ES-module-style bundler output.
#    Use any static server:
bunx serve .
#    or: npx http-server .
#    or: bunx http-server .
```

Then open **http://localhost:3000** (or whatever port your server uses) in a browser.

## What it demonstrates

| Concept | Implementation |
|---------|---------------|
| **Three principals** | Super Admin (full access + policy management), Admin (full cars access), Support (restricted) |
| **Protected actions** | Every cars-table click calls `decide()` through Mizan before mutating state |
| **Denial reasons** | `matching-denial` for the delete override, `no-grant` for missing update permission |
| **Decision banner** | Current decision shown above the fold: actor, action, ALLOW/DENY, reason |
| **Decision trace** | Running log of every evaluation, visible below the table |
| **Policy editor** | Super Admin only — grant/revoke Support's update, add/remove delete-deny override |
| **Temporal schedule** | Configurable business hours with controllable evaluation clock; `outside-schedule` when outside |
| **Presentation mode** | Denied table actions shown disabled with reason, or hidden entirely |
| **Security disclaimer** | Explicit statement that UI toggles don't enforce — production must check server-side |

## Permission matrix

| Permission | Super Admin | Admin | Support |
|-----------|-------------|-------|---------|
| `cars.read` | ✅ | ✅ | ✅ |
| `cars.create` | ✅ | ✅ | ✅ |
| `cars.update` | ✅ | ✅ | ❌ `no-grant` |
| `cars.delete` | ✅ | ✅ (schedule) | ❌ `matching-denial` |
| `manage-policy` | ✅ | ❌ `no-grant` | ❌ `no-grant` |
## How the schedule works

Super Admin can enable/disable the schedule restriction on Admin's `cars.delete`
and adjust the UTC business-hours window. A controllable evaluation clock
advances or rewinds time — within hours the permission allows, outside it
returns `outside-schedule`. Admin and Support can see the schedule status but
cannot modify the settings.

The schedule restriction is enforced by the real Mizan `cars.delete` decision
evaluated at the demo clock time. Changes to the schedule are separately gated
by the real Mizan `manage-policy` decision, so non-Super Admin users are blocked
by the authorization engine, not just by disabled UI controls.

## Stack

- Plain TypeScript + semantic HTML + CSS (no React, Vite, TanStack, UI kit)
- `bun build` for compilation
- `@mizan/core` for all authorization evaluation
- `@mizan/memory` MemoryAdapter for role-based grants
- Custom `MutablePolicySource` for runtime policy controls

## Production caveat

This demo's policy editor modifies **in-memory state only**. A production
application would:
1. Store policy in a database or policy-as-code engine
2. Repeat every Mizan `decide()` call on the server or API boundary
3. Never rely on UI hiding or disabling for enforcement
