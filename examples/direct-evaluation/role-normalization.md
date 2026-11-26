# Role normalization

`@mizan/core/normalization` converts trusted role definitions and assignments into `EffectiveFact` values. It does not load host records, check the current time, or decide access. Pass the facts to `evaluate` at the host-selected instant.

```ts
import { evaluate } from "@mizan/core";
import { expandRoles } from "@mizan/core/normalization";

const { facts } = expandRoles(
  [{ name: "records-editor", permissions: [{ permission: "records.edit", effect: "grant" }] }],
  [{ roleName: "records-editor", scope: { organization: "north" }, expiresAt: 1_800_000_000_000 }],
  [{ permission: "records.edit", effect: "deny", startsAt: 1_700_000_000_000 }],
);

const decision = evaluate({
  action: "records.edit",
  at: Date.now(),
  scope: { organization: "north" },
  snapshot: { facts, knownActions: ["records.edit"] },
});
```

A generic administrative adapter can map a stored role permission to the role definition and a user's role link to an assignment. A separately recorded revoke maps to a direct `deny` fact with its active window. Mizan preserves that denial and lets `evaluate` apply it over a grant.

The host remains responsible for validating the administrator, writing grant/revoke records and audit entries in its transaction, enforcing its recovery procedure, and making the protected update atomic with the authorization check when needed. This helper does not replace the host's administrative service, audit system, storage, or transaction policy.

Unknown role references, duplicate role names, malformed facts, and schedule or other unsupported fields throw `AuthorizationFault`. Scope conflicts and empty validity intersections produce no effective fact and appear in the bounded diagnostics. Diagnostics cap at 20 entries; `omittedDiagnostics` reports the remaining count.
