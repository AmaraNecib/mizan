# Mizan #59 design

Tier: High-assurance. Base: `fd30fb5fe9a40c1a87b5404477502dfe9cd8276f`.

## Authorized seam

Add a pure `expandRoles` function at `@mizan/core/normalization`. Callers pass role definitions, role assignments, and optional direct effective facts. The result contains effective facts and bounded diagnostics. The helper does not evaluate a permission or read the clock. The host may pass its result to `evaluate` through the existing direct-evaluation seam.

## Input and output

Use dedicated role-definition and assignment types expressed with the core's effective fact vocabulary. Role permission facts carry permission pattern, effect, optional scope, absolute epoch-millisecond bounds, and optional provenance. Assignments carry a role name, optional scope, validity bounds, and optional provenance. Definitions and assignments do not hardcode a principal identifier or storage shape.

Return `{ facts, diagnostics }`. Diagnostics are capped and report omitted facts caused by conflicting scope values or an empty validity intersection. Missing role references, duplicate role names, unsupported schedule/semantic keys, and malformed values throw `AuthorizationFault`.

## Normalization rules

Validate every definition, assignment, and direct fact before expansion, including unused roles. Require plain data records, string-keyed known properties, dense arrays, safe integer bounds, supported permission patterns and effects. Reject accessors and symbols. Copies isolate results from caller-owned scopes and arrays.

Assignment and permission scopes combine by dimension. Equal duplicate values remain; conflicting values suppress that effective fact. Validity uses the maximum present start and minimum present expiry. A start greater than or equal to expiry suppresses the fact. Apply both rules to grants and denials. Assignment provenance takes precedence only when the permission fact has none; otherwise keep permission provenance. Append validated direct facts without semantic changes.

## Tests

Test only the public package subpath. Use vertical red-green slices for basic grant expansion, intersection of scope and validity for both effects, empty/conflicting intersections, direct facts, validation of unused definitions and malformed objects, duplicate/missing roles, and unsupported schedule fields including explicitly undefined schedules. Add a generic administrative adapter fixture and consumer runtime/type probe. The fixture maps a host role grant and active revoke denial; host audit, recovery and transaction ownership are explicit, with no claim that Mizan replaces the administrative service.

## Risks and limits

The package does not define a host role table, principal model, revocation transaction, audit log, recovery process, or authorization/write atomicity. Normalization preserves supplied constraints; it cannot establish that host data is complete or current. Recurring schedules remain unsupported and fail explicitly.

## Proof record

Each red and green command, result, and typecheck will be recorded under `.scratch/evidence/59/`. Run guard Phase 1 with full typecheck and tests before committing. Parent owns independent review and integration lifecycle.
