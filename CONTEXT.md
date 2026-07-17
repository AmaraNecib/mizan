# Mizan Authorization

Mizan is an open-source, runtime-neutral TypeScript authorization library. It evaluates authorization facts supplied by the host application or an adapter; authentication, persistence, and cache ownership remain outside the core.

## Language

**Authorization**:
The decision about whether a subject may perform an action in a given context.
_Avoid_: Authentication, which establishes who the subject is.

**Decision layer**:
The part of Mizan that evaluates authorization facts and returns an allow or deny decision.
_Avoid_: Auth service, authorization database, policy server.

**Authorization adapter**:
An integration module that obtains authorization data from one or more host data sources and exposes one or more named authorization sources to Mizan. Each registered source is a focused resolver/capability; source plans compose those sources. An adapter may be built in, custom, extended, or composed from another adapter, but it does not make the final authorization decision. Built-in adapters expose structural source contracts that can be configured, replaced, or wrapped without class inheritance. If an adapter internally uses multiple stores, that composition remains its implementation detail unless exposed as separate sources.
_Avoid_: Database adapter when the source is a JWT, session, JSON document, API, or another non-database source.

Built-in adapters are defaults for common data models and integrations, not a requirement to publish an adapter for every host schema. A project may keep a private adapter inside its own repository, configure a built-in adapter, decorate or replace one capability, or implement the adapter from scratch. Once the adapter satisfies Mizan's source and capability contracts, the core consumes its normalized outcomes and makes the authorization decision without caring where the data originated. An adapter that violates the contract is not interchangeable merely because it returns similarly named values.

**Authorization management capability**:
An optional host-facing capability for changing or administering authorization data, such as creating roles, assigning access, applying overrides, or importing definitions. It is separate from the decision layer: the core can evaluate authorization without requiring management operations, and an adapter or plugin may expose only the operations its host model supports. Management does not impose a universal CRUD schema or replace host-owned business validation and persistence.
_Avoid_: Making `can()` depend on a management API, or assuming every host can support the same role and relationship mutations.

**Authorization capability**:
A named, optional group of operations exposed by an adapter or plugin, such as role management, permission synchronization, import/export, auditing, or another host-specific extension. Capabilities are explicit integration surfaces rather than mandatory methods on the core or on every adapter; the decision layer remains usable when a capability is absent.
_Avoid_: A universal adapter interface filled with unrelated optional methods, or silently pretending an unsupported capability exists.

Management operations are independent by default: creating a permission catalog entry does not grant it, granting a permission to a role does not assign that role to a principal, and assigning a role does not replace direct grants or denials. An adapter may optionally expose a host-native transaction helper to compose these operations atomically; Mizan does not emulate transactions across unrelated stores.

Management creation has two intentional modes: strict creation reports a conflict when the identity already exists, while an idempotent ensure operation returns the existing matching definition or creates it for seeding, synchronization, and startup setup. Ensure must not silently overwrite a conflicting existing definition; conflicts remain explicit.

**Capability extension**:
An adapter or plugin may add a new named capability or decorate an existing capability with lifecycle behavior such as before, after, and error handling. This provides integration points for auditing, logging, metrics, monitoring, and host-specific validation without moving those concerns into the authorization evaluator. Whether a hook is observational or allowed to control an operation is an explicit contract decision, not an implicit side effect.
_Avoid_: Hidden hooks that change authorization outcomes or silently alter management data.

Observers are non-controlling lifecycle extensions: they may record or measure an operation but cannot change its input, result, or success. Interceptors are explicitly controlling extensions: they may validate, transform, or reject an operation according to their declared contract. An observer is never implicitly promoted to an interceptor.

Applications choose extension order through an explicit Mizan composition tool rather than relying on hidden global plugin priority. The extension kind should also be explicit in the API: an interceptor is constructed and typed as a controlling wrapper, while an observer is constructed and typed as a non-controlling lifecycle listener.

Observer failures are best-effort by default: a logging, metrics, or monitoring failure must not silently change a successful management operation into a failed one. A host may explicitly require a durable observer when the operation must not succeed without the audit or side effect; required observer failure is then an explicit operation policy rather than an implicit hook behavior.

Decision observers may observe `can()` or `decide()` outcomes for auditing, metrics, and monitoring, but ordinary capability interceptors cannot alter those authorization outcomes. Any extension that controls authorization semantics must be an explicit evaluator or policy extension so the core does not acquire a hidden second decision engine.

Custom capabilities are generic over their input, result, and host context, and their types are inferred from registration. Built-in and user-defined capability operations, interceptors, and observers therefore retain their domain-specific types without requiring the core to know every business operation; runtime capability absence remains an explicit unsupported condition.

The built-in management seams are conceptually separated by responsibility: permission management creates or ensures catalog definitions; role management creates or ensures role definitions and manages role-to-permission relationships; role assignment manages principal-to-role relationships; and override management creates or removes direct grants and denials. `protectCapability` is a core helper that wraps any capability with an explicit authorization check while leaving the raw capability available to trusted jobs, seeds, and migrations.

`Deny` is an authorization fact and is distinct from removing a grant or revoking an authentication session. `Ensure` is an idempotent operation mode for stable management identities such as permissions, roles, or assignments; temporal or overlapping access rules require explicit rule-management semantics rather than an ambiguous generic ensure.

In the initial management surface, `deny()` creates a direct denial for a principal. Removing a permission from a role is a separate `removePermission()` operation; role-level denial facts are deferred until a concrete use case requires their additional precedence and management semantics.

Import/export is an optional capability, not a mandatory core management API. Import supports a validation-only dry run and an explicit apply mode; apply is additive and idempotent by default, does not silently delete omitted data, and reports missing principals, conflicts, and mapping failures. Destructive replacement requires a separate explicit contract. The importer composes management capabilities through the host adapter rather than writing a universal schema directly.

Portable authorization documents use a canonical Mizan shape with a version and semantic principal references; adapters provide the mapping from those references to host-specific users, employees, tenants, and relationships. Host storage records are not themselves the portable import format.

Capability identifiers are explicit and collision-safe: built-in names are reserved, custom adapter and plugin capabilities use a namespace, and duplicate registration fails during setup. Replacing an existing capability is never an accidental side effect of registration; it requires an explicit decorator or replacement operation.

Mizan is authorization-model neutral. A built-in RBAC adapter may cover common role and permission schemas, while custom schemas use custom sources or adapter mappings. ABAC and other business-specific semantics are supplied through explicit typed evaluator extensions; adapters provide facts or attributes and do not return hidden final allow/deny decisions.

**Adapter conformance suite**:
A repository-internal set of generic contract tests used to verify Mizan's own core, built-in adapters, source composition, decorators, replacements, and test fixtures. It may use the monorepo's chosen development runtime and test runner, such as Bun and `bun:test`; that tooling is not a runtime dependency of Mizan's library packages. The suite uses neutral principals, permissions, roles, grants, and denials and does not require publishing private adapters or revealing host schemas.
Private project adapters may test the same contract locally with their own runner. The test scenarios and fixture boundaries should remain easy to extract later into a minimal, separately published `@mizan/testing` package, but that package is deferred and does not block v0.1.
_Avoid_: Making the runtime depend on Bun or confusing Mizan's internal test suite with the future public adapter-testing package.

Optional sources and guards are adapter- and plan-dependent. A JWT-only adapter may intentionally expose only a verified authorization source and no cache or revocation guard. The core conformance suite must not require those optional features, but a plan that explicitly requires a missing guard or authoritative source must reject the configuration or fail closed; it must not silently downgrade to JWT-only authorization.

The internal test suite must cover source-plan and guard semantics independently with deterministic test sources: fallback, merge, authoritative empty/unavailable results, deny precedence, guard short-circuiting, and per-request memoization. Adapter integration suites run only the source and optional capabilities an adapter declares; a read-only JWT adapter is not required to pass cache, revocation, or management tests.

**Authorization source**:
A single adapter-backed resolver of authorization-related data. A source may read a token claim set, memory snapshot, Redis store, database, API, file, or another host-defined data source; its storage technology does not determine whether it is a cache, fallback, or authoritative source. In v0.1, a source resolves a context-wide fact set from the verified context, evaluation time, and cancellation signal rather than receiving a permission or resource query; Mizan evaluates individual permissions afterward. Multiple named sources may contribute to the same authorization concern, but their ordering and composition belong to a source plan rather than to an implicit source-internal adapter list.
_Avoid_: Inferring a source's authority or freshness from names such as `cache`, `database`, or `jwt`.

**Source plan**:
A named, application-defined, type-safe composition of authorization sources that defines how facts are obtained, such as fallback, merge, or an authoritative requirement. A plan is selected by application policy for a permission or authorization concern; Mizan evaluates the resulting facts. In a merge plan, source facts form an additive union, duplicate facts are idempotent, and matching denials remain restrictive; source members are required by default unless explicitly marked optional. `required` describes whether a source must return an acceptable result, not whether it must independently grant the permission. Mizan derives types for source and plan references and validates runtime references, but it does not invent semantic plan names. Authority and freshness are plan behavior, not permanent properties inferred from a source or adapter name; the same source may be ordinary in one plan and required authoritative in another.
_Avoid_: A universal hardcoded adapter order, or treating source selection as an adapter's authorization decision.

**Authorization snapshot**:
The normalized, evaluation-ready set of semantic authorization facts—such as roles, permissions, assignments, grants, and denies—supplied for an authentication context so Mizan can make a decision. Facts may carry decision-relevant metadata such as effect, temporal validity, scope, and explanation information, but the snapshot is not a precomputed allow or deny result.
An authorization context may resolve multiple plan-scoped fact sets lazily; Mizan does not require one universal snapshot to be loaded before every `can()` call.
_Avoid_: Raw database record, token payload, or adapter-specific response.

**Authorization fact**:
A semantic statement about a subject's authorization, such as role membership, a permission grant or denial, validity, or scope, that an adapter supplies and Mizan interprets. Source-specific records are normalized into canonical core facts before evaluation; an adapter may preserve role definitions/assignments or provide already-flattened grants and denials, but it does not decide whether the action is allowed. Unknown semantic fact kinds are not silently accepted as effective authorization; new fact semantics require an explicit evaluator/extension.
_Avoid_: Database row, pivot record, or unprocessed token claim.

**Grant and denial precedence**:
Active role-derived grants, direct grants, and temporary grants are additive. An active matching denial is restrictive and overrides those grants for the same permission after temporal and scope filtering. If no matching grant remains, the result is deny by default.
_Avoid_: Treating every override as replacing the user's complete permission set, or allowing a denial for one permission to remove unrelated permissions.

**Authorization scope**:
An optional semantic boundary that limits where an authorization fact applies, such as an organization, workspace, team, or other host-defined domain. In the canonical model, a fact carries at most one scope; adapters normalize source-specific scope arrays into separate facts. An omitted scope is global, while an explicitly empty source collection produces no fact rather than a global fact. Mizan may support simple scope matching without hardcoding a particular tenant concept; richer ownership and attribute-based conditions remain later extensions.
_Avoid_: A mandatory `tenantId` field, database-specific foreign key.

**Permission catalog**:
The application-defined set of permission keys recognized as valid. It may be declared in code, generated from an authoritative source through adapter tooling, or combined as a static-plus-runtime catalog. Static keys provide compile-time types; runtime keys must be validated by the catalog before a strict authorization API accepts them. Runtime catalog loading, snapshots, TTLs, version checks, and invalidation are host-controlled; Mizan does not assume that an in-memory refresh reaches every deployed or serverless instance. Unknown raw keys are denied; authorization checks do not create or mutate the catalog.
_Avoid_: The permissions currently granted to one principal, or a role-to-permission assignment store.

**Authorization policy**:
Application-owned configuration that maps permissions or authorization concerns to source plans and required assurance. It may require a cache-first plan for ordinary operations or an authoritative source for sensitive operations. Code-defined permission, source, and plan identifiers should be type-safe; runtime-defined identifiers must be validated when loaded and unknown references must not silently fall back.
For v0.1, source plans and routing for sensitive permissions are defined in TypeScript, while roles, assignments, grants, denials, and temporal data may come from runtime adapters. Policy routing is deterministic: exact permission rules outrank the most-specific namespace rule, which outranks the global rule; ambiguous equally specific rules are invalid. Callers cannot select or weaken a plan at the `can()` call site.
_Avoid_: Embedding storage-specific assumptions in the Mizan core, or exposing freshness and source selection as repeated untyped strings at every `can()` call.

**Source availability policy**:
A source plan distinguishes a normal `miss` from an `unavailable` source. A successfully resolved complete empty fact set is a valid answer and is not a miss. A miss may continue to the next source according to the plan. An unavailable non-authoritative cache may also continue to an explicitly configured authoritative fallback, while an unavailable authoritative source denies by default. Mizan must not silently fail open or infer fallback behavior from the source's storage technology or name.
_Avoid_: Treating outages as empty authorization data, or globally falling back to stale or weaker sources for sensitive decisions.

**Source error semantics**:
Invalid source/plan/catalog configuration is rejected before the evaluator serves decisions. Expected runtime failures such as timeouts are represented as `unavailable` and handled by the selected plan; they are not silently converted into `miss` or empty facts. Malformed adapter output is a contract error that fails closed and is surfaced diagnostically, rather than being treated as valid authorization data.

**Source freshness policy**:
A source may report whether its resolved facts are fresh, stale, or unknown, while the source plan decides which states may be used. Missing or unverifiable freshness is `unknown`, never implicitly `fresh`. The v0.1 default is `stale: "fallback"`: stale or unknown data is not used automatically, the plan tries an acceptable next source, and the final result denies if no trustworthy source remains. An application or plan may explicitly opt into stale data for eventual-consistency use cases; sensitive authorization and revocation guards should retain a fresh or authoritative requirement.
_Avoid_: Letting a global relaxed setting silently weaken a sensitive plan, or making Mizan own cache TTL and invalidation logic.

**Authorization guard**:
A precondition evaluated before permission facts, such as session validity, token revocation, or principal suspension. A guard may use its own source plan and may deny the authorization context before Mizan evaluates grants, roles, or permission patterns. Revocation is not itself a permission grant and should not be mixed into ordinary authorization-source merging.
Guard outcomes are separate from authorization facts: a passing guard permits evaluation to continue, a denial short-circuits the context, and an unavailable authoritative guard fails closed according to its plan. Multiple configured guards compose with an all-must-pass rule. For v0.1, a request-bound `forContext()` evaluates and memoizes the guard result for that authorization context only; the result is never shared across requests. Cross-request TTLs and shared guard caches remain host-owned future optimizations. Trusted `forPrincipal()` usage does not automatically require a session guard.
_Avoid_: Allowing a permission grant to override a failed session guard, or treating a revocation lookup as ordinary permission data.

**Request authorization context**:
A request-bound evaluator created from a host-verified authentication context. It memoizes the guard result once per request, coalesces concurrent resolution of the same plan, and resolves each required authorization source plan lazily. Results for a plan may be reused by later checks in the same request, while different plans—such as cache-first for reads and authoritative database access for deletes—remain independent. No result is shared across requests by the core.
_Avoid_: Treating `forContext()` as a long-lived user authorization object, or eagerly loading every possible permission source for every request.

**Authorization check API**:
The core `can(permission)` operation is asynchronous for every source type, including in-memory and token-backed sources, so callers have one consistent and safe contract. A synchronous API is not part of the v0.1 core contract; a later sync-only snapshot API must be explicit rather than returning `boolean | Promise<boolean>`. The core also exposes `decide(permission)`, which returns a structured decision with a stable reason code; `can()` returns only that decision's boolean result.
The default decision does not expose raw facts, claims, database rows, or adapter internals. An explicit explanation mode may add bounded plan/source provenance and matched-fact summaries for trusted diagnostics or auditing.

The v0.1 core `can(permission)` contract evaluates context-wide authorization facts. Resource-aware ownership and ABAC behavior are explicit typed evaluator extensions rather than hidden adapter decisions or a mandatory resource argument on every check. Adapters supply facts and attributes; an evaluator extension interprets resource-specific semantics.

Expected authorization outcomes do not throw: missing grants, matching denials, expired facts, failed revocation guards, and source unavailability resolve to a denied boolean or a structured denied decision according to the source plan. Invalid configuration, malformed adapter output, and incompatible extension contracts are developer-facing errors that fail explicitly rather than being disguised as ordinary denial.

Structured decisions use stable machine-readable reason codes. Human-readable messages and bounded plan/source/fact details are opt-in explanation data for trusted diagnostics or auditing; raw claims, rows, and adapter internals are not part of the default result.

**Permission pattern**:
A limited permission matcher used by the evaluator. The v0.1 model supports an exact key, the global pattern `*`, and a namespace pattern such as `files.*`; patterns do not make undefined permission keys valid, and arbitrary glob or regular-expression semantics are not part of the core contract.
_Avoid_: Treating a pattern as a business operation, or allowing unrestricted pattern syntax from untrusted data.

**Principal**:
The subject whose authorization is being evaluated, identified by a trusted authentication context or by trusted server-side code. A principal is not a raw token and must not be accepted from an untrusted client claim without host-side verification.
_Avoid_: Token, session record, arbitrary client-supplied user ID.

**Role assignment**:
A semantic fact linking a principal to a role. An assignment may carry temporal validity, an optional authorization scope, and source metadata; adapters translate the host application's relationship into this fact.
_Avoid_: A particular user-role table, group membership record, or permanently active role string.

**Role definition**:
A semantic authorization construct that associates a role with permission facts. A role definition does not authorize a principal until an applicable role assignment is active. Role-derived facts may retain their role provenance for explainable decisions; sources without role information may provide flattened grants instead.
_Avoid_: A database row shape, an authentication role claim treated as trusted by itself, or an executable business operation.

**Temporal validity and schedule**:
An authorization fact may have an optional absolute validity window and an optional recurring schedule. Absolute validity uses a half-open interval: `startsAt <= now < expiresAt`; a missing start means immediately active, a missing expiry means no absolute expiry, and both missing means permanent. If a schedule exists, the fact is active only when both the absolute window and schedule match. The v0.1 schedule contract supports an IANA time zone, weekly windows, date-specific windows, multiple windows per day, and overnight windows such as `22:00-06:00`; an absent schedule means active throughout the absolute window. Full calendar recurrence rules, holidays, and complex exception systems remain future extensions.
_Avoid_: Treating an expiry timestamp as a complete scheduling engine, relying on the server's implicit local time zone, or silently interpreting an empty schedule as global access.

**Authentication context**:
Verified identity and request information supplied by the host authentication layer to an authorization adapter. It may carry the principal for a request, while the host remains responsible for authenticating and validating that identity.
For v0.1, it may include a verified principal, opaque session or token identifiers for guards, request metadata, and other host-controlled metadata. Raw tokens, cookies, credentials, and unverified claims remain outside the core; adapters may translate verified host data into authorization facts, but Mizan makes the final authorization decision.
_Avoid_: Token parser, session manager.

**Cache ownership**:
The host application owns the cache store and its freshness, invalidation, and revocation policy. Mizan may provide interfaces or composition helpers but does not require or own a cache service.
