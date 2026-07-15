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
A host-provided module that obtains authorization facts from a data source and presents them to Mizan in the form required by the core.
_Avoid_: Database adapter when the source is a JWT, session, JSON document, API, or another non-database source.

**Authentication context**:
Verified identity and request information supplied by the host authentication layer to an authorization adapter.
_Avoid_: Token parser, session manager.

**Cache ownership**:
The host application owns the cache store and its freshness, invalidation, and revocation policy. Mizan may provide interfaces or composition helpers but does not require or own a cache service.

