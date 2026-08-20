# Cirreum.Authentication.External Changelog

All notable changes to **Cirreum.Authentication.External** are documented in this file.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) — [SemVer](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Updated

- Updated NuGet packages.

## [2.1.1] - 2026-08-19

### Updated

- Updated NuGet packages.

## [2.1.0] - 2026-08-17

### Added

- **Declares `SubjectKind.Human`.** BYOID schemes federate a customer's own identity provider —
  the caller is that customer's user, not the tenant as a thing. The registrar registers and
  declares the scheme in one call through `IAuthenticationBuilder.AddScheme` (the registration
  funnel, `Cirreum.AuthenticationProvider` 3.0.1), carrying the instance's `ClaimAuthority`
  block — this registrar overrides `RegisterScheme` wholesale, so it declares for itself.

### Changed

- `RegisterScheme` takes `IAuthenticationBuilder` per the `Cirreum.AuthenticationProvider` 3.0.1
  contract consolidation. Registrar plumbing only; not app-facing surface.

### Updated

- Updated NuGet packages.

## [2.0.3] - 2026-08-04

### Updated

- Updated NuGet packages (Cirreum spine 4.2.0 wave: `Cirreum.Contracts` 4.2.0 / `Cirreum.Domain` 4.2.0 and current patch releases).

## [2.0.2] - 2026-07-31

### Updated

- Updated NuGet packages (Cirreum spine 4.0.1 wave: `Cirreum.Contracts` 4.0.1 / `Cirreum.Domain` 4.0.1 / `Cirreum.Kernel` 2.0.1 / `Cirreum.AuthenticationProvider` 2.0.3).

## [2.0.1] - 2026-07-29

### Updated

- Updated NuGet packages.

## [2.0.0] - 2026-07-27

### Added

- **Tenant-resolution caching.** `IExternalTenantResolver` previously ran on every authenticated
  request, so a resolver reading tenant rows from a database made a round trip per request while
  JWKS and IdP metadata were already cached. Configured under `TenantResolverCache`
  (`DurationSeconds`, `NotFoundDurationSeconds`, `MaxEntries`) and **off unless `DurationSeconds`
  is set** — caching widens the window in which a tenant disabled at the source still
  authenticates, which is a trade an operator opts into rather than inherits.
- **`ExternalTenantConfigurationChanged`**, an authentication event an application publishes when
  a tenant's configuration changes. The framework invalidates that tenant's cache entry on every
  replica; there is no cache interface to implement, mirroring how `CredentialRevoked` reaches the
  denylist. Cross-replica delivery needs no extra wiring where coordination broadcast is already
  configured.
- **`ExternalTenantConfig.AudienceClaim` and `RequiredClaims`**, for tenants whose IdP does not fit
  the standard audience model. AWS Cognito is the case: its access tokens carry the app client ID in
  `client_id` and may have no `aud` at all, while its ID tokens carry it in `aud` — so validating
  `aud` rejects every access token, and neither kind is distinguished by it. Such a tenant sets
  `AudienceClaim = "client_id"` and `RequiredClaims = { "token_use": "access" }`.

  The two are coupled by the framework rather than by documentation: moving the audience off `aud`
  removes the check that separates an access token from an ID token, so a configuration that does so
  without supplying a claim that distinguishes them is **rejected at resolution time**. Both are
  plain data on the tenant record, so a tenant of this shape is a database row rather than a code
  path, and no vendor is named anywhere in the framework.
- **`ExternalClaimTypes`**, naming the two claims the handler stamps and reserves — `tenant_slug` and
  `auth_scheme`.
- **`ExternalTenantConfig.ValidAlgorithms`**, pinning the signing algorithms accepted for a tenant.
  Null by default, which accepts whatever that tenant's published keys support; the correct set is
  the tenant's decision and a framework-wide default would reject anyone signing with something else.
- **`ExternalDefaults.HttpClientName`** — the named `IHttpClientFactory` client used for tenant IdP
  metadata and signing keys, so an application can supply a proxy, pinned certificate, or different
  pooling without the package growing a setting for each. Registered with
  `ExternalDefaults.DefaultMetadataTimeout` (10 seconds).

### Changed

- **`AddExternalTenantResolver<T>()` no longer takes a `configure` callback.** The options type it
  configured shipped empty and nothing ever read the callback. Tenant-resolution settings are
  configuration, and now live in `appsettings.json` with the rest of the instance's settings.
- **`ExternalConfigurationManager` takes an `IHttpClientFactory`.** It previously constructed a bare
  `HttpClient` per metadata address and held it for the lifetime of the process, with no timeout and
  no seam for an application to shape the handler.
- **`ExternalResolutionContext.TokenAudience` is now `TokenAudiences`**, an `IReadOnlyList<string>`,
  because `aud` may be an array. A resolver reading the old scalar takes the first entry or checks
  `Contains`.
- **`AllowedClientIds` is matched case-sensitively.** A client ID is an opaque identifier and no
  major IdP documents it as case-insensitive, so folding case could only widen the set of accepted
  callers.
- **A request presenting no credential now receives a bare `WWW-Authenticate: Bearer` challenge**
  rather than one carrying `error="invalid_token"`. RFC 6750 §3.1 scopes that error to a credential
  that was supplied and rejected; announcing it unconditionally tells a client its token failed when
  it never sent one.
- **`ExternalAuthenticationOptions` is now a single instance.** The registrar built one object for
  the extractor, scheme selector and tenant cache, while `AddScheme` configured a second for the
  handler, kept in step by a hand-written property-by-property copy. Consumers resolving the bare
  type now receive the same instance the handler reads, post-configuration included.

### Removed

- The `idp_type` claim stamped onto the transformed identity. It was derived from
  `ClaimsHelper.ResolveProvider` — removed in `Cirreum.Kernel` 2.0.0 — and nothing in the framework
  or in any consuming application ever read it. An emitted-but-unread claim is indistinguishable
  from a working one until someone tries to use it, so it goes rather than being re-sourced.

  The `auth_scheme` claim stamped alongside it is unaffected. That one is load-bearing: it carries
  the resolved scheme, is treated as reserved, and is what downstream per-scheme dispatch depends
  on.
- **`DynamicExternalTenantOptions`**, the empty options type behind the removed `configure`
  callback.
- **Two token pre-checks that inspected what a token said about itself.** A missing `typ` header no
  longer rejects the token: `typ` is optional under RFC 7519 and omitting it is legal, so requiring
  it turned away valid tokens from IdPs the operator does not control. The `typ == "id_token"`
  check is also gone — no IdP emits that value, so it never fired, and OpenID Connect defines no
  standard marker for an ID token. Audience validation is what rejects an ID token presented as an
  access token, on every IdP: a tenant's `ValidAudiences` name this API while an ID token's `aud`
  names the client that requested sign-in. `RequireAccessTokenType` still enforces RFC 9068
  `at+jwt` for tenants whose IdP emits it.

### Fixed

- **An array-valued `aud` was read as no audience at all.** `aud` may be a single string or an array
  (RFC 7519 §4.1.3). The pre-read asked for a string, which for an array yields a single coerced
  value rather than failing — so a multi-audience token reached the resolver and the cache key with
  a partial audience, and a tenant whose `AudienceClaim` named an array-valued claim had valid
  tokens rejected. Claims are now read array-first, with a scalar fallback.
- **A malformed token could escape as an unhandled exception.** `CanReadToken` is a shallow
  structural check; `ReadJsonWebToken` still parses JSON and can throw on input that passes it, and
  the pre-read sits ahead of the validation `try`. It is now guarded, and a token that cannot be
  read fails authentication rather than the request.
- **A blank configured audience matched a blank token audience.** `ValidAudiences` is `required`, but
  nothing stopped it holding an empty string, and a token presenting an empty audience then compared
  equal — a missing configuration becoming an acceptance rather than a rejection. Blank and
  whitespace-only entries are now discarded before comparison, and a tenant left with no usable entry
  is refused outright rather than validated against an empty set. Applies to both the standard `aud`
  path and a relocated `AudienceClaim`.
- **A token carrying no `aud` claim crashed the request instead of failing authentication.** The
  pre-read used `GetPayloadValue`, which throws when the claim is absent, so the exception escaped
  `HandleAuthenticateAsync` and surfaced as a 500 rather than a 401. Omitting `aud` is legal, and it
  is what AWS Cognito issues.
- **Tenant-cache settings never reached the handler's options.** The hand-written copy between the
  two options instances had fallen three properties behind. Nothing failed, because the only reader
  of those three held the other instance — the class of defect the single-instance change above
  removes.
- `DetailedErrors` lost its documentation when properties were inserted between its doc comment and
  its declaration.
- `ExternalAuthenticationInstanceSettings` documented its configuration section as
  `Cirreum:Authorization:...`, the pre-1.0 path. The correct section is
  `Cirreum:Authentication:Providers:External:Instances:{name}`.

### Security

- **A tenant's token can no longer shadow the claims the framework stamps.** `tenant_slug` and
  `auth_scheme` were appended to an identity that might already carry them — from the token itself,
  or from a `ClaimMappings` entry targeting them, since the mapping target was unrestricted. That
  left two claims of the same type, and `FindFirst` returns the token's because it was added first:
  a tenant-spoofing primitive on the multi-tenant boundary. Both are now reserved via
  `ExternalClaimTypes`, discarded from the incoming identity before the resolved values are stamped,
  and the discard is logged.
- **`RequireHttpsMetadata` now enforces HTTPS, and no longer disables certificate validation.** It
  was never passed to the configuration manager, so an `http://` metadata address was fetched
  regardless of the setting. What the flag actually controlled was whether TLS certificate
  validation was turned off — so setting it `false` for a local IdP silently accepted any
  certificate in whatever environment that configuration reached. Enforcement now happens at fetch
  time, and certificate validation is no longer configurable: an application that needs a custom
  handler for local development reconfigures `ExternalDefaults.HttpClientName`, which is a
  code-level opt-in rather than a JSON flag that travels to production.
- **Metadata retrieval is bounded by a 10-second timeout.** `HttpClient` defaults to 100 seconds,
  long enough that a tenant IdP which stops responding holds the authenticating request open
  instead of failing it.

## [1.1.1] - 2026-07-24

### Updated

- Updated NuGet packages.

## [1.1.0] - 2026-07-24

### Fixed

- **The scheme is now registered under the configured instance key**, as the framework
  contract requires ("the instance key IS the scheme name" — the base registrar stamps it onto
  `settings.Scheme`). The registrar previously hardcoded `ExternalDefaults.AuthenticationScheme`
  for both `AddScheme` and the `ISchemeSelector`, so a host whose instance key was anything else
  (the documented sample used `default`) had its selector stamp a scheme name that no
  `IApplicationUserResolver.Scheme` could match. Per-scheme dispatch silently no-op'd: the
  application user never loaded and no error was raised.
- **A second configured External instance now fails composition with a diagnostic.** External
  serves every tenant through one scheme, resolving each tenant's issuer at request time, so a
  second instance adds no routing capability. Previously the duplicate registration silently
  discarded the second instance's options (`TryAddSingleton` keeps the first) and then collided
  on the scheme name, surfacing as an opaque ASP.NET *"Scheme already exists"* when the
  authentication options were materialized. The guard is collection-scoped, so multiple hosts
  composed in one process stay isolated.
- **README examples now compile against the shipped API.** The tenant-resolver sample used a
  `ResolveAsync(string, …)` signature and an `ExternalTenantConfig { Authority, Audience }`
  initializer, neither of which exists — the real seam is
  `ResolveAsync(ExternalResolutionContext, …)` returning the required `Slug` / `IsEnabled` /
  `MetadataAddress` / `ValidAudiences`. The registration snippet also bypassed the shipped
  `AddExternalTenantResolver<T>()` composition verb, and the selector was described with a
  `SchemeCategory` that does not exist.

### Changed

- **`AddExternalTenantResolver<T>()` registers the resolver as `Scoped` by default** (was
  `Singleton`), and takes an optional `ServiceLifetime`. Every documented example — including
  the one on `IExternalTenantResolver` itself — injects a scoped store (`DbContext`,
  `IDbConnection`); registering those as a singleton is a captive dependency that throws under
  scope validation, which is on by default in Development. A resolver that holds its own cache
  and takes no scoped dependencies can pass `lifetime: ServiceLifetime.Singleton`.

### Updated

- Updated NuGet packages.

## [1.0.6] - 2026-07-20

### Updated

- Updated NuGet packages.

## [1.0.5] - 2026-07-19

### Updated

- Updated NuGet packages.

## [1.0.1] - 2026-07-04

### Updated

- Updated NuGet packages.

## [1.0.0] - 2026-07-03

### Added

- Initial release. BYOID (Bring-Your-Own-IDp) external authentication scheme of the Cirreum framework, established as part of the **Cirreum 1.0 Foundation Reset** wave.
- **Renamed and re-homed from the deprecated `Cirreum.Authorization.External`** following the Three Security Pillars separation.
- Multi-tenant JWT validation with tenant-indicator resolution (header / path-segment / subdomain) per `TenantIdentifierSource`.
- Per-tenant JWKS caching via `IExternalConfigurationManager`.
- Pluggable `IExternalTenantResolver` — apps implement this to map a tenant indicator to a tenant config (Authority, Audience, etc.) from their own data store.
- `TenantNotFoundBehavior` controls handling of unknown tenants: `Reject`, `RejectWithLogging`, `Fallback`.
- **NEW — `ExternalAuthenticationSchemeSelector`** implements the `ISchemeSelector` contract with `SchemeCategory.Tenant`. The dynamic forward resolver picks the External scheme when a tenant indicator + `Authorization: Bearer` header are both present. **Replaces** the legacy static `ExternalSchemeSelector` helper class (logic preserved; shape upgraded to the new contract).

### Changed

- `RegisterScheme` no longer calls the retired `AuthorizationSchemeRegistry.RegisterCustomScheme(...)` — registration moves to the new `ISchemeSelector` model.
- Dropped redundant explicit `Microsoft.AspNetCore.DataProtection` package reference.
- Dropped explicit `Cirreum.Core 5.x` reference (replaced by transitive Kernel reach via Cirreum.AuthenticationProvider for `Cirreum.Security` types).

### Migration

Apps consuming `Cirreum.Authorization.External` migrate by installing `Cirreum.Authentication.External` and switching their composition root from `AddAuthorization(...)` to `AddAuthentication(...)`. The static `ExternalSchemeSelector` is gone — apps wiring `ForwardDefaultSelector` lambdas around it will need to switch to the new `ISchemeSelector` registration model. See [`docs/MIGRATION-v1.md`](MIGRATION-v1.md).
