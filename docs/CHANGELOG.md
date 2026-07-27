# Cirreum.Authentication.External Changelog

All notable changes to **Cirreum.Authentication.External** are documented in this file.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) â€” [SemVer](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

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
  contract requires ("the instance key IS the scheme name" â€” the base registrar stamps it onto
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
  `ResolveAsync(string, â€¦)` signature and an `ExternalTenantConfig { Authority, Audience }`
  initializer, neither of which exists â€” the real seam is
  `ResolveAsync(ExternalResolutionContext, â€¦)` returning the required `Slug` / `IsEnabled` /
  `MetadataAddress` / `ValidAudiences`. The registration snippet also bypassed the shipped
  `AddExternalTenantResolver<T>()` composition verb, and the selector was described with a
  `SchemeCategory` that does not exist.

### Changed

- **`AddExternalTenantResolver<T>()` registers the resolver as `Scoped` by default** (was
  `Singleton`), and takes an optional `ServiceLifetime`. Every documented example â€” including
  the one on `IExternalTenantResolver` itself â€” injects a scoped store (`DbContext`,
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
- Pluggable `IExternalTenantResolver` â€” apps implement this to map a tenant indicator to a tenant config (Authority, Audience, etc.) from their own data store.
- `TenantNotFoundBehavior` controls handling of unknown tenants: `Reject`, `RejectWithLogging`, `Fallback`.
- **NEW â€” `ExternalAuthenticationSchemeSelector`** implements the `ISchemeSelector` contract with `SchemeCategory.Tenant`. The dynamic forward resolver picks the External scheme when a tenant indicator + `Authorization: Bearer` header are both present. **Replaces** the legacy static `ExternalSchemeSelector` helper class (logic preserved; shape upgraded to the new contract).

### Changed

- `RegisterScheme` no longer calls the retired `AuthorizationSchemeRegistry.RegisterCustomScheme(...)` â€” registration moves to the new `ISchemeSelector` model.
- Dropped redundant explicit `Microsoft.AspNetCore.DataProtection` package reference.
- Dropped explicit `Cirreum.Core 5.x` reference (replaced by transitive Kernel reach via Cirreum.AuthenticationProvider for `Cirreum.Security` types).

### Migration

Apps consuming `Cirreum.Authorization.External` migrate by installing `Cirreum.Authentication.External` and switching their composition root from `AddAuthorization(...)` to `AddAuthentication(...)`. The static `ExternalSchemeSelector` is gone â€” apps wiring `ForwardDefaultSelector` lambdas around it will need to switch to the new `ISchemeSelector` registration model. See [`docs/MIGRATION-v1.md`](MIGRATION-v1.md).
