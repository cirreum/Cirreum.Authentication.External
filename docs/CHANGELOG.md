# Cirreum.Authentication.External Changelog

All notable changes to **Cirreum.Authentication.External** are documented in this file.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) â€” [SemVer](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

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
