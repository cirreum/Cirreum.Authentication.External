# Cirreum.Authentication.External Changelog

All notable changes to **Cirreum.Authentication.External** are documented in this file.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) — [SemVer](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

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
