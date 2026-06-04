# Cirreum.Authentication.External 1.0.0 — BYOID under the right pillar

## Why this release exists

BYOID (Bring-Your-Own-IDp) multi-tenant JWT validation proves caller identity — it's authentication, not authorization. The **Cirreum 1.0 Foundation Reset** moves this package from the deprecated `Cirreum.Authorization.External` to its correct pillar.

The release also adopts selector-based dispatch (`ISchemeSelector` with `SchemeCategory.Tenant`), replacing the legacy static `ExternalSchemeSelector` helper.

## What's new

### Selector-based dispatch

`ExternalAuthenticationSchemeSelector` implements `ISchemeSelector` with `SchemeCategory.Tenant`. The dynamic forward resolver picks External when a tenant indicator (header / path segment / subdomain per configuration) and an `Authorization: Bearer` header are both present.

Apps no longer need to wire `ForwardDefaultSelector` lambdas — the runtime iterates registered selectors.

### Static helper retired

The legacy static `ExternalSchemeSelector` class is gone. Detection logic survives on the new instance class. The static methods `HasTenantIdentifier`, `HasBearerToken`, and `HasConflictingIndicators` are kept as static helpers on `ExternalAuthenticationSchemeSelector` for apps that compose conflict-detection logic at startup.

## What's preserved

- `IExternalTenantResolver` — your tenant lookup remains unchanged
- Tenant identification (Header / PathSegment / Subdomain)
- `TenantNotFoundBehavior` (Reject / RejectWithLogging / Fallback)
- JWKS caching via `IExternalConfigurationManager`
- `ExternalAuthenticationHandler` validation pipeline
- Per-instance JWKS cache duration, clock skew, detailed errors

## Compatibility

- **.NET 10.0** target.
- **Microsoft.Identity.Web 4.9.0+**.
- **Cirreum.AuthenticationProvider 1.0.0+** (provides the `ISchemeSelector` contract).
- **Cirreum.Providers 1.2.0+**.
- Apps migrating from `Cirreum.Authorization.External` follow [`MIGRATION-v1.md`](MIGRATION-v1.md). One behavioral change requires action: removing `ForwardDefaultSelector` lambdas.

## See also

- [`MIGRATION-v1.md`](MIGRATION-v1.md), [`CHANGELOG.md`](CHANGELOG.md)
