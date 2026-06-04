# Migration to Cirreum.Authentication.External v1.0

**From:** `Cirreum.Authorization.External 1.0.x` (now deprecated)
**To:** `Cirreum.Authentication.External 1.0.0`

## Why v1

BYOID (Bring-Your-Own-IDp) multi-tenant JWT validation proves *who* the caller is — authentication, not authorization. The **Cirreum 1.0 Foundation Reset** moves this package to the Authentication pillar.

This release also adopts the new `ISchemeSelector` model for dispatch, replacing the legacy static `ExternalSchemeSelector` helper class.

## Breaking Changes — Find/Replace Table

| Before | After |
|---|---|
| `<PackageReference Include="Cirreum.Authorization.External" ... />` | `<PackageReference Include="Cirreum.Authentication.External" ... />` |
| `ExternalAuthorizationRegistrar` | `ExternalAuthenticationRegistrar` |
| `ExternalAuthorizationInstanceSettings` | `ExternalAuthenticationInstanceSettings` |
| `ExternalAuthorizationSettings` | `ExternalAuthenticationSettings` |
| `static ExternalSchemeSelector.ShouldHandleRequest(...)` | Use `ExternalAuthenticationSchemeSelector` (an `ISchemeSelector` service) instead |
| `AddAuthorization(authz => authz.AddExternal(...))` | `AddAuthentication(auth => auth.AddExternal(...))` |
| `Cirreum:Authorization:Providers:External:Instances:{name}` | `Cirreum:Authentication:Providers:External:Instances:{name}` |

## What Changed Behaviorally

### Selector dispatch

Previously: apps wired `ForwardDefaultSelector` lambdas that called `ExternalSchemeSelector.ShouldHandleRequest(...)` and returned the External scheme name on match.

Now: the package registers `ExternalAuthenticationSchemeSelector` as an `ISchemeSelector` service with `SchemeCategory.Tenant`. The dynamic forward resolver iterates these selectors and picks the External scheme automatically. **Apps no longer need to write `ForwardDefaultSelector` lambdas for External.**

### Static helper retired

The static `ExternalSchemeSelector` class is gone. The detection logic survives on `ExternalAuthenticationSchemeSelector` (now a regular instance class implementing `ISchemeSelector`). The static methods `HasTenantIdentifier`, `HasBearerToken`, and `HasConflictingIndicators` survive as static helpers on the new class.

## What Didn't Change

- Tenant resolution (`IExternalTenantResolver`) — your custom resolver implementation works unchanged
- `TenantIdentifierSource` semantics (Header / PathSegment / Subdomain)
- `TenantNotFoundBehavior` semantics (Reject / RejectWithLogging / Fallback)
- JWKS caching duration and `IExternalConfigurationManager` interface
- `ExternalAuthenticationHandler` validation pipeline
- Detailed-error and clock-skew options

## Migration Walkthrough

1. **Update `<PackageReference>`** in your csproj.
2. Apply the find/replace table above across your codebase.
3. **Update `appsettings.json`** configuration root.
4. **Remove any `ForwardDefaultSelector` lambdas** wiring `ExternalSchemeSelector.ShouldHandleRequest(...)`. The new `ISchemeSelector` registration replaces this.
5. **Move the `AddExternal` call** from `AddAuthorization(...)` to `AddAuthentication(...)`.
6. Rebuild and verify multi-tenant routing still works end-to-end.
