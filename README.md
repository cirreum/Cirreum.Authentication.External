# Cirreum Authentication - External (BYOID)

[![NuGet Version](https://img.shields.io/nuget/v/Cirreum.Authentication.External.svg?style=flat-square&labelColor=1F1F1F&color=003D8F)](https://www.nuget.org/packages/Cirreum.Authentication.External/)
[![License](https://img.shields.io/badge/license-MIT-F2F2F2?style=flat-square&labelColor=1F1F1F)](https://github.com/cirreum/Cirreum.Authentication.External/blob/main/LICENSE)
[![.NET](https://img.shields.io/badge/.NET-10.0-003D8F?style=flat-square&labelColor=1F1F1F)](https://dotnet.microsoft.com/)

**Multi-tenant external IdP (BYOID) authentication scheme for the Cirreum framework**

## Overview

**Cirreum.Authentication.External** enables a single API to accept JWT bearer tokens from **multiple customer Identity Providers** (Okta, Auth0, customer Entra tenants, etc.) without federating those IdPs into yours. The customer's existing IdP issues tokens; your API validates them per-tenant using the resolved tenant configuration.

Use this package when your customers want to sign in to your API with their own IdP credentials. Use `Cirreum.Authentication.Oidc` or `Cirreum.Authentication.Entra` instead when you have a single, configured-by-you IdP.

## How it works

1. The inbound request carries a **tenant indicator** — a header (`X-Tenant-Slug`), a path segment (`/tenants/{slug}/...`), or a subdomain (`{tenant}.api.example.com`).
2. The package's `IExternalTenantResolver` (your implementation) maps that indicator to the tenant's **configuration**: OIDC metadata address, valid audiences, etc.
3. JWKS metadata is fetched from the tenant's `.well-known/openid-configuration` and cached per `JwksCacheDurationMinutes`.
4. The inbound `Authorization: Bearer {jwt}` is validated against the resolved per-tenant configuration.
5. On success, the `ClaimsPrincipal` reflects the tenant's claims.

The dynamic forward resolver picks this scheme (via `ExternalAuthenticationSchemeSelector`) when both a tenant indicator and a Bearer token are present on the request.

### One scheme, many tenants

External is a **single-instance** provider: it serves every tenant through one scheme, resolving each tenant's issuer at request time. Per-tenant variance belongs in your `IExternalTenantResolver`, not in additional configured instances — a second enabled instance fails composition with a diagnostic.

As with every Cirreum authentication provider, **the configured instance key is the scheme name**. That name is what `[Authorize(AuthenticationSchemes = ...)]` matches and what an `IApplicationUserResolver.Scheme` must return to be dispatched for External-authenticated requests.

## Installation

```bash
dotnet add package Cirreum.Authentication.External
```

## Configuration

```json
{
  "Cirreum": {
    "Authentication": {
      "Providers": {
        "External": {
          "Instances": {
            "Byoid": {
              "Enabled": true,
              "TenantIdentifierSource": "Header",
              "TenantHeaderName": "X-Tenant-Slug",
              "JwksCacheDurationMinutes": 60,
              "RequireHttpsMetadata": true,
              "TenantNotFoundBehavior": "Reject",
              "ClockSkewSeconds": 30,
              "DetailedErrors": false
            }
          }
        }
      }
    }
  }
}
```

The instance key (`Byoid` above) becomes the scheme name; `ExternalDefaults.AuthenticationScheme` is that conventional key. Do **not** set a `Scheme` value in configuration — the registrar derives it from the key and fails loudly on a mismatch.

Then register your tenant resolver inside the `AddAuthentication(...)` composition callback:

```csharp
builder.AddAuthentication(auth => auth
    .AddExternalTenantResolver<MyTenantResolver>());
```

The resolver is registered **scoped** by default, so it can consume a scoped store (a `DbContext`, a unit of work, a repository). A resolver that holds its own cache and takes no scoped dependencies can opt in:

```csharp
auth.AddExternalTenantResolver<MyCachingResolver>(lifetime: ServiceLifetime.Singleton);
```

## Implementing the tenant resolver

```csharp
public sealed class MyTenantResolver(IDbConnection db) : IExternalTenantResolver {

    public async Task<ExternalTenantConfig?> ResolveAsync(
        ExternalResolutionContext context,
        CancellationToken cancellationToken = default) {

        var row = await db.QueryFirstOrDefaultAsync(
            "SELECT Slug, IsActive, MetadataUrl, Audience FROM Tenants WHERE Slug = @Slug",
            new { Slug = context.TenantSlug });

        if (row is null) {
            return null;
        }

        return new ExternalTenantConfig {
            Slug = row.Slug,
            IsEnabled = row.IsActive,
            MetadataAddress = row.MetadataUrl,
            ValidAudiences = [row.Audience]
        };
    }
}
```

`ExternalResolutionContext` also carries the token's issuer and audience, so a resolver can key on those instead of — or alongside — the tenant slug.

## What changed

### Selector-based dispatch

`ExternalAuthenticationSchemeSelector` implements `ISchemeSelector` at `SchemeSelectorPriority.External`, ahead of the generic `JwtAudienceSchemeSelector`, so the stricter "tenant indicator **and** Bearer both required" probe runs first. The dynamic forward resolver picks External when:
1. A tenant indicator is present (per configured `TenantIdentifierSource`)
2. An `Authorization: Bearer` header is present

The legacy static `ExternalSchemeSelector` helper class is retired. Detection logic survives as static methods on the new instance class for apps that compose conflict-detection at startup.

## Security considerations

- **Tenant configuration trust** — your `IExternalTenantResolver` must return only verified, currently-active tenant configurations. Cache invalidation on tenant deactivation is your responsibility.
- **HTTPS enforcement** — `RequireHttpsMetadata: true` (default) blocks JWKS fetches over plain HTTP.
- **Clock skew** — `ClockSkewSeconds: 30` is a reasonable default; tighten for high-trust tenants.
- **TenantNotFoundBehavior** — `Reject` is the safe default; `Fallback` is only appropriate when your fallback is your own IdP under your control.
- **Token type** — tokens with no `typ` header are rejected, and an `id_token` is never accepted as an access token. Set `RequireAccessTokenType` on the resolved tenant config to additionally require `at+jwt`.
- **Authorized party** — populate `AllowedClientIds` on the resolved tenant config to restrict which of a tenant's client applications may call your API (matched against `azp`, then `client_id`).

## License

MIT — see [LICENSE](LICENSE).

---

**Cirreum Foundation Framework**
*Layered simplicity for modern .NET*
