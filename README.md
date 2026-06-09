# Cirreum Authentication - External (BYOID)

[![NuGet Version](https://img.shields.io/nuget/v/Cirreum.Authentication.External.svg?style=flat-square&labelColor=1F1F1F&color=003D8F)](https://www.nuget.org/packages/Cirreum.Authentication.External/)
[![License](https://img.shields.io/badge/license-MIT-F2F2F2?style=flat-square&labelColor=1F1F1F)](https://github.com/cirreum/Cirreum.Authentication.External/blob/main/LICENSE)
[![.NET](https://img.shields.io/badge/.NET-10.0-003D8F?style=flat-square&labelColor=1F1F1F)](https://dotnet.microsoft.com/)

**Multi-tenant external IdP (BYOID) authentication scheme for the Cirreum framework**

## Overview

**Cirreum.Authentication.External** enables a single API to accept JWT bearer tokens from **multiple customer Identity Providers** (Okta, Auth0, customer Entra tenants, etc.) without federating those IdPs into yours. The customer's existing IdP issues tokens; your API validates them per-tenant using the resolved tenant configuration.

Use this package when your customers want to sign in to your API with their own IdP credentials. Use `Cirreum.Authentication.Oidc` or `Cirreum.Authentication.Entra` instead when you have a single, configured-by-you IdP.

## How it works

1. The inbound request carries a **tenant indicator** — a header (`X-Tenant-Id`), a path segment (`/tenants/{slug}/...`), or a subdomain (`{tenant}.api.example.com`).
2. The package's `IExternalTenantResolver` (your implementation) maps that indicator to the tenant's **configuration**: Authority URL, Audience, etc.
3. JWKS metadata is fetched from the tenant's `.well-known/openid-configuration` and cached per `JwksCacheDurationMinutes`.
4. The inbound `Authorization: Bearer {jwt}` is validated against the resolved per-tenant configuration.
5. On success, the `ClaimsPrincipal` reflects the tenant's claims.

The dynamic forward resolver picks this scheme (via `ExternalAuthenticationSchemeSelector` — `SchemeCategory.Tenant`) when both a tenant indicator and a Bearer token are present on the request.

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
            "default": {
              "Enabled": true,
              "TenantIdentifierSource": "Header",
              "TenantHeaderName": "X-Tenant-Id",
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

Then register your tenant resolver:

```csharp
builder.Services.AddSingleton<IExternalTenantResolver, MyTenantResolver>();
```

## Implementing the tenant resolver

```csharp
public sealed class MyTenantResolver(IDbConnection db) : IExternalTenantResolver {

    public async Task<ExternalTenantConfig?> ResolveAsync(
        string tenantIdentifier,
        CancellationToken cancellationToken) {

        var row = await db.QueryFirstOrDefaultAsync(
            "SELECT Authority, Audience FROM Tenants WHERE Slug = @Slug AND IsActive = 1",
            new { Slug = tenantIdentifier });

        if (row is null) {
            return null;
        }

        return new ExternalTenantConfig {
            Authority = row.Authority,
            Audience = row.Audience
        };
    }
}
```

## What changed

### Selector-based dispatch

`ExternalAuthenticationSchemeSelector` implements `ISchemeSelector` with `SchemeCategory.Tenant`. The dynamic forward resolver picks External when:
1. A tenant indicator is present (per configured `TenantIdentifierSource`)
2. An `Authorization: Bearer` header is present

The legacy static `ExternalSchemeSelector` helper class is retired. Detection logic survives as static methods on the new instance class for apps that compose conflict-detection at startup.

## Security considerations

- **Tenant configuration trust** — your `IExternalTenantResolver` must return only verified, currently-active tenant configurations. Cache invalidation on tenant deactivation is your responsibility.
- **HTTPS enforcement** — `RequireHttpsMetadata: true` (default) blocks JWKS fetches over plain HTTP.
- **Clock skew** — `ClockSkewSeconds: 30` is a reasonable default; tighten for high-trust tenants.
- **TenantNotFoundBehavior** — `Reject` is the safe default; `Fallback` is only appropriate when your fallback is your own IdP under your control.

## License

MIT — see [LICENSE](LICENSE).

---

**Cirreum Foundation Framework**
*Layered simplicity for modern .NET*
