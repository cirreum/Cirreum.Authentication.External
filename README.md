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
              "DetailedErrors": false,
              "TenantResolverCache": {
                "DurationSeconds": 0
              }
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

### Caching tenant resolution

Your resolver runs on **every authenticated request**. For a resolver reading tenant rows from a database, that is a round trip per request — JWKS and IdP metadata are already cached, but tenant resolution was not.

Caching is **off by default** (`DurationSeconds: 0`), because it widens the window in which a tenant you disabled at the source still authenticates. Enable it by setting a duration:

```json
"TenantResolverCache": {
  "DurationSeconds": 300,
  "NotFoundDurationSeconds": 30,
  "MaxEntries": 1000
}
```

`NotFoundDurationSeconds` caches the *absence* of a tenant, so an unknown slug cannot be used to generate database load. It is deliberately short so a newly created tenant becomes reachable quickly. `MaxEntries` bounds the cache; entries are keyed on the tenant slug together with the token's issuer and audience, never on the token itself.

Rather than waiting out the duration, close the staleness window by publishing an event wherever your application changes a tenant's configuration — disabling it, rotating its IdP, changing its audience:

```csharp
await publisher.PublishAsync(
    new ExternalTenantConfigurationChanged(tenantSlug, DateTimeOffset.UtcNow));
```

The framework invalidates that tenant's cache entry on **every replica**, provided coordination broadcast is configured. There is no cache interface to implement and nothing to register — publishing the event is the whole integration.

### Reshaping the metadata HTTP client

Metadata and signing-key retrieval uses a named client registered with a 10-second timeout. To supply a proxy, a pinned certificate, or different pooling:

```csharp
builder.Services.AddHttpClient(ExternalDefaults.HttpClientName)
    .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler { /* ... */ });
```

This affects outbound metadata retrieval only. Token validation is local and unaffected.

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

### Tenants whose IdP doesn't use `aud`

`ValidAudiences` must name **your API**, never a client ID — that is what separates an access token from an ID token, since an ID token's audience is the client that requested sign-in.

Some IdPs don't fit that model. AWS Cognito puts the app client ID in `client_id` on access tokens and may omit `aud` entirely, while its ID tokens carry it in `aud`, so validating `aud` rejects every access token. Cognito does mark the difference, with a `token_use` claim that is `access` or `id`:

```csharp
return new ExternalTenantConfig {
    Slug = row.Slug,
    IsEnabled = row.IsActive,
    MetadataAddress = row.MetadataUrl,
    ValidAudiences = [row.AppClientId],
    AudienceClaim = "client_id",
    RequiredClaims = new Dictionary<string, string> { ["token_use"] = "access" }
};
```

**These two are coupled and the framework enforces it.** Moving the audience off `aud` removes the check that distinguishes an access token from an ID token, so a config that sets `AudienceClaim` without any `RequiredClaims` is rejected at resolution time and authenticates no one. You can't get the dangerous half on its own.

`RequiredClaims` works on its own for any IdP that marks token kind with a claim. Values are compared ordinally and case-sensitively; an absent claim fails.

## What changed

### Selector-based dispatch

`ExternalAuthenticationSchemeSelector` implements `ISchemeSelector` at `SchemeSelectorPriority.External`, ahead of the generic `JwtAudienceSchemeSelector`, so the stricter "tenant indicator **and** Bearer both required" probe runs first. The dynamic forward resolver picks External when:
1. A tenant indicator is present (per configured `TenantIdentifierSource`)
2. An `Authorization: Bearer` header is present

The legacy static `ExternalSchemeSelector` helper class is retired. Detection logic survives as static methods on the new instance class for apps that compose conflict-detection at startup.

## Security considerations

- **Audience is the boundary** — `ValidAudiences` on the resolved tenant config must name **your API**, never a client ID. An access token's audience is the API it was issued for; an ID token's audience is the client that requested sign-in. This is what stops an ID token being replayed against your API as a bearer token, and it holds on every IdP — OpenID Connect defines no standard marker identifying a token as an ID token, so nothing else can. Audience validation is mandatory and fails closed: a tenant config with no valid audiences rejects every token rather than skipping the check.
- **Relocating the audience requires a replacement discriminator** — `AudienceClaim` moves the check off `aud` for an IdP that carries the audience elsewhere, which also moves it off the access-token/ID-token boundary. `RequiredClaims` must then supply a claim that restores it. The framework rejects a tenant config that does the first without the second, so this cannot be got wrong by setting one field and forgetting the other.
- **Tenant configuration trust** — your `IExternalTenantResolver` must return only verified, currently-active tenant configurations. When resolution caching is enabled, publish `ExternalTenantConfigurationChanged` on deactivation rather than waiting out `DurationSeconds`.
- **HTTPS enforcement** — `RequireHttpsMetadata: true` (default) rejects a non-HTTPS metadata address at fetch time. It does **not** control certificate validation, which always applies; use the named HTTP client above if a development environment needs a custom handler.
- **Clock skew** — `ClockSkewSeconds: 30` is a reasonable default; tighten for high-trust tenants.
- **TenantNotFoundBehavior** — `Reject` is the safe default; `Fallback` is only appropriate when your fallback is your own IdP under your control.
- **Token type** — set `RequireAccessTokenType` on the resolved tenant config to require RFC 9068 `at+jwt`. Opt-in per tenant, because most IdPs — Entra, Cognito, Auth0 — emit plain `JWT` for access tokens by default, so requiring it of a tenant whose IdP does not stamp it rejects every one of their tokens.
- **Authorized party** — populate `AllowedClientIds` on the resolved tenant config to restrict which of a tenant's client applications may call your API (matched against `azp`, then `client_id`).
- **Outbound traffic** — token validation is entirely local. The only request made to a tenant's IdP is metadata retrieval, coalesced across concurrent callers and floored at one attempt per five minutes, so a caller presenting invalid tokens cannot generate load on a customer's identity provider through your API.

## License

MIT — see [LICENSE](LICENSE).

---

**Cirreum Foundation Framework**
*Layered simplicity for modern .NET*
