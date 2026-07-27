# Migration to Cirreum.Authentication.External v2.0

**From:** `Cirreum.Authentication.External 1.1.x`
**To:** `Cirreum.Authentication.External 2.0.0`

## Read this first

Two of the changes below can break a **running deployment** on upgrade, without any code change on
your side, because they affect how tenant IdP metadata is fetched. Check them before you deploy:

1. If any tenant's `MetadataAddress` uses `http://`, it now fails unless that instance sets
   `RequireHttpsMetadata: false`.
2. If any environment relied on `RequireHttpsMetadata: false` to accept a self-signed or otherwise
   untrusted certificate, that no longer works at all.

Everything else is a compile-time change or a loosening.

## Breaking changes

### 1. `RequireHttpsMetadata` now enforces HTTPS

**Before:** the setting was never passed to the configuration manager. An `http://` metadata address
was fetched whether the flag was `true` or `false`.

**Now:** a non-HTTPS metadata address is rejected at fetch time when the flag is `true` (the
default).

**What to do:** confirm every tenant record's `MetadataAddress` uses `https://`. A tenant IdP
reachable only over HTTP — a local container, typically — needs `RequireHttpsMetadata: false` on
that instance:

```json
{
  "Cirreum": {
    "Authentication": {
      "Providers": {
        "External": {
          "Instances": {
            "customerIdp": {
              "RequireHttpsMetadata": false
            }
          }
        }
      }
    }
  }
}
```

### 2. `RequireHttpsMetadata: false` no longer disables certificate validation

**Before:** setting the flag `false` installed
`HttpClientHandler.DangerousAcceptAnyServerCertificateValidator`, disabling TLS certificate
validation for tenant metadata retrieval.

**Now:** certificate validation always applies. The flag controls the URL scheme and nothing else,
which is what its name — and the ASP.NET Core option it is named after — has always meant.

**What to do:** if a development environment depended on this to reach an IdP with a self-signed
certificate, trust the certificate on the machine (`dotnet dev-certs https --trust`, or import the
IdP's certificate), or reconfigure the named HTTP client in that environment only:

```csharp
if (builder.Environment.IsDevelopment()) {
	builder.Services.AddHttpClient(ExternalDefaults.HttpClientName)
		.ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler {
			ServerCertificateCustomValidationCallback =
				HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
		});
}
```

This is deliberately more work than flipping a JSON flag. The previous behaviour let a development
setting travel to production inside a configuration file and silently accept any certificate there.

### 3. `AddExternalTenantResolver<T>()` no longer takes a `configure` callback

**Before:**

```csharp
auth.AddExternalTenantResolver<MyTenantResolver>(options => {
	// ...
});
```

**Now:**

```csharp
auth.AddExternalTenantResolver<MyTenantResolver>();
```

The options type the callback configured (`DynamicExternalTenantOptions`) shipped with no members —
it was an explicit placeholder, documented as *"reserved for 1.x expansion — caching duration, retry
policy"*. Nothing ever read the callback, so no behaviour is lost. The `ServiceLifetime` parameter is
unchanged.

The caching it reserved space for now exists, as configuration rather than as a code callback, so it
sits with the rest of the instance's settings and can differ per environment without a rebuild — see
*Tenant-resolution caching* below.

### 4. `ExternalConfigurationManager`'s constructor changed

It now takes an `IHttpClientFactory`:

```csharp
// Before
new ExternalConfigurationManager(refreshInterval, logger)

// Now
new ExternalConfigurationManager(refreshInterval, httpClientFactory, logger)
```

This only affects code that constructs the type directly. Applications resolving
`IExternalConfigurationManager` from the container are unaffected — the registrar wires the factory.

### 5. The `idp_type` claim is no longer stamped

It was derived from `ClaimsHelper.ResolveProvider`, removed in `Cirreum.Kernel` 2.0.0.

**What to do:** nothing, unless your application read the claim. If it did, the replacement depends
on what the check meant:

| The check meant | Replace with |
|---|---|
| "which context authenticated this request?" | the `auth_scheme` claim, still stamped and unchanged |
| "what did the token assert about its issuer?" | `UserProfile.Issuer` |
| "is a capability available?" | the capability itself, not the provider behind it |

## Loosened — no action needed

Two token pre-checks were removed. Both only ever rejected; nothing that previously succeeded now
fails.

- **A missing `typ` header no longer rejects the token.** `typ` is optional under RFC 7519 §5.1 and
  omitting it is legal, so requiring it turned away valid tokens from IdPs you do not control.
- **The `typ == "id_token"` check is gone.** No IdP emits that value, so the check never fired, and
  OpenID Connect defines no standard marker identifying a token as an ID token.

An ID token presented as an access token is still rejected — by audience validation, which is
mandatory and fails closed. This is worth confirming for your tenants:

> **`ValidAudiences` must name your API, never a client ID.** An access token's audience is the API
> it was issued for; an ID token's audience is the client that requested sign-in. If a tenant's
> `ValidAudiences` contains a client ID, ID tokens issued to that client will validate successfully.

`RequireAccessTokenType` is unchanged and still enforces RFC 9068 `at+jwt` per tenant.

## New — opt-in

### Tenant-resolution caching

`IExternalTenantResolver` runs on every authenticated request. For a resolver reading tenant rows
from a database that is a round trip per request, where JWKS and IdP metadata were already cached.

Caching is **off by default**, because it widens the window in which a tenant disabled at the source
still authenticates. Enable it by setting a duration:

```json
{
  "Cirreum": {
    "Authentication": {
      "Providers": {
        "External": {
          "Instances": {
            "customerIdp": {
              "TenantResolverCache": {
                "DurationSeconds": 300,
                "NotFoundDurationSeconds": 30,
                "MaxEntries": 1000
              }
            }
          }
        }
      }
    }
  }
}
```

To close the staleness window rather than wait it out, publish an event when a tenant's
configuration changes:

```csharp
await publisher.PublishAsync(new ExternalTenantConfigurationChanged(tenantSlug, DateTimeOffset.UtcNow));
```

The framework invalidates that tenant's entry on every replica. There is no cache interface to
implement.

### Reshaping the metadata HTTP client

Metadata and signing-key retrieval uses a named `IHttpClientFactory` client, registered with a
10-second timeout (`HttpClient`'s own default is 100 seconds):

```csharp
builder.Services.AddHttpClient(ExternalDefaults.HttpClientName)
	.ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler { /* ... */ });
```

This affects outbound metadata retrieval only. Token validation is local and unaffected.

## What didn't change

- `IExternalTenantResolver` — your resolver implementation works unchanged
- `TenantIdentifierSource` semantics (Header / PathSegment / Subdomain)
- `TenantNotFoundBehavior` semantics (Reject / RejectWithLogging / Fallback)
- The `auth_scheme` claim and per-scheme dispatch
- Clock-skew, detailed-error, and JWKS cache-duration settings
- The `IExternalConfigurationManager` interface
