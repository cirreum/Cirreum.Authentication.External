# Cirreum.Authentication.External 2.0.0

A security and stewardship release for the BYOID scheme, plus tenant-resolution caching.

Full detail and step-by-step upgrade instructions: [`docs/MIGRATION-v2.md`](MIGRATION-v2.md).

## Check these two before deploying

Both can break a **running** deployment on upgrade with no code change on your side, because they
change how tenant IdP metadata is fetched.

**1. `RequireHttpsMetadata` now enforces HTTPS.** It was never passed to the configuration manager,
so an `http://` metadata address was fetched whether the flag was `true` or `false`. Confirm every
tenant record's `MetadataAddress` uses `https://`, or set `RequireHttpsMetadata: false` on instances
that legitimately reach an HTTP endpoint.

**2. `RequireHttpsMetadata: false` no longer disables certificate validation.** That is what the flag
actually did before — it installed `DangerousAcceptAnyServerCertificateValidator`, so a setting a
developer flipped to reach a local IdP silently accepted any certificate in whatever environment the
configuration reached. Certificate validation now always applies. A development environment that
needs a custom handler reconfigures `ExternalDefaults.HttpClientName` in code, scoped to that
environment.

## Other breaking changes

- **`AddExternalTenantResolver<T>()` lost its `configure` callback.** The options type behind it
  shipped with no members and nothing ever read the callback, so no behaviour is lost. Delete the
  argument.
- **`ExternalConfigurationManager`'s constructor takes an `IHttpClientFactory`.** Only affects code
  constructing the type directly; resolving `IExternalConfigurationManager` from the container is
  unaffected.
- **The `idp_type` claim is no longer stamped.** It derived from `ClaimsHelper.ResolveProvider`,
  removed in `Cirreum.Kernel` 2.0.0. The `auth_scheme` claim is unchanged.

## Loosened — no action needed

Two token pre-checks were removed. Both only ever rejected, so nothing that previously succeeded now
fails.

A missing `typ` header no longer rejects the token — `typ` is optional under RFC 7519 and omitting it
is legal, so requiring it turned away valid tokens from IdPs you do not control. The
`typ == "id_token"` check is gone because no IdP emits that value; it never fired.

An ID token presented as an access token is still rejected — by audience validation, which is
mandatory and fails closed. Worth confirming for your tenants: **`ValidAudiences` must name your API,
never a client ID.** An access token's audience is the API it was issued for; an ID token's audience
is the client that requested sign-in.

## New

**Tenant-resolution caching.** `IExternalTenantResolver` runs on every authenticated request, so a
resolver reading tenant rows from a database made a round trip per request while JWKS and metadata
were already cached. Off by default — caching widens the window in which a tenant disabled at the
source still authenticates. Enable with `TenantResolverCache.DurationSeconds`.

To close that window rather than wait it out, publish `ExternalTenantConfigurationChanged` when a
tenant's configuration changes; the framework invalidates that tenant's entry on every replica. There
is no cache interface to implement.

**A named HTTP client for metadata retrieval** — `ExternalDefaults.HttpClientName`, registered with a
10-second timeout. `HttpClient` defaults to 100 seconds, long enough that a tenant IdP which stops
responding holds the authenticating request open instead of failing it. Reconfigure the named client
to supply a proxy, a pinned certificate, or different pooling.

## Fixed

- **Tenant-cache settings never reached the handler's options.** The registrar built one options
  instance for the extractor, scheme selector and cache, and `AddScheme` configured a second for the
  handler, kept in step by a hand-written property-by-property copy that had fallen three properties
  behind. There is now one instance, so the copy — and the class of defect — is gone.
- `ExternalAuthenticationInstanceSettings` documented its configuration section as the pre-1.0
  `Cirreum:Authorization:...` path.
- `DetailedErrors` lost its documentation when properties were inserted between its doc comment and
  its declaration.
