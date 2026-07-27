# Backlog

Deferred work for **Cirreum.Authentication.External**. Items here are tracked but not yet ready
to ship — either because the cost outweighs the benefit in isolation, or
because they're waiting on a forcing function (a related change, a consumer
upgrade, a coordinated multi-repo rollout).

## How this file works

- Each item is a `###` heading so it can be linked to and parsed.
- Each item declares **`SemVer:`** (`Patch` | `Minor` | `Major` | `Unspecified`),
  **`Trigger:`** (the human-readable condition that will make it ready), and
  **`Noted:`** (the date the item was added).
- The Cirreum DevOps release scripts (`PatchRelease`, `MinorRelease`,
  `MajorRelease`) surface items at-or-below the requested bump level so the
  operator can decide whether to fold them in before tagging.
- Items that ship: move from this file to `docs/CHANGELOG.md` under
  `[Unreleased]`. Items that grow into design discussions: promote to an ADR.

## Queued

### Deepen test coverage: the handler request path

**SemVer:** Patch
**Trigger:** Next substantive change to the External scheme's validation or resolution flow.
**Noted:** 2026-07-18 *(shrunk 2026-07-19 — the original item's test project, composition-path
tests for `AddExternalTenantResolver<T>`, and `TenantIdentifierExtractor` coverage shipped.
Shrunk again 2026-07-26 — `ExternalConfigurationManager` now has `RequireHttpsMetadata`
enforcement and refresh coverage.)*

What remains is the request-path machinery that needs a real harness:
`ExternalAuthenticationHandler` (token validation flow, `TenantNotFoundBehavior` branches,
`ValidateTenantInPath` defense-in-depth check, `RequireAccessTokenType`) plus
`ExternalAuthenticationSchemeSelector`. Model the handler harness on
`SessionTicketAuthenticationHandlerTests` / the ApiKey handler tests (DefaultHttpContext + scheme
+ NullLogger).

### Support AWS Cognito tenants: audience opt-out coupled to a token-use requirement

**SemVer:** Minor
**Trigger:** A prospective tenant runs AWS Cognito.
**Noted:** 2026-07-26

Cognito does not fit the audience-validation model External relies on. Its **access** tokens put the
app client ID in `client_id` and may carry no `aud` at all, unless resource binding adds one. Its
**ID** tokens put the app client ID in `aud`. `ExternalAuthenticationHandler` sets
`ValidateAudience = true` unconditionally, so a Cognito tenant's access tokens fail validation today
and External cannot serve them.

Cognito does mark the distinction, in a claim inside the JWT: `token_use` is `"access"` or `"id"`.
(Not to be confused with `access_token`, the OAuth *response field* carrying the JWT — `token_use` is
a claim within it.) No other IdP emits it, so it can never be required globally.

**Implement the two halves together or not at all.** Relaxing audience validation for a tenant is
what makes `token_use` load-bearing: audience validation is otherwise the only thing stopping an ID
token being replayed as a bearer token, and OpenID Connect defines no standard marker for an ID
token to fall back on. A per-tenant shape along the lines of "validate `client_id` against
`AllowedClientIds` instead of `aud`, **and** require `token_use == access`" keeps them inseparable,
so no configuration can select the dangerous half alone.

What must not ship is a bare `ValidateAudience: false` switch, or a standalone `token_use` check —
the first removes the defense, the second looks like a replacement for it while applying to one
vendor.
