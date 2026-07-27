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

### Confirm whether AWS Cognito tenants can validate at all

**SemVer:** Unspecified
**Trigger:** A prospective tenant runs AWS Cognito.
**Noted:** 2026-07-26

Cognito access tokens are reported to omit `aud` entirely, carrying `client_id` in its place.
`ExternalAuthenticationHandler` sets `ValidateAudience = true` unconditionally, so if that holds,
a Cognito tenant's access tokens fail validation outright and External cannot serve them. Confirm
against a real Cognito token before deciding anything — this came out of a code review, not a
failed integration.

If it holds, the options are a per-tenant audience opt-out paired with the existing
`AllowedClientIds` check (which already validates `client_id`), or documenting Cognito as
unsupported. What must not happen is a general "audience optional" switch: audience validation
being mandatory and fail-closed is the entire reason an ID token presented as an access token
cannot pass, and there is no standard token claim to fall back on if it is relaxed.
