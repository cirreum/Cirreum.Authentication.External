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

### Deepen test coverage: handler + configuration manager

**SemVer:** Patch
**Trigger:** Next substantive change to the External scheme's validation or resolution flow.
**Noted:** 2026-07-18 *(shrunk 2026-07-19 — the original item's test project, composition-path
tests for `AddExternalTenantResolver<T>`, and `TenantIdentifierExtractor` coverage shipped.)*

The remaining untested surface is the request-path machinery that needs richer harnessing:
`ExternalAuthenticationHandler` (token validation flow, `TenantNotFoundBehavior` branches,
`ValidateTenantInPath` defense-in-depth check) and `ExternalConfigurationManager` (JWKS caching /
`RequireHttpsMetadata` enforcement), plus `ExternalAuthenticationSchemeSelector`. Model the handler
harness on `SessionTicketAuthenticationHandlerTests` / the ApiKey handler tests (DefaultHttpContext
+ scheme + NullLogger).
