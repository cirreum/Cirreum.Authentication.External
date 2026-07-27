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

### Verify a real AWS Cognito tenant end to end

**SemVer:** Unspecified  
**Trigger:** A prospective tenant runs AWS Cognito.  
**Noted:** 2026-07-26

`AudienceClaim` + `RequiredClaims` shipped in 2.0.0 to make a Cognito-shaped tenant expressible
(`AudienceClaim = "client_id"`, `RequiredClaims = { "token_use": "access" }`), and the pre-check
paths are covered by `ExternalAuthenticationHandlerTests`. What has **not** been exercised is a real
Cognito token against a real Cognito JWKS endpoint — the design was derived from documentation, not
from a working integration.

Worth confirming when a Cognito tenant is actually available: that Cognito's issuer matches its
metadata document's `issuer` (or that `ValidIssuerOverride` is needed), and that nothing else in the
validation path assumes an `aud`.
