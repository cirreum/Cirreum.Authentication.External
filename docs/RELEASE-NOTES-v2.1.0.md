# Cirreum.Authentication.External 2.1.0 — BYOID declares its people and its authority in one call

## Why this release exists

The attribute-authority model has providers declare what kind of party they authenticate and lets
applications declare who owns their callers' claims. External (BYOID) federates a customer's own
identity provider — the caller is that customer's user, not the tenant as a thing — and BYOID
deployments are exactly where the application typically owns roles while the customer's IdP
supplies identity. This release makes both declarations part of registering the scheme.

## What's new

**Registration and declaration are one call.** The registrar registers its handler scheme through
`IAuthenticationBuilder.AddScheme`, carrying `SubjectKind.Human` and the instance's
`ClaimAuthority` block (`Profile` / `Roles`) in the same act. External overrides the base
registration wholesale — single-instance-per-host, dynamic tenant resolution — so it declares
for itself, and now cannot register without declaring.

## Compatibility

- **Applications have nothing to change.** Instance configuration, the tenant resolver, and
  composition are untouched.
- **`RegisterScheme` changed signature** per the `Cirreum.AuthenticationProvider` 3.0.x contract
  consolidation (takes `IAuthenticationBuilder`). A framework-invoked member no application calls
  directly; shipped as a Minor with that scope stated deliberately.
- The declarations are read by higher-layer packages releasing later in the same wave; until
  then they change no behavior.

## See also

- `Cirreum.AuthenticationProvider 3.0.1` — the registration funnel.
- `Cirreum.Kernel 2.1.0` — the `SubjectKind` / `ClaimAuthority` vocabulary.
