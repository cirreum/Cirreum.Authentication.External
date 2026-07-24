namespace Cirreum.Authentication.External;

/// <summary>
/// Records that an External instance has already claimed this host's single External scheme
/// registration, so a second configured instance fails fast with a diagnostic instead of
/// silently competing for the same singletons.
/// </summary>
/// <remarks>
/// The marker is registered into the service collection rather than held in a static, so
/// multiple hosts composed in the same process (the integration-test norm) stay fully isolated.
/// </remarks>
/// <param name="Scheme">The scheme name — the instance key — that claimed the registration.</param>
internal sealed record ExternalSchemeClaim(string Scheme);
