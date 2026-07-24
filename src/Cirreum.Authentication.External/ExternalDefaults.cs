namespace Cirreum.Authentication.External;

/// <summary>
/// Default values for BYOID authentication.
/// </summary>
public static class ExternalDefaults {
	/// <summary>
	/// The conventional instance key — and therefore scheme name — for BYOID.
	/// </summary>
	/// <remarks>
	/// The scheme name is the configured instance key
	/// (<c>Cirreum:Authentication:Providers:External:Instances:{key}</c>), so this constant
	/// matches the registered scheme only for a host that names its instance accordingly.
	/// Use it for <c>[Authorize(AuthenticationSchemes = ...)]</c> and for the
	/// <c>IApplicationUserResolver.Scheme</c> of a host following the convention; a host that
	/// names its instance differently must use that key instead.
	/// </remarks>
	public const string AuthenticationScheme = "Byoid";

	/// <summary>
	/// The default HTTP header name for tenant identification.
	/// </summary>
	public const string DefaultTenantHeaderName = "X-Tenant-Slug";

	/// <summary>
	/// The default path segment index for tenant identification (0-based).
	/// </summary>
	public const int DefaultTenantPathSegmentIndex = 0;

	/// <summary>
	/// The default JWKS cache duration.
	/// </summary>
	public static readonly TimeSpan DefaultJwksCacheDuration = TimeSpan.FromHours(1);
}
