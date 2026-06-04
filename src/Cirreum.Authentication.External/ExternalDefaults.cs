namespace Cirreum.Authentication.External;

/// <summary>
/// Default values for BYOID authentication.
/// </summary>
public static class ExternalDefaults {
	/// <summary>
	/// The default authentication scheme name for BYOID.
	/// </summary>
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
