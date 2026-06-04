namespace Cirreum.Authentication.Configuration;

using Cirreum.AuthenticationProvider.Configuration;
using Cirreum.Authentication.External;

/// <summary>
/// Settings for a single External (BYOID) provider instance.
/// Maps to: Cirreum:Authorization:Providers:External:Instances:{name}
/// </summary>
/// <remarks>
/// <para>
/// External authentication enables your API to accept tokens from multiple customer
/// Identity Providers (Okta, Auth0, customer Entra tenants, etc.) without requiring
/// federation into your identity provider.
/// </para>
/// <para>
/// Unlike other authorization providers that use static configuration, External
/// resolves tenant IdP configuration at runtime via <see cref="IExternalTenantResolver"/>.
/// </para>
/// </remarks>
public class ExternalAuthenticationInstanceSettings
	: AuthenticationProviderInstanceSettings {

	/// <summary>
	/// How to extract the tenant identifier from incoming requests.
	/// Valid values: "Header", "PathSegment", "Subdomain"
	/// Default: "Header"
	/// </summary>
	public string TenantIdentifierSource { get; set; } = "Header";

	/// <summary>
	/// The HTTP header name containing the tenant identifier.
	/// Only used when <see cref="TenantIdentifierSource"/> is "Header".
	/// Default: "X-Tenant-Slug"
	/// </summary>
	public string TenantHeaderName { get; set; } = ExternalDefaults.DefaultTenantHeaderName;

	/// <summary>
	/// The URL path segment index (0-based) containing the tenant identifier.
	/// Only used when <see cref="TenantIdentifierSource"/> is "PathSegment".
	/// Default: 0 (e.g., /{tenant}/resource)
	/// </summary>
	public int TenantPathSegmentIndex { get; set; } = ExternalDefaults.DefaultTenantPathSegmentIndex;

	/// <summary>
	/// Whether to also validate that the tenant identifier in the path matches
	/// the tenant identifier from the primary source (defense in depth).
	/// Default: false
	/// </summary>
	public bool ValidateTenantInPath { get; set; }

	/// <summary>
	/// The path segment index to validate against when <see cref="ValidateTenantInPath"/> is true.
	/// Default: 0
	/// </summary>
	public int ValidationPathSegmentIndex { get; set; } = 0;

	/// <summary>
	/// JWKS cache duration in minutes. Controls how long signing keys from tenant IdPs are cached.
	/// Default: 60
	/// </summary>
	public int JwksCacheDurationMinutes { get; set; } = 60;

	/// <summary>
	/// Whether to require HTTPS for IdP metadata endpoints.
	/// Default: true (recommended for production)
	/// </summary>
	public bool RequireHttpsMetadata { get; set; } = true;

	/// <summary>
	/// Behavior when a tenant identifier is provided but the tenant cannot be resolved.
	/// Valid values: "Reject", "RejectWithLogging", "Fallback"
	/// Default: "Reject" (fail closed)
	/// </summary>
	public string TenantNotFoundBehavior { get; set; } = "Reject";

	/// <summary>
	/// Clock skew tolerance in seconds for token validation.
	/// Default: 300 (5 minutes)
	/// </summary>
	public int ClockSkewSeconds { get; set; } = 300;

	/// <summary>
	/// If true, return detailed error messages in responses.
	/// WARNING: Only enable in development. Leaks authentication structure information.
	/// Default: false
	/// </summary>
	public bool DetailedErrors { get; set; }

}