namespace Cirreum.Authentication.External;

using Microsoft.AspNetCore.Authentication;

/// <summary>
/// Options for the External authentication handler.
/// </summary>
public class ExternalAuthenticationOptions : AuthenticationSchemeOptions {

	/// <summary>
	/// How to extract the tenant identifier from incoming requests.
	/// Default: <see cref="TenantIdentifierSource.Header"/>
	/// </summary>
	public TenantIdentifierSource TenantIdentifierSource { get; set; } = TenantIdentifierSource.Header;

	/// <summary>
	/// The HTTP header name containing the tenant identifier.
	/// Only used when <see cref="TenantIdentifierSource"/> is <see cref="TenantIdentifierSource.Header"/>.
	/// Default: "X-Tenant-Slug"
	/// </summary>
	public string TenantHeaderName { get; set; } = ExternalDefaults.DefaultTenantHeaderName;

	/// <summary>
	/// The URL path segment index (0-based) containing the tenant identifier.
	/// Only used when <see cref="TenantIdentifierSource"/> is <see cref="TenantIdentifierSource.PathSegment"/>.
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
	/// How long to cache JWKS (signing keys) from tenant IdPs.
	/// Default: 1 hour
	/// </summary>
	public TimeSpan JwksCacheDuration { get; set; } = ExternalDefaults.DefaultJwksCacheDuration;

	/// <summary>
	/// Whether to require HTTPS for IdP metadata endpoints.
	/// Default: true (recommended for production)
	/// </summary>
	public bool RequireHttpsMetadata { get; set; } = true;

	/// <summary>
	/// Behavior when a tenant identifier is provided but the tenant cannot be resolved.
	/// Default: <see cref="TenantNotFoundBehavior.Reject"/>
	/// </summary>
	public TenantNotFoundBehavior TenantNotFoundBehavior { get; set; } = TenantNotFoundBehavior.Reject;

	/// <summary>
	/// If true, return detailed error messages in responses.
	/// WARNING: Only enable in development. Leaks authentication structure information.
	/// Default: false
	/// </summary>
	public bool DetailedErrors { get; set; }

	/// <summary>
	/// Clock skew tolerance for token validation.
	/// Default: 5 minutes
	/// </summary>
	public TimeSpan ClockSkew { get; set; } = TimeSpan.FromMinutes(5);

}