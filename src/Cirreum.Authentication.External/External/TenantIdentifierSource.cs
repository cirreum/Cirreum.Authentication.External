namespace Cirreum.Authentication.External;

/// <summary>
/// Specifies how the tenant identifier is extracted from incoming requests.
/// </summary>
public enum TenantIdentifierSource {
	/// <summary>
	/// Extract tenant identifier from an HTTP header.
	/// </summary>
	Header,

	/// <summary>
	/// Extract tenant identifier from a URL path segment.
	/// </summary>
	PathSegment,

	/// <summary>
	/// Extract tenant identifier from the request subdomain.
	/// </summary>
	Subdomain
}
