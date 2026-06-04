namespace Cirreum.Authentication.External;

/// <summary>
/// Context provided to the tenant resolver containing all available hints
/// for resolving the tenant configuration.
/// </summary>
public record ExternalResolutionContext {
	/// <summary>
	/// The tenant slug extracted from the request (header, path, or subdomain).
	/// This is the primary identifier used to resolve tenant configuration.
	/// </summary>
	public string? TenantSlug { get; init; }

	/// <summary>
	/// The issuer claim from the JWT token, if available.
	/// Can be used as a fallback for resolution or validation.
	/// </summary>
	public string? TokenIssuer { get; init; }

	/// <summary>
	/// The audience claim from the JWT token, if available.
	/// Can be used for additional validation.
	/// </summary>
	public string? TokenAudience { get; init; }

	/// <summary>
	/// The raw JWT token, if needed for advanced scenarios.
	/// </summary>
	public string? RawToken { get; init; }
}
