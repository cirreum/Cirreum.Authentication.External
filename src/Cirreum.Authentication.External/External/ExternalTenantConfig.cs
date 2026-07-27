namespace Cirreum.Authentication.External;

/// <summary>
/// Configuration for a tenant's identity provider in the BYOID system.
/// Returned by <see cref="IExternalTenantResolver"/> to configure JWT validation.
/// </summary>
public record ExternalTenantConfig {

	/// <summary>
	/// The tenant's unique slug/identifier.
	/// </summary>
	public required string Slug { get; init; }

	/// <summary>
	/// Whether this tenant is enabled for authentication.
	/// Disabled tenants will receive 401 responses.
	/// </summary>
	public required bool IsEnabled { get; init; }

	/// <summary>
	/// Display name for logging and error messages.
	/// </summary>
	public string? DisplayName { get; init; }

	/// <summary>
	/// The OIDC metadata endpoint URL for this tenant's IdP.
	/// Example: https://acme.okta.com/.well-known/openid-configuration
	/// </summary>
	/// <remarks>
	/// Cirreum will fetch the JWKS endpoint and issuer from this metadata.
	/// </remarks>
	public required string MetadataAddress { get; init; }

	/// <summary>
	/// Expected audience claim value(s) for token validation.
	/// At least one audience must match for the token to be valid.
	/// </summary>
	public required IReadOnlyList<string> ValidAudiences { get; init; }

	/// <summary>
	/// Optional: Override the issuer validation.
	/// Use when the metadata issuer doesn't match the token issuer.
	/// </summary>
	public string? ValidIssuerOverride { get; init; }

	/// <summary>
	/// Optional: Custom claim mappings for normalization.
	/// Key = source claim type from the IdP.
	/// Value = target Cirreum claim type.
	/// </summary>
	/// <remarks>
	/// Use this when the tenant's IdP uses non-standard claim names.
	/// Example: { "groups": "roles" } to map Okta groups to roles.
	/// </remarks>
	public IReadOnlyDictionary<string, string>? ClaimMappings { get; init; }

	/// <summary>
	/// Optional: Allowed client IDs (azp claim) for this tenant.
	/// If specified, the token's <c>azp</c> or <c>client_id</c> claim must match one of these values.
	/// </summary>
	/// <remarks>
	/// <para>
	/// This prevents tokens issued to one client application from being used by another.
	/// For example, a token issued to "partner-mobile-app" cannot be used by "partner-web-app"
	/// unless both are in this list.
	/// </para>
	/// <para>
	/// If null or empty, client ID validation is skipped (any client is allowed).
	/// </para>
	/// </remarks>
	public IReadOnlyList<string>? AllowedClientIds { get; init; }

	/// <summary>
	/// Whether to require the token to carry the RFC 9068 access-token type (<c>typ: at+jwt</c>).
	/// </summary>
	/// <remarks>
	/// <para>
	/// Enable only for a tenant whose IdP is known to emit it. RFC 9068 defines a profile that an
	/// access token may conform to, not a requirement on OAuth access tokens generally: an IdP may
	/// equally issue <c>typ: "JWT"</c>, omit <c>typ</c> altogether — it is optional under RFC 7519 —
	/// or mark the token's kind with a claim of its own. Requiring <c>at+jwt</c> of a tenant whose
	/// IdP does none of those rejects every token they present.
	/// </para>
	/// <para>
	/// This is a narrowing check, not the boundary between an access token and an ID token. That
	/// boundary is <see cref="ValidAudiences"/>, which must name this API: an access token's
	/// audience is the API it was issued for, while an ID token's audience is the client that
	/// requested sign-in.
	/// </para>
	/// </remarks>
	public bool RequireAccessTokenType { get; init; }

}
