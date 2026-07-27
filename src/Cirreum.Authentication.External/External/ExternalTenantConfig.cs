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
	/// <remarks>
	/// These must name <strong>your API</strong>, never a client ID. This is the boundary between an
	/// access token and an ID token: an access token's audience is the API it was issued for, while
	/// an ID token's audience is the client that requested sign-in. List a client ID here and ID
	/// tokens issued to that client will validate successfully.
	/// </remarks>
	public required IReadOnlyList<string> ValidAudiences { get; init; }

	/// <summary>
	/// The claim carrying the token's audience. Defaults to <c>aud</c>.
	/// </summary>
	/// <remarks>
	/// <para>
	/// Set this only for an IdP that puts the audience somewhere else. AWS Cognito is the case that
	/// motivates it: its access tokens carry the app client ID in <c>client_id</c> and may have no
	/// <c>aud</c> at all, while its ID tokens carry it in <c>aud</c> — so validating <c>aud</c>
	/// rejects every access token, and the token kinds are distinguished by neither.
	/// </para>
	/// <para>
	/// Changing this moves the check off the standard audience validation and onto an explicit
	/// comparison against <see cref="ValidAudiences"/>, which means it no longer separates access
	/// tokens from ID tokens on its own. <see cref="RequiredClaims"/> must therefore be populated
	/// with something that does; a configuration that moves the audience without supplying one is
	/// rejected at resolution time rather than silently accepting ID tokens.
	/// </para>
	/// </remarks>
	public string AudienceClaim { get; init; } = ExternalDefaults.DefaultAudienceClaim;

	/// <summary>
	/// Claims the token must carry, with exactly these values. Key = claim type, value = required
	/// value.
	/// </summary>
	/// <remarks>
	/// <para>
	/// For an IdP that marks what kind of token it issued with a claim of its own. AWS Cognito emits
	/// <c>token_use</c>, which is <c>access</c> on an access token and <c>id</c> on an ID token, so a
	/// Cognito tenant sets <c>{ "token_use": "access" }</c>. No other major IdP emits that claim,
	/// which is why this is per-tenant data rather than a framework-wide check.
	/// </para>
	/// <para>
	/// Comparison is ordinal and case-sensitive — these are protocol values, not user input. A claim
	/// that is absent fails, as does a token that cannot be read.
	/// </para>
	/// </remarks>
	public IReadOnlyDictionary<string, string>? RequiredClaims { get; init; }

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
