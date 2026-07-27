namespace Cirreum.Authentication.External;

/// <summary>
/// Context provided to the tenant resolver containing all available hints
/// for resolving the tenant configuration.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Everything on this type is untrusted.</strong> The slug is taken from a request header,
/// path segment or subdomain, and the token values are read from the JWT payload <em>before</em> its
/// signature has been verified — anyone can mint a JWT asserting any issuer or audience. They are
/// routing hints, nothing more.
/// </para>
/// <para>
/// That is safe as long as a resolver uses them only to <strong>select</strong> a stored tenant
/// configuration, never to <strong>populate</strong> one. Looking up a row by issuer is fine, because
/// the row still had to exist and an operator still had to approve it. Building an
/// <see cref="ExternalTenantConfig"/> whose <see cref="ExternalTenantConfig.MetadataAddress"/> or
/// <see cref="ExternalTenantConfig.ValidAudiences"/> come from the token is not: it would let a
/// caller nominate the keys their own token is validated against, which validates every token.
/// </para>
/// </remarks>
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
	/// The audience claim values from the JWT token, empty when the token carries none or could not
	/// be read.
	/// </summary>
	/// <remarks>
	/// A collection because <c>aud</c> may be a single string or an array — both are legal under
	/// RFC 7519 §4.1.3, and a token carrying several audiences is ordinary rather than exotic.
	/// </remarks>
	public IReadOnlyList<string> TokenAudiences { get; init; } = [];

	/// <summary>
	/// The raw JWT token, if needed for advanced scenarios.
	/// </summary>
	public string? RawToken { get; init; }
}
