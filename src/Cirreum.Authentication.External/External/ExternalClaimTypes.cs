namespace Cirreum.Authentication.External;

/// <summary>
/// Claim types the External handler stamps onto every authenticated identity itself.
/// </summary>
/// <remarks>
/// <para>
/// These are <strong>reserved</strong>. A claim of one of these types arriving in a tenant's token,
/// or produced by an <see cref="ExternalTenantConfig.ClaimMappings"/> entry that targets one, is
/// discarded before the handler stamps its own — otherwise the identity would carry two claims of
/// the same type and <c>FindFirst</c> would return the token's, because it was added first.
/// </para>
/// <para>
/// For <see cref="TenantSlug"/> that is the difference between a claim describing which tenant the
/// framework resolved and one the caller chose. Read them expecting exactly one of each.
/// </para>
/// </remarks>
public static class ExternalClaimTypes {

	/// <summary>
	/// The slug of the tenant whose configuration validated this token, as resolved by the framework.
	/// </summary>
	public const string TenantSlug = "tenant_slug";

	/// <summary>
	/// The authentication scheme that authenticated the request — the configured instance key.
	/// </summary>
	public const string AuthScheme = "auth_scheme";

}
