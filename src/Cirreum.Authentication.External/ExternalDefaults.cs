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

	/// <summary>
	/// How long a "tenant not found" resolution is remembered when tenant caching is enabled.
	/// Deliberately short, so a newly-created tenant becomes reachable quickly.
	/// </summary>
	public const int DefaultTenantCacheNotFoundSeconds = 30;

	/// <summary>The default ceiling on distinct tenants held in the resolution cache.</summary>
	public const int DefaultTenantCacheMaxEntries = 1_000;

	/// <summary>
	/// The claim that carries a token's audience under OAuth 2.0 and OpenID Connect, and the default
	/// for <c>ExternalTenantConfig.AudienceClaim</c>.
	/// </summary>
	public const string DefaultAudienceClaim = "aud";

	/// <summary>
	/// The name of the <see cref="System.Net.Http.IHttpClientFactory"/> client used to retrieve
	/// tenant IdP metadata and signing keys.
	/// </summary>
	/// <remarks>
	/// <para>
	/// Named so an app can reshape the handler — a proxy, a pinned certificate, different pooling,
	/// a longer timeout for a slow IdP — without the framework growing a setting for each:
	/// </para>
	/// <code>
	/// builder.Services.AddHttpClient(ExternalDefaults.HttpClientName)
	///     .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler { /* ... */ });
	/// </code>
	/// <para>
	/// Reconfiguring this client affects only outbound metadata retrieval, never inbound token
	/// validation, which is entirely local.
	/// </para>
	/// </remarks>
	public const string HttpClientName = "Cirreum.Authentication.External";

	/// <summary>
	/// The default timeout for a tenant IdP metadata or signing-key request.
	/// </summary>
	/// <remarks>
	/// <see cref="System.Net.Http.HttpClient"/> defaults to 100 seconds, which on this path means a
	/// tenant IdP that stops responding holds the authenticating request open for that long. Ten
	/// seconds is generous for a metadata document; raise it for a specific deployment by
	/// reconfiguring <see cref="HttpClientName"/>.
	/// </remarks>
	public static readonly TimeSpan DefaultMetadataTimeout = TimeSpan.FromSeconds(10);
}
