namespace Cirreum.Authentication;

using Cirreum.AuthenticationProvider;
using Cirreum.Authentication.Configuration;
using Cirreum.Authentication.External;

using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

/// <summary>
/// Registrar for External (BYOID) authorization provider instances.
/// </summary>
/// <remarks>
/// <para>
/// External authentication enables APIs to accept tokens from multiple customer
/// Identity Providers (Okta, Auth0, customer Entra tenants, etc.) without requiring
/// federation into your identity provider.
/// </para>
/// <para>
/// This registrar validates configuration from appsettings.json and registers
/// the authentication handler. To complete the setup, a tenant resolver must be
/// registered via the <c>AddExternalAuth&lt;TResolver&gt;()</c> extension method.
/// </para>
/// </remarks>
public sealed class ExternalAuthenticationRegistrar
	: AuthenticationProviderRegistrar<
		ExternalAuthenticationSettings,
		ExternalAuthenticationInstanceSettings> {

	/// <inheritdoc/>
	public override string ProviderName => "External";

	/// <inheritdoc/>
	public override void ValidateSettings(ExternalAuthenticationInstanceSettings settings) {

		// Validate TenantIdentifierSource is a valid value
		if (!Enum.TryParse<TenantIdentifierSource>(settings.TenantIdentifierSource, ignoreCase: true, out var source)) {
			throw new InvalidOperationException(
				$"External provider instance '{settings.Scheme}' has invalid TenantIdentifierSource '{settings.TenantIdentifierSource}'. " +
				$"Valid values are: Header, PathSegment, Subdomain.");
		}

		// When using Header source, TenantHeaderName is required
		if (source == TenantIdentifierSource.Header &&
			string.IsNullOrWhiteSpace(settings.TenantHeaderName)) {
			throw new InvalidOperationException(
				$"External provider instance '{settings.Scheme}' requires TenantHeaderName when TenantIdentifierSource is Header.");
		}

		// Validate TenantNotFoundBehavior is a valid value
		if (!Enum.TryParse<TenantNotFoundBehavior>(settings.TenantNotFoundBehavior, ignoreCase: true, out _)) {
			throw new InvalidOperationException(
				$"External provider instance '{settings.Scheme}' has invalid TenantNotFoundBehavior '{settings.TenantNotFoundBehavior}'. " +
				$"Valid values are: Reject, RejectWithLogging, Fallback.");
		}

		// Validate path segment index is non-negative
		if (settings.TenantPathSegmentIndex < 0) {
			throw new InvalidOperationException(
				$"External provider instance '{settings.Scheme}' has invalid TenantPathSegmentIndex. Must be >= 0.");
		}

		// Validate JWKS cache duration is positive
		if (settings.JwksCacheDurationMinutes <= 0) {
			throw new InvalidOperationException(
				$"External provider instance '{settings.Scheme}' has invalid JwksCacheDurationMinutes. Must be > 0.");
		}

		// Validate clock skew is non-negative
		if (settings.ClockSkewSeconds < 0) {
			throw new InvalidOperationException(
				$"External provider instance '{settings.Scheme}' has invalid ClockSkewSeconds. Must be >= 0.");
		}

	}

	/// <inheritdoc/>
	protected override void RegisterScheme(
		string key,
		ExternalAuthenticationInstanceSettings settings,
		IServiceCollection services,
		IConfiguration configuration,
		AuthenticationBuilder authBuilder) {

		// External serves every tenant through one scheme, resolving each tenant's issuer at
		// request time via IExternalTenantResolver — per-tenant variance is data, not
		// configuration instances. A second instance would add no routing capability while
		// silently competing for the same singleton options and extractor, so fail fast here
		// rather than let TryAdd keep the first instance's settings and discard the rest.
		var claimed = services
			.FirstOrDefault(d => d.ImplementationInstance is ExternalSchemeClaim)?
			.ImplementationInstance as ExternalSchemeClaim;

		if (claimed is not null) {
			throw new InvalidOperationException(
				$"External provider instance '{settings.Scheme}' cannot be registered because instance " +
				$"'{claimed.Scheme}' already claimed this host's External scheme. External supports a " +
				$"single instance per host — it resolves every tenant dynamically through " +
				$"{nameof(IExternalTenantResolver)}, so per-tenant configuration belongs in that resolver " +
				$"rather than in additional configured instances.");
		}

		services.AddSingleton(new ExternalSchemeClaim(settings.Scheme));

		var scheme = settings.Scheme;

		// Register the authentication handler under the instance key — the framework contract
		// is that the instance key IS the scheme name (the base registrar stamps it onto
		// settings.Scheme), and every downstream per-scheme lookup — the AuthenticatedScheme
		// stamp, IApplicationUserResolver dispatch, boundary resolution — keys off that name.
		// Note: The handler will fail gracefully if IExternalTenantResolver is not registered.
		// The resolver is added via the AddExternalTenantResolver<T>() extension method.
		authBuilder.AddScheme<ExternalAuthenticationOptions, ExternalAuthenticationHandler>(
			scheme,
			configureOptions: o => ApplySettings(settings, o));

		// AuthenticationHandler<TOptions> reads its options through IOptionsMonitor.Get(scheme), so
		// the named instance configured above is the one the handler sees. Services outside the
		// handler resolve the bare type instead; registering that as a projection of the same named
		// instance keeps every consumer on one object. Registering a separately-built singleton
		// would create a second instance that only stays correct while someone remembers to update
		// two places at once.
		services.TryAddSingleton(sp =>
			sp.GetRequiredService<IOptionsMonitor<ExternalAuthenticationOptions>>().Get(scheme));

		// Register core services that don't require the resolver
		services.TryAddSingleton<ITenantIdentifierExtractor>(sp =>
			new TenantIdentifierExtractor(sp.GetRequiredService<ExternalAuthenticationOptions>()));

		// A named client so an app can reshape the outbound handler without the framework growing a
		// setting per knob. The timeout is the default that matters: HttpClient's own is 100
		// seconds, long enough that a tenant IdP which stops responding holds the authenticating
		// request open rather than failing it.
		services.AddHttpClient(ExternalDefaults.HttpClientName, static client => {
			client.Timeout = ExternalDefaults.DefaultMetadataTimeout;
		});

		services.TryAddSingleton<IExternalConfigurationManager>(sp =>
			new ExternalConfigurationManager(
				sp.GetRequiredService<ExternalAuthenticationOptions>().JwksCacheDuration,
				sp.GetRequiredService<IHttpClientFactory>(),
				sp.GetRequiredService<ILogger<ExternalConfigurationManager>>()));

		// Register the scheme selector — the dynamic forward resolver
		// iterates ISchemeSelector services in (Category, Priority) order and picks
		// the first that claims the request. External claims when a tenant indicator
		// + Bearer token are both present.
		services.AddSingleton<ISchemeSelector>(sp =>
			new ExternalAuthenticationSchemeSelector(
				scheme,
				sp.GetRequiredService<ExternalAuthenticationOptions>()));
	}

	// The one place settings become options. It runs as the named-options configuration for the
	// scheme, so there is nowhere else a property can be set — and nowhere else to forget one.
	private static void ApplySettings(
		ExternalAuthenticationInstanceSettings settings,
		ExternalAuthenticationOptions options) {

		options.TenantHeaderName = settings.TenantHeaderName;
		options.TenantPathSegmentIndex = settings.TenantPathSegmentIndex;
		options.ValidateTenantInPath = settings.ValidateTenantInPath;
		options.ValidationPathSegmentIndex = settings.ValidationPathSegmentIndex;
		options.JwksCacheDuration = TimeSpan.FromMinutes(settings.JwksCacheDurationMinutes);
		options.RequireHttpsMetadata = settings.RequireHttpsMetadata;
		options.DetailedErrors = settings.DetailedErrors;
		options.ClockSkew = TimeSpan.FromSeconds(settings.ClockSkewSeconds);
		options.TenantCacheDuration = TimeSpan.FromSeconds(settings.TenantResolverCache.DurationSeconds);
		options.TenantCacheNotFoundDuration = TimeSpan.FromSeconds(settings.TenantResolverCache.NotFoundDurationSeconds);
		options.TenantCacheMaxEntries = settings.TenantResolverCache.MaxEntries;

		// Parse TenantIdentifierSource
		if (Enum.TryParse<TenantIdentifierSource>(settings.TenantIdentifierSource, ignoreCase: true, out var source)) {
			options.TenantIdentifierSource = source;
		}

		// Parse TenantNotFoundBehavior
		if (Enum.TryParse<TenantNotFoundBehavior>(settings.TenantNotFoundBehavior, ignoreCase: true, out var behavior)) {
			options.TenantNotFoundBehavior = behavior;
		}
	}

}