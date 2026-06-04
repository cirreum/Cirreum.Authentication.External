namespace Cirreum.Authentication;

using Cirreum.AuthenticationProvider;
using Cirreum.Authentication.Configuration;
using Cirreum.Authentication.External;

using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;

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

		// Build ExternalAuthenticationOptions from settings
		var options = BuildOptionsFromSettings(settings);

		// Register the options as a singleton for the handler and other services
		services.TryAddSingleton(options);

		// Register core services that don't require the resolver
		services.TryAddSingleton<ITenantIdentifierExtractor>(sp =>
			new TenantIdentifierExtractor(sp.GetRequiredService<ExternalAuthenticationOptions>()));

		services.TryAddSingleton<IExternalConfigurationManager>(sp =>
			new ExternalConfigurationManager(
				options.JwksCacheDuration,
				sp.GetRequiredService<ILogger<ExternalConfigurationManager>>()));

		// Register the authentication handler
		// Note: The handler will fail gracefully if IExternalTenantResolver is not registered
		// The resolver is added via AddExternalAuth<TResolver>() extension method
		authBuilder.AddScheme<ExternalAuthenticationOptions, ExternalAuthenticationHandler>(
			ExternalDefaults.AuthenticationScheme,
			configureOptions: o => {
				o.TenantIdentifierSource = options.TenantIdentifierSource;
				o.TenantHeaderName = options.TenantHeaderName;
				o.TenantPathSegmentIndex = options.TenantPathSegmentIndex;
				o.ValidateTenantInPath = options.ValidateTenantInPath;
				o.ValidationPathSegmentIndex = options.ValidationPathSegmentIndex;
				o.JwksCacheDuration = options.JwksCacheDuration;
				o.RequireHttpsMetadata = options.RequireHttpsMetadata;
				o.TenantNotFoundBehavior = options.TenantNotFoundBehavior;
				o.DetailedErrors = options.DetailedErrors;
				o.ClockSkew = options.ClockSkew;
			});

		// Register the scheme selector — the dynamic forward resolver
		// iterates ISchemeSelector services in (Category, Priority) order and picks
		// the first that claims the request. External claims when a tenant indicator
		// + Bearer token are both present.
		services.AddSingleton<ISchemeSelector>(sp =>
			new ExternalAuthenticationSchemeSelector(
				ExternalDefaults.AuthenticationScheme,
				sp.GetRequiredService<ExternalAuthenticationOptions>()));
	}

	private static ExternalAuthenticationOptions BuildOptionsFromSettings(
		ExternalAuthenticationInstanceSettings settings) {

		var options = new ExternalAuthenticationOptions {
			TenantHeaderName = settings.TenantHeaderName,
			TenantPathSegmentIndex = settings.TenantPathSegmentIndex,
			ValidateTenantInPath = settings.ValidateTenantInPath,
			ValidationPathSegmentIndex = settings.ValidationPathSegmentIndex,
			JwksCacheDuration = TimeSpan.FromMinutes(settings.JwksCacheDurationMinutes),
			RequireHttpsMetadata = settings.RequireHttpsMetadata,
			DetailedErrors = settings.DetailedErrors,
			ClockSkew = TimeSpan.FromSeconds(settings.ClockSkewSeconds)
		};

		// Parse TenantIdentifierSource
		if (Enum.TryParse<TenantIdentifierSource>(settings.TenantIdentifierSource, ignoreCase: true, out var source)) {
			options.TenantIdentifierSource = source;
		}

		// Parse TenantNotFoundBehavior
		if (Enum.TryParse<TenantNotFoundBehavior>(settings.TenantNotFoundBehavior, ignoreCase: true, out var behavior)) {
			options.TenantNotFoundBehavior = behavior;
		}

		return options;
	}

}