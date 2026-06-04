namespace Cirreum.Authentication;

using Cirreum.Authentication.External;
using Cirreum.AuthenticationProvider;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

/// <summary>
/// Extensions on <see cref="IAuthenticationBuilder"/> contributed by the External (BYOID)
/// package. Available inside the <c>configure</c> callback of
/// <c>AddAuthentication(...)</c> on the umbrella package.
/// </summary>
public static class ExternalAuthenticationBuilderExtensions {

	/// <summary>
	/// Registers a dynamic <see cref="IExternalTenantResolver"/> implementation that
	/// resolves per-tenant IdP configuration at request time (typically from a
	/// database). External authentication requires a tenant resolver — without one,
	/// the External scheme has no way to map tenant indicators to validation parameters.
	/// </summary>
	/// <typeparam name="T">The app's <see cref="IExternalTenantResolver"/> implementation.</typeparam>
	/// <param name="builder">The Cirreum authentication builder.</param>
	/// <param name="configure">Optional callback to configure dynamic-resolver options.</param>
	/// <returns>The builder for chaining.</returns>
	public static IAuthenticationBuilder AddExternalTenantResolver<T>(
		this IAuthenticationBuilder builder,
		Action<DynamicExternalTenantOptions>? configure = null)
		where T : class, IExternalTenantResolver {

		ArgumentNullException.ThrowIfNull(builder);

		builder.Services.Replace(
			ServiceDescriptor.Singleton<IExternalTenantResolver, T>());

		if (configure is not null) {
			builder.Services.Configure(configure);
		}

		return builder;
	}

}

/// <summary>
/// Options for the dynamic External tenant resolver — caching, retry, etc.
/// Reserved for 1.x expansion; v1.0 carries no fields (just establishes the options-class hook).
/// </summary>
public sealed class DynamicExternalTenantOptions {
	// Reserved for 1.x — caching duration, retry policy, etc.
}
