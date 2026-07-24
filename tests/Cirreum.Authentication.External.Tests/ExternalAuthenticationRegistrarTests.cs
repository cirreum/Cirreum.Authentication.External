namespace Cirreum.Authentication.External.Tests;

using Cirreum.Authentication.Configuration;
using Cirreum.AuthenticationProvider;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

/// <summary>
/// Registration-path proofs for <see cref="ExternalAuthenticationRegistrar"/>. The framework
/// contract is that the configured instance key IS the scheme name — every downstream
/// per-scheme lookup (the AuthenticatedScheme stamp, IApplicationUserResolver dispatch,
/// boundary resolution) keys off it, so a registrar that registers under a different name
/// silently breaks that dispatch with no error.
/// </summary>
public sealed class ExternalAuthenticationRegistrarTests {

	private static ExternalAuthenticationSettings SettingsFor(params string[] instanceKeys) {
		var settings = new ExternalAuthenticationSettings();
		foreach (var key in instanceKeys) {
			settings.Instances[key] = new ExternalAuthenticationInstanceSettings {
				Enabled = true,
				TenantIdentifierSource = "Header",
				TenantHeaderName = "X-Tenant-Slug"
			};
		}
		return settings;
	}

	private static (IServiceCollection Services, AuthenticationBuilder AuthBuilder) NewComposition() {
		var services = new ServiceCollection();
		services.AddLogging();
		return (services, new AuthenticationBuilder(services));
	}

	private static void Register(ExternalAuthenticationSettings settings, IServiceCollection services, AuthenticationBuilder authBuilder) =>
		new ExternalAuthenticationRegistrar().Register(
			settings, services, new ConfigurationBuilder().Build(), authBuilder);

	// -------------------------------------------------------------------------
	// Scheme name == instance key
	// -------------------------------------------------------------------------

	[Fact]
	public void The_scheme_is_registered_under_the_instance_key() {
		var (services, authBuilder) = NewComposition();

		Register(SettingsFor("customerIdp"), services, authBuilder);

		using var provider = services.BuildServiceProvider();
		var schemes = provider.GetRequiredService<IOptions<AuthenticationOptions>>().Value.SchemeMap;

		schemes.Should().ContainKey("customerIdp");
	}

	[Fact]
	public void The_scheme_selector_reports_the_instance_key_not_the_default_constant() {
		// The selector's scheme name is what SchemeResolver stamps into
		// Items[AuthenticationContextKeys.AuthenticatedScheme] — the value every per-scheme
		// consumer matches on. Registering the hardcoded default here while the base stamped
		// settings.Scheme = key is exactly the silent-no-match trap.
		var (services, authBuilder) = NewComposition();
		Register(SettingsFor("customerIdp"), services, authBuilder);

		using var provider = services.BuildServiceProvider();
		var selector = provider.GetServices<ISchemeSelector>().OfType<ExternalAuthenticationSchemeSelector>().Single();

		var context = new DefaultHttpContext();
		context.Request.Headers["X-Tenant-Slug"] = "acme";
		context.Request.Headers.Authorization = "Bearer token";

		var (matches, schemeName) = selector.TrySelect(context);

		matches.Should().BeTrue();
		schemeName.Should().Be("customerIdp");
	}

	[Fact]
	public void An_instance_named_for_the_convention_still_registers_the_conventional_scheme() {
		var (services, authBuilder) = NewComposition();

		Register(SettingsFor(ExternalDefaults.AuthenticationScheme), services, authBuilder);

		using var provider = services.BuildServiceProvider();
		provider.GetRequiredService<IOptions<AuthenticationOptions>>().Value.SchemeMap
			.Should().ContainKey(ExternalDefaults.AuthenticationScheme);
	}

	// -------------------------------------------------------------------------
	// Single-instance invariant
	// -------------------------------------------------------------------------

	[Fact]
	public void A_second_configured_instance_fails_fast_with_a_diagnostic() {
		// Previously: the second AddScheme call collided on the hardcoded name (an opaque
		// ASP.NET "Scheme already exists" thrown later, at options materialization) while
		// TryAddSingleton silently kept the first instance's options.
		var (services, authBuilder) = NewComposition();

		var act = () => Register(SettingsFor("primary", "secondary"), services, authBuilder);

		act.Should().Throw<InvalidOperationException>()
			.WithMessage("*single instance per host*");
	}

	[Fact]
	public void A_disabled_second_instance_does_not_trip_the_guard() {
		var (services, authBuilder) = NewComposition();
		var settings = SettingsFor("primary");
		settings.Instances["secondary"] = new ExternalAuthenticationInstanceSettings { Enabled = false };

		var act = () => Register(settings, services, authBuilder);

		act.Should().NotThrow();
	}

	[Fact]
	public void A_separate_composition_is_isolated_from_the_first() {
		// The guard is collection-scoped, not static — two hosts in one process (the
		// integration-test norm) must each be able to register their own External instance.
		var (firstServices, firstAuthBuilder) = NewComposition();
		Register(SettingsFor("primary"), firstServices, firstAuthBuilder);

		var (secondServices, secondAuthBuilder) = NewComposition();
		var act = () => Register(SettingsFor("primary"), secondServices, secondAuthBuilder);

		act.Should().NotThrow();
	}

	// -------------------------------------------------------------------------
	// Resolver lifetime
	// -------------------------------------------------------------------------

	[Fact]
	public void The_tenant_resolver_is_scoped_by_default_so_it_can_consume_a_scoped_store() {
		var services = new ServiceCollection();
		var builder = Substitute.For<IAuthenticationBuilder>();
		builder.Services.Returns(services);

		builder.AddExternalTenantResolver<ScopedStoreResolver>();

		services.Single(d => d.ServiceType == typeof(IExternalTenantResolver))
			.Lifetime.Should().Be(ServiceLifetime.Scoped);
	}

	[Fact]
	public void A_scoped_resolver_resolves_under_scope_validation() {
		// Regression: a Singleton-registered resolver consuming a scoped store throws
		// "Cannot consume scoped service ... from singleton" once scope validation is on
		// (the default in Development) — the shape both the README and the interface's own
		// XML example show.
		var services = new ServiceCollection();
		services.AddScoped<TenantStore>();
		var builder = Substitute.For<IAuthenticationBuilder>();
		builder.Services.Returns(services);

		builder.AddExternalTenantResolver<ScopedStoreResolver>();

		using var provider = services.BuildServiceProvider(new ServiceProviderOptions {
			ValidateScopes = true,
			ValidateOnBuild = true
		});
		using var scope = provider.CreateScope();

		scope.ServiceProvider.GetRequiredService<IExternalTenantResolver>()
			.Should().BeOfType<ScopedStoreResolver>();
	}

	[Fact]
	public void A_caching_resolver_can_opt_into_singleton() {
		var services = new ServiceCollection();
		var builder = Substitute.For<IAuthenticationBuilder>();
		builder.Services.Returns(services);

		builder.AddExternalTenantResolver<CachingResolver>(lifetime: ServiceLifetime.Singleton);

		services.Single(d => d.ServiceType == typeof(IExternalTenantResolver))
			.Lifetime.Should().Be(ServiceLifetime.Singleton);
	}

	private sealed class TenantStore;

	private sealed class ScopedStoreResolver(TenantStore store) : IExternalTenantResolver {
		public Task<ExternalTenantConfig?> ResolveAsync(
			ExternalResolutionContext context,
			CancellationToken cancellationToken = default) {
			_ = store;
			return Task.FromResult<ExternalTenantConfig?>(null);
		}
	}

	private sealed class CachingResolver : IExternalTenantResolver {
		public Task<ExternalTenantConfig?> ResolveAsync(
			ExternalResolutionContext context,
			CancellationToken cancellationToken = default) =>
			Task.FromResult<ExternalTenantConfig?>(null);
	}
}
