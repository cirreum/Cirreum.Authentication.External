namespace Cirreum.Authentication.External.Tests;

using Cirreum.AuthenticationProvider;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

/// <summary>
/// Composition-path proofs for <c>AddExternalTenantResolver&lt;T&gt;()</c>: the verb must register the
/// supplied resolver (replacing any prior registration — the documented last-wins seam) and wire the
/// optional options callback. Guards the untested-composition-verb escape vector behind
/// Cirreum.Authentication.ApiKey issue #1, where the provider's composition verb threw unconditionally
/// through five published versions because no test ever invoked it.
/// </summary>
public sealed class ExternalTenantResolverCompositionTests {

	private static IAuthenticationBuilder CreateBuilder(IServiceCollection services) {
		var builder = Substitute.For<IAuthenticationBuilder>();
		builder.Services.Returns(services);
		builder.AuthBuilder.Returns(new AuthenticationBuilder(services));
		builder.Configuration.Returns(new ConfigurationBuilder().Build());
		return builder;
	}

	[Fact]
	public void AddExternalTenantResolver_registers_the_supplied_resolver() {
		var services = new ServiceCollection();
		var builder = CreateBuilder(services);

		builder.AddExternalTenantResolver<StubTenantResolver>();

		using var provider = services.BuildServiceProvider();
		provider.GetRequiredService<IExternalTenantResolver>().Should().BeOfType<StubTenantResolver>();
	}

	[Fact]
	public void AddExternalTenantResolver_replaces_a_preexisting_registration() {
		var services = new ServiceCollection();
		services.AddSingleton<IExternalTenantResolver, StubTenantResolver>();
		var builder = CreateBuilder(services);

		builder.AddExternalTenantResolver<OtherTenantResolver>();

		services.Count(d => d.ServiceType == typeof(IExternalTenantResolver)).Should().Be(1);
		using var provider = services.BuildServiceProvider();
		provider.GetRequiredService<IExternalTenantResolver>().Should().BeOfType<OtherTenantResolver>();
	}

	[Fact]
	public void AddExternalTenantResolver_wires_the_options_callback() {
		var services = new ServiceCollection();
		var builder = CreateBuilder(services);
		var configured = false;

		builder.AddExternalTenantResolver<StubTenantResolver>(_ => configured = true);

		using var provider = services.BuildServiceProvider();
		provider.GetRequiredService<IOptions<DynamicExternalTenantOptions>>().Value.Should().NotBeNull();
		configured.Should().BeTrue();
	}

	[Fact]
	public void AddExternalTenantResolver_throws_on_a_null_builder() {
		IAuthenticationBuilder builder = null!;

		var act = () => builder.AddExternalTenantResolver<StubTenantResolver>();

		act.Should().Throw<ArgumentNullException>();
	}

	private class StubTenantResolver : IExternalTenantResolver {
		public Task<ExternalTenantConfig?> ResolveAsync(
			ExternalResolutionContext context,
			CancellationToken cancellationToken = default) => Task.FromResult<ExternalTenantConfig?>(null);
	}

	private sealed class OtherTenantResolver : StubTenantResolver;
}
