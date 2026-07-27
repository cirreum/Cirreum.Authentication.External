namespace Cirreum.Authentication.External.Tests;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using System.Net;

/// <summary>
/// Outbound-behaviour proofs for <see cref="ExternalConfigurationManager"/>. This is the only
/// component that talks to a tenant's IdP, so what it does — and declines to do — on the wire is
/// the framework's stewardship of a customer's identity provider.
/// </summary>
public sealed class ExternalConfigurationManagerTests {

	private const string HttpMetadata = "http://idp.example.com/.well-known/openid-configuration";

	private sealed class RecordingHandler : HttpMessageHandler {

		public int Requests { get; private set; }

		protected override Task<HttpResponseMessage> SendAsync(
			HttpRequestMessage request,
			CancellationToken cancellationToken) {

			this.Requests++;
			return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
		}
	}

	private static (ExternalConfigurationManager Manager, RecordingHandler Handler) NewManager() {
		var handler = new RecordingHandler();
		var services = new ServiceCollection();
		services.AddLogging();
		services.AddHttpClient(ExternalDefaults.HttpClientName)
			.ConfigurePrimaryHttpMessageHandler(() => handler);

		var provider = services.BuildServiceProvider();

		var manager = new ExternalConfigurationManager(
			TimeSpan.FromHours(1),
			provider.GetRequiredService<IHttpClientFactory>(),
			provider.GetRequiredService<ILogger<ExternalConfigurationManager>>());

		return (manager, handler);
	}

	[Fact]
	public async Task An_http_metadata_address_is_rejected_before_anything_reaches_the_wire() {
		// RequireHttpsMetadata previously did not enforce anything: an http address was fetched
		// either way, and setting the flag false disabled certificate validation instead — the
		// opposite of what the name promises.
		var (manager, handler) = NewManager();

		var act = async () => await manager.GetConfigurationAsync(HttpMetadata, requireHttps: true);

		await act.Should().ThrowAsync<Exception>();
		handler.Requests.Should().Be(0);
	}

	[Fact]
	public async Task An_http_metadata_address_is_permitted_when_https_is_not_required() {
		// The escape hatch for a local IdP container still works — it just no longer doubles as a
		// switch for certificate validation.
		var (manager, handler) = NewManager();

		var act = async () => await manager.GetConfigurationAsync(HttpMetadata, requireHttps: false);

		// The stub answers 404, so retrieval fails regardless; the proof is that it was attempted.
		await act.Should().ThrowAsync<Exception>();
		handler.Requests.Should().BeGreaterThan(0);
	}

	[Fact]
	public async Task Refreshing_an_address_that_was_never_retrieved_does_nothing() {
		var (manager, handler) = NewManager();

		await manager.RefreshConfigurationAsync(HttpMetadata);

		handler.Requests.Should().Be(0);
	}
}
