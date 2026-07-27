namespace Cirreum.Authentication.External;

using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System.Collections.Concurrent;
using System.Net.Http;

/// <summary>
/// Default implementation that caches configuration managers per metadata address.
/// </summary>
/// <remarks>
/// Each tenant IdP is fetched at most once per five minutes — the refresh floor — and normally once
/// per <paramref name="refreshInterval"/>, with concurrent callers coalesced onto a single request
/// and the last known-good document served while a refresh is failing.
/// Token validation itself is local, so a caller presenting invalid tokens generates no outbound
/// traffic to the tenant's IdP at all.
/// </remarks>
public class ExternalConfigurationManager(
	TimeSpan refreshInterval,
	IHttpClientFactory httpClientFactory,
	ILogger<ExternalConfigurationManager> logger
) : IExternalConfigurationManager {

	private readonly ConcurrentDictionary<string, ConfigurationManager<OpenIdConnectConfiguration>> _managers = new();

	public async Task<OpenIdConnectConfiguration> GetConfigurationAsync(
		string metadataAddress,
		bool requireHttps,
		CancellationToken ct = default) {

		var manager = this._managers.GetOrAdd(metadataAddress, addr => this.CreateManager(addr, requireHttps));

		try {
			return await manager.GetConfigurationAsync(ct);
		} catch (Exception ex) {
			logger.LogError(ex, "Failed to retrieve OIDC configuration from {MetadataAddress}", metadataAddress);
			throw;
		}
	}

	public async Task RefreshConfigurationAsync(string metadataAddress, CancellationToken ct = default) {
		if (this._managers.TryGetValue(metadataAddress, out var manager)) {
			manager.RequestRefresh();
			await manager.GetConfigurationAsync(ct);
		}
	}

	private ConfigurationManager<OpenIdConnectConfiguration> CreateManager(
		string metadataAddress,
		bool requireHttps) {

		if (logger.IsEnabled(LogLevel.Debug)) {
			logger.LogDebug("Creating OIDC configuration manager for {MetadataAddress}", metadataAddress);
		}

		// HttpDocumentRetriever.RequireHttps rejects a non-https metadata address at fetch time.
		// Certificate validation is deliberately not configurable: an app that genuinely needs a
		// custom handler for local development reconfigures ExternalDefaults.HttpClientName, which
		// is a code-level opt-in rather than a JSON flag that travels to production.
		var documentRetriever = new HttpDocumentRetriever(
			httpClientFactory.CreateClient(ExternalDefaults.HttpClientName)) {
			RequireHttps = requireHttps
		};

		return new ConfigurationManager<OpenIdConnectConfiguration>(
			metadataAddress,
			new OpenIdConnectConfigurationRetriever(),
			documentRetriever) {
			AutomaticRefreshInterval = refreshInterval,
			RefreshInterval = TimeSpan.FromMinutes(5) // Minimum time between refresh attempts
		};

	}

}
