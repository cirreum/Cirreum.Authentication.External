namespace Cirreum.Authentication.External;

using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System.Collections.Concurrent;

/// <summary>
/// Default implementation that caches configuration managers per metadata address.
/// </summary>
public class ExternalConfigurationManager(
	TimeSpan refreshInterval,
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

		var httpClient = new HttpClient(new HttpClientHandler {
			ServerCertificateCustomValidationCallback = requireHttps
				? null
				: HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
		});

		return new ConfigurationManager<OpenIdConnectConfiguration>(
			metadataAddress,
			new OpenIdConnectConfigurationRetriever(),
			httpClient) {
			AutomaticRefreshInterval = refreshInterval,
			RefreshInterval = TimeSpan.FromMinutes(5) // Minimum time between refresh attempts
		};

	}

}