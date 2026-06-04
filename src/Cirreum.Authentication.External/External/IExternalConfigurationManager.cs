namespace Cirreum.Authentication.External;

using Microsoft.IdentityModel.Protocols.OpenIdConnect;

/// <summary>
/// Caches OIDC configuration (including JWKS) per tenant IdP.
/// </summary>
public interface IExternalConfigurationManager {
	/// <summary>
	/// Get the OIDC configuration for a tenant's IdP.
	/// </summary>
	/// <param name="metadataAddress">The OIDC metadata endpoint URL.</param>
	/// <param name="requireHttps">Whether to require HTTPS.</param>
	/// <param name="ct">Cancellation token.</param>
	/// <returns>The OIDC configuration including signing keys.</returns>
	Task<OpenIdConnectConfiguration> GetConfigurationAsync(
		string metadataAddress,
		bool requireHttps,
		CancellationToken ct = default);

	/// <summary>
	/// Force refresh the configuration for a specific metadata address.
	/// </summary>
	/// <param name="metadataAddress">The OIDC metadata endpoint URL.</param>
	/// <param name="ct">Cancellation token.</param>
	Task RefreshConfigurationAsync(string metadataAddress, CancellationToken ct = default);
}