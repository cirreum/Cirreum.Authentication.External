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
	/// <param name="requireHttps">
	/// Whether the metadata address must use HTTPS. When <see langword="true"/> a non-HTTPS address
	/// is rejected at fetch time.
	/// </param>
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
	/// <remarks>
	/// <para>
	/// The on-demand seam for the case the automatic refresh interval does not cover: a tenant has
	/// rotated their signing keys out of band and their users would otherwise fail authentication
	/// until the next scheduled refresh. Resolve this service and call it from wherever the app
	/// learns of the rotation — an admin action, a webhook from the tenant's IdP.
	/// </para>
	/// <para>
	/// Refresh attempts are floored at five minutes by the underlying configuration manager, so
	/// calling this in a loop cannot turn into load on the tenant's IdP. Nothing in the framework
	/// calls it on a validation failure, and it should not be wired that way: that would let anyone
	/// presenting a malformed token trigger outbound requests to a customer's IdP.
	/// </para>
	/// <para>
	/// Does nothing when the address has no cached configuration — there is nothing to refresh
	/// until a first successful retrieval.
	/// </para>
	/// </remarks>
	Task RefreshConfigurationAsync(string metadataAddress, CancellationToken ct = default);
}