namespace Cirreum.Authentication.External;

using Cirreum.Authentication.Events;

/// <summary>
/// Handles <see cref="ExternalTenantConfigurationChanged"/> by dropping whatever the tenant cache
/// holds for that tenant, so the next request re-resolves from the application's own store.
/// </summary>
/// <remarks>
/// Idempotent, and safe on a replica that never cached the tenant — the same event may be delivered
/// more than once in a distributed deployment, and to replicas that never served that tenant.
/// </remarks>
internal sealed class ExternalTenantCacheInvalidationHandler(
	ExternalTenantCache cache
) : IAuthenticationEventHandler<ExternalTenantConfigurationChanged> {

	/// <inheritdoc />
	public ValueTask HandleAsync(
		ExternalTenantConfigurationChanged evt,
		CancellationToken cancellationToken = default) {

		if (evt is not null) {
			cache.InvalidateTenant(evt.TenantSlug);
		}

		return ValueTask.CompletedTask;
	}

}
