namespace Cirreum.Authentication.External;

/// <summary>
/// Wraps the application's <see cref="IExternalTenantResolver"/> with the tenant cache, so the
/// authentication handler resolves tenants the same way whether caching is on or off.
/// </summary>
/// <remarks>
/// <para>
/// A decorator rather than a branch inside the handler: the handler asks for a tenant and gets one,
/// and whether that came from a store or from memory is not its concern. It also keeps the
/// application's resolver testable in isolation from the caching behavior.
/// </para>
/// <para>
/// Registered with the same lifetime as the resolver it wraps — the application's resolver is
/// scoped by default, since one reading tenant rows from a <c>DbContext</c> cannot be a singleton.
/// The cache itself is a singleton, which is why it is injected rather than held here.
/// </para>
/// </remarks>
internal sealed class CachingExternalTenantResolver(
	IExternalTenantResolver inner,
	ExternalTenantCache cache
) : IExternalTenantResolver {

	/// <inheritdoc />
	public async Task<ExternalTenantConfig?> ResolveAsync(
		ExternalResolutionContext context,
		CancellationToken cancellationToken = default) {

		ArgumentNullException.ThrowIfNull(context);

		if (!cache.IsEnabled) {
			return await inner.ResolveAsync(context, cancellationToken);
		}

		// A hit carrying a null configuration is a cached "not found", not a miss — returning it is
		// the whole point of caching negative results.
		if (cache.Get(context) is { } hit) {
			return hit.Config;
		}

		var resolved = await inner.ResolveAsync(context, cancellationToken);

		// A throwing resolver never reaches here, so a failure is never cached. The handler treats
		// that as a hard failure, and repeating the attempt next request is the correct behavior for
		// a store that is temporarily unavailable.
		cache.Set(context, resolved);
		return resolved;
	}

}
