namespace Cirreum.Authentication.Events;

using Cirreum.Messaging;

/// <summary>
/// Published by an application when a tenant's external identity configuration changes — disabled,
/// re-enabled, re-pointed at different metadata, or given different valid audiences.
/// </summary>
/// <param name="TenantSlug">
/// The tenant whose configuration changed, as the application's
/// <c>IExternalTenantResolver</c> identifies it.
/// </param>
/// <param name="OccurredAt">When the change occurred, in the publishing system's authority.</param>
/// <remarks>
/// <para>
/// The framework's only reaction is to forget what it cached for that tenant, so the next request
/// re-resolves. The event deliberately carries no description of <em>what</em> changed: the
/// re-resolve reads the current truth from the application's own store, which is authoritative
/// either way. That also keeps one event covering disable, enable, and edit rather than three that
/// all mean "read it again".
/// </para>
/// <para>
/// Publishing is only necessary when tenant caching is enabled
/// (<c>DynamicExternalTenantOptions.CacheDuration</c>). With caching off the resolver already runs
/// every request, and publishing is a harmless no-op — so an application can publish
/// unconditionally rather than branching on configuration it does not own.
/// </para>
/// <para>
/// Rides the authentication event bus, so a deployment with coordination composed delivers it to
/// every replica rather than only the one that handled the administrative request. Without
/// coordination it invalidates the local process only, and other replicas correct themselves when
/// their cached entry expires.
/// </para>
/// </remarks>
[MessageVersion(ExternalEventMessages.TenantConfigurationChanged, "1")]
public sealed record ExternalTenantConfigurationChanged(
	string TenantSlug,
	DateTimeOffset OccurredAt
) : IAuthenticationEvent;
