namespace Cirreum.Authentication.Events;

/// <summary>
/// The stable <c>[MessageVersion]</c> identifiers for the External (BYOID) authentication events.
/// </summary>
/// <remarks>
/// Mirrors the framework's own <c>EventMessages</c> in <c>Cirreum.Kernel</c>, which is internal to
/// that package — a track shipping its own events supplies its own identifiers. The
/// <c>authentication.</c> prefix is the shared wire namespace; <c>external-</c> distinguishes this
/// track's events from the framework-wide ones, so an identifier is unambiguous about which package
/// owns the type it resolves to.
/// </remarks>
internal static class ExternalEventMessages {

	/// <summary>The stable message identifier for the <c>ExternalTenantConfigurationChanged</c> event.</summary>
	public const string TenantConfigurationChanged = "authentication.external-tenant-configuration-changed";

}
