namespace Cirreum.Authentication.External;

/// <summary>
/// Specifies behavior when a tenant identifier is provided but the tenant cannot be resolved.
/// </summary>
public enum TenantNotFoundBehavior {
	/// <summary>
	/// Return 401 Unauthorized. Tenant identifier was provided but couldn't be resolved.
	/// Most secure - recommended for production.
	/// </summary>
	Reject,

	/// <summary>
	/// Fall through to other authentication schemes.
	/// Use with caution - only if you have a legitimate mixed-auth scenario
	/// where requests without tenant context should try other schemes.
	/// </summary>
	/// <remarks>
	/// WARNING: This can create security vulnerabilities if not carefully considered.
	/// Only use when you have endpoints that genuinely need to accept either
	/// External authentication OR other authentication methods.
	/// </remarks>
	Fallback,

	/// <summary>
	/// Log warning and reject. Helps identify misconfiguration during rollout.
	/// </summary>
	RejectWithLogging
}