namespace Cirreum.Authentication.Configuration;

using Cirreum.Authentication.External;

/// <summary>
/// Caching for <see cref="IExternalTenantResolver"/> results.
/// Maps to: Cirreum:Authentication:Providers:External:Instances:{name}:TenantResolverCache
/// </summary>
/// <remarks>
/// <para>
/// Without caching the resolver runs on <em>every authenticated request</em>, which for the common
/// database-backed implementation is a round trip per request.
/// </para>
/// <para>
/// It is nonetheless <b>off by default</b>. This sits on an authentication path, and reusing a
/// tenant's configuration widens the window in which a disabled tenant still authenticates — a
/// decision to make deliberately, not one to inherit. An application whose resolver already caches
/// internally wants it left off.
/// </para>
/// </remarks>
public class TenantResolverCacheSettings {

	/// <summary>
	/// How long a resolved tenant configuration is reused before the resolver is asked again.
	/// <c>0</c> — the default — disables tenant caching entirely.
	/// </summary>
	/// <remarks>
	/// When enabled, publish <c>ExternalTenantConfigurationChanged</c> after changing a tenant and
	/// the entry is dropped immediately — across every replica where coordination is composed.
	/// Expiry is the backstop, not the mechanism.
	/// </remarks>
	public int DurationSeconds { get; set; }

	/// <summary>
	/// How long a "tenant not found" resolution is remembered. Ignored when
	/// <see cref="DurationSeconds"/> is <c>0</c>.
	/// </summary>
	/// <remarks>
	/// Caching the negative result is a robustness concern, not a micro-optimization: without it, a
	/// caller supplying unknown tenant identifiers costs one resolver call — typically one database
	/// query — per request, with no upper bound. Kept deliberately shorter than
	/// <see cref="DurationSeconds"/> so a newly-created tenant becomes reachable quickly.
	/// </remarks>
	public int NotFoundDurationSeconds { get; set; } = ExternalDefaults.DefaultTenantCacheNotFoundSeconds;

	/// <summary>The maximum number of entries held. Defaults to 1000.</summary>
	/// <remarks>
	/// Cache keys derive from request-supplied values, so the population is caller-influenced and
	/// needs a ceiling. On saturation the cache <b>evicts</b> — it never refuses to resolve. That is
	/// the opposite of what a revocation denylist does on saturation, and deliberately: a denylist
	/// that forgets an entry re-admits a revoked credential, while a cache that forgets one merely
	/// asks the resolver again.
	/// </remarks>
	public int MaxEntries { get; set; } = ExternalDefaults.DefaultTenantCacheMaxEntries;

}
