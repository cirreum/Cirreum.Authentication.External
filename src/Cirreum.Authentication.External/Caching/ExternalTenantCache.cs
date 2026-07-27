namespace Cirreum.Authentication.External;

using System.Collections.Concurrent;

/// <summary>
/// Process-wide cache of resolved tenant configurations, keyed by the request-derived hints the
/// application's <see cref="IExternalTenantResolver"/> was given.
/// </summary>
/// <remarks>
/// <para>
/// Internal by design. Applications do not evict entries directly — they publish
/// <see cref="Events.ExternalTenantConfigurationChanged"/> and the framework reacts, the same way
/// an application publishes <c>CredentialRevoked</c> rather than writing to a denylist. That keeps
/// eviction working identically whether the application runs on one replica or twenty.
/// </para>
/// <para>
/// A resolution that produced nothing is cached too, under a shorter lifetime. Skipping that would
/// leave the resolver — usually a database query — running once per request for any caller
/// supplying unknown tenant identifiers.
/// </para>
/// </remarks>
internal sealed class ExternalTenantCache(ExternalAuthenticationOptions? options) {

	// Unit Separator: cannot occur in a slug, an issuer URI, or an audience, so composing a key
	// from three parts cannot collide with a different triple that happens to concatenate the same.
	private const char KeySeparator = '';

	private readonly ConcurrentDictionary<string, Entry> _entries = new(StringComparer.Ordinal);
	// Null when the External scheme was never composed - a tenant resolver registered on its own.
	// Caching is off in that case, the only sensible reading of "no scheme configured".
	private readonly ExternalAuthenticationOptions _options = options ?? new ExternalAuthenticationOptions();

	internal bool IsEnabled => this._options.TenantCacheDuration > TimeSpan.Zero;

	/// <summary>
	/// The cached outcome for this resolution context, or <see langword="null"/> when there is no
	/// live entry. A hit carrying a <see langword="null"/> configuration is a cached "not found" —
	/// distinguishable from a miss, which is the point of returning a wrapper.
	/// </summary>
	internal Entry? Get(ExternalResolutionContext context) {
		if (!this.IsEnabled) {
			return null;
		}

		if (!this._entries.TryGetValue(KeyFor(context), out var entry)) {
			return null;
		}

		if (entry.ExpiresAt <= DateTimeOffset.UtcNow) {
			this._entries.TryRemove(KeyFor(context), out _);
			return null;
		}

		return entry;
	}

	/// <summary>
	/// Records a resolution outcome. A <see langword="null"/> <paramref name="config"/> is cached as
	/// "not found" under <see cref="ExternalAuthenticationOptions.TenantCacheNotFoundDuration"/>.
	/// </summary>
	internal void Set(ExternalResolutionContext context, ExternalTenantConfig? config) {
		if (!this.IsEnabled) {
			return;
		}

		var lifetime = config is null ? this._options.TenantCacheNotFoundDuration : this._options.TenantCacheDuration;
		if (lifetime <= TimeSpan.Zero) {
			return;
		}

		this.EvictIfSaturated();

		this._entries[KeyFor(context)] = new Entry(
			config,
			DateTimeOffset.UtcNow.Add(lifetime),
			context.TenantSlug);
	}

	/// <summary>
	/// Drops every entry resolved for a tenant slug. Idempotent, and a no-op when nothing matches —
	/// the event that triggers it may be delivered more than once, or to a replica that never
	/// cached that tenant.
	/// </summary>
	/// <remarks>
	/// Entries resolved without a slug (an application keying purely on the token issuer) carry no
	/// slug to match, so they are not evicted here and expire on their own. Supplying
	/// <see cref="ExternalResolutionContext.TenantSlug"/> is what makes immediate invalidation
	/// possible.
	/// </remarks>
	internal void InvalidateTenant(string tenantSlug) {
		if (string.IsNullOrWhiteSpace(tenantSlug)) {
			return;
		}

		foreach (var pair in this._entries) {
			if (string.Equals(pair.Value.TenantSlug, tenantSlug, StringComparison.OrdinalIgnoreCase)) {
				this._entries.TryRemove(pair.Key, out _);
			}
		}
	}

	/// <summary>Drops everything. Used by tests and by a full configuration reload.</summary>
	internal void Clear() => this._entries.Clear();

	internal int Count => this._entries.Count;

	// Expired entries first — they cost nothing to lose. Only if that leaves no room does anything
	// live get dropped, and then it is the entry closest to expiring, which the resolver would have
	// been asked for soonest anyway.
	private void EvictIfSaturated() {
		if (this._entries.Count < this._options.TenantCacheMaxEntries) {
			return;
		}

		var now = DateTimeOffset.UtcNow;
		foreach (var pair in this._entries) {
			if (pair.Value.ExpiresAt <= now) {
				this._entries.TryRemove(pair.Key, out _);
			}
		}

		if (this._entries.Count < this._options.TenantCacheMaxEntries) {
			return;
		}

		foreach (var pair in this._entries.OrderBy(p => p.Value.ExpiresAt).Take(this._entries.Count / 4 + 1)) {
			this._entries.TryRemove(pair.Key, out _);
		}
	}

	// The raw token is deliberately absent: it is a credential, and it is unique per request, so
	// keying on it would both store credentials under themselves and give every request a miss.
	// Audiences are ordered so that the same set presented in a different order is one entry rather
	// than two.
	private static string KeyFor(ExternalResolutionContext context) =>
		string.Concat(
			context.TenantSlug?.ToLowerInvariant(), KeySeparator,
			context.TokenIssuer, KeySeparator,
			string.Join(KeySeparator, context.TokenAudiences.Order(StringComparer.Ordinal)));

	internal sealed record Entry(
		ExternalTenantConfig? Config,
		DateTimeOffset ExpiresAt,
		string? TenantSlug);

}
