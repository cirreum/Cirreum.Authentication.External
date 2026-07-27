namespace Cirreum.Authentication.External.Tests;

using Cirreum.Authentication.Events;
using Cirreum.Authentication.External;

/// <summary>
/// Proofs for tenant-resolution caching. The resolver runs on every authenticated request, so for
/// the common database-backed implementation these decide whether that is one query per request or
/// one per cache lifetime — and, for the negative-caching cases, whether an unknown tenant
/// identifier costs a query every time it is supplied.
/// </summary>
public sealed class ExternalTenantCacheTests {

	private static ExternalTenantCache Cache(Action<ExternalAuthenticationOptions>? configure = null) {
		var options = new ExternalAuthenticationOptions();
		configure?.Invoke(options);
		return new ExternalTenantCache(options);
	}

	private static ExternalResolutionContext Context(
		string? slug = "acme",
		string? issuer = "https://idp.acme.example",
		string? audience = "api://acme",
		string? rawToken = "token-1") =>
		new() {
			TenantSlug = slug,
			TokenIssuer = issuer,
			TokenAudiences = audience is null ? [] : [audience],
			RawToken = rawToken
		};

	[Fact]
	public void The_same_audiences_in_a_different_order_are_one_entry() {
		// The key is composed from the audiences, so an unordered join would give a token presenting
		// [a, b] and one presenting [b, a] separate entries for the same tenant.
		var cache = Cache(o => o.TenantCacheDuration = TimeSpan.FromMinutes(5));
		var forward = new ExternalResolutionContext {
			TenantSlug = "acme", TokenIssuer = "https://idp.acme.example", TokenAudiences = ["a", "b"]
		};
		var reversed = forward with { TokenAudiences = ["b", "a"] };

		cache.Set(forward, Config());

		cache.Get(reversed).Should().NotBeNull();
		cache.Count.Should().Be(1);
	}

	private static ExternalTenantConfig Config(string slug = "acme", bool enabled = true) =>
		new() {
			Slug = slug,
			IsEnabled = enabled,
			DisplayName = slug,
			MetadataAddress = $"https://idp.{slug}.example/.well-known/openid-configuration",
			ValidAudiences = [$"api://{slug}"]
		};

	/// <summary>A resolver that counts calls, so a cache hit is observable as a call that did not happen.</summary>
	private sealed class CountingResolver(ExternalTenantConfig? result) : IExternalTenantResolver {
		public int Calls { get; private set; }
		public Task<ExternalTenantConfig?> ResolveAsync(
			ExternalResolutionContext context, CancellationToken cancellationToken = default) {
			this.Calls++;
			return Task.FromResult(result);
		}
	}

	// -------------------------------------------------------------------------
	// Off by default
	// -------------------------------------------------------------------------

	[Fact]
	public async Task Caching_is_off_unless_a_duration_is_configured() {
		// The default sits on an authentication path: reusing a tenant's configuration widens the
		// window in which a disabled tenant still authenticates, so it is opted into rather than
		// inherited.
		var inner = new CountingResolver(Config());
		var resolver = new CachingExternalTenantResolver(inner, Cache());

		await resolver.ResolveAsync(Context());
		await resolver.ResolveAsync(Context());

		inner.Calls.Should().Be(2);
	}

	// -------------------------------------------------------------------------
	// Positive and negative caching
	// -------------------------------------------------------------------------

	[Fact]
	public async Task A_resolved_tenant_is_reused_within_the_cache_duration() {
		var inner = new CountingResolver(Config());
		var resolver = new CachingExternalTenantResolver(
			inner, Cache(o => o.TenantCacheDuration = TimeSpan.FromMinutes(5)));

		var first = await resolver.ResolveAsync(Context());
		var second = await resolver.ResolveAsync(Context());

		inner.Calls.Should().Be(1);
		second.Should().BeSameAs(first);
	}

	[Fact]
	public async Task A_not_found_result_is_cached_too() {
		// Without this, a caller supplying unknown tenant identifiers costs one resolver call -
		// typically one database query - per request, with no upper bound.
		var inner = new CountingResolver(null);
		var resolver = new CachingExternalTenantResolver(
			inner, Cache(o => o.TenantCacheDuration = TimeSpan.FromMinutes(5)));

		var first = await resolver.ResolveAsync(Context(slug: "does-not-exist"));
		var second = await resolver.ResolveAsync(Context(slug: "does-not-exist"));

		first.Should().BeNull();
		second.Should().BeNull();
		inner.Calls.Should().Be(1, "a cached miss must be distinguishable from no cache entry");
	}

	[Fact]
	public async Task A_faulting_resolver_is_never_cached() {
		// A store that is temporarily unavailable must be retried, not remembered as a failure.
		var cache = Cache(o => o.TenantCacheDuration = TimeSpan.FromMinutes(5));
		var resolver = new CachingExternalTenantResolver(new ThrowingResolver(), cache);

		await Assert.ThrowsAsync<InvalidOperationException>(() => resolver.ResolveAsync(Context()));

		cache.Count.Should().Be(0);
	}

	private sealed class ThrowingResolver : IExternalTenantResolver {
		public Task<ExternalTenantConfig?> ResolveAsync(
			ExternalResolutionContext context, CancellationToken cancellationToken = default) =>
			throw new InvalidOperationException("tenant store unavailable");
	}

	// -------------------------------------------------------------------------
	// Key composition
	// -------------------------------------------------------------------------

	[Fact]
	public async Task The_raw_token_is_not_part_of_the_cache_key() {
		// It is a credential, and it is unique per request — keying on it would store credentials
		// under themselves and give every request a miss, defeating the cache entirely.
		var inner = new CountingResolver(Config());
		var resolver = new CachingExternalTenantResolver(
			inner, Cache(o => o.TenantCacheDuration = TimeSpan.FromMinutes(5)));

		await resolver.ResolveAsync(Context(rawToken: "token-1"));
		await resolver.ResolveAsync(Context(rawToken: "a-completely-different-token"));

		inner.Calls.Should().Be(1);
	}

	[Fact]
	public async Task Different_tenants_do_not_share_an_entry() {
		var inner = new CountingResolver(Config());
		var resolver = new CachingExternalTenantResolver(
			inner, Cache(o => o.TenantCacheDuration = TimeSpan.FromMinutes(5)));

		await resolver.ResolveAsync(Context(slug: "acme", issuer: "https://idp.acme.example"));
		await resolver.ResolveAsync(Context(slug: "globex", issuer: "https://idp.globex.example"));

		inner.Calls.Should().Be(2);
	}

	// -------------------------------------------------------------------------
	// Invalidation
	// -------------------------------------------------------------------------

	[Fact]
	public async Task The_event_handler_drops_the_tenant_so_the_next_request_re_resolves() {
		var inner = new CountingResolver(Config());
		var cache = Cache(o => o.TenantCacheDuration = TimeSpan.FromMinutes(5));
		var resolver = new CachingExternalTenantResolver(inner, cache);
		var handler = new ExternalTenantCacheInvalidationHandler(cache);

		await resolver.ResolveAsync(Context());
		await handler.HandleAsync(new ExternalTenantConfigurationChanged("acme", DateTimeOffset.UtcNow));
		await resolver.ResolveAsync(Context());

		inner.Calls.Should().Be(2, "the entry was dropped, so the store is authoritative again");
	}

	[Fact]
	public async Task Invalidation_is_idempotent_and_safe_for_an_unknown_tenant() {
		// The event may be delivered more than once, and to a replica that never cached the tenant.
		var cache = Cache(o => o.TenantCacheDuration = TimeSpan.FromMinutes(5));
		var handler = new ExternalTenantCacheInvalidationHandler(cache);

		await handler.HandleAsync(new ExternalTenantConfigurationChanged("never-seen", DateTimeOffset.UtcNow));
		await handler.HandleAsync(new ExternalTenantConfigurationChanged("never-seen", DateTimeOffset.UtcNow));

		cache.Count.Should().Be(0);
	}

	[Fact]
	public async Task Invalidation_leaves_other_tenants_alone() {
		var cache = Cache(o => o.TenantCacheDuration = TimeSpan.FromMinutes(5));
		var acme = new CachingExternalTenantResolver(new CountingResolver(Config("acme")), cache);
		var globex = new CachingExternalTenantResolver(new CountingResolver(Config("globex")), cache);

		await acme.ResolveAsync(Context(slug: "acme"));
		await globex.ResolveAsync(Context(slug: "globex", issuer: "https://idp.globex.example"));

		await new ExternalTenantCacheInvalidationHandler(cache)
			.HandleAsync(new ExternalTenantConfigurationChanged("acme", DateTimeOffset.UtcNow));

		cache.Count.Should().Be(1);
	}

	// -------------------------------------------------------------------------
	// Bounded
	// -------------------------------------------------------------------------

	[Fact]
	public async Task The_cache_stays_bounded_under_caller_supplied_tenant_identifiers() {
		// Keys derive from request-supplied values, so the population is caller-influenced. On
		// saturation this evicts rather than refusing to resolve — the opposite of a revocation
		// denylist, and deliberately: a forgotten cache entry costs a query, a forgotten denylist
		// entry re-admits a revoked credential.
		var cache = Cache(o => {
			o.TenantCacheDuration = TimeSpan.FromMinutes(5);
			o.TenantCacheMaxEntries = 20;
		});
		var resolver = new CachingExternalTenantResolver(new CountingResolver(Config()), cache);

		for (var i = 0; i < 200; i++) {
			await resolver.ResolveAsync(Context(slug: $"tenant-{i}", issuer: $"https://idp{i}.example"));
		}

		cache.Count.Should().BeLessThanOrEqualTo(20);
	}

}
