namespace Cirreum.Authentication.External.Tests;

using Cirreum.AuthenticationProvider;
using Microsoft.AspNetCore.Http;

/// <summary>
/// Dispatch proofs for <see cref="ExternalAuthenticationSchemeSelector"/>.
/// </summary>
/// <remarks>
/// The selector decides whether a request belongs to External at all. Claiming one it cannot serve
/// denies a request another scheme would have authenticated; declining one it should serve hands the
/// request to a scheme with no tenant context. Both fail silently, which is why the probe requires a
/// tenant indicator <em>and</em> a Bearer token rather than either alone.
/// </remarks>
public sealed class ExternalAuthenticationSchemeSelectorTests {

	private const string Scheme = "customerIdp";

	private static ExternalAuthenticationSchemeSelector Selector(
		Action<ExternalAuthenticationOptions>? configure = null) {

		var options = new ExternalAuthenticationOptions {
			TenantIdentifierSource = TenantIdentifierSource.Header,
			TenantHeaderName = ExternalDefaults.DefaultTenantHeaderName
		};
		configure?.Invoke(options);
		return new ExternalAuthenticationSchemeSelector(Scheme, options);
	}

	private static DefaultHttpContext Request(
		bool tenantHeader = true,
		string? authorization = "Bearer a-token",
		string? path = null,
		string? host = null) {

		var context = new DefaultHttpContext();
		if (tenantHeader) {
			context.Request.Headers[ExternalDefaults.DefaultTenantHeaderName] = "acme";
		}
		if (authorization is not null) {
			context.Request.Headers.Authorization = authorization;
		}
		if (path is not null) {
			context.Request.Path = path;
		}
		if (host is not null) {
			context.Request.Host = new HostString(host);
		}
		return context;
	}

	[Fact]
	public void Both_indicators_present_claims_the_configured_scheme_name() {
		var (matches, schemeName) = Selector().TrySelect(Request());

		matches.Should().BeTrue();
		schemeName.Should().Be(Scheme);
	}

	[Fact]
	public void A_bearer_token_without_a_tenant_indicator_is_not_ours() {
		// The generic JWT selector at a lower priority handles this one.
		var (matches, schemeName) = Selector().TrySelect(Request(tenantHeader: false));

		matches.Should().BeFalse();
		schemeName.Should().BeNull();
	}

	[Fact]
	public void A_tenant_indicator_without_a_bearer_token_is_not_ours() {
		var (matches, _) = Selector().TrySelect(Request(authorization: null));

		matches.Should().BeFalse();
	}

	[Theory]
	[InlineData("bearer a-token")]
	[InlineData("BEARER a-token")]
	public void The_bearer_prefix_is_matched_case_insensitively(string authorization) {
		// RFC 9110 §11.1: the auth scheme token is case-insensitive.
		Selector().TrySelect(Request(authorization: authorization)).Matches.Should().BeTrue();
	}

	[Theory]
	[InlineData("Basic dXNlcjpwYXNz")]
	[InlineData("a-token")]
	[InlineData("")]
	public void A_non_bearer_authorization_header_is_not_ours(string authorization) {
		Selector().TrySelect(Request(authorization: authorization)).Matches.Should().BeFalse();
	}

	[Fact]
	public void The_path_segment_source_claims_a_request_carrying_that_segment() {
		var selector = Selector(o => o.TenantIdentifierSource = TenantIdentifierSource.PathSegment);

		selector.TrySelect(Request(tenantHeader: false, path: "/acme/resource"))
			.Matches.Should().BeTrue();
	}

	[Fact]
	public void The_path_segment_source_declines_a_path_too_short_to_carry_it() {
		var selector = Selector(o => {
			o.TenantIdentifierSource = TenantIdentifierSource.PathSegment;
			o.TenantPathSegmentIndex = 2;
		});

		selector.TrySelect(Request(tenantHeader: false, path: "/acme/resource"))
			.Matches.Should().BeFalse();
	}

	[Theory]
	[InlineData("acme.example.com", true)]
	[InlineData("www.example.com", false)]
	[InlineData("example", false)]
	public void The_subdomain_source_ignores_www_and_bare_hosts(string host, bool expected) {
		var selector = Selector(o => o.TenantIdentifierSource = TenantIdentifierSource.Subdomain);

		selector.TrySelect(Request(tenantHeader: false, host: host)).Matches.Should().Be(expected);
	}

	[Fact]
	public void It_runs_ahead_of_the_generic_jwt_selector() {
		// The ordering is the point: External's stricter probe must be asked before a selector that
		// claims any Bearer token, or a tenant request is answered by the wrong scheme.
		Selector().Priority.Should().Be(SchemeSelectorPriority.External);
		Selector().Priority.Should().BeLessThan(SchemeSelectorPriority.Audience);
	}

	[Fact]
	public void A_null_context_is_declined_rather_than_thrown_on() {
		Selector().TrySelect(null!).Matches.Should().BeFalse();
	}

	[Fact]
	public void Conflicting_tenant_and_api_key_headers_are_detectable() {
		var context = Request();
		context.Request.Headers["X-Api-Key"] = "some-key";

		var options = new ExternalAuthenticationOptions {
			TenantIdentifierSource = TenantIdentifierSource.Header,
			TenantHeaderName = ExternalDefaults.DefaultTenantHeaderName
		};

		ExternalAuthenticationSchemeSelector
			.HasConflictingIndicators(context, options, ["X-Api-Key"])
			.Should().BeTrue();

		ExternalAuthenticationSchemeSelector
			.HasConflictingIndicators(Request(), options, ["X-Api-Key"])
			.Should().BeFalse();
	}
}
