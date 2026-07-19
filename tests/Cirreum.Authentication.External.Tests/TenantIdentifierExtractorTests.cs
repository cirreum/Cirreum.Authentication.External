namespace Cirreum.Authentication.External.Tests;

using Microsoft.AspNetCore.Http;

/// <summary>
/// Proofs for the default <see cref="TenantIdentifierExtractor"/>: each
/// <see cref="TenantIdentifierSource"/> extracts from its own request surface and returns
/// <see langword="null"/> (never throws) when the identifier is absent or malformed.
/// </summary>
public sealed class TenantIdentifierExtractorTests {

	private static TenantIdentifierExtractor CreateExtractor(Action<ExternalAuthenticationOptions>? configure = null) {
		var options = new ExternalAuthenticationOptions();
		configure?.Invoke(options);
		return new TenantIdentifierExtractor(options);
	}

	[Fact]
	public void Header_source_extracts_the_default_header() {
		var extractor = CreateExtractor();
		var context = new DefaultHttpContext();
		context.Request.Headers["X-Tenant-Slug"] = "acme";

		extractor.Extract(context).Should().Be("acme");
	}

	[Fact]
	public void Header_source_honors_a_custom_header_name() {
		var extractor = CreateExtractor(o => o.TenantHeaderName = "X-Partner-Tenant");
		var context = new DefaultHttpContext();
		context.Request.Headers["X-Partner-Tenant"] = "acme";

		extractor.Extract(context).Should().Be("acme");
	}

	[Fact]
	public void Header_source_returns_null_when_the_header_is_absent() {
		var extractor = CreateExtractor();

		extractor.Extract(new DefaultHttpContext()).Should().BeNull();
	}

	[Theory]
	[InlineData("/acme/resource", 0, "acme")]
	[InlineData("/api/acme/resource", 1, "acme")]
	[InlineData("/acme", 3, null)]
	[InlineData("/acme", -1, null)]
	[InlineData("", 0, null)]
	public void PathSegment_source_extracts_by_index(string path, int index, string? expected) {
		var extractor = CreateExtractor(o => {
			o.TenantIdentifierSource = TenantIdentifierSource.PathSegment;
			o.TenantPathSegmentIndex = index;
		});
		var context = new DefaultHttpContext();
		context.Request.Path = path;

		extractor.Extract(context).Should().Be(expected);
	}

	[Theory]
	[InlineData("acme.example.com", "acme")]
	[InlineData("www.acme.example.com", "acme")]
	[InlineData("localhost", null)]
	public void Subdomain_source_extracts_the_first_label(string host, string? expected) {
		var extractor = CreateExtractor(o => o.TenantIdentifierSource = TenantIdentifierSource.Subdomain);
		var context = new DefaultHttpContext();
		context.Request.Host = new HostString(host);

		extractor.Extract(context).Should().Be(expected);
	}
}
