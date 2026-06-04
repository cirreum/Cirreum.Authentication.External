namespace Cirreum.Authentication.External;

using Microsoft.AspNetCore.Http;

/// <summary>
/// Default implementation of <see cref="ITenantIdentifierExtractor"/>.
/// </summary>
public class TenantIdentifierExtractor(
	ExternalAuthenticationOptions options
) : ITenantIdentifierExtractor {

	public string? Extract(HttpContext context) {
		return options.TenantIdentifierSource switch {
			TenantIdentifierSource.Header => this.ExtractFromHeader(context),
			TenantIdentifierSource.PathSegment => this.ExtractFromPath(context, options.TenantPathSegmentIndex),
			TenantIdentifierSource.Subdomain => ExtractFromSubdomain(context),
			_ => null
		};
	}

	public string? ExtractFromPath(HttpContext context, int segmentIndex) {
		var path = context.Request.Path.Value;
		if (string.IsNullOrEmpty(path)) {
			return null;
		}

		// Remove leading slash and split
		var segments = path.TrimStart('/').Split('/', StringSplitOptions.RemoveEmptyEntries);

		if (segmentIndex < 0 || segmentIndex >= segments.Length) {
			return null;
		}

		return segments[segmentIndex];
	}

	private string? ExtractFromHeader(HttpContext context) {
		if (context.Request.Headers.TryGetValue(options.TenantHeaderName, out var values)) {
			return values.FirstOrDefault();
		}
		return null;
	}

	private static string? ExtractFromSubdomain(HttpContext context) {
		var host = context.Request.Host.Host;
		if (string.IsNullOrEmpty(host)) {
			return null;
		}

		// Split by dots and take the first segment as the tenant
		var parts = host.Split('.');
		if (parts.Length < 2) {
			// No subdomain (e.g., localhost or single-part domain)
			return null;
		}

		// First part is the subdomain/tenant
		// Skip common prefixes like "www"
		var subdomain = parts[0];
		if (subdomain.Equals("www", StringComparison.OrdinalIgnoreCase)) {
			return parts.Length > 2 ? parts[1] : null;
		}

		return subdomain;
	}

}