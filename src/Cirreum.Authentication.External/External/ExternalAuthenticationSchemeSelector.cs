namespace Cirreum.Authentication.External;

using Cirreum.AuthenticationProvider;
using Microsoft.AspNetCore.Http;
using Microsoft.Net.Http.Headers;

/// <summary>
/// <see cref="ISchemeSelector"/> for the External (BYOID) authentication scheme.
/// Probes the inbound request for the configured tenant indicator (header / path
/// segment / subdomain) and the standard <c>Authorization: Bearer</c> header; when
/// both are present, routes to the External scheme.
/// </summary>
/// <remarks>
/// <para>
/// Registered at
/// <see cref="SchemeSelectorPriority.External"/> (400) so the stricter "tenant
/// indicator + Bearer both required" probe runs ahead of the generic
/// <c>JwtAudienceSchemeSelector</c> at 900 — External can fail-closed cleanly when
/// only one indicator is present.
/// </para>
/// <para>
/// External does not implement <see cref="IBearerSchemeSelector"/>: it requires a
/// separate tenant indicator alongside the Bearer token, so it doesn't compete in
/// the Bearer-prefix-uniqueness invariant against ApiKey / SessionTicket.
/// </para>
/// </remarks>
public sealed class ExternalAuthenticationSchemeSelector(
	string schemeName,
	ExternalAuthenticationOptions options
) : ISchemeSelector {

	/// <inheritdoc/>
	public int Priority => SchemeSelectorPriority.External;

	/// <inheritdoc/>
	public (bool Matches, string? SchemeName) TrySelect(HttpContext context) {

		if (context is null) {
			return (false, null);
		}

		if (!HasTenantIdentifier(context, options)) {
			return (false, null);
		}

		if (!HasBearerToken(context)) {
			return (false, null);
		}

		return (true, schemeName);
	}

	/// <summary>
	/// Checks for the configured tenant identifier on the inbound request.
	/// Supports header, path-segment, and subdomain identification.
	/// </summary>
	public static bool HasTenantIdentifier(HttpContext context, ExternalAuthenticationOptions options) {
		return options.TenantIdentifierSource switch {
			TenantIdentifierSource.Header => context.Request.Headers.ContainsKey(options.TenantHeaderName),
			TenantIdentifierSource.PathSegment => HasPathSegment(context, options.TenantPathSegmentIndex),
			TenantIdentifierSource.Subdomain => HasSubdomain(context),
			_ => false
		};
	}

	/// <summary>
	/// Checks for an <c>Authorization: Bearer</c> header.
	/// </summary>
	public static bool HasBearerToken(HttpContext context) {
		var authHeader = context.Request.Headers[HeaderNames.Authorization].ToString();
		return !string.IsNullOrEmpty(authHeader)
			&& authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase);
	}

	/// <summary>
	/// Checks whether the inbound request carries indicators that conflict with
	/// other schemes (e.g., both a tenant slug header and an ApiKey header). Used
	/// at composition time to surface configuration conflicts.
	/// </summary>
	public static bool HasConflictingIndicators(
		HttpContext context,
		ExternalAuthenticationOptions options,
		IEnumerable<string> apiKeyHeaderNames) {

		if (options.TenantIdentifierSource == TenantIdentifierSource.Header) {
			var hasTenantHeader = context.Request.Headers.ContainsKey(options.TenantHeaderName);
			var hasApiKeyHeader = apiKeyHeaderNames.Any(h => context.Request.Headers.ContainsKey(h));
			return hasTenantHeader && hasApiKeyHeader;
		}

		return false;
	}

	private static bool HasPathSegment(HttpContext context, int index) {
		var path = context.Request.Path.Value;
		if (string.IsNullOrEmpty(path)) {
			return false;
		}

		var segments = path.TrimStart('/').Split('/', StringSplitOptions.RemoveEmptyEntries);
		return index >= 0 && index < segments.Length;
	}

	private static bool HasSubdomain(HttpContext context) {
		var host = context.Request.Host.Host;
		if (string.IsNullOrEmpty(host)) {
			return false;
		}

		var parts = host.Split('.');
		if (parts.Length < 2) {
			return false;
		}

		// Skip "www" subdomain.
		var subdomain = parts[0];
		return !subdomain.Equals("www", StringComparison.OrdinalIgnoreCase);
	}

}
