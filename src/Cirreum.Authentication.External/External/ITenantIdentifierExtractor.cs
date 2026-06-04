namespace Cirreum.Authentication.External;

using Microsoft.AspNetCore.Http;

/// <summary>
/// Extracts tenant identifiers from HTTP requests based on configured source.
/// </summary>
public interface ITenantIdentifierExtractor {
	/// <summary>
	/// Extract the tenant identifier from the request.
	/// </summary>
	/// <param name="context">The HTTP context.</param>
	/// <returns>The tenant identifier, or null if not found.</returns>
	string? Extract(HttpContext context);

	/// <summary>
	/// Extract the tenant identifier from a specific path segment for validation.
	/// </summary>
	/// <param name="context">The HTTP context.</param>
	/// <param name="segmentIndex">The 0-based path segment index.</param>
	/// <returns>The tenant identifier from the path, or null if not found.</returns>
	string? ExtractFromPath(HttpContext context, int segmentIndex);
}