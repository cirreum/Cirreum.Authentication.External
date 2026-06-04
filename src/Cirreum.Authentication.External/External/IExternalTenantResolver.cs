namespace Cirreum.Authentication.External;
/// <summary>
/// Resolves tenant identity configuration from a backing store (database, cache, etc.).
/// </summary>
/// <remarks>
/// <para>
/// Implement this interface to provide tenant-specific IdP configuration for BYOID authentication.
/// The resolver is called during authentication to determine how to validate tokens for a given tenant.
/// </para>
/// <para>
/// The resolver is responsible for:
/// <list type="bullet">
///   <item>Looking up tenant configuration by slug or issuer</item>
///   <item>Caching configuration if desired (Cirreum caches JWKS separately)</item>
///   <item>Returning null if the tenant is not found</item>
/// </list>
/// </para>
/// </remarks>
/// <example>
/// <code>
/// public class DatabaseTenantResolver : IExternalTenantResolver {
///     private readonly MyDbContext _db;
///
///     public DatabaseTenantResolver(MyDbContext db) {
///         _db = db;
///     }
///
///     public async Task&lt;ExternalTenantConfig?&gt; ResolveAsync(
///         ExternalResolutionContext context,
///         CancellationToken ct) {
///
///         var tenant = await _db.Tenants
///             .FirstOrDefaultAsync(t => t.Slug == context.TenantSlug, ct);
///
///         if (tenant is null) return null;
///
///         return new ExternalTenantConfig {
///             Slug = tenant.Slug,
///             IsEnabled = tenant.IsEnabled,
///             DisplayName = tenant.Name,
///             MetadataAddress = tenant.OidcMetadataUrl,
///             ValidAudiences = [tenant.Audience]
///         };
///     }
/// }
/// </code>
/// </example>
public interface IExternalTenantResolver {
	/// <summary>
	/// Resolve tenant identity configuration from the provided context.
	/// </summary>
	/// <param name="context">
	/// Context containing hints for resolution (tenant slug, token issuer, etc.).
	/// </param>
	/// <param name="cancellationToken">Cancellation token.</param>
	/// <returns>
	/// The tenant configuration if found, or null if the tenant does not exist.
	/// </returns>
	Task<ExternalTenantConfig?> ResolveAsync(ExternalResolutionContext context, CancellationToken cancellationToken = default);
}